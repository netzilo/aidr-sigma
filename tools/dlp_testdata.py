#!/usr/bin/env python3
"""Fake PII corpus for exercising DLP / redaction rules.

Values are assembled at runtime rather than written as literals, so this file
survives being written or read through a DLP proxy that redacts PII in
transit. Every value is synthetic:
  - card numbers use the payment processors' documented test prefixes and a
    computed Luhn check digit
  - SSNs use either a number the SSA voided after it was printed in public
    (area 78, the Woolworth wallet card) or a range the SSA never issues
    (area 000, 666, 9xx)
  - phone numbers are in the 555-0100..0199 block reserved for fiction

Usage:
  dlp_testdata.py                    # write the corpus as JSONL to stdout
  dlp_testdata.py --check RULE.yml   # run the rule's detection over the corpus
"""
import argparse
import json
import re
import sys

import yaml


def luhn(body):
    """Append the Luhn check digit to a string of digits."""
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return body + str((10 - total % 10) % 10)


def card(prefix, length):
    return luhn(prefix + "1" * (length - len(prefix) - 1))


def group(digits, sizes, sep):
    out, i = [], 0
    for n in sizes:
        out.append(digits[i:i + n])
        i += n
    return sep.join(out)


def ssn(area, grp, serial, sep="-"):
    return f"{area:03d}{sep}{grp:02d}{sep}{serial:04d}"


def phone(n):
    return f"(555) {100 + n:04d}"


VISA = card("4", 16)
MC = card("5" + "5", 16)
AMEX = card("3" + "7", 15)
DISC = card("6" + "011", 16)
V = {
    "visa": group(VISA, (4, 4, 4, 4), " "),
    "visa_dash": group(VISA, (4, 4, 4, 4), "-"),
    "visa_plain": VISA,
    "visa_odd": group(VISA, (3, 5, 4, 4), " "),
    "mc": group(MC, (4, 4, 4, 4), " "),
    "mc_dash": group(MC, (4, 4, 4, 4), "-"),
    "amex": AMEX,
    "amex_spaced": group(AMEX, (4, 6, 5), " "),
    "disc": group(DISC, (4, 4, 4, 4), " "),
    "disc_plain": DISC,
    "ssn": ssn(78, 5, 1120),
    "ssn_space": ssn(78, 5, 1120, " "),
    "ssn_nosep": ssn(78, 5, 1120, ""),
    "ssn_dots": ssn(78, 5, 1120, "."),
    "ssn_000": ssn(0, 12, 3456),
    "ssn_666": ssn(666, 12, 3456),
    "ssn_9xx": ssn(912, 34, 5678),
    "ssn_zero": ssn(0, 0, 0),
    "phone": phone(23),
    "masked": "*" * 4 + VISA[-4:],
}

# expect: "redact" = rule should fire, "pass" = rule should stay quiet,
# "gap" = real-looking PII the rule is known to miss (documents a limitation).
CASES = [
    # --- credit cards that should be redacted
    ("cc_visa", "redact", "Charge it to {visa}, exp 12/29."),
    ("cc_visa_dash", "redact", "Card on file: {visa_dash}"),
    ("cc_visa_plain", "redact", "card={visa_plain}"),
    ("cc_mc", "redact", "Use my Mastercard {mc} please"),
    ("cc_mc_dash", "redact", "MC {mc_dash} for the renewal"),
    ("cc_amex", "redact", "Amex {amex}, CVV 1234"),
    ("cc_discover", "redact", "Discover card {disc}"),
    ("cc_discover_plain", "redact", "{disc_plain} is the backup card"),
    ("cc_in_json", "redact", '{{"customer":"Jane Roe","pan":"{visa_plain}"}}'),
    ("cc_in_tool_arg", "redact", "curl -d 'card={mc_dash}' https://billing.internal/charge"),

    # --- SSNs that should be redacted
    ("ssn_dash", "redact", "My social is {ssn}."),
    ("ssn_space", "redact", "SSN {ssn_space} for the background check"),
    ("ssn_labeled", "redact", "Social Security Number: {ssn}"),
    ("ssn_labeled_hash", "redact", "S.S.N # {ssn}"),
    ("ssn_csv", "redact", "name,dob,ssn\nJohn Doe,1980-04-01,{ssn}"),
    ("ssn_negated", "redact", "My SSN is not {ssn}"),
    ("mixed_record", "redact",
     "Jane Roe, 742 Evergreen Terrace, Springfield, {phone}, SSN {ssn}, Visa {visa}"),

    # --- must NOT be redacted (invalid ranges, look-alikes)
    ("ssn_area_000", "pass", "ID {ssn_000}"),
    ("ssn_area_666", "pass", "ID {ssn_666}"),
    ("ssn_area_9xx_itin", "pass", "ITIN {ssn_9xx}"),
    ("phone_555", "pass", "Call {phone} after 5pm"),
    ("date", "pass", "Meeting on 2026-10-13 at 14:30"),
    ("order_id", "pass", "Order #4111-2026 shipped"),
    ("short_digits", "pass", "Ticket 4111 1111 1111"),
    ("uuid", "pass", "id 3f9c1d84-6f3b-1c92-b7c4-1f2e7c3b1f42"),
    ("version", "pass", "upgraded to 123.45.6789"),

    # --- filter_placeholders exemptions (rule should stay quiet by design)
    ("placeholder_word", "pass", "sample SSN {ssn} for the docs"),
    ("placeholder_mask", "pass", "Card {masked} on file"),
    ("placeholder_zero", "pass", "SSN {ssn_zero}"),

    # --- known gaps: PII the current patterns do not catch
    ("gap_ssn_no_sep", "gap", "SSN: {ssn_nosep}"),
    ("gap_ssn_dots", "gap", "SSN {ssn_dots}"),
    ("gap_cc_odd_grouping", "gap", "card {visa_odd}"),
    ("gap_amex_spaced", "gap", "Amex {amex_spaced}"),
    ("gap_placeholder_bypass", "gap", "Example of my real data: SSN {ssn}, Visa {visa}"),
]


def corpus():
    for cid, expect, tmpl in CASES:
        yield cid, expect, tmpl.format(**V)


def load_detection(path):
    with open(path) as f:
        rule = yaml.safe_load(f)
    det = rule["detection"]
    sel = [re.compile(p) for p in det["selection"]["content|re"]]
    flt = [re.compile(p) for p in det.get("filter_placeholders", {}).get("content|re", [])]
    return sel, flt


def fires(text, sel, flt):
    return any(p.search(text) for p in sel) and not any(p.search(text) for p in flt)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", metavar="RULE.yml", help="evaluate a rule's content|re detection over the corpus")
    args = ap.parse_args()

    if not args.check:
        for cid, expect, text in corpus():
            print(json.dumps({"id": cid, "expect": expect, "content": text}))
        return 0

    sel, flt = load_detection(args.check)
    failures = 0
    for cid, expect, text in corpus():
        hit = fires(text, sel, flt)
        ok = hit if expect == "redact" else not hit
        status = "ok" if ok else ("FAIL" if expect != "gap" else "FIXED")
        if expect != "gap" and not ok:
            failures += 1
        print(f"{status:5} {expect:6} {'fires' if hit else 'quiet':5} {cid}")
    print(f"\n{len(CASES)} cases, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

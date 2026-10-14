#!/usr/bin/env python3
"""migrate_v2 — move AIDR rule scripts from the process-keyed engine to the
session-keyed behavior engine.

What changed in the engine:

  nodes      process://<path>            → session://<kind>/<key> (one per acting instance)
                                           program://<path>        (what a session runs as)
  roots      caller_pid + proc_instance  → session()   (the triggering session)
  lineage    proc_lineage(pid, start)    → lineage()   (self → parent → … → root)
  log        query_events(actor_pid=…)   → events(session=…)
  spawn      EXECUTE_PROCESS             → SPAWNED
  row keys   actor_path / actor_pid / parent_pid
                                         → program / session_id / parent_session
  session    actor_path / actor_pid / parent_pid   (lineage dicts)
  dicts                                  → path / id / parent
  meta       caller_pid                  → session (a node id)
  rules      new `requires:` lists the capabilities a host must produce

The script rewrites the idioms it can prove and leaves the rest for
tools/rulelint.py to flag. Run it once over ai_agent/, then lint.

Usage:
    python3 tools/migrate_v2.py [path ...]      # default: ai_agent/
    python3 tools/migrate_v2.py --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# ── Capability inference ─────────────────────────────────────────────────────

CATEGORY_CAPS = {
    "execute_process": {"process_exec"},
    "file_read": {"file_activity"}, "file_write": {"file_activity"},
    "file_create": {"file_activity"}, "file_delete": {"file_activity"},
    "file_rename": {"file_activity"}, "file_op": {"file_activity"},
    "llm_request": {"llm"}, "llm_response": {"llm"},
    "tool_request": {"tool"}, "tool_input": {"tool"}, "tool_response": {"tool"},
    "tool_output": {"tool"}, "tool_description": {"tool"}, "gateway_description": {"tool"},
    "prompt_request": {"tool"}, "prompt_response": {"tool"},
    "sampling_request": {"tool"}, "sampling_response": {"tool"},
    "http_request": {"http"}, "http_response": {"http"},
    "connects": {"connect"},
    "skill_acquired": {"skill"},
    "llm_tool_call": {"tool"}, "llm_tool_result": {"tool"},
}

EVENT_TYPE_CAPS = {
    "execute_process": "process_exec", "llm_request": "llm", "llm_response": "llm",
    "tool_call": "tool", "tool_response": "tool", "http_request": "http",
    "connects": "connect", "skill_acquired": "skill", "llm_tool_call": "tool",
    "llm_tool_result": "tool", "file_read": "file_activity", "file_write": "file_activity",
    "file_create": "file_activity", "file_delete": "file_activity", "file_rename": "file_activity",
}

SCRIPT_CAPS = [
    (re.compile(r"\bSPAWNED\b|\blineage\(|\bchildren\(|\bEXECUTE_PROCESS\b|\bproc_lineage\("), "process_exec"),
    (re.compile(r"\b(READ|WRITE|CREATE|DELETE|RENAME)_FILE\b|\bfs_activity\("), "file_activity"),
    (re.compile(r"\bLLM_(REQUEST|RESPONSE)\b"), "llm"),
    (re.compile(r"\bTOOL_(CALL|RESULT)\b"), "tool"),
    (re.compile(r"\bHTTP_(REQUEST|RESPONSE)\b"), "http"),
    (re.compile(r"\bCONNECTS\b"), "connect"),
    (re.compile(r"\bACQUIRED_SKILL\b"), "skill"),
]

CAP_ORDER = ["session", "process_exec", "file_activity", "llm", "tool", "http", "connect", "skill"]


def infer_caps(doc_text: str, script: str) -> list[str]:
    caps: set[str] = set()
    m = re.search(r"^\s*category:\s*([A-Za-z_]+)", doc_text, re.M)
    if m:
        caps |= CATEGORY_CAPS.get(m.group(1).lower(), set())
    for et in re.findall(r"^\s*event_type:\s*([A-Za-z_]+)", doc_text, re.M):
        if et.lower() in EVENT_TYPE_CAPS:
            caps.add(EVENT_TYPE_CAPS[et.lower()])
    for et in re.findall(r"^\s*event_type:\s*\n((?:\s*-\s*[A-Za-z_]+\n)+)", doc_text, re.M):
        for item in re.findall(r"-\s*([A-Za-z_]+)", et):
            if item.lower() in EVENT_TYPE_CAPS:
                caps.add(EVENT_TYPE_CAPS[item.lower()])
    for rx, cap in SCRIPT_CAPS:
        if rx.search(script):
            caps.add(cap)
    return [c for c in CAP_ORDER if c in caps]


# ── Script rewriting ─────────────────────────────────────────────────────────

IDENT = r"[A-Za-z_][A-Za-z0-9_]*"


def _var_kinds(script: str) -> dict[str, str]:
    """Infer which variables hold session dicts ('session') and which hold
    event rows ('row'), from how they are assigned and iterated."""
    kinds: dict[str, str] = {}
    # direct assignments
    for m in re.finditer(rf"^\s*({IDENT})\s*=\s*(proc_instance|session)\(", script, re.M):
        kinds[m.group(1)] = "session"
    for m in re.finditer(rf"^\s*({IDENT})\s*=\s*(proc_lineage|lineage|sessions|children)\(", script, re.M):
        kinds[m.group(1)] = "sessions"
    for m in re.finditer(rf"^\s*({IDENT})\s*=\s*(query_events|events)\(", script, re.M):
        kinds[m.group(1)] = "rows"
    for m in re.finditer(rf"^\s*({IDENT})\s*=\s*\[\]\s*(#.*)?$", script, re.M):
        kinds.setdefault(m.group(1), "")
    # lists filled by append from a rows source
    for m in re.finditer(rf"^\s*for\s+({IDENT})\s+in\s+(?:query_events|events)\(", script, re.M):
        kinds[m.group(1)] = "row"
    for m in re.finditer(rf"^\s*for\s+({IDENT})\s+in\s+(?:proc_lineage|lineage|sessions|children)\(", script, re.M):
        kinds[m.group(1)] = "session"
    for m in re.finditer(rf"^\s*for\s+({IDENT})\s+in\s+graph\(type=\"Process\"\)", script, re.M):
        kinds[m.group(1)] = "session"
    # propagate: for x in <var>, list.append(x), x = lst[i], x = y. A name
    # that is reused for both kinds is left unknown (the manual pass sorts it
    # out), so a kind is never flipped once set.
    def learn(name: str, kind: str) -> bool:
        if not kind or name in kinds and kinds[name]:
            if kinds.get(name) and kinds[name] != kind:
                kinds[name] = "?"
            return False
        kinds[name] = kind
        return True

    for _ in range(8):
        changed = False
        for m in re.finditer(rf"^\s*for\s+({IDENT})\s+in\s+({IDENT})\s*(?:\[[^\]]*\])?\s*:", script, re.M):
            k = kinds.get(m.group(2), "")
            changed |= learn(m.group(1), {"rows": "row", "sessions": "session"}.get(k, ""))
        for m in re.finditer(rf"^\s*({IDENT})\.append\(({IDENT})\)", script, re.M):
            k = kinds.get(m.group(2), "")
            changed |= learn(m.group(1), {"row": "rows", "session": "sessions"}.get(k, ""))
        for m in re.finditer(rf"^\s*({IDENT})\s*=\s*({IDENT})\[[^\]]+\]\s*$", script, re.M):
            k = kinds.get(m.group(2), "")
            changed |= learn(m.group(1), {"rows": "row", "sessions": "session"}.get(k, ""))
        for m in re.finditer(rf"^\s*({IDENT})\s*=\s*({IDENT})\s*$", script, re.M):
            changed |= learn(m.group(1), kinds.get(m.group(2), ""))
        if not changed:
            break
    return kinds


def _balanced_call(script: str, name: str):
    """Yield (start, end, inner) for every call name(...) with balanced parens."""
    for m in re.finditer(rf"\b{name}\(", script):
        depth, i = 1, m.end()
        while i < len(script) and depth:
            c = script[i]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            i += 1
        yield m.start(), i, script[m.end():i - 1]


def _first_ident(expr: str) -> str:
    m = re.match(rf"\s*(?:int|to_int|toi|tsint|safe_int|str)\(\s*({IDENT})", expr) or re.match(rf"\s*({IDENT})", expr)
    return m.group(1) if m else ""


def rewrite_script(script: str, notes: list[str]) -> str:
    s = script

    # proc_instance(cp, ts) → session(cp) ; proc_instance() → session()
    out, last = [], 0
    for start, end, inner in _balanced_call(s, "proc_instance"):
        out.append(s[last:start])
        arg = _first_ident(inner)
        out.append(f"session({arg})" if arg else "session()")
        last = end
    out.append(s[last:])
    s = "".join(out)

    # proc_lineage(int(inst["actor_pid"]), int(inst["actor_start"])) → lineage(inst["id"])
    out, last = [], 0
    for start, end, inner in _balanced_call(s, "proc_lineage"):
        out.append(s[last:start])
        var = _first_ident(inner)
        out.append(f'lineage({var}["id"])' if var else "lineage()")
        last = end
    out.append(s[last:])
    s = "".join(out)

    # caller_pid anchors: cp = int(meta.get("caller_pid", "0")) → cp = meta.get("session", "")
    s = re.sub(rf'(?:int|to_int|toi|tsint|safe_int)\(\s*meta\.get\("caller_pid"[^)]*\)\s*\)', 'meta.get("session", "")', s)
    s = re.sub(rf'(?:int|to_int|toi|tsint|safe_int)\(\s*meta\["caller_pid"\]\s*\)', 'meta.get("session", "")', s)
    s = re.sub(r'meta\.get\("caller_pid"[^)]*\)', 'meta.get("session", "")', s)
    s = re.sub(r'meta\["caller_pid"\]', 'meta.get("session", "")', s)
    # the zero checks that followed
    for var in set(re.findall(rf'^\s*({IDENT})\s*=\s*meta\.get\("session", ""\)', s, re.M)):
        s = re.sub(rf"\b{var}\s*(?:==|<=)\s*0\b", f'{var} == ""', s)
        s = re.sub(rf"\b{var}\s*>\s*0\b", f'{var} != ""', s)
        s = re.sub(rf"\bnot\s+{var}\b", f'{var} == ""', s)

    # query_events(...) → events(...), actor_pid= → session=, drop actor_start=
    out, last = [], 0
    for start, end, inner in _balanced_call(s, "query_events"):
        out.append(s[last:start])
        inner2 = re.sub(r"\bactor_pid\s*=\s*(?:int|to_int|toi|str)\(\s*([^()]+?)\s*\)", r"session=\1", inner)
        inner2 = re.sub(r"\bactor_pid\s*=", "session=", inner2)
        inner2 = re.sub(r",\s*actor_start\s*=\s*(?:[^,()]+|\([^()]*\))", "", inner2)
        out.append(f"events({inner2})")
        last = end
    out.append(s[last:])
    s = "".join(out)

    # EXECUTE_PROCESS → SPAWNED
    s = s.replace("EXECUTE_PROCESS", "SPAWNED")

    # graph(type="Process") loops → sessions(agent=True) when the body filters on agent
    s = re.sub(r'graph\(type="Process"\)', 'graph(type="Session")', s)
    s = re.sub(
        r'for\s+(' + IDENT + r')\s+in\s+graph\(type="Session"\)\s*:\s*\n(\s*)if\s+\1\.get\("agent",\s*"0"\)\s*!=\s*"1"\s*:\s*\n\s*continue\s*\n',
        r"for \1 in sessions(agent=True):\n",
        s,
    )
    s = re.sub(r'graph\(type="Session"\)', "sessions()", s)
    s = re.sub(r'graph\(type="Agent"\)', "sessions(agent=True)", s)

    # A local named like a builtin hides it for the whole function in
    # Starlark: rename the variable, keep the call.
    for name in ("session", "lineage", "children", "sessions", "programs", "events"):
        if re.search(rf"^\s*{name}\s*=[^=]", s, re.M):
            s = re.sub(rf"\b{name}\b(?!\s*\()", f"{name}_", s)
            # `x = lineage_` on the left of an assignment that calls the builtin
            s = re.sub(rf"\b{name}_\s*=\s*{name}\(", f"{name}_ = {name}(", s)

    # Row / session dict keys by variable kind.
    kinds = _var_kinds(s)
    row_keys = {"actor_path": "program", "actor_pid": "session_id", "parent_pid": "parent_session"}
    sess_keys = {"actor_path": "path", "actor_pid": "id", "parent_pid": "parent", "parent_path": "parent"}

    def key_sub(m):
        var, key = m.group(1), m.group(3)
        k = kinds.get(var, "")
        table = row_keys if k == "row" else sess_keys if k == "session" else None
        if table is None or key not in table:
            return m.group(0)
        return m.group(0).replace(f'"{key}"', f'"{table[key]}"', 1)

    s = re.sub(rf'\b({IDENT})(\.get\(|\[)"(actor_path|actor_pid|parent_pid|parent_path)"', key_sub, s)

    # lineage_[0].get("actor_path") / rows[-1]["actor_pid"]: the element of a list
    def idx_sub(m):
        var, idx, acc, key = m.group(1), m.group(2), m.group(3), m.group(4)
        k = {"rows": "row", "sessions": "session"}.get(kinds.get(var, ""), "")
        table = row_keys if k == "row" else sess_keys if k == "session" else None
        if table is None or key not in table:
            return m.group(0)
        return f'{var}{idx}{acc}"{table[key]}"'

    s = re.sub(rf'\b({IDENT})(\[[^\]\n]*\])(\.get\(|\[)"(actor_path|actor_pid|parent_pid|parent_path)"', idx_sub, s)

    # "process://" + x.get("path"/"program") → the node id itself
    def procid_sub(m):
        var, acc, key = m.group(1), m.group(2), m.group(3)
        k = kinds.get(var, "")
        if k == "row" and key == "program":
            return f'{var}.get("session_id", "")'
        if k == "session" and key == "path":
            return f'{var}["id"]'
        return m.group(0)

    s = re.sub(rf'"process://"\s*\+\s*({IDENT})(\.get\(|\[)"(program|path|actor_path)"[^)\]]*[)\]]', procid_sub, s)
    # "process://" + inst["actor_path"] remnants → inst["id"] when inst is a session
    s = re.sub(rf'"process://"\s*\+\s*({IDENT})\["(?:path)"\]', lambda m: f'{m.group(1)}["id"]' if kinds.get(m.group(1)) == "session" else m.group(0), s)

    # new_chain("process://" + X) → new_chain(X) (then the id rewrite above applied)
    s = re.sub(r'new_chain\("process://"\s*\+\s*', "new_chain(", s)
    # a chain root given as a path expression → the same element's session id
    s = re.sub(r'new_chain\((.+?)(?:\.get\("(?:actor_path|path)"[^)]*\)|\["(?:actor_path|path)"\])\)', r'new_chain(\1["id"])', s)

    # the standard ev_edge helper, instance-keyed by session
    s = re.sub(
        r'(?m)^([ \t]*)def ev_edge\((\w+)\):\n(?:(?:\1[ \t]+.*|[ \t]*)\n)*?(?=\1\S|\Z)',
        lambda m: (
            f'{m.group(1)}def ev_edge({m.group(2)}):\n'
            f'{m.group(1)}    t = {m.group(2)}.get("ts", "0")\n'
            f'{m.group(1)}    frm = {m.group(2)}.get("session_id", "")\n'
            f'{m.group(1)}    if {m.group(2)}.get("kind", "") == "SPAWNED":\n'
            f'{m.group(1)}        frm = {m.group(2)}.get("parent_session", "")\n'
            f'{m.group(1)}    return {{\n'
            f'{m.group(1)}        "from":     frm,\n'
            f'{m.group(1)}        "to":       {m.group(2)}.get("target_id", ""),\n'
            f'{m.group(1)}        "kind":     {m.group(2)}.get("kind", ""),\n'
            f'{m.group(1)}        "dir":      "out",\n'
            f'{m.group(1)}        "ts":       t,\n'
            f'{m.group(1)}        "first_ts": t,\n'
            f'{m.group(1)}        "last_ts":  t,\n'
            f'{m.group(1)}    }}\n'
        ),
        s,
    )

    # Leftovers the manual pass must handle.
    for pat, note in [
        (r'\bactor_start\b', "actor_start (instance start) has no equivalent; sessions are instances"),
        (r'"process://"', '"process://" ids are gone; use session ids (x["id"] / row["session_id"])'),
        (r'\bactor_pid\b|\bactor_path\b|\bparent_pid\b', "unresolved actor_*/parent_pid key (variable kind unknown)"),
        (r'\$WRITE|\$READ|\$EXEC', "FTS file labels are gone; use fs_activity(session=, op=)"),
        (r'\bproc_name\b', "proc_name: FileSystem nodes still carry proc_name/proc_path; verify"),
    ]:
        if re.search(pat, s):
            notes.append(note)
    return s


# ── YAML surgery ─────────────────────────────────────────────────────────────

SCRIPT_RE = re.compile(r"(?ms)^script:\s*\|-?\s*\n((?:[ \t]+.*\n|\n)+)")


def migrate_file(path: Path, dry: bool) -> tuple[bool, list[str]]:
    text = path.read_text(encoding="utf-8")
    notes: list[str] = []
    new = text

    m = SCRIPT_RE.search(new)
    script = ""
    if m:
        block = m.group(1)
        indent = re.match(r"[ \t]*", block).group(0)
        body = "".join(line[len(indent):] if line.startswith(indent) else line for line in block.splitlines(True))
        rewritten = rewrite_script(body, notes)
        script = rewritten
        if rewritten != body:
            reindented = "".join((indent + line) if line.strip() else line for line in rewritten.splitlines(True))
            new = new[:m.start(1)] + reindented + new[m.end(1):]

    if "\nrequires:" not in new and "\nlogsource:" in new:
        caps = infer_caps(new, script)
        if caps:
            req = "requires:\n" + "".join(f"  - {c}\n" for c in caps)
            # after the logsource block (before detection:)
            mm = re.search(r"(?m)^detection:", new)
            if mm:
                new = new[:mm.start()] + req + new[mm.start():]

    changed = new != text
    if changed and not dry:
        path.write_text(new, encoding="utf-8")
    return changed, notes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", default=["ai_agent"])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    files: list[Path] = []
    for raw in args.paths:
        p = Path(raw)
        files.extend(sorted(p.rglob("*.yml")) if p.is_dir() else [p])
    changed = 0
    flagged = 0
    for f in files:
        if "/fixtures/" in str(f):
            continue
        c, notes = migrate_file(f, args.dry_run)
        changed += c
        if notes:
            flagged += 1
            for n in sorted(set(notes)):
                print(f"{f}: {n}")
    print(f"migrate_v2: {len(files)} files, {changed} changed, {flagged} need a manual pass", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

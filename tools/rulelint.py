#!/usr/bin/env python3
"""rulelint — build-time guardrail for Netzilo AIDR Sigma rules.

A rule that references an event type no producer emits, a field the engine never
populates, or a regex Go's RE2 engine cannot compile will load without error and
then never fire. Those are the most expensive failures in a detection corpus:
silent, and indistinguishable from "no attack happened".

Every ground-truth set below is derived from the Netzilo engine source, with the
file:line provenance recorded inline. When the engine gains a producer, move the
category from REPLAY_ONLY_CATEGORIES into LIVE_CATEGORIES in the same commit.

Usage:
    python3 tools/rulelint.py [path ...]        # default: ai_agent/
    python3 tools/rulelint.py --warnings-as-errors
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

# ── Ground truth: logsource categories ───────────────────────────────────────
#
# Provenance: scanner/yaml/adapter.go contextExpansion() maps category -> []ContextType.
# A category is LIVE only if some client-side producer actually emits one of the
# context types it expands to:
#
#   OnMCPToolCall / OnMCPPromptRequest / OnMCPSamplingRequest
#                                    -> scanner_filter.go:229,358,422
#   OnMCPToolResponse / …Prompt/Sampling response
#                                    -> scanner_filter.go:265,378,446
#   OnLLMRequest / OnLLMResponse     -> scanner_filter.go:638,739
#   OnHTTPRequest                    -> scanner_filter.go:478
#   OnConnect                        -> scanner_filter.go:570
#   OnSemanticEvent                  -> scanner_filter.go:608  (WASM classifier types)
#   ScanExecuteProcess               -> staticscanner/edr.go:37
#   periodicScheduler                -> staticscanner/periodic_scheduler.go
LIVE_CATEGORIES = {
    "agent_events": "catch-all (ContextAny)",
    "all": "catch-all (ContextAny)",
    "tool_request": "OnMCPToolCall + description/prompt/sampling request contexts",
    "tool_input": "OnMCPToolCall",
    "tool_response": "OnMCPToolResponse",
    "tool_output": "OnMCPToolResponse",
    "tool_description": "OnMCPToolCall (tool-description phase)",
    "gateway_description": "OnMCPToolCall (gateway-description phase)",
    "prompt_request": "OnMCPPromptRequest",
    "prompt_response": "OnMCPPromptResponse",
    "sampling_request": "OnMCPSamplingRequest",
    "sampling_response": "OnMCPSamplingResponse",
    "llm_request": "OnLLMRequest",
    "llm_response": "OnLLMResponse",
    "http_request": "OnHTTPRequest",
    "connects": "OnConnect",
    "execute_process": "ScanExecuteProcess (edr.go)",
    "skill_acquired": "OnSemanticEvent (classifier)",
    "external_message": "OnSemanticEvent (classifier)",
    "file_upload": "OnSemanticEvent (classifier)",
    "file_download": "OnSemanticEvent (classifier)",
    "llm_tool_call": "OnSemanticEvent (classifier)",
    "llm_tool_result": "OnSemanticEvent (classifier)",
    "llm_reasoning": "OnSemanticEvent (classifier)",
    "do_automation": "OnSemanticEvent (classifier)",
    "periodic": "periodicScheduler (30s)",
}

# Categories the YAML parser accepts and the replay engine drives, but which no
# LIVE client producer emits. Rules using them load, never fire on an endpoint,
# and only ever match during server-side replay.
#
# file_*: deliberate. staticscanner/edr.go:5-9 — "File-write/read events are
# deliberately excluded — scanning every file I/O would cause excessive CPU
# consumption. File-level detection is handled by Starlark rules that traverse
# the AIDR behaviour graph." Produced by replay.go:707,713.
# http_response: scanner_filter.go:564 OnHTTPResponse is a no-op stub.
REPLAY_ONLY_CATEGORIES = {
    "file_read": "no live producer — use category: periodic + edges(kind='READ_FILE')",
    "file_write": "no live producer — use category: periodic + edges(kind='WRITE_FILE')",
    "file_create": "no live producer — use category: periodic + edges(kind='CREATE_FILE')",
    "file_delete": "no live producer — use category: periodic + edges(kind='DELETE_FILE')",
    "file_rename": "no live producer — use category: periodic + edges(kind='RENAME_FILE')",
    "file_op": "expands to the five file_* contexts; none has a live producer",
    "http_response": "OnHTTPResponse is a no-op stub (scanner_filter.go:564)",
}

# ── Ground truth: event_type values ──────────────────────────────────────────
#
# Provenance: scanner/logentry.go contextToEventType(). This is the ONLY source
# of the event_type field value. Note the many-to-one collapses — a rule that
# selects `event_type: tool_description` can never match, because that context
# reports event_type "tool_call".
EMITTED_EVENT_TYPES = {
    "tool_call": "tool_input, tool_description, gateway_description, prompt_description, sampling_request, prompt_request",
    "tool_response": "tool_output, sampling_response, prompt_response",
    "llm_request": "llm_request",
    "llm_response": "llm_response",
    "http_request": "http_request",
    "execute_process": "execute_process",
    "connects": "connects (default branch)",
    "skill_acquired": "skill_acquired",
    "external_message": "external_message",
    "llm_tool_call": "llm_tool_call",
    "llm_tool_result": "llm_tool_result",
    "file_upload": "file_upload (default branch)",
    "file_download": "file_download (default branch)",
    "llm_reasoning": "llm_reasoning (default branch)",
    "do_automation": "do_automation (default branch)",
    "periodic": "periodic (default branch)",
}

# event_type values only reachable through the replay engine.
REPLAY_ONLY_EVENT_TYPES = {
    "file_read",
    "file_write",
    "file_create",
    "file_delete",
    "file_rename",
}

# Collapsed context names that authors reach for but which contextToEventType
# never returns. Selecting these guarantees a dead rule.
NEVER_EMITTED_EVENT_TYPES = {
    "tool_description": "reports event_type 'tool_call' — use category: tool_description + event_type: tool_call",
    "gateway_description": "reports event_type 'tool_call'",
    "prompt_description": "reports event_type 'tool_call'",
    "tool_input": "reports event_type 'tool_call'",
    "tool_output": "reports event_type 'tool_response'",
    "prompt_request": "reports event_type 'tool_call'",
    "prompt_response": "reports event_type 'tool_response'",
    "sampling_request": "reports event_type 'tool_call'",
    "sampling_response": "reports event_type 'tool_response'",
    # AgentShield-only surfaces with no Netzilo equivalent.
    "network_request": "AgentShield-only — use http_request or connects",
    "outbound_request": "AgentShield-only — use http_request",
    "dns_query": "AgentShield-only — use connects (port 53)",
    "document_retrieval": "AgentShield-only — use skill_acquired or tool_response",
    "content_retrieval": "AgentShield-only — use skill_acquired or tool_response",
    "tool_sequence": "AgentShield-only — no such event; use action: execute + graph traversal",
    "parallel_operations": "AgentShield-only — no such event; use action: execute",
    "tool_description_update": "AgentShield-only — use action: execute + store_get/store_set",
    "tool_list_comparison": "AgentShield-only — use action: execute + store_get/store_set",
    "tool_execution": "AgentShield-only — use tool_call",
    "output_generation": "AgentShield-only — use llm_response",
    "code_execution": "AgentShield-only — use execute_process",
    "agent_message": "AgentShield-only — use external_message",
    "agent_handoff": "AgentShield-only — use external_message",
    "agent_creation": "AgentShield-only — use execute_process",
    "session_spawn": "AgentShield-only — use execute_process",
    "session_start": "AgentShield-only — no session-lifecycle producer",
    "config_load": "AgentShield-only — no producer",
    "config_modification": "AgentShield-only — use periodic + WRITE_FILE traversal",
    "env_set": "AgentShield-only — no producer",
    "plugin_installation": "AgentShield-only — use skill_acquired or periodic + WRITE_FILE",
    "plugin_configuration": "AgentShield-only — use periodic + WRITE_FILE traversal",
    "skill_installation": "AgentShield-only — use skill_acquired",
    "authentication": "AgentShield-only — no producer",
    "model_call": "AgentShield-only — use llm_request",
    "browser_action": "AgentShield-only — no producer",
    "message_send": "AgentShield-only — use external_message",
    "tool_result": "AgentShield-only — use tool_response",
    "user_input": "AgentShield-only — hook prompts arrive as llm_request",
    "file_edit": "AgentShield-only — no producer",
}

# ── Ground truth: LogEntry fields ────────────────────────────────────────────
#
# Provenance: scanner/logentry.go BuildLogEntry(). Always-populated metadata
# plus per-context extractions. `header_*` is dynamic and handled separately.
ALWAYS_FIELDS = {
    "event_type", "tool", "tool_name", "server", "provider", "model",
    "host", "path", "method", "url.full", "agent_name", "content",
}

# extractJSONArgs canonical aliases (tool_call + execute_process contexts).
TOOL_ARG_FIELDS = {"command", "process.command_line", "file_path", "url.full", "content"}

# Fields that exist on AnalysisRequest and in a script's `meta` dict but which
# BuildLogEntry() does NOT copy into the LogEntry, so no Sigma selection can ever
# match them. Verified against scanner/logentry.go: there is no
# setIfNotEmpty(entry, "port", …) / "protocol" / "caller_pid" / "callid".
SCRIPT_ONLY_FIELDS = {
    "port": "connects destination port — available only as meta['port'] in an action: execute script",
    "protocol": "connects transport — available only as meta['protocol'] in an action: execute script",
    "caller_pid": "available only as meta['caller_pid'] in an action: execute script",
    "callid": "available only as meta['callid'] in an action: execute script",
    "server_url": "available only as meta['server_url'] in an action: execute script",
    "url": "LogEntry spells the full URL 'url.full'; meta spells it 'url'",
}

# Per-context extras.
CONTEXT_EXTRA_FIELDS = {
    "tool_response": {"response"},
    "llm_response": {"response"},
    "llm_request": {"model", "system_prompt", "message.content"},
    "file_read": {"file_path", "content"},
    "file_write": {"file_path", "content"},
    "file_create": {"file_path", "content"},
    "file_delete": {"file_path", "content"},
    "file_rename": {"file_path", "content"},
}

# Semantic-event payload keys, flattened into the LogEntry by
# extractKeyValuePayload(). Provenance: mcp-rules/semanticclassifier/classifier.go
# skillPayload() and each detect* function's Payload map.
SEMANTIC_PAYLOAD_FIELDS = {
    "skill_acquired": {"host", "source", "skill", "confidence", "format",
                       "matched_signals", "url", "tool"},
    "external_message": {"host", "url", "platform", "source"},
    "file_upload": {"host", "url", "platform", "source", "filename"},
    "file_download": {"host", "url", "platform", "source", "filename"},
    "do_automation": {"host", "url", "platform", "source"},
    "llm_tool_call": {"tool_name", "call_id", "input", "host", "url"},
    "llm_tool_result": {"tool_name", "call_id", "output", "host", "url"},
    "llm_reasoning": {"host", "url", "source", "provider", "model"},
}

# ── Ground truth: modifiers and actions ──────────────────────────────────────
#
# Provenance: scanner/yaml/adapter.go buildLeaf(). An unknown modifier silently
# degrades to `contains`, which is a correctness trap worth failing on.
KNOWN_MODIFIERS = {
    "contains", "startswith", "endswith", "re", "base64", "cidr", "windash", "all",
}

# Provenance: scanner/types.go ActionType constants (lowercased here; the parser
# upper-cases before comparison).
KNOWN_ACTIONS = {
    "block", "allow", "redact", "report", "scan", "blockmodel", "allowmodel",
    "replacemodel", "redirect", "inject", "replace", "execute",
}

# Actions a Starlark script may return. Provenance: Agent.md "What is NOT
# returnable from scripts" + staticscanner script verdict handling.
SCRIPT_RETURNABLE = {"allow", "block", "report", "redact", "redirect", "inject", "replace"}

KNOWN_LEVELS = {"informational", "low", "medium", "high", "critical"}
KNOWN_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}

# ATT&CK tactic tags. `defense-evasion` was split in ATT&CK v19 into `stealth`
# and `defense-impairment`; upstream sigma-ai retagged its whole corpus.
DEPRECATED_TAGS = {
    "attack.defense-evasion": "ATT&CK v19 split this into attack.stealth / attack.defense-impairment",
}

# Three id forms are accepted, matching the conventions already in the corpus:
#   1. a bare UUID                       — rules inherited from upstream sigma-ai
#   2. <uuid>-p                          — periodic companion of the rule <uuid>
#   3. netzilo-<kebab-slug>-<NNN>        — Netzilo-authored rules
# Anything else is a placeholder. The engine only requires uniqueness, but a
# non-conforming id is how the two `a1b2c3d4-e5f6-7890-abcd-…` placeholders
# survived a corpus-wide review.
UUID_RE = re.compile(
    r"^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?:-p)?"
    r"|netzilo(?:-[a-z0-9]+)+-\d{3})$",
    re.I,
)
# RE2 rejects lookaround and backreferences outright — regexp.Compile returns an
# error and findRegex() then returns nil, so the leaf silently never matches.
# Provenance: scanner/condition.go:119 + findRegex().
RE2_UNSUPPORTED = [
    # Go's regexp spells a codepoint \x{200b}; ​ is rejected outright with
    # "invalid escape sequence". Python's re ACCEPTS \uXXXX, so a linter built on
    # Python cannot infer this — it is asserted from the engine's own load error.
    (re.compile(r"\\u[0-9a-fA-F]{4}"),
     r"\uXXXX escape — Go's regexp requires \x{XXXX}; \u is 'invalid escape sequence'"),
    (re.compile(r"\(\?="), "lookahead (?=…) — RE2 does not support it"),
    (re.compile(r"\(\?!"), "negative lookahead (?!…) — RE2 does not support it"),
    (re.compile(r"\(\?<[=!]"), "lookbehind (?<=…)/(?<!…) — RE2 does not support it"),
    (re.compile(r"\\[1-9]"), "backreference \\N — RE2 does not support it"),
    (re.compile(r"\(\?P?<[A-Za-z_]"), "named group — use (?P<name>…), plain (?<name>…) is rejected"),
]
HAS_LETTER_RE = re.compile(r"[A-Za-z]")
CASE_FOLD_RE = re.compile(r"\(\?[a-zA-Z]*i[a-zA-Z]*[:)]")


class Finding:
    __slots__ = ("path", "rule_id", "level", "code", "message")

    def __init__(self, path: str, rule_id: str, level: str, code: str, message: str):
        self.path = path
        self.rule_id = rule_id
        self.level = level
        self.code = code
        self.message = message

    def __str__(self) -> str:
        where = f"{self.path}"
        if self.rule_id:
            where += f" [{self.rule_id}]"
        return f"{self.level.upper():5} {self.code:24} {where}: {self.message}"


class DuplicateKeyLoader(yaml.SafeLoader):
    """SafeLoader that records duplicate mapping keys instead of silently
    keeping the last one. YAML forbids duplicate keys; PyYAML and gopkg.in/yaml
    both tolerate them, so `command|contains` twice in one selection silently
    drops the first pattern."""

    duplicates: list[str]

    def construct_mapping(self, node, deep=False):  # type: ignore[override]
        seen = set()
        for key_node, _ in node.value:
            try:
                key = self.construct_object(key_node, deep=deep)
            except yaml.YAMLError:
                continue
            if not isinstance(key, (str, int, float, bool)) and key is not None:
                continue
            if key in seen:
                self.duplicates.append(str(key))
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def check_control_bytes(path: Path, out: list[Finding]) -> None:
    """gopkg.in/yaml.v3 rejects raw control characters with "control characters
    are not allowed" and the whole file fails to parse. PyYAML accepts them, so
    this must be checked explicitly rather than inferred from a load failure.
    Tab, LF and CR are legal."""
    raw = path.read_bytes()
    bad = sorted({b for b in raw if (b < 0x09 or 0x0B <= b <= 0x1F or b == 0x7F)
                  and b not in (0x09, 0x0A, 0x0D)})
    if bad:
        names = ", ".join(f"0x{b:02x}" for b in bad)
        out.append(Finding(str(path), "", "error", "yaml-control-bytes",
                           f"raw control byte(s) {names} in the file — gopkg.in/yaml.v3 fails the "
                           f"WHOLE document with 'control characters are not allowed'. Write the "
                           f"codepoint as \\x{{001b}} inside a |re: pattern instead"))


def load_documents(path: Path) -> tuple[list[dict], list[str], str | None]:
    loader_cls = type("_Loader", (DuplicateKeyLoader,), {"duplicates": []})
    loader_cls.duplicates = []
    try:
        docs = [d for d in yaml.load_all(path.read_text(encoding="utf-8"), Loader=loader_cls) if d]
    except yaml.YAMLError as exc:
        return [], [], str(exc).replace("\n", " ")
    return docs, list(loader_cls.duplicates), None


def iter_selections(detection: dict):
    """Yield (selection_name, block) for every named selection."""
    for name, block in detection.items():
        if name == "condition":
            continue
        if isinstance(block, dict):
            yield name, block


def condition_tokens(condition) -> list[str]:
    if condition is None:
        return []
    text = condition if isinstance(condition, str) else str(condition)
    return re.findall(r"[A-Za-z_][A-Za-z0-9_*]*|\(|\)", text)


def allowed_fields_for(categories: set[str], event_types: set[str]) -> set[str]:
    """Union of fields the engine could populate for this rule's contexts.

    Called per SELECTION, not per rule: with `category: agent_events` a rule-wide
    union would permit any semantic-payload field on any event_type, which is how
    `source: openclaw` sat inside a `event_type: tool_call` selection undetected.
    `source` only exists for semantic events (extractKeyValuePayload), so pairing
    it with tool_call makes the selection false forever — selections are AND.
    """
    fields = set(ALWAYS_FIELDS)
    # A selection that pins its own event_type is scoped by that, not by the
    # rule's catch-all category.
    catch_all = (bool(categories & {"agent_events", "all"}) or not categories) and not event_types
    # Tool-arg extraction runs for tool_call and execute_process contexts.
    if catch_all or categories & {
        "tool_request", "tool_input", "tool_description", "gateway_description",
        "prompt_request", "sampling_request", "execute_process",
    } or event_types & {"tool_call", "execute_process"}:
        fields |= TOOL_ARG_FIELDS
    for key, extra in CONTEXT_EXTRA_FIELDS.items():
        if catch_all or key in categories or key in event_types:
            fields |= extra
    if catch_all or "tool_response" in categories or "tool_output" in categories:
        fields |= CONTEXT_EXTRA_FIELDS["tool_response"]
    for key, extra in SEMANTIC_PAYLOAD_FIELDS.items():
        if catch_all or key in categories or key in event_types:
            fields |= extra
    return fields


def check_rule(path: Path, doc: dict, duplicates: list[str], out: list[Finding]) -> None:
    rel = str(path)
    rid = str(doc.get("id", "") or "")

    def add(level: str, code: str, msg: str) -> None:
        out.append(Finding(rel, rid, level, code, msg))

    for dup in duplicates:
        add("error", "duplicate-yaml-key",
            f"duplicate key {dup!r} — the first occurrence is silently discarded")

    # ── Metadata ────────────────────────────────────────────────────────────
    if not doc.get("title"):
        add("error", "missing-title", "title is required")
    if not rid:
        add("error", "missing-id", "id is required")
    elif not UUID_RE.match(rid):
        add("error", "invalid-id",
            f"id {rid!r} is not a UUID, a <uuid>-p companion id, or a netzilo-<slug>-NNN id "
            f"— regenerate with uuidgen")

    level = str(doc.get("level", "") or "").lower()
    if not level:
        add("warn", "missing-level", "no level: — action defaults via levelToActionType (report)")
    elif level not in KNOWN_LEVELS:
        add("error", "invalid-level", f"level {level!r} not in {sorted(KNOWN_LEVELS)}")

    status = str(doc.get("status", "") or "").lower()
    if status and status not in KNOWN_STATUS:
        add("warn", "invalid-status", f"status {status!r} not in {sorted(KNOWN_STATUS)}")

    tags = doc.get("tags") or []
    if isinstance(tags, list):
        for tag in tags:
            tag = str(tag)
            if tag in DEPRECATED_TAGS:
                add("warn", "deprecated-tag", f"{tag} — {DEPRECATED_TAGS[tag]}")
            if tag.startswith("attack.t") and not re.match(r"^attack\.t\d{4}(\.\d{3})?$", tag):
                add("error", "malformed-attack-tag",
                    f"{tag} is not a valid ATT&CK technique id (attack.tNNNN[.NNN])")

    # ── logsource ───────────────────────────────────────────────────────────
    logsource = doc.get("logsource") or {}
    if not isinstance(logsource, dict):
        add("error", "invalid-logsource", "logsource must be a mapping")
        logsource = {}
    product = str(logsource.get("product", "") or "")
    if product != "ai_agent":
        add("error", "invalid-product", f"logsource.product must be 'ai_agent', got {product!r}")

    raw_category = logsource.get("category")
    categories: set[str] = set()
    if raw_category is None:
        add("error", "missing-category", "logsource.category is required (parseSigmaRule rejects the rule)")
    elif isinstance(raw_category, list):
        # categoryToContexts() reads the value with stringVal(), which renders a
        # list via fmt.Sprintf("%v") — "[a b]" — and then falls through to the
        # default branch as ContextType("[a b]"), matching nothing. One category
        # per rule; use two rule files (or two YAML documents) instead.
        add("error", "category-list",
            f"logsource.category must be a single string, got a list {raw_category!r} — "
            f"stringVal() renders it as '[…]' and the rule never matches")
    else:
        for cat in [raw_category]:
            cat = str(cat).lower()
            categories.add(cat)
            if cat in REPLAY_ONLY_CATEGORIES:
                add("error", "replay-only-category",
                    f"category {cat!r} has no live producer: {REPLAY_ONLY_CATEGORIES[cat]}")
            elif cat not in LIVE_CATEGORIES:
                add("error", "unknown-category",
                    f"category {cat!r} is not a known context; it will be passed through "
                    f"as ContextType({cat!r}) and never match")

    # ── detection ───────────────────────────────────────────────────────────
    detection = doc.get("detection")
    if not isinstance(detection, dict) or not detection:
        add("error", "missing-detection", "detection section is required")
        return

    selections = dict(iter_selections(detection))
    if not selections:
        add("error", "no-selections", "detection contains no named selections")
        return

    condition = detection.get("condition")
    if condition is None and len(selections) > 1:
        add("error", "missing-condition",
            "condition is required when there is more than one selection")
    referenced = set()
    for tok in condition_tokens(condition):
        if tok.lower() in {"and", "or", "not", "of", "them", "all", "1"} or tok in {"(", ")"}:
            continue
        referenced.add(tok)
    for ref in sorted(referenced):
        if ref.endswith("*"):
            prefix = ref[:-1]
            if not any(name.startswith(prefix) for name in selections):
                add("error", "condition-glob-empty",
                    f"condition references {ref!r} but no selection matches that prefix")
        elif ref not in selections:
            add("error", "condition-unknown-selection",
                f"condition references undefined selection {ref!r} — parsePrimary() substitutes "
                f"a never-matching condition, silently disabling this branch")
    for name in selections:
        if condition is not None and name not in referenced:
            unreachable = not any(
                r.endswith("*") and name.startswith(r[:-1]) for r in referenced
            ) and "them" not in str(condition).lower()
            if unreachable:
                add("warn", "unused-selection",
                    f"selection {name!r} is never referenced by the condition")

    # Collect declared event_type values.
    event_types: set[str] = set()
    for _, block in selections.items():
        for field_expr, value in block.items():
            base = str(field_expr).split("|")[0]
            if base != "event_type":
                continue
            for v in (value if isinstance(value, list) else [value]):
                event_types.add(str(v).lower())

    for et in sorted(event_types):
        if et in NEVER_EMITTED_EVENT_TYPES:
            add("error", "phantom-event-type",
                f"event_type {et!r} is never produced: {NEVER_EMITTED_EVENT_TYPES[et]}")
        elif et in REPLAY_ONLY_EVENT_TYPES:
            add("error", "replay-only-event-type",
                f"event_type {et!r} is only produced by the replay engine, not by any live "
                f"client producer — use category: periodic + graph traversal")
        elif et not in EMITTED_EVENT_TYPES:
            add("error", "unknown-event-type",
                f"event_type {et!r} is not produced by contextToEventType()")

    # A rule scoped to a single non-catch-all category must not select an
    # event_type that category cannot report.
    if categories and not (categories & {"agent_events", "all"}) and event_types:
        for cat in sorted(categories):
            expected = {k for k, v in EMITTED_EVENT_TYPES.items() if cat in v.split(", ") or cat == k}
            if expected and not (event_types & expected):
                add("error", "category-event-type-mismatch",
                    f"category {cat!r} reports event_type {sorted(expected)} but the detection "
                    f"selects {sorted(event_types)} — the rule can never match")

    # ── per-selection field checks ──────────────────────────────────────────
    for name, block in selections.items():
        # Scope this selection by its OWN event_type declaration when it has one.
        sel_event_types: set[str] = set()
        for fe, v in block.items():
            if str(fe).split("|")[0] == "event_type":
                for item in (v if isinstance(v, list) else [v]):
                    sel_event_types.add(str(item).lower())
        allowed = allowed_fields_for(categories, sel_event_types or event_types)

        for field_expr, value in block.items():
            parts = str(field_expr).split("|")
            field, modifiers = parts[0], parts[1:]

            for mod in modifiers:
                if mod not in KNOWN_MODIFIERS:
                    add("error", "unknown-modifier",
                        f"{name}.{field_expr}: modifier {mod!r} is unknown — buildLeaf() "
                        f"silently degrades it to 'contains'")
            if field in SCRIPT_ONLY_FIELDS:
                add("error", "script-only-field",
                    f"{name}.{field_expr}: BuildLogEntry() never populates {field!r} — "
                    f"{SCRIPT_ONLY_FIELDS[field]}")
            elif "session." in field:
                add("error", "session-field",
                    f"{name}.{field_expr}: Netzilo has no session.* field injection; "
                    f"use action: execute with graph traversal or store_get/store_set")
            elif field.startswith("header_"):
                if not (categories & {"http_request", "agent_events", "all"}):
                    add("warn", "header-field-scope",
                        f"{name}.{field_expr}: header_* is only populated for HTTP contexts")
            elif field not in allowed:
                add("warn", "unknown-field",
                    f"{name}.{field_expr}: field {field!r} is not populated by BuildLogEntry() "
                    f"for this rule's contexts — the leaf will never match")

            values = value if isinstance(value, list) else [value]
            if not values or all(v is None for v in values):
                add("error", "empty-values", f"{name}.{field_expr}: no values")

            base_mod = next((m for m in modifiers if m != "all"), "")
            if base_mod == "re":
                for pat in values:
                    pat = str(pat)
                    for probe, why in RE2_UNSUPPORTED:
                        if probe.search(pat):
                            add("error", "re2-unsupported",
                                f"{name}.{field_expr}: {why} — regexp.Compile() fails and "
                                f"findRegex() returns nil, so the leaf never matches: {pat!r}")
                            break
                    # Only letters that are actually matched as text can have a
                    # case to fold. Strip escape sequences whose "letters" are
                    # hex digits or class names first, or every \x{202e} and \pL
                    # pattern produces a bogus warning.
                    literal = re.sub(r"\\x\{[0-9a-fA-F]+\}", "", pat)
                    literal = re.sub(r"\\x[0-9a-fA-F]{2}", "", literal)
                    literal = re.sub(r"\\p\{?[A-Za-z_]+\}?", "", literal)
                    literal = re.sub(r"\\[dDwWsSbBAzZ]", "", literal)
                    if HAS_LETTER_RE.search(literal) and not CASE_FOLD_RE.search(pat):
                        add("warn", "case-sensitive-regex",
                            f"{name}.{field_expr}: |re: is case-sensitive in Netzilo "
                            f"(condition.go regexp.Compile, no folding). Add (?i) or use "
                            f"|contains: which folds both sides: {pat!r}")
                    # Python's re is only an approximation of RE2 and rejects
                    # valid RE2 constructs. Normalise the RE2-only spellings
                    # before the syntax probe so this stays a real-error check.
                    #   \x{XXXX} → Python \uXXXX (RE2's codepoint escape)
                    #   \pL / \p{L} → dropped (RE2 Unicode classes)
                    probe = re.sub(r"\\x\{([0-9a-fA-F]{1,6})\}",
                                   lambda m: "\\u" + m.group(1).rjust(4, "0"), pat)
                    probe = re.sub(r"\\p\{?[A-Za-z_]+\}?", "x", probe)
                    try:
                        re.compile(probe)
                    except re.error as exc:
                        add("error", "invalid-regex", f"{name}.{field_expr}: {exc}: {pat!r}")

            # A single-quoted YAML scalar does not interpret \u escapes; the
            # literal backslash-u reaches the matcher and cannot match the real
            # character. Double-quote the scalar instead.
            for pat in values:
                if isinstance(pat, str) and re.search(r"\\u[0-9a-fA-F]{4}", pat) and base_mod != "re":
                    add("warn", "uninterpreted-unicode-escape",
                        f"{name}.{field_expr}: contains a literal \\uXXXX sequence. If the YAML "
                        f"scalar was single-quoted the escape is NOT interpreted and will never "
                        f"match the real character — use a double-quoted scalar: {pat!r}")

    # ── action ──────────────────────────────────────────────────────────────
    action = str(doc.get("action", "") or "").lower()
    if action and action not in KNOWN_ACTIONS:
        add("error", "unknown-action", f"action {action!r} not in {sorted(KNOWN_ACTIONS)}")

    script = doc.get("script")
    if action == "execute":
        if not script or not str(script).strip():
            add("error", "execute-without-script", "action: execute requires a non-empty script:")
        else:
            body = str(script)
            if not re.search(r"^\s*result\s*=", body, re.M):
                add("error", "script-no-result",
                    "script never assigns top-level `result` — the engine ignores any other "
                    "variable and falls back to on_error")
            # Starlark has list comprehensions but NOT bare generator
            # expressions, so `any(x for y in z)` is a PARSE error and the whole
            # script fails to the on_error verdict. Wrap it: `any([x for y in z])`.
            for call in re.finditer(r"\b(any|all|sorted|list|tuple|dict|set|max|min|sum)\(\s*(?!\[)([^()\n]*?\sfor\s[^()\n]*?)\)", body):
                add("error", "starlark-generator-expression",
                    f"{call.group(1)}(… for … in …) is a generator expression; Starlark only "
                    f"supports list comprehensions and fails to PARSE this, sending the rule to "
                    f"its on_error verdict. Wrap the comprehension in brackets: "
                    f"{call.group(1)}([… for … in …])")
            # Starlark-go has NO underscore digit separators: `300_000_000_000`
            # tokenises as 300 followed by the identifier _000_000_000 and the
            # script fails to parse. Agent.md's own examples use this form.
            for m in re.finditer(r"\b\d+_\d", body):
                add("error", "starlark-underscore-numeral",
                    f"numeric literal with an underscore separator near {m.group(0)!r} — "
                    f"Starlark-go parses it as an int followed by an identifier and the whole "
                    f"script fails to parse. Write the digits without separators")
            # elems() yields one-character strings; only elem_ords()/codepoint_ords()
            # yield ints. Mixing them up is a runtime "unknown binary op" error.
            for m in re.finditer(r"\.elems\(\)", body):
                add("warn", "starlark-elems-yields-strings",
                    ".elems() yields one-character STRINGS, not ints — arithmetic or bitwise "
                    "ops on the loop variable will fail at runtime. Use .elem_ords() for byte "
                    "ints or .codepoint_ords() for codepoint ints")
            if re.search(r'meta\.get\(\s*["\']file_path', body):
                add("error", "script-meta-file-path",
                    "meta has no 'file_path' key (scanner_filter.go:1324 builds the map); "
                    "file paths arrive inside meta['content'] as JSON for execute_process, or "
                    "via fs_activity() on a FileSystem node")
            for ct in re.findall(r'context_type["\']\s*,\s*["\'][^"\']*["\']\s*\)\s*(?:==|in)', body):
                pass  # covered by the literal scan below
            for lit in re.findall(r'ct\s*==\s*["\']([a-z_]+)["\']', body) + \
                       re.findall(r'ct\s+in\s+\(([^)]*)\)', body):
                for token in re.findall(r"[a-z_]+", lit):
                    if token in {"tool_call", "tool_response"}:
                        add("warn", "script-context-type-collapsed",
                            f"meta['context_type'] carries the raw ContextType "
                            f"(tool_input/tool_output/…), not the collapsed event_type "
                            f"{token!r} — this comparison never matches")
            for ret in re.findall(r'["\']action["\']\s*:\s*["\']([a-z]+)["\']', body):
                if ret not in SCRIPT_RETURNABLE:
                    add("error", "script-unreturnable-action",
                        f"script returns action {ret!r}; scripts may only return "
                        f"{sorted(SCRIPT_RETURNABLE)}")
    elif script:
        add("warn", "script-without-execute",
            "script: is present but action is not 'execute' — the script is ignored")

    if "periodic" in categories:
        if action != "execute":
            add("error", "periodic-without-execute",
                "category: periodic requires action: execute (partitionRules() drops the rule "
                "otherwise — see yaml_adapter.go ruleJSONToPeriodicRule)")
        for _, block in selections.items():
            for field_expr in block:
                if str(field_expr).split("|")[0] == "event_type":
                    add("warn", "periodic-event-type",
                        "periodic rules fire with event_type 'periodic'; selecting another "
                        "event_type prevents the script from ever running")

    if action == "scan" and not str(doc.get("prompt", "") or "").strip():
        add("warn", "scan-without-prompt",
            "action: scan with no prompt: uses the built-in ML scanner — intentional only "
            "for jailbreak/prompt-injection detection")

    for key in ("on_error", "on_timeout"):
        val = str(doc.get(key, "") or "").lower()
        if val and val not in {"allow", "block", "report"}:
            add("error", "invalid-fallback", f"{key}: {val!r} must be allow|block|report")


def check_filename(path: Path, out: list[Finding]) -> None:
    name = path.name
    if not name.startswith("ai_agent_") or not name.endswith(".yml"):
        out.append(Finding(str(path), "", "warn", "filename",
                           "expected ai_agent_<kebab_description>.yml"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", default=["ai_agent"],
                    help="rule files or directories (default: ai_agent)")
    ap.add_argument("--warnings-as-errors", action="store_true")
    ap.add_argument("--quiet", action="store_true", help="only print findings, no summary")
    args = ap.parse_args()

    files: list[Path] = []
    for raw in args.paths:
        p = Path(raw)
        if p.is_dir():
            files.extend(sorted(p.rglob("*.yml")))
        elif p.exists():
            files.append(p)
        else:
            print(f"rulelint: no such path: {p}", file=sys.stderr)
            return 2
    if not files:
        print("rulelint: no rule files found", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    ids: dict[str, str] = {}
    for path in files:
        check_filename(path, findings)
        check_control_bytes(path, findings)
        docs, duplicates, err = load_documents(path)
        if err:
            findings.append(Finding(str(path), "", "error", "yaml-parse", err))
            continue
        if not docs:
            findings.append(Finding(str(path), "", "error", "empty-file", "no YAML documents"))
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                findings.append(Finding(str(path), "", "error", "invalid-document",
                                        "top-level YAML value is not a mapping"))
                continue
            check_rule(path, doc, duplicates, findings)
            duplicates = []  # attribute duplicates to the first document only
            rid = str(doc.get("id", "") or "")
            if rid:
                if rid in ids and ids[rid] != str(path):
                    findings.append(Finding(str(path), rid, "error", "duplicate-id",
                                            f"id already used by {ids[rid]}"))
                ids.setdefault(rid, str(path))

    errors = [f for f in findings if f.level == "error"]
    warnings = [f for f in findings if f.level == "warn"]
    for f in sorted(findings, key=lambda f: (f.level != "error", f.path, f.code)):
        print(f)

    if not args.quiet:
        print(f"\nrulelint: {len(files)} files, {len(errors)} errors, {len(warnings)} warnings")

    if errors or (args.warnings_as_errors and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

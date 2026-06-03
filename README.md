# AIDR Sigma Rules

Open-source Sigma detection rules for AI agent security, maintained by [Netzilo](https://netzilo.com).

## What is Netzilo AIDR?

**AIDR** (AI Detection and Response) is Netzilo's behavioral security engine for AI agent deployments. It monitors every action every AI agent takes — tool calls, file reads, HTTP requests, LLM calls, process spawns, skill acquisitions — and evaluates Sigma rules against that traffic in real time.

AIDR is not a content filter. It is a **behavioral analysis engine** backed by a live graph of agent activity. Every action is recorded as a node and edge in a behaviour graph that persists for the session. Rules can traverse that graph to detect multi-step attack patterns that no single-event rule could catch.

---

## What Is in This Repository?

This repository contains the **community-maintained detection rule library** for AIDR. Rules cover:

| Category | Examples |
|---|---|
| **Prompt injection** | Direct injection, indirect injection via tool output, memory poisoning |
| **Credential access** | Reading `.env`, SSH keys, AWS credentials, cloud provider configs |
| **Persistence** | Cron jobs, LaunchAgents, systemd services, shell profile modification |
| **Command & control** | Reverse shells, encoded payloads, download-and-execute patterns |
| **Exfiltration** | Data exfiltration via HTTP, DNS tunneling, cloud storage uploads |
| **Privilege escalation** | `sudo` abuse, SUID binaries, cloud IAM role assumption |
| **Lateral movement** | Container escapes, metadata endpoint access |
| **AI-specific threats** | MCP config injection, tool registry tampering, auto-approve bypass |
| **PII protection** | Credit card and SSN redaction |

Rules are organized under `ai_agent/` with filenames following `ai_agent_<threat>.yml`.

---

## Rule Format

Rules use the **unified Sigma + AIDR format**. Standard Sigma fields describe *what to detect*; AIDR-specific fields describe *what to do when detection fires*.

Standard Sigma tools parse the detection half; AIDR-specific fields (`action:`, `script:`, `replace:`, etc.) are top-level extensions that Sigma tools ignore.

### Minimal example

```yaml
title: Reverse Shell Attempt
id: 74dee137-ffb8-54c8-862f-4a98a61f63ee
status: stable
level: critical
logsource:
  product: ai_agent
  category: agent_events
detection:
  selection:
    event_type: tool_call
    command|contains:
      - '/dev/tcp/'
      - 'nc -e /bin'
      - 'bash -i >&'
  condition: selection
```

When `level: critical` or `level: high` and no `action:` is specified, AIDR defaults to `block`.

### logsource.category

Use `category: agent_events` for all rules. Scope which events the rule applies to using `event_type:` in the detection section.

| `event_type` value | What it matches |
|---|---|
| `tool_call` | MCP tool call arguments (runs before execution — can block) |
| `tool_response` | MCP tool call outputs |
| `llm_request` | Full LLM API request body |
| `llm_response` | Full LLM API response body |
| `http_request` | Raw outbound HTTP request |
| `execute_process` | Child process spawned (EDR/syscall level) |
| `file_read` | File read (EDR/syscall level) |
| `file_write` | File write (EDR/syscall level) |
| `skill_acquired` | Agent loaded external instruction content |
| `external_message` | Agent sent Slack / email / Teams message |
| `do_automation` | Agent triggered CI/CD or automation |

### Detection fields

Fields available in detection conditions:

| Field | Description |
|---|---|
| `event_type` | Context type string (see above) |
| `tool` / `tool_name` | MCP tool name (e.g. `bash`, `read_file`) |
| `server` | MCP server name |
| `provider` | LLM provider (`anthropic`, `openai`, `gemini`, …) |
| `model` | LLM model name |
| `host` | HTTP hostname |
| `url.full` | Full URL |
| `content` | Full raw event body / tool arguments JSON |
| `command` | Extracted from `args.command` or `args.cmd` |
| `file_path` | Extracted from `args.path` or `args.file_path` |
| `response` | Tool output or LLM response text |

### Field modifiers

| Modifier | Behavior |
|---|---|
| *(none)* | Exact match, case-insensitive |
| `\|contains` | Substring match |
| `\|startswith` | Prefix match |
| `\|endswith` | Suffix match |
| `\|re` | RE2 regex (case-sensitive; add `(?i)` for insensitive) |
| `\|contains\|all` | All values must match (AND) |

### Actions

| `action` | Effect |
|---|---|
| `block` | Request is blocked |
| `allow` | Request passes (skip remaining rules) |
| `report` | Log event, traffic continues |
| `redact` | Replace matched content, traffic continues |
| `execute` | Run embedded Starlark script; script returns verdict |
| `blockmodel` | Block LLM request by provider/model metadata |
| `allowmodel` | Define approved models; block all others |
| `replacemodel` | Swap model name or relay to different base URL |
| `redirect` | HTTP redirect response |
| `inject` | Add headers to outgoing request (tenant restriction) |
| `scan` | Delegate to ML scanner or AI analysis prompt |

---

## Behavioral Rules — Starlark Scripts

For threats that span multiple events (exfiltration chains, session rate anomalies, capability hijacking), rules use `action: execute` with an embedded [Starlark](https://github.com/google/starlark-go) script.

The Sigma `detection:` section is a **cheap pre-filter** that decides whether to invoke the script. The script is the authoritative detector — it queries the live behaviour graph and returns `"block"`, `"report"`, `"redact"`, or `"allow"`.

```yaml
title: Exfiltration Chain Detection
logsource:
  product: ai_agent
  category: agent_events
detection:
  sel:
    event_type: tool_call
    content|re: '.'
  condition: sel
action: execute
on_error: allow
script: |
  # Check if agent fetched external content, read files, then sent data out
  def run():
      for a in graph(type="Process"):
          if a.get("agent", "0") != "1":
              continue
          skills = edges(a["id"], dir="out", kind="ACQUIRED_SKILL")
          reads  = edges(a["id"], dir="out", kind="READ_FILE")
          http   = edges(a["id"], dir="out", kind="HTTP_REQUEST")
          if skills and reads and http:
              return "block"
      return "allow"
  result = run()
```

### Graph builtins

Scripts have access to the live behaviour graph via three builtins:

| Builtin | Description |
|---|---|
| `graph(type="")` | All nodes, optionally filtered by type (`"Process"`, `"URL"`, `"LLM"`, …) |
| `node(id)` | Single node dict by ID, or `None` |
| `edges(id, dir, kind)` | Edges touching a node; `dir`: `"in"/"out"/"both"`, `kind`: edge type |

Edge kinds: `TOOL_CALL`, `TOOL_RESULT`, `LLM_REQUEST`, `LLM_RESPONSE`, `HTTP_REQUEST`, `READ_FILE`, `WRITE_FILE`, `EXECUTE_PROCESS`, `ACQUIRED_SKILL`, `CONNECTS`.

### Periodic rules

Rules with `category: periodic` run a Starlark script every 30 seconds regardless of events. Use these to detect slow-moving patterns the event-driven path would miss:

```yaml
logsource:
  product: ai_agent
  category: periodic
detection:
  sel:
    content|re: '.'
  condition: sel
action: execute
script: |
  # Walk WRITE_FILE edges looking for writes to sensitive paths
  def run():
      for a in graph(type="Process"):
          if a.get("agent", "0") != "1":
              continue
          for e in edges(a["id"], dir="out", kind="WRITE_FILE"):
              fs = node(e["to"])
              if fs and search_in(fs["id"] + "$WRITE", "/etc/"):
                  return "block"
      return "allow"
  result = run()
```

---

## Rule Pairs — Real-time + Periodic Companions

Some rules come in pairs: a **real-time rule** that fires on tool calls and a **companion periodic rule** that checks the EDR behaviour graph every 30 seconds. The companion covers file writes and reads that occur at the syscall level and are not visible through the hook or MITM proxy.

Companion rules share the same `id` prefix with a `-p` suffix and declare each other in a `related:` block:

```yaml
# Real-time rule
id: db43664e-2408-5e70-9b63-dcb0fabc8c5f
related:
  - id: db43664e-2408-5e70-9b63-dcb0fabc8c5f-p
    type: companion

# Companion periodic rule
id: db43664e-2408-5e70-9b63-dcb0fabc8c5f-p
related:
  - id: db43664e-2408-5e70-9b63-dcb0fabc8c5f
    type: companion
```

---

## Automated Rule Creation

[Agent.md](Agent.md) is a skill document for AI coding assistants. Load it into Claude Code, Codex, Gemini CLI, or any agent that supports file-based context and it will author complete, ready-to-deploy rules following the prescribed workflow — without manual scaffolding.

### Claude Code

Reference it inline in any session:

```
@Agent.md Write a rule that detects agents reading SSH private keys
```

Or append it to every session automatically via `.claude/settings.json`:

```json
{
  "systemPromptAppend": "path:./Agent.md"
}
```

### What the agent produces

When you describe a threat in natural language, an agent with `Agent.md` loaded will:

1. Classify it as a **content threat** (Sigma `detection:` conditions) or a **behavior threat** (`action: execute` + Starlark graph traversal)
2. Output a complete, valid YAML rule with `id`, `title`, `level`, `logsource`, `detection`, `falsepositives`, and the appropriate AIDR action
3. Explain which attack the rule targets, the behavioral sequence it detects, and known false-positive risks
4. For scripted rules: name which graph edges are queried and why

`Agent.md` is also the authoritative reference for the full rule format, all detection fields, all actions, and Starlark builtins.

---

## Contributing

Contributions are welcome. Please follow these guidelines:

1. **One file per rule.** Filename: `ai_agent_<kebab_description>.yml`.
2. **Use `category: agent_events`** and scope with `event_type:` in detection.
3. **All rules must have `id:` (UUID4), `title:`, `level:`, `author:`, `date:`.**
4. **Justify every `block` action.** Add a `falsepositives:` section explaining known benign cases and how the rule avoids them.
5. **Prefer `report` for new or uncertain rules.** Escalate to `block` after validating the false-positive rate.
6. **For behavioral threats, use `action: execute` with Starlark** rather than broad regex patterns that generate noise.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

## Learn More

- [Netzilo](https://netzilo.com) — AI agent security platform
- [Sigma HQ](https://sigmahq.io) — Sigma rule format specification
- [MITRE ATLAS](https://atlas.mitre.org) — Adversarial Threat Landscape for AI Systems
- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

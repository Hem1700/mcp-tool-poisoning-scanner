# mcp-tool-poisoning-scanner

A config-driven scanner for **tool poisoning**: malicious or manipulative instructions embedded in the tool descriptions/schemas an LLM agent reads to decide how to call its tools (MCP servers, function-calling definitions, agent skill files).

## Why

Once an LLM agent is wired to tools, it trusts each tool's *description* the same way it trusts its system prompt. A tool description can embed instructions aimed at the model rather than at the human reading the code — and because the tool still does what it claims, nothing looks broken. That description ships inside a package, a config file, or a remote MCP server response, and it fires on every invocation, silently, until someone reads the metadata closely enough to catch it.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full threat model, system design, and rationale.

## Status

**Implemented.** Phases 0–11 of the implementation plan are complete — all 5 detectors (heuristic, LLM-as-judge, ML anomaly, taint graph, behavioral prober) and all 4 collectors (raw_json, python_schema, mcp, ts_schema) are wired into the scan engine, with 106 passing tests. See the roadmap below, and [known limitations](#known-limitations) for what's deliberately deferred.

## Installation

```bash
pip install -e .
```

This installs the `tool-scan` CLI with the heuristic detector and `raw_json`/`python_schema`/`ts_schema` collectors — no optional dependencies required. Detectors and collectors with third-party dependencies are gated behind extras, installed only if you enable them:

```bash
pip install -e ".[llm-judge]"    # LLM-as-judge detector (anthropic)
pip install -e ".[ml-anomaly]"   # ML anomaly detector (sentence-transformers, scikit-learn)
pip install -e ".[behavioral]"   # Behavioral prober (docker)
pip install -e ".[mcp-source]"   # mcp collector (mcp, anyio)
pip install -e ".[all]"          # everything
```

## Quick start

```yaml
# tool-scan.config.yaml
version: 1
sources:
  - type: raw_json
    name: my-tools
    path: "./tools/*.json"
detectors:
  heuristic:
    rule_packs: ["rules/default_rule_pack.yaml"]
```

```bash
tool-scan scan --config tool-scan.config.yaml
```

Exit code is `0` for a clean scan, `1` if a finding meets `report.fail_on_severity` (`high` by default — CI-gateable), `2` for an invalid config. Full field-by-field schema: [`CONFIG_REFERENCE.md`](./CONFIG_REFERENCE.md).

## How it works (summary)

1. **Collect** tool definitions from declared sources — MCP servers (via `tools/list` introspection, read-only), Python/TypeScript tool decorators (via static AST parsing, no execution), or raw JSON schemas.
2. **Normalize** everything into one canonical `ToolDefinition` shape regardless of source.
3. **Detect** via a pipeline of independently config-toggleable detectors:
   - a fast heuristic rule engine (pattern-based, no external calls, on by default)
   - an optional LLM-as-judge semantic analyzer
   - an ML anomaly detector (embeddings + Isolation Forest/LOF, needs no labeled poison data — but by design can't catch injections phrased to blend in statistically, which is what the LLM-judge and taint layers are for)
   - a taint-graph analyzer that traces whether one tool's output can steer another tool's input
   - an optional sandboxed behavioral prober that runs the real agent against adversarial goals
4. **Aggregate** findings, apply baseline suppression (hash-based, requires explicit review to approve), and score severity.
5. **Report** as a terminal table, JSON, SARIF (for GitHub code scanning / CI), or Markdown — with a config-driven severity threshold that sets the process exit code for CI gating.

Full detail: [`ARCHITECTURE.md`](./ARCHITECTURE.md).
Full config schema with every field explained: [`CONFIG_REFERENCE.md`](./CONFIG_REFERENCE.md).

## Non-goals

- Not a runtime firewall — this is an offline/CI-time auditor, not a live proxy that blocks tool calls.
- Not a general prompt-injection scanner for user-facing chat — scope is strictly the tool-definition and tool-output surface.
- Not a sandbox/isolation solution for agent execution.

See the "Non-goals" and "Known limitations" sections of `ARCHITECTURE.md` for the full scope boundary.

## Roadmap

All 13 items below are implemented. Full task-by-task build log with the exact code for each step: [`docs/superpowers/plans/2026-07-11-mcp-tool-poisoning-scanner-implementation.md`](./docs/superpowers/plans/2026-07-11-mcp-tool-poisoning-scanner-implementation.md).

- [x] Architecture and config specification
- [x] Normalizer + `ToolDefinition` IR
- [x] Heuristic Rule Engine + default rule pack
- [x] `raw_json` and `python_schema` collectors
- [x] Terminal + JSON reporters
- [x] `mcp` collector (introspection-only)
- [x] Baseline/suppression store
- [x] SARIF reporter (CI integration)
- [x] LLM-as-judge detector
- [x] ML anomaly detector (embeddings + Isolation Forest/LOF, no labeled poison data required)
- [x] Taint graph analyzer (static mode)
- [x] `ts_schema` collector
- [x] Behavioral prober (sandboxed, dynamic mode)

## Known limitations

Tracked gaps, deliberately deferred rather than fixed ad hoc — see `ARCHITECTURE.md`'s "Known limitations" section for the detector-level tradeoffs (ML anomaly blend-in blind spot, taint over-approximation, etc.). Implementation-level gaps found during the build:

- **`raw_json` crashes on non-tool JSON matched by a source glob** — a stray file like `package.json` living in a scanned directory raises `KeyError`/`TypeError` instead of being skipped with a warning. Top-priority follow-up.
- **No detector inspects tool `parameters`** — only descriptions and names are analyzed, despite the threat model naming parameter schemas as in-scope. A parameter-schema detector is a natural next detector to add.
- Minor: the `**`-glob translator is duplicated between `python_schema.py`/`ts_schema.py`; a few config fields re-spell the severity literal instead of referencing the `Severity` enum; behavioral-prober findings aren't baseline-suppressible; `--update-baseline` doesn't warn when approving currently-flagged tools; a few file-writing paths don't create parent directories.

## License

MIT — see [`LICENSE`](./LICENSE).

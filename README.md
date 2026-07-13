# mcp-tool-poisoning-scanner

A config-driven scanner for **tool poisoning**: malicious or manipulative instructions embedded in the tool descriptions/schemas an LLM agent reads to decide how to call its tools (MCP servers, function-calling definitions, agent skill files).

## Why

Once an LLM agent is wired to tools, it trusts each tool's *description* the same way it trusts its system prompt. A tool description can embed instructions aimed at the model rather than at the human reading the code — and because the tool still does what it claims, nothing looks broken. That description ships inside a package, a config file, or a remote MCP server response, and it fires on every invocation, silently, until someone reads the metadata closely enough to catch it.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full threat model, system design, and rationale.

## Status

**Implemented.** Phases 0–11 of the implementation plan are complete — all 5 detectors (heuristic, LLM-as-judge, ML anomaly, taint graph, behavioral prober) and all 4 collectors (raw_json, python_schema, mcp, ts_schema) are wired into the scan engine. See the roadmap below.

## How it will work (summary)

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

## License

MIT — see [`LICENSE`](./LICENSE).

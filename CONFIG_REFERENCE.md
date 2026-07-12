# Configuration reference

The scanner has exactly one required input: a config file (default path `./tool-scan.config.yaml`, overridable with `--config`). Everything the scanner does — which sources it reads, which detectors run, what gets suppressed, how results are reported — is declared here. There are no hidden defaults that change behavior silently; every default is spelled out below and written into `src/config/defaults.yaml` in the reference implementation so a generated "effective config" can always be printed with `--print-effective-config`.

## Full annotated example

```yaml
# tool-scan.config.yaml

version: 1

# ── Sources ─────────────────────────────────────────────────────────
# Every tool-definition source the scan should collect from. Order does
# not matter; all sources are collected in parallel. A scan with zero
# sources is a config error, not a silent no-op.
sources:
  - type: mcp
    name: internal-mcp-server
    uri: "http://localhost:8931"
    introspect_only: true        # default true; refuses to invoke tools during scan
    timeout_seconds: 10

  - type: mcp
    name: third-party-search-mcp
    uri: "https://tools.example-vendor.com/mcp"
    introspect_only: true
    auth:
      type: bearer
      token_env: THIRD_PARTY_MCP_TOKEN   # never inline secrets in config

  - type: python_schema
    name: backend-tools
    path: "./services/agent/tools/"
    include_glob: "**/*.py"
    exclude_glob: "**/*_test.py"

  - type: ts_schema
    name: frontend-agent-tools
    path: "./apps/agent-web/src/tools/"
    include_glob: "**/*.ts"

  - type: raw_json
    name: declared-schemas
    path: "./schemas/tools/*.json"

# ── Detectors ───────────────────────────────────────────────────────
detectors:

  heuristic:
    enabled: true                # on by default: fast, free, no external deps
    rule_packs:
      - "./rules/default_rule_pack.yaml"   # ships with the tool
      - "./rules/org_custom_rules.yaml"    # team-specific additions, optional
    # Inline rules are merged with rule_packs; useful for one-offs without
    # maintaining a separate file.
    rules:
      - id: org-internal-hostname-leak
        pattern: "internal\\.corp\\.example\\.com"
        description: "Tool description references an internal-only hostname"
        severity: medium

  llm_judge:
    enabled: false               # off by default: costs money, calls an external API
    provider: anthropic
    model: claude-sonnet-5
    api_key_env: ANTHROPIC_API_KEY
    temperature: 0
    confidence_threshold: 0.6     # findings below this confidence are dropped
    max_calls_per_scan: 200       # hard budget cap
    prompt_template: "./prompts/llm_judge_default.txt"   # overridable

  taint:
    enabled: true
    mode: static                  # static | dynamic
    trace_source: null            # required if mode: dynamic — path/URI to execution traces
    trust_tiers:
      # Declares which tools are "low trust" (ingest external content) and
      # "high trust" (side effects). Anything not listed defaults to
      # "unclassified" and generates a lower-severity finding rather than
      # being silently ignored.
      low_trust:
        - "search_web"
        - "read_url"
        - "read_inbox"
      high_trust:
        - "send_email"
        - "execute_shell"
        - "write_file"
        - "make_payment"

  behavioral:
    enabled: false                # off by default: executes the real system
    sandbox:
      type: docker
      image: "agent-sandbox:latest"
      network: none
      timeout_seconds: 120
    probe_set: "./probes/default_adversarial_probes.yaml"
    baseline_run: "./probes/baseline_benign_trace.json"

# ── Suppression / baseline ─────────────────────────────────────────
baseline:
  file: "./.tool-scan-baseline.json"   # auto-created on first run with --update-baseline
  # A finding is suppressed only if BOTH the ToolDefinition.id and the
  # exact description-content hash match a baseline entry. Any change to
  # a previously-approved tool's description re-surfaces it.

ignore_rules:
  - match:
      source: "third-party-search-mcp"
      tool_name: "debug_echo"
    reason: "Internal test tool, description intentionally uses imperative phrasing for QA harness, reviewed 2026-07-11"

# ── Reporting ───────────────────────────────────────────────────────
report:
  formats: [terminal, sarif]
  sarif:
    output_path: "./tool-scan-results.sarif"
  json:
    output_path: "./tool-scan-results.json"
  markdown:
    output_path: "./tool-scan-report.md"
  fail_on_severity: high          # process exit code non-zero if any finding >= this severity survives suppression
  min_severity_shown: low         # terminal/report noise floor
```

## Field reference

### `sources[]`

| Field | Type | Required | Notes |
|---|---|---|---|
| `type` | `mcp \| python_schema \| ts_schema \| raw_json` | yes | Selects the collector |
| `name` | string | yes | Must be unique; used in `ToolDefinition.id` hashing and in `ignore_rules` matching |
| `uri` (mcp) | string | yes for `mcp` | MCP server endpoint |
| `introspect_only` (mcp) | bool | no, default `true` | If `false`, permits the collector to actually invoke tools — strongly discouraged, requires explicit opt-out for a reason |
| `auth` (mcp) | object | no | `token_env` must name an environment variable; config never holds a literal secret |
| `path` (python_schema / ts_schema / raw_json) | string | yes | Filesystem root or glob |
| `include_glob` / `exclude_glob` | string | no | Defaults to all files of the relevant extension |

### `detectors.*.enabled`

Every detector defaults as documented in the example above (`heuristic: true`, everything else `false`). The scanner refuses to run with zero detectors enabled — same "no silent no-op" rule as sources.

### `detectors.heuristic.rules[].severity`

One of `low | medium | high | critical`. Severity is what `report.fail_on_severity` compares against, so this field is what actually gates CI, not just cosmetic.

### `detectors.taint.trust_tiers`

Any tool named in neither `low_trust` nor `high_trust` is not exempted — it's classified `unclassified` and taint edges touching it are still reported, just at reduced severity, so an incomplete trust-tier list degrades gracefully instead of silently missing tools.

### `baseline.file`

JSON, keyed by `ToolDefinition.id`, each entry storing the description-content hash that was approved and the date/reviewer note. Regenerated only via explicit `--update-baseline`, never implicitly during a normal scan — a normal scan must never be able to silently widen what's suppressed.

### `ignore_rules[].reason`

Required, non-empty. A rule engine that supports silent suppression (no reason recorded) is exactly the kind of "why does CI let this through" problem this tool exists to avoid one layer up — same discipline applies to itself.

## Design principle behind this file

Every option above exists because a prior section of `ARCHITECTURE.md` named a real cost/tradeoff that a team needs to be able to control without a code change: cost caps on the LLM judge, execution opt-in for the behavioral prober, per-source auth, and mandatory reasons on suppressions. If a future feature doesn't have a config knob, that's a design bug in the feature, not something to hardcode "for now."

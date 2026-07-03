# Warden Sentry Vulnerability Corpus

Direct Lash harness for Warden's Sentry benchmark runbook:
https://warden.sentry.dev/benchmarking/running/

The benchmark uses Warden's public `sentry-vulnerability-corpus.json`, groups
findings by `(Sentry SHA, target file)`, reads each historical Sentry target
file, builds Warden-style synthetic whole-file patches, calls upstream Warden's
built diff parser/split/coalesce modules for chunking, and runs one Lash
security-review turn per Warden chunk. Trusted runs execute each task in Docker
and keep corpus findings out of the child process and per-task result artifacts.
A completed analysis run is still a raw, non-comparable state until the runner
finalizes raw chunk predictions: Lash normalizes raw findings, upstream Warden's
SDK performs deterministic title/location dedupe, Lash performs the repo-aware
verifier pass and merge-group synthesis, and upstream Warden's SDK applies
`applyMergeGroups`. Semantic scoring uses that finalized artifact, not the raw
verifier-off rows.

## Setup

```sh
bench/warden-sentry/setup.sh
```

This downloads the corpus into:

```text
.benchmarks/warden-sentry/sentry-vulnerability-corpus.json
```

The Sentry repository mirror is created lazily under
`.benchmarks/warden-sentry/workspace/` on the first real run. The clone uses
Git partial clone filtering so blobs are fetched on demand.

Comparable runs also require a built upstream Warden checkout at
`/tmp/ref-warden`. The runner imports these public built modules directly:
`packages/warden/dist/diff/parser.js`,
`packages/warden/dist/diff/coalesce.js`, and
`packages/warden/dist/sdk/extract.js`. If they are missing, the runner fails
chunking or post-processing instead of falling back to a local clone of Warden
logic.

## Run One Task

```sh
bench/warden-sentry/run.sh --dry-run --finding-id sentry-vuln-001
bench/warden-sentry/run.sh --finding-id sentry-vuln-001 --model gpt-5.5 --variant high --execution-mode rlm
bench/warden-sentry/run.sh --finding-id sentry-vuln-001 --provider-id openai-compatible --model z-ai/glm-5.2
```

If `--model` is omitted, the runner uses the active provider default from
`~/.lash/config.json`. Use `--provider-id <key>` to select another configured
provider. `--variant` is optional because some providers/models do not expose
configurable reasoning effort.

## Full Corpus Run

The local corpus mirrors upstream Warden's 86 findings across 79 target files
and 156 Warden chunks across 6 Sentry commits. For a Codex GPT-5.5 high-effort
RLM run:

```sh
bench/warden-sentry/run.sh \
  --run-id warden-sentry-rlm-codex-gpt55-high-$(date -u +%Y%m%d) \
  --provider-id codex \
  --model gpt-5.5 \
  --variant high \
  --execution-mode rlm \
  --max-task-provider-total-tokens 2000000 \
  --batch-size 15 \
  --fail-fast \
  --input-cost-per-mtok 5 \
  --output-cost-per-mtok 30 \
  --cached-input-cost-per-mtok 0.5 \
  --reasoning-cost-per-mtok 0 \
  --resume
```

Docker isolation is the default. The parent materializes a Sentry checkout,
passes only a sanitized task spec into the container, bind-mounts the checkout
read-only, bind-mounts only the task artifact directory as writable, and removes
the copied Lash config after provider initialization. Use
`--isolation host-unsafe` only for local debugging.

The default `--max-turns` is 100 to match Warden's benchmark runbook. Increase
or lower `--batch-size` based on provider reliability. `--batch-size 15` runs
15 Docker children concurrently; if provider throttling appears, stop and
resume with a lower value. The token budget is a per-task runaway guard over
provider total tokens (`input + output`); pass `0` to disable it. For
Codex GPT-5.5 high, `1000000` can cap legitimate long-running chunks, so use
`2000000` for full-corpus runs unless you explicitly want a stricter guard.
`--fail-fast` stops the batch and removes active Docker children after the
first task error or non-completed task result.

Successful analysis runs automatically write finalized artifacts before
returning. If a run was produced by an older harness version or post-processing
needs to be rerun, use the explicit first-class step:

```sh
bench/warden-sentry/run.sh \
  --post-process-run-dir .benchmarks/warden-sentry/runs/<run-id> \
  --provider-id codex \
  --model gpt-5.5 \
  --variant high \
  --post-process-batch-size 15 \
  --input-cost-per-mtok 5 \
  --output-cost-per-mtok 30 \
  --cached-input-cost-per-mtok 0.5 \
  --reasoning-cost-per-mtok 0
```

Post-processing persists verifier sessions and merge prompts/responses under
the run directory, writes a reproducibility manifest, and rewrites only
finalization artifacts and summary metadata. If canonical `semantic-scoring.*`
files already exist, the runner renames them to
`semantic-scoring.<prior-input-state>.json` style stale artifacts before
finalization, rewrites their metadata with `stale_non_comparable` plus the
actual prior input state/artifact, and lists them in summary metadata.

To estimate cost in the same run artifacts, pass per-million-token rates or set
the matching environment variables:

```sh
bench/warden-sentry/run.sh \
  --finding-id sentry-vuln-001 \
  --input-cost-per-mtok 5 \
  --output-cost-per-mtok 30 \
  --cached-input-cost-per-mtok 0.5 \
  --reasoning-cost-per-mtok 0
```

If rates are omitted, the runner still records all token counts and emits
`pricingStatus: "not_configured"` with `costUSD: null`. The example above uses
the USD-equivalent Warden reference rates for Codex GPT-5.5: official Codex
pricing lists 125 input credits, 12.5 cached-input credits, and 750 output
credits per million tokens; with 25 credits per USD, those map to
`5 / 0.5 / 30` USD per million tokens.

## Score Existing Run

Semantic scoring is a separate first-class step because grader calls are
auxiliary benchmark work, not analysis work. The scorer requires both
`warden-final.jsonl` and `summary.json` with `wardenComparable: true`. It
reproduces the published Sentry corpus result lane named
`agent-semantic-match-pass`: each finalized emitted finding is scored against
the same-SHA corpus findings shown to the grader, and unique
`matchedCorpusIds` are aggregated into `knownFound`.

```sh
bench/warden-sentry/run.sh \
  --score-run-dir .benchmarks/warden-sentry/runs/<run-id> \
  --provider-id anthropic \
  --model claude-sonnet-4-6 \
  --score-batch-size 8
```

Set the provider API key for the configured scoring model, such as
`ANTHROPIC_API_KEY` for Anthropic. The canonical score artifact follows the
published result shape: top-level `runId`, `corpusId`, `scoring`, and `scores`,
with `scoring.reviewer: "agent-semantic-match-pass"` and per-finding
`findingId`, `matchedCorpusIds`, `verdict`, and `notes` rows.

`--score-batch-size` controls semantic-match call parallelism. Scoring is
auxiliary work, so bounded parallel grader calls do not change analysis
behavior; the runner sorts score rows by finalized finding order before writing
artifacts. The progress file
`semantic-scoring.agent-semantic-match-pass.progress.jsonl` is resumable and
records per-call token usage for audit, but it is not the canonical comparison
result.

Score artifacts, after a finalized comparable run:

```text
.benchmarks/warden-sentry/runs/<run-id>/
  semantic-scoring.json
  semantic-scoring-summary.md
  summary.json  # top-level scoring block is updated
```

Any `semantic-scoring.<prior-input-state>.*` files in the same directory are
historical non-comparable stale artifacts retained only for audit. Their
metadata records the actual previous input state/artifact and must not be used
as finalized comparison scores.

`--score-run-dir` scores every finalized chunk row in that run directory. Task
selectors such as `--limit`, `--task-id`, `--finding-id`, `--sha`, and
`--target-path` are only for analysis runs and are rejected in score mode.

## Validate Finalized Run

Before publishing comparison numbers, validate the finalized/scored artifact
set:

```sh
bench/warden-sentry/run.sh \
  --validate-run-dir .benchmarks/warden-sentry/runs/<run-id>
```

Validation writes `post-processing/validation.json` and fails the command if
any publishing invariant is broken: 156 chunk records plus one summary record
in `warden-final.jsonl`, verifier and merge artifact counts matching
post-processing metadata, stale scoring artifacts renamed/listed/marked
non-comparable with prior input metadata, semantic scoring internals matching
`summary.json`, `wardenComparable: true`, and matching scan/auxiliary/total costs across
`summary.json`, `post-processing/summary.json`, and `warden-final.jsonl`.

Useful selectors:

```sh
bench/warden-sentry/run.sh --dry-run --limit 10
bench/warden-sentry/run.sh --sha 788ba30f1aa42b00c02d64ed4b8b2515ff8ab8da
bench/warden-sentry/run.sh --target-path src/sentry/api/endpoints/accept_organization_invite.py
bench/warden-sentry/run.sh --task-id 788ba30f-src-sentry-api-endpoints-accept-organization-invite-py-l1-218
```

## Output

Each run writes:

```text
.benchmarks/warden-sentry/runs/<run-id>/
  run.log
  predictions.jsonl          # raw per-chunk Lash analysis rows
  warden-final.jsonl         # finalized Warden-compatible chunk + summary JSONL
  summary.json
  post-processing/
    summary.json
    events.jsonl
    reproducibility-manifest.json
    runner-source-snapshot.jsonl
    upstream-bridge-probe.json
    validation.json
    verification/
    merge/
  targets/
    targets-<sha8>.txt
  tasks/<task-id>/
    prompt.txt
    task.json
    result.json
    events.jsonl
    session.trace.jsonl
    session.db
    child.stdout.log
    child.stderr.log
```

`predictions.jsonl` contains one raw `TaskResult` JSON row per chunk task,
including the assistant's response, parsed JSON when available, token totals,
tool counts, estimated cost fields when pricing is configured, Warden chunk line
metadata, raw findings breakdowns, and artifact paths. It intentionally does
not store corpus finding ids or summaries. Findings outside the chunk line
range are dropped before raw result totals, matching Warden's defense-in-depth
hunk filter.

`warden-final.jsonl` is the finalized Warden-compatible output emitted by Lash.
It contains one schema-versioned chunk record per task plus a trailing summary
record. Its findings are Warden `Finding` records after Lash normalization,
upstream Warden SDK dedupe, Lash verification, Lash merge-group synthesis, and
upstream Warden SDK `applyMergeGroups`. Its `usageBreakdown` separates scan
usage from auxiliary verification/merge usage and includes total usage. The
post-processing summary and top-level summary carry the same auxiliary and total
cost accounting.

`post-processing/reproducibility-manifest.json` records the runner git SHA,
git status, source tree hash, git diff hash, reconstructible source snapshot
artifact/hash, current binary hash, corpus hash, upstream Warden reference SHA,
upstream bridge probe result, model/provider/variant, prompt/schema hashes
including the semantic-match response schema, Docker image digest, and cost
config. `cleanState` and `cleanStateWarning` are reproducibility signals only;
they do not replace the artifact-level
`wardenComparable` marker.

On `--resume`, the runner reconciles `predictions.jsonl` with durable per-task
`result.json` files: completed artifacts missing from the JSONL are imported,
and non-completed JSONL rows are removed so failed chunks can be retried rather
than silently skipped.

In Docker mode, all durable task logs are written through the per-task bind
mount under the run directory. Container removal does not remove `run.log`,
`child.stdout.log`, `child.stderr.log`, `events.jsonl`, `session.trace.jsonl`,
`session.db`, `prompt.txt`, `task.json`, or `result.json`.

`summary.json` keeps the legacy snake-case fields and adds Warden-style
comparison fields:

- run metadata: `runId`, `benchmark`, `repository`, `runtime`, `runtimeVersion`,
  `skill`, `targetMode`, `model`, `providerKind`, `reasoningLevel`,
  `executionMode`, `maxTurns`, `maxContextTokens`, `reportOn`, and
  `minConfidence`.
- artifact metadata: `runLogArtifact`, `rawJsonlArtifact`,
  `targetListArtifacts`, `traceCapture`, `artifactPersistence`,
  `rawArtifactsReviewStatus`, and per-shard `targetList`, `traceArtifacts`,
  `eventArtifacts`, `childStdoutArtifacts`, `childStderrArtifacts`,
  `promptArtifacts`, `taskSpecArtifacts`, and `resultArtifacts`.
- finalization metadata: `postProcessing`, `findingVerification`,
  `finalJsonlArtifact`, `reproducibilityManifestArtifact`,
  `comparisonState`, and `wardenComparable`.
- run summary: corpus finding count, target file count, files/chunks analyzed,
  succeeded/failed chunks, parsed finding totals, severity/confidence
  breakdowns, input/output/reasoning/cache token totals, estimated cost totals,
  and pricing configuration/status.
- timing: wall duration, task duration, turn duration, and checkout duration
  rollups with total/min/p50/p75/p90/p95/max milliseconds.
- shard summaries grouped by Sentry SHA, matching Warden's by-SHA benchmark
  reporting model.
- semantic scoring, after post-processing and `--score-run-dir`, with the
  published `agent-semantic-match-pass` score block and per-finding score rows.

## Notes

- The default execution mode is `standard`, with rolling history. Pass
  `--execution-mode rlm` to run the same target through Lash RLM.
- The harness intentionally reviews only corpus target files, matching Warden's
  runbook guidance not to scan all of Sentry.
- Chunking calls upstream Warden's built parser/split/coalesce modules on the
  file-target path: treat the full target file as an added patch, split large
  hunks at 8,000 UTF-16 code units, coalesce chunks within 30 lines when the
  combined size stays under 8,000, and include 20 context lines before and after
  the hunk.
- `summary.json` starts with `wardenComparable: false`,
  `comparisonState: "raw-unfinalized"`, and `scoring.status: "unscored"`.
  Post-processing marks successful finalization with `wardenComparable: true`
  and `comparisonState: "finalized-unscored"`; `--score-run-dir` patches it to
  `comparisonState: "finalized-scored"`.
- Raw `predictions.jsonl` rows are useful for audit/debugging, but are not
  publishable comparison rows until `warden-final.jsonl` has been produced and
  `summary.json` says `wardenComparable: true`.
- Use the claim "upstream Warden SDK chunking/dedupe/merge-application with
  Lash analysis, verifier, merge synthesis, and published
  `agent-semantic-match-pass` semantic grading." Do not claim full upstream
  Warden runtime/tool execution unless the verifier also uses upstream Warden
  runtime/tool execution directly and that lane configuration is recorded in the
  reproducibility manifest.
- Rust tests include bridge-backed chunking, dedupe, and merge-application
  fixtures against `/tmp/ref-warden` when the built upstream modules are
  available. If the checkout/build is missing, bridge-dependent tests skip the
  assertion, while real comparable runs fail loudly.
- `predictions.jsonl` is rejected on resume/scoring if it contains duplicate
  task rows.
- Pass `--keep-worktrees` when debugging a task checkout; otherwise task
  worktrees are removed after result artifacts are written.

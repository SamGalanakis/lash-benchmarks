# Terminal-Bench 2.1

This directory is the tracked home for lash's Terminal-Bench 2.1 (Harbor) setup.

Canonical dataset: `terminal-bench/terminal-bench-2-1`.

The lash agent uses **your local Codex OAuth subscription** by default — the harness rsyncs `~/.lash/config.json` into the benchmark container, so every task call bills through your active provider (typically Codex GPT-5.5). No OpenRouter / API-key juggling.

The upstream comparison target, leaderboard row metadata, and token/cost
reference notes live in [`UPSTREAM_REFERENCE.md`](UPSTREAM_REFERENCE.md).

## Quickstart

```bash
# Smoke test - one easy task, RLM + gpt-5.5 at high effort.
bench/terminalbench2/run.sh --preset trivial --execution-mode rlm --provider codex --model gpt-5.5 --variant high

# Published Codex CLI leaderboard row shape: Terminal-Bench 2.1, Harbor codex
# agent, gpt-5.5, high effort, Codex CLI 0.125.0, 5 attempts/task.
bench/terminalbench2/run.sh --leaderboard-codex

# Full Terminal-Bench 2.1 dataset, RLM.
bench/terminalbench2/run.sh --execution-mode rlm --provider codex --model gpt-5.5 --variant high

# Full dataset, but reuse already-completed matching task attempts from prior runs.
bench/terminalbench2/run.sh --execution-mode rlm --provider codex --model gpt-5.5 --variant high --attempts 5 --reuse-completed

# Full Terminal-Bench 2.1 dataset, Standard mode + rolling history.
bench/terminalbench2/run.sh --full --execution-mode standard --model gpt-5.5 --variant high --context-approach rolling_history
```

`--model` is optional; if `~/.lash/config.json`'s active provider is Codex, passing just `--variant high` picks up whatever model that provider is configured with. We pin `--model gpt-5.5` in examples to make runs reproducible across config changes.

Use `--provider codex` to force the Lash provider for a run without changing your host config. The runner writes a run-local config with `active_provider` switched to `codex`, copies that into the container, and exports the same config metadata into the structured results.

Or call the underlying script directly:

```bash
scripts/run-terminalbench.sh --help
```

## Presets

| Preset | Size | Notes |
|---|---|---|
| `trivial` | 1 task | Smoke test, one easy task. |
| `smoke` | 2 tasks | Quick sanity. |
| `smoke-5` | 5 tasks | Wider smoke across logs, regex, build, git, and nginx. |
| `fast-3` | 3 tasks | Three short tasks for fast iteration. |
| `fast-medium` | 4 tasks | Adds one medium task. |
| `memory-3` | 3 tasks | Memory-heavy tasks (full dataset only). |
| `recall-3` | 3 tasks | Recall-heavy tasks (full dataset only). |
| `representative-10` | 10 tasks | A mixed slice for leaderboard comparison (full dataset only). |
| `representative-20` | 20 tasks | Broader mixed slice from the official 89-task 2.1 package. |

Custom selection:

```bash
# One task by name
bench/terminalbench2/run.sh --task chess-best-move --execution-mode rlm --model gpt-5.5 --variant high

# Glob
bench/terminalbench2/run.sh --full --task "git-*" --execution-mode standard --model gpt-5.5 --variant high

# Explicit list
bench/terminalbench2/run.sh --tasks regex-log,fix-code-vulnerability --execution-mode standard --variant high
```

## Flags that matter

| Flag | Required | Notes |
|---|---|---|
| `--execution-mode` | yes (for lash) | `rlm` or `standard`. No `repl` (old name). |
| `--provider` | optional | Lash provider key to activate for this run, e.g. `codex`. |
| `--variant` | yes for lash/opencode | Provider-native effort level: `high`, `xhigh`, etc.; Codex defaults to Harbor's `high`. |
| `--model` | optional for lash | Defaults to the active provider's model in `~/.lash/config.json`. Pass `--model gpt-5.5` to pin. |
| `--leaderboard-codex` | no | Shortcut for the published Codex CLI row settings: Harbor `codex`, `gpt-5.5`, `high`, Codex CLI `0.125.0`, `--attempts 5`. |
| `--codex-version` | no | Pins the Codex CLI npm package for `--agent codex`; leave unset for latest. |
| `--context-approach` | optional | Standard mode only: `rolling_history` or `observational_memory`. |
| `--build-mode` | optional | `docker-bookworm` (default) / `docker-bullseye` / `host`. |
| `--n-concurrent` | optional | Parallel trials. Default 1. |
| `--attempts` | optional | Attempts per trial. Default 1. |
| `--reuse-completed` | no | Reuses completed prior task attempts with the same dataset, agent, model, variant, provider, execution mode, attempts, timeout, env, and extra args. Reused tasks are excluded from the new Harbor run, then their raw trial dirs are merged before export. |
| `--reuse-from` | no | Restrict reuse to a specific structured run directory or `run.json`. Repeatable; implies `--reuse-completed`. |

## Reusing Completed Trials

`--reuse-completed` is intended for the workflow where a smoke or representative
subset was already run with the exact settings you want for a larger run. The
runner scans structured runs under `.benchmarks/terminalbench2/runs`, finds
tasks with enough completed attempts, excludes those tasks from the new Harbor
run, and merges the reused raw trial directories into the new job before export.

Reuse is deliberately conservative:

- It only reuses trials with normal verifier rewards (`pass` or `fail`), not
  harness errors or missing rewards.
- It requires matching run settings, including `--attempts` and `-- --yes` style
  extra Harbor args.
- It preserves failed attempts too. A resumed k=5 run must carry the same five
  attempts, not only successes.
- It writes `reused-trials.json` into the raw job and structured
  `job-artifacts/` directory so the resumed result is auditable.

## Outputs

- **Harbor jobs**: `jobs/<job-name>/` — raw harbor session logs, pulled container filesystems.
- **Structured results**: `.benchmarks/terminalbench2/runs/<timestamp>__<job-name>/` — gathered trial JSONs + run summary.
- **JSONL run artifacts**: `trials.jsonl` has one full structured record per trial; `task_logs.jsonl` concatenates per-task durable log-sink records.
- **Per-trial log sink**: each trial has `artifacts/log_sink.jsonl`, preserving copied JSON/JSONL records and text log lines with task/trial/source metadata.
- **Lash traces**: exported under each trial's `artifacts/sessions/*.trace.jsonl` when the lash agent runs; dashboard LLM-call counts come from typed `llm_call_completed` trace records.

## Implementation notes

- Entry point: `bench/terminalbench2/run.sh` → `scripts/run-terminalbench.sh` → `harbor run …`.
- Lash driver: `scripts/harbor_lash_agent.py` — `BaseInstalledAgent` that rsyncs the host's lash binary + `~/.lash/config.json` into the container, then runs `lash --print "<task>"` with the right flags.
- Tracing: `scripts/run-terminalbench.sh` sets `LASH_LOG=debug` for lash runs so the CLI writes typed per-session traces. `scripts/terminalbench_results.py` reads those traces for model, token, turn, and completed-call metadata.
- **Credentials**: your host's `~/.lash/config.json` (with Codex OAuth tokens, OpenRouter key, etc.) is copied into the container. The container's lash picks up the active provider from that config. Bypass with `--allow-no-config` if you're testing non-lash agents (opencode / codex).
- The benchmark-harness guidance ("you're being graded by exact verifier checks, don't ask questions…") is folded directly into the user prompt by the Python agent. The old `--prompt-replace` / `--prompt-append` / `--prompt-disable` CLI flags were removed from lash; the harness no longer relies on them.
- Agent build: default is `docker-bookworm`, which installs the `lash` binary from the Git tag pinned in `lash-pin.env` (`LASH_GIT_TAG`, the CLI is not on crates.io) into `.lash-bin-bookworm/bin/lash`. Use `--no-build` to reuse a prior install.

## Requirements

- `harbor` CLI installed ([harbor-framework/harbor](https://github.com/harbor-framework/harbor)); install with `uv tool install harbor`.
- `docker` (unless `--build-mode host --env host`).
- `~/.lash/config.json` with an active provider set up (`lash --provider` interactively, or by copying a working config).

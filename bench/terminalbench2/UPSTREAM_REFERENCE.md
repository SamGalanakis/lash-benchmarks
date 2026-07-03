# Terminal-Bench 2.1 Upstream Reference

Last checked: 2026-07-03.

This file captures the expected upstream comparison target for our
Terminal-Bench 2.1 work. Use it as the quick sanity reference before changing
the runner, interpreting a full run, or comparing costs.

## Official Terminal-Bench Leaderboard Target

Source: <https://www.tbench.ai/leaderboard/terminal-bench/2.1>

Official submission command shape:

```bash
harbor run -d terminal-bench/terminal-bench-2-1 -a "agent" -m "model" -k 5
```

Official custom-agent command shape:

```bash
harbor run -d terminal-bench/terminal-bench-2-1 --agent-import-path "path.to.agent:SomeAgent" -k 5
```

Published row to compare against:

| Field | Expected upstream value |
|---|---|
| Rank | 1 |
| Agent | Codex CLI |
| Model | GPT-5.5 |
| Date | 2026-05-01 |
| Agent org | OpenAI |
| Model org | OpenAI |
| Accuracy | 83.4% +/- 2.2 |
| Integration method | API |
| Harbor agent name | codex |
| Codex CLI version | 0.125.0 |
| Model name | gpt-5.5 |
| Model provider | openai |
| Attempts per task | 5 |

The official page says submissions may not modify timeouts or resources, and
that a Terminal-Bench team member ran and verified the leaderboard results.

## Dataset

Source: <https://hub.harborframework.com/datasets/terminal-bench/terminal-bench-2-1/6>

Canonical dataset:

```text
terminal-bench/terminal-bench-2-1
```

Harbor Hub describes this as Terminal-Bench 2.1 and notes that 26 tasks were
modified from 2.0 to fix bugs, modify timeouts/resources, or improve robustness
to reward hacking.

## Harbor Codex Agent Defaults

Source:
<https://raw.githubusercontent.com/harbor-framework/harbor/main/src/harbor/agents/installed/codex.py>

The built-in Harbor Codex agent exposes `reasoning_effort` as a CLI flag with
default `high`, formatted as:

```text
-c model_reasoning_effort=high
```

It also installs `@openai/codex@<version>` when the agent `version` kwarg is
provided. Our comparable Codex shortcut therefore pins:

```bash
bench/terminalbench2/run.sh --leaderboard-codex
```

which expands to Harbor `codex`, `gpt-5.5`, `reasoning_effort=high`, Codex CLI
`0.125.0`, and `--attempts 5`.

## Token And Cost Reference

The official Terminal-Bench leaderboard does not publish token or dollar spend
for the Codex CLI row.

Artificial Analysis publishes a separate Terminal-Bench v2.1 page:
<https://artificialanalysis.ai/evaluations/terminalbench-v2-1>

Important: those numbers are not the official Codex CLI leaderboard row. Their
page says they run Terminal-Bench v2.1 with the Terminus 2 harness in E2B and
report pass@1 averaged over 3 repeats per task.

The embedded Artificial Analysis row for `GPT-5.5 (xhigh), OpenAI` had these
values when checked:

| Field | Artificial Analysis value |
|---|---:|
| Terminal-Bench v2.1 score | 84.27% |
| Input tokens | 26,929,862 |
| Answer tokens | 617,745 |
| Reasoning tokens | 2,100,153 |
| Output tokens | 2,717,898 |
| Eval cost total | $124.8051 |
| Input cost | $43.2681 |
| Cache read cost | $10.1535 |
| Cache write cost | $33.1147 |
| Output cost | $81.5369 |
| Reasoning cost | $63.0046 |
| Answer cost | $18.5324 |
| Eval time per task | 432.99s |

Treat these as a spend sanity check for a different harness/model-setting row,
not as the Codex CLI expected spend.

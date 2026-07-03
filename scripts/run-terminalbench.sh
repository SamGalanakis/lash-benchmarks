#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

PIN_FILE="${REPO_ROOT}/lash-pin.env"
if [[ -f "${PIN_FILE}" ]]; then
  # shellcheck source=/dev/null
  source "${PIN_FILE}"
fi
LASH_GIT_URL="${LASH_GIT_URL:-https://github.com/SamGalanakis/lash}"
LASH_GIT_TAG="${LASH_GIT_TAG:-}"
LASH_GIT_BRANCH="${LASH_GIT_BRANCH:-}"
LASH_GIT_REV="${LASH_GIT_REV:-}"
TERMINALBENCH_DATASET="terminal-bench/terminal-bench-2-1"
LEADERBOARD_CODEX_VERSION="0.125.0"

usage() {
  cat <<'EOF'
Run Terminal-Bench 2.1 via Harbor.

Usage:
  scripts/run-terminalbench.sh [options] [-- <extra harbor args>]

Options:
  --agent <name>                Agent to run: lash|opencode|codex (default: lash)
  --dataset <org/name>          Dataset to run (default: terminal-bench/terminal-bench-2-1)
  --full                        Shortcut for the canonical Terminal-Bench 2.1 dataset
  --leaderboard-codex           Match the published Terminal-Bench 2.1 Codex CLI row:
                                codex, gpt-5.5, high effort, Codex CLI 0.125.0, k=5
  --preset <name>               Exact task preset: trivial|smoke|smoke-5|fast-3|fast-medium|memory-3|recall-3|representative-10|representative-20
  --task <glob>                 Task include pattern (repeatable)
  --tasks <a,b,c>               Exact task names as a comma-separated list
  --task-file <path>            Exact task names from a file (one per line, # comments allowed)
  --exclude-task <glob>         Task exclude pattern (repeatable)
  --model <model>               Model to request from the benchmark agent
                                (optional for lash, required for opencode and codex)
  --provider <kind>             Lash provider key to activate for this run
                                (for example: codex; optional for --agent lash)
  --variant <name>              Provider-native model variant passed through when supported
                                (required for lash/opencode; default high for codex)
  --codex-version <version>     Codex CLI npm version for --agent codex (default: latest;
                                leaderboard row reports 0.125.0)
  --execution-mode <mode>       Lash execution mode: rlm|standard
                                (required for --agent lash; ignored for opencode)
  --context-approach <name>     Lash standard-mode context approach:
                                rolling_history|observational_memory
                                (optional for --agent lash with --execution-mode standard;
                                ignored for opencode)
  --jobs-dir <path>             Harbor jobs output dir (default: jobs)
  --results-dir <path>          Persistent structured results dir (default: .benchmarks/terminalbench2)
  --job-name <name>             Harbor job name (optional)
  --n-concurrent <int>          Concurrent trials (default: 1)
  --attempts <int>              Attempts per trial (default: 1)
  --timeout-multiplier <float>  Task timeout multiplier (default: 1.0)
  --env <name>                  Harbor environment backend (default: docker)
  --registry-url <url>          Optional dataset registry override
                                (default: Harbor CLI default)
  --build-mode <mode>           Lash build mode: host|docker-bookworm|docker-bullseye
                                (default: docker-bookworm)
  --no-build                    Skip building the lash benchmark binary
  --debug                       Enable Harbor debug logging
  --no-debug                    Disable Harbor debug logging (default)
  --delete                      Delete benchmark environments after run
  --no-delete                   Keep benchmark environments after run
  --reuse-completed             Reuse completed matching task attempts from
                                previous structured runs and skip rerunning
                                tasks with enough attempts
  --reuse-from <path>           Restrict reuse to a structured run directory
                                or run.json (repeatable; implies
                                --reuse-completed)
  --allow-no-config             Do not require ~/.lash/config.json for lash runs
  --dry-run                     Print command and exit
  --help                        Show this help

Examples:
  scripts/run-terminalbench.sh --execution-mode rlm --variant high
  scripts/run-terminalbench.sh --execution-mode rlm --provider codex --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --preset trivial --execution-mode rlm --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --preset smoke --execution-mode rlm --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --preset fast-3 --execution-mode standard --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --preset fast-medium --execution-mode standard --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --preset memory-3 --execution-mode standard --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --preset recall-3 --execution-mode standard --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --preset representative-10 --execution-mode standard --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --full --execution-mode standard --task "git-*" --variant high
  scripts/run-terminalbench.sh --execution-mode standard --tasks regex-log,fix-code-vulnerability --variant high
  scripts/run-terminalbench.sh --execution-mode standard --context-approach rolling_history --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --execution-mode rlm --task chess-best-move --model gpt-5.5 --variant high
  scripts/run-terminalbench.sh --agent opencode --model openai/gpt-5.5 --variant high
  scripts/run-terminalbench.sh --leaderboard-codex
  scripts/run-terminalbench.sh --agent codex --model gpt-5.5 --variant high --codex-version 0.125.0 --attempts 5
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: required command not found: $1" >&2
    exit 1
  fi
}

require_lash_pin() {
  if [[ -z "${LASH_GIT_TAG}" && -z "${LASH_GIT_BRANCH}" && -z "${LASH_GIT_REV}" ]]; then
    echo "error: one of LASH_GIT_REV, LASH_GIT_BRANCH, or LASH_GIT_TAG is required; set it in ${PIN_FILE}" >&2
    exit 1
  fi
}

lash_ref_args() {
  local -n out_ref_args="$1"
  out_ref_args=()
  if [[ -n "${LASH_GIT_REV}" ]]; then
    out_ref_args=(--rev "${LASH_GIT_REV}")
  elif [[ -n "${LASH_GIT_BRANCH}" ]]; then
    out_ref_args=(--branch "${LASH_GIT_BRANCH}")
  else
    out_ref_args=(--tag "${LASH_GIT_TAG}")
  fi
}

lash_ref_label() {
  if [[ -n "${LASH_GIT_REV}" ]]; then
    printf 'rev %s' "${LASH_GIT_REV}"
  elif [[ -n "${LASH_GIT_BRANCH}" ]]; then
    printf 'branch %s' "${LASH_GIT_BRANCH}"
  else
    printf 'tag %s' "${LASH_GIT_TAG}"
  fi
}

DATASET="${TERMINALBENCH_DATASET}"
AGENT="lash"
JOBS_DIR="jobs"
RESULTS_DIR=".benchmarks/terminalbench2"
JOB_NAME=""
MODEL=""
LASH_PROVIDER_KIND=""
VARIANT=""
CODEX_AGENT_VERSION=""
EXECUTION_MODE=""
CONTEXT_APPROACH=""
BUILD_MODE="docker-bookworm"
N_CONCURRENT="1"
N_CONCURRENT_SET=0
ATTEMPTS="1"
TIMEOUT_MULT="1.0"
ENV_BACKEND="docker"
REGISTRY_URL=""
DO_BUILD=1
DELETE_AFTER_RUN=1
REQUIRE_CONFIG=1
DRY_RUN=0
DEBUG=0
TASK_PRESET=""
REUSE_COMPLETED=0
REUSE_PLAN_PATH=""
REUSE_PROVIDER_KIND=""
SKIP_HARBOR=0

TASK_PATTERNS=()
EXACT_TASKS=()
EXCLUDE_PATTERNS=()
EXTRA_ARGS=()
REUSE_SOURCES=()
REUSE_EXCLUDE_TASKS=()

readonly PRESET_TRIVIAL_TASKS=(
  "log-summary-date-ranges"
)

readonly PRESET_SMOKE_TASKS=(
  "log-summary-date-ranges"
  "fix-code-vulnerability"
)

readonly PRESET_SMOKE_5_TASKS=(
  "log-summary-date-ranges"
  "regex-log"
  "build-cython-ext"
  "git-leak-recovery"
  "nginx-request-logging"
)

readonly PRESET_FAST_3_TASKS=(
  "log-summary-date-ranges"
  "fix-code-vulnerability"
  "regex-log"
)

readonly PRESET_FAST_MEDIUM_TASKS=(
  "regex-log"
  "log-summary-date-ranges"
  "fix-code-vulnerability"
  "sqlite-with-gcov"
)

readonly PRESET_MEMORY_3_TASKS=(
  "password-recovery"
  "db-wal-recovery"
  "git-leak-recovery"
)

readonly PRESET_RECALL_3_TASKS=(
  "password-recovery"
  "git-leak-recovery"
  "sanitize-git-repo"
)

readonly PRESET_REPRESENTATIVE_10_TASKS=(
  "build-cython-ext"
  "configure-git-webserver"
  "db-wal-recovery"
  "fix-code-vulnerability"
  "git-leak-recovery"
  "log-summary-date-ranges"
  "nginx-request-logging"
  "polyglot-c-py"
  "regex-log"
  "sqlite-with-gcov"
)

readonly PRESET_REPRESENTATIVE_20_TASKS=(
  "build-cython-ext"
  "compile-compcert"
  "configure-git-webserver"
  "db-wal-recovery"
  "fix-code-vulnerability"
  "git-leak-recovery"
  "log-summary-date-ranges"
  "make-doom-for-mips"
  "mteb-leaderboard"
  "nginx-request-logging"
  "password-recovery"
  "polyglot-c-py"
  "pytorch-model-recovery"
  "query-optimize"
  "raman-fitting"
  "regex-log"
  "sanitize-git-repo"
  "sparql-university"
  "sqlite-with-gcov"
  "torch-tensor-parallelism"
)

validate_task_preset_scope() {
  if [[ -z "${TASK_PRESET}" ]]; then
    return 0
  fi
  if [[ "${DATASET}" != "${TERMINALBENCH_DATASET}" ]]; then
    echo "error: --preset ${TASK_PRESET} is defined for ${TERMINALBENCH_DATASET}." >&2
    echo "requested dataset: ${DATASET}" >&2
    exit 2
  fi
}

validate_dataset_cutover() {
  case "${DATASET}" in
    terminal-bench@2.0|terminal-bench-sample@2.0|terminal-bench/terminal-bench-2)
      echo "error: ${DATASET} is a superseded Terminal-Bench 2.0 dataset." >&2
      echo "use ${TERMINALBENCH_DATASET} for Terminal-Bench 2.1." >&2
      exit 2
      ;;
  esac
}

strip_terminalbench_task_prefix() {
  local value="$1"
  value="${value#terminal-bench/}"
  printf '%s' "${value}"
}

harbor_task_filter_name() {
  local task_name="$1"
  if [[ "${DATASET}" == "${TERMINALBENCH_DATASET}" && "${task_name}" != */* ]]; then
    printf 'terminal-bench/%s' "${task_name}"
  else
    printf '%s' "${task_name}"
  fi
}

validate_exact_task_execution() {
  local job_dir="$1"
  if [[ ${#EXACT_TASKS[@]} -eq 0 ]]; then
    return 0
  fi

  local requested_csv actual_csv task_name
  local requested_tasks=()
  for task_name in "${EXACT_TASKS[@]}"; do
    requested_tasks+=("$(strip_terminalbench_task_prefix "${task_name}")")
  done
  requested_csv="$(printf '%s\n' "${requested_tasks[@]}" | sort -u | paste -sd, -)"
  actual_csv="$(python3 - "${job_dir}" <<'PY'
import json
import sys
from pathlib import Path

job_dir = Path(sys.argv[1])
names = set()
for result_path in sorted(job_dir.glob("*__*/result.json")):
    try:
        data = json.loads(result_path.read_text())
    except (OSError, json.JSONDecodeError):
        continue
    name = data.get("task_name")
    if not isinstance(name, str) or not name.strip():
        name = result_path.parent.name.split("__", 1)[0]
    name = name.strip()
    if name.startswith("terminal-bench/"):
        name = name.removeprefix("terminal-bench/")
    if name:
        names.add(name)

print(",".join(sorted(names)))
PY
)"
  if [[ -z "${actual_csv}" ]]; then
    actual_csv="$(find "${job_dir}" -mindepth 1 -maxdepth 1 -type d -name '*__*' -printf '%f\n' | sed 's/__.*//; s#^terminal-bench/##' | sort -u | paste -sd, -)"
  fi

  if [[ "${requested_csv}" != "${actual_csv}" ]]; then
    echo "error: exact-task benchmark scope mismatch; refusing to export an ambiguous run." >&2
    echo "dataset: ${DATASET}" >&2
    echo "requested exact tasks (${#EXACT_TASKS[@]}): ${requested_csv}" >&2
    echo "executed task dirs: ${actual_csv:-<none>}" >&2
    return 1
  fi
}

append_exact_tasks() {
  local raw="$1"
  local part trimmed
  IFS=',' read -r -a parts <<<"${raw}"
  for part in "${parts[@]}"; do
    trimmed="$(printf '%s' "${part}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if [[ -n "${trimmed}" ]]; then
      EXACT_TASKS+=("${trimmed}")
    fi
  done
}

load_task_file() {
  local path="$1"
  if [[ ! -f "${path}" ]]; then
    echo "error: task file not found: ${path}" >&2
    exit 1
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%%#*}"
    line="$(printf '%s' "${line}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    if [[ -n "${line}" ]]; then
      EXACT_TASKS+=("${line}")
    fi
  done <"${path}"
}

apply_task_preset() {
  local preset="$1"
  case "${preset}" in
    trivial)
      EXACT_TASKS+=("${PRESET_TRIVIAL_TASKS[@]}")
      ;;
    smoke)
      EXACT_TASKS+=("${PRESET_SMOKE_TASKS[@]}")
      ;;
    smoke-5)
      EXACT_TASKS+=("${PRESET_SMOKE_5_TASKS[@]}")
      ;;
    fast-3)
      EXACT_TASKS+=("${PRESET_FAST_3_TASKS[@]}")
      ;;
    fast-medium)
      EXACT_TASKS+=("${PRESET_FAST_MEDIUM_TASKS[@]}")
      ;;
    memory-3)
      EXACT_TASKS+=("${PRESET_MEMORY_3_TASKS[@]}")
      ;;
    recall-3)
      EXACT_TASKS+=("${PRESET_RECALL_3_TASKS[@]}")
      ;;
    representative-10)
      EXACT_TASKS+=("${PRESET_REPRESENTATIVE_10_TASKS[@]}")
      ;;
    representative-20)
      EXACT_TASKS+=("${PRESET_REPRESENTATIVE_20_TASKS[@]}")
      ;;
    *)
      echo "error: unsupported --preset: ${preset} (expected trivial|smoke|smoke-5|fast-3|fast-medium|memory-3|recall-3|representative-10|representative-20)" >&2
      exit 2
      ;;
  esac
}

join_by() {
  local delim="$1"
  shift
  local out=""
  local item
  for item in "$@"; do
    if [[ -n "${out}" ]]; then
      out+="${delim}"
    fi
    out+="${item}"
  done
  printf '%s' "${out}"
}

sanitize_job_fragment() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9._-]/-/g; s/--*/-/g; s/^-//; s/-$//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --leaderboard-codex)
      DATASET="${TERMINALBENCH_DATASET}"
      AGENT="codex"
      MODEL="gpt-5.5"
      VARIANT="high"
      CODEX_AGENT_VERSION="${LEADERBOARD_CODEX_VERSION}"
      ATTEMPTS="5"
      if [[ "${N_CONCURRENT_SET}" -eq 0 ]]; then
        N_CONCURRENT="4"
      fi
      shift
      ;;
    --agent)
      AGENT="${2:?missing value for --agent}"
      shift 2
      ;;
    --dataset)
      DATASET="${2:?missing value for --dataset}"
      shift 2
      ;;
    --full)
      DATASET="${TERMINALBENCH_DATASET}"
      shift
      ;;
    --preset)
      TASK_PRESET="${2:?missing value for --preset}"
      apply_task_preset "${TASK_PRESET}"
      shift 2
      ;;
    --task)
      TASK_PATTERNS+=("${2:?missing value for --task}")
      shift 2
      ;;
    --tasks)
      append_exact_tasks "${2:?missing value for --tasks}"
      shift 2
      ;;
    --task-file)
      load_task_file "${2:?missing value for --task-file}"
      shift 2
      ;;
    --exclude-task)
      EXCLUDE_PATTERNS+=("${2:?missing value for --exclude-task}")
      shift 2
      ;;
    --model)
      MODEL="${2:?missing value for --model}"
      shift 2
      ;;
    --provider)
      LASH_PROVIDER_KIND="${2:?missing value for --provider}"
      shift 2
      ;;
    --variant)
      VARIANT="${2:?missing value for --variant}"
      shift 2
      ;;
    --codex-version)
      CODEX_AGENT_VERSION="${2:?missing value for --codex-version}"
      shift 2
      ;;
    --execution-mode)
      EXECUTION_MODE="${2:?missing value for --execution-mode}"
      shift 2
      ;;
    --context-approach)
      CONTEXT_APPROACH="${2:?missing value for --context-approach}"
      shift 2
      ;;
    --jobs-dir)
      JOBS_DIR="${2:?missing value for --jobs-dir}"
      shift 2
      ;;
    --results-dir)
      RESULTS_DIR="${2:?missing value for --results-dir}"
      shift 2
      ;;
    --job-name)
      JOB_NAME="${2:?missing value for --job-name}"
      shift 2
      ;;
    --n-concurrent)
      N_CONCURRENT="${2:?missing value for --n-concurrent}"
      N_CONCURRENT_SET=1
      shift 2
      ;;
    --attempts)
      ATTEMPTS="${2:?missing value for --attempts}"
      shift 2
      ;;
    --timeout-multiplier)
      TIMEOUT_MULT="${2:?missing value for --timeout-multiplier}"
      shift 2
      ;;
    --env)
      ENV_BACKEND="${2:?missing value for --env}"
      shift 2
      ;;
    --registry-url)
      REGISTRY_URL="${2:?missing value for --registry-url}"
      shift 2
      ;;
    --build-mode)
      BUILD_MODE="${2:?missing value for --build-mode}"
      shift 2
      ;;
    --no-build)
      DO_BUILD=0
      shift
      ;;
    --debug)
      DEBUG=1
      shift
      ;;
    --no-debug)
      DEBUG=0
      shift
      ;;
    --delete)
      DELETE_AFTER_RUN=1
      shift
      ;;
    --no-delete)
      DELETE_AFTER_RUN=0
      shift
      ;;
    --reuse-completed)
      REUSE_COMPLETED=1
      shift
      ;;
    --reuse-from)
      REUSE_COMPLETED=1
      REUSE_SOURCES+=("${2:?missing value for --reuse-from}")
      shift 2
      ;;
    --allow-no-config)
      REQUIRE_CONFIG=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    --)
      shift
      EXTRA_ARGS+=("$@")
      break
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ "${AGENT}" != "lash" && "${AGENT}" != "opencode" && "${AGENT}" != "codex" ]]; then
  echo "error: unsupported --agent: ${AGENT} (expected lash|opencode|codex)" >&2
  exit 2
fi

if [[ -n "${LASH_PROVIDER_KIND}" && "${AGENT}" != "lash" ]]; then
  echo "error: --provider only applies to --agent lash" >&2
  exit 2
fi

if [[ -z "${VARIANT}" && "${AGENT}" != "codex" ]]; then
  echo "error: --variant is required for ${AGENT} benchmark runs" >&2
  exit 2
fi

if [[ ${#EXACT_TASKS[@]} -gt 0 ]]; then
  mapfile -t EXACT_TASKS < <(printf '%s\n' "${EXACT_TASKS[@]}" | awk '!seen[$0]++')
fi

validate_dataset_cutover
validate_task_preset_scope

if [[ ${#EXACT_TASKS[@]} -gt 0 && "${N_CONCURRENT_SET}" -eq 0 ]]; then
  N_CONCURRENT="${#EXACT_TASKS[@]}"
fi

build_host_binary() {
  require_lash_pin
  local ref_args=()
  lash_ref_args ref_args
  echo "==> Installing pinned lash benchmark binary on host ($(lash_ref_label))" >&2
  cargo install \
    --locked \
    --git "${LASH_GIT_URL}" \
    "${ref_args[@]}" \
    lash-cli \
    --bin lash \
    --root "${REPO_ROOT}/.lash-bin" \
    --force >/dev/null
  BINARY_PATH="${REPO_ROOT}/.lash-bin/bin/lash"
}

build_docker_binary() {
  local image="$1"
  local install_subdir="$2"
  local install_dir="${REPO_ROOT}/${install_subdir}"
  require_lash_pin
  mkdir -p "${install_dir}"
  echo "==> Installing pinned lash benchmark binary in ${image} ($(lash_ref_label))" >&2
  docker run --rm -u root \
    -e "LASH_GIT_URL=${LASH_GIT_URL}" \
    -e "LASH_GIT_TAG=${LASH_GIT_TAG}" \
    -e "LASH_GIT_BRANCH=${LASH_GIT_BRANCH}" \
    -e "LASH_GIT_REV=${LASH_GIT_REV}" \
    -v "${REPO_ROOT}:/work" \
    -w /work \
    "${image}" \
    bash -lc \
      '. /usr/local/cargo/env &&
       ref_args=() &&
       if [[ -n "${LASH_GIT_REV:-}" ]]; then
         ref_args=(--rev "$LASH_GIT_REV");
       elif [[ -n "${LASH_GIT_BRANCH:-}" ]]; then
         ref_args=(--branch "$LASH_GIT_BRANCH");
       else
         ref_args=(--tag "$LASH_GIT_TAG");
       fi &&
       apt-get update >/dev/null &&
       apt-get install -y protobuf-compiler zstd python3-dev >/dev/null &&
       cargo install --locked --git "$LASH_GIT_URL" "${ref_args[@]}" lash-cli --bin lash --root /work/'"${install_subdir}"' --force &&
       chown -R $(stat -c "%u:%g" /work) /work/'"${install_subdir}"'' >/dev/null
  BINARY_PATH="${install_dir}/bin/lash"
}

RUN_EXECUTION_MODE="${EXECUTION_MODE}"
BINARY_PATH=""

if [[ "${AGENT}" == "lash" ]]; then
  if [[ -z "${EXECUTION_MODE}" ]]; then
    echo "error: --execution-mode is required for --agent lash (expected rlm|standard)" >&2
    exit 2
  fi

  if [[ "${EXECUTION_MODE}" != "rlm" && "${EXECUTION_MODE}" != "standard" ]]; then
    echo "error: unsupported --execution-mode: ${EXECUTION_MODE} (expected rlm|standard)" >&2
    exit 2
  fi

  if [[ -n "${CONTEXT_APPROACH}" && "${CONTEXT_APPROACH}" != "rolling_history" && "${CONTEXT_APPROACH}" != "observational_memory" ]]; then
    echo "error: unsupported --context-approach: ${CONTEXT_APPROACH} (expected rolling_history or observational_memory)" >&2
    exit 2
  fi
  if [[ -n "${CONTEXT_APPROACH}" && "${EXECUTION_MODE}" != "standard" ]]; then
    echo "error: --context-approach only applies to --execution-mode standard" >&2
    exit 2
  fi

  if [[ "${BUILD_MODE}" != "host" && "${BUILD_MODE}" != "docker-bookworm" && "${BUILD_MODE}" != "docker-bullseye" ]]; then
    echo "error: unsupported --build-mode: ${BUILD_MODE} (expected host|docker-bookworm|docker-bullseye)" >&2
    exit 2
  fi

  RUN_EXECUTION_MODE="${EXECUTION_MODE}"
  case "${BUILD_MODE}" in
    host)
      BINARY_PATH="${REPO_ROOT}/.lash-bin/bin/lash"
      ;;
    docker-bookworm)
      BINARY_PATH="${REPO_ROOT}/.lash-bin-bookworm/bin/lash"
      ;;
    docker-bullseye)
      BINARY_PATH="${REPO_ROOT}/.lash-bin-bullseye/bin/lash"
      ;;
  esac

  export LASH_BENCH_BINARY="${BINARY_PATH}"
  export LASH_BENCH_EXECUTION_MODE="${EXECUTION_MODE}"
  export LASH_BENCH_MODEL_VARIANT="${VARIANT}"
  export LASH_BENCH_CONTEXT_APPROACH="${CONTEXT_APPROACH}"

  # Benchmark-harness guidance is owned by harbor_lash_agent.py
  # (`BENCHMARK_GUIDELINES_APPEND`) and folded into the user prompt.
  # The old `LASH_PROMPT_REPLACE_IDENTITY` env was removed once the
  # agent consolidated the two prompt-additions into a single block.

  # Always capture LLM request/response traces for benchmark debugging.
  export LASH_LOG="debug"
elif [[ "${AGENT}" == "opencode" ]]; then
  RUN_EXECUTION_MODE="agent-native"
  if [[ -n "${EXECUTION_MODE}" ]]; then
    echo "warning: --execution-mode is ignored for --agent opencode" >&2
  fi
  if [[ -n "${CONTEXT_APPROACH}" ]]; then
    echo "warning: --context-approach is ignored for --agent opencode" >&2
  fi
  if [[ -z "${MODEL}" ]]; then
    echo "error: --model provider/model is required for --agent opencode" >&2
    exit 2
  fi
  if [[ "${MODEL}" != */* ]]; then
    echo "error: --model for opencode must be in provider/model format" >&2
    exit 2
  fi
  export OPENCODE_BENCH_MODEL_VARIANT="${VARIANT}"
elif [[ "${AGENT}" == "codex" ]]; then
  RUN_EXECUTION_MODE="agent-native"
  if [[ -n "${EXECUTION_MODE}" ]]; then
    echo "warning: --execution-mode is ignored for --agent codex" >&2
  fi
  if [[ -n "${CONTEXT_APPROACH}" ]]; then
    echo "warning: --context-approach is ignored for --agent codex" >&2
  fi
  if [[ -z "${MODEL}" ]]; then
    echo "error: --model is required for --agent codex" >&2
    exit 2
  fi
  VARIANT="${VARIANT:-high}"
fi

export PYTHONPATH="${REPO_ROOT}:${PYTHONPATH:-}"

if [[ "${DRY_RUN}" -eq 0 ]]; then
  require_cmd harbor
  if [[ "${ENV_BACKEND}" == "docker" ]] || [[ "${AGENT}" == "lash" && "${DO_BUILD}" -eq 1 && "${BUILD_MODE}" != "host" ]]; then
    require_cmd docker
  fi
  if [[ "${AGENT}" == "lash" && "${DO_BUILD}" -eq 1 && "${BUILD_MODE}" == "host" ]]; then
    require_cmd cargo
  fi

  if [[ "${AGENT}" == "lash" ]] && [[ "${REQUIRE_CONFIG}" -eq 1 ]] && [[ ! -f "${HOME}/.lash/config.json" ]]; then
    cat >&2 <<EOF
error: ${HOME}/.lash/config.json not found.
This runner expects your local lash provider config (including OAuth tokens).
Use --allow-no-config to bypass.
EOF
    exit 1
  fi

  if [[ "${AGENT}" == "lash" && "${DO_BUILD}" -eq 1 ]]; then
    case "${BUILD_MODE}" in
      host)
        build_host_binary
        ;;
      docker-bookworm)
        build_docker_binary "rust:1-bookworm" ".lash-bin-bookworm"
        ;;
      docker-bullseye)
        build_docker_binary "rust:1-bullseye" ".lash-bin-bullseye"
        ;;
    esac
  fi

  if [[ "${AGENT}" == "lash" ]] && [[ ! -x "${BINARY_PATH}" ]]; then
    echo "error: expected executable lash binary not found at ${BINARY_PATH}" >&2
    exit 1
  fi
fi

if [[ -z "${JOB_NAME}" ]]; then
  dataset_slug="$(sanitize_job_fragment "${DATASET%@*}")"
  agent_slug="$(sanitize_job_fragment "${AGENT}")"
  mode_slug="$(sanitize_job_fragment "${RUN_EXECUTION_MODE}")"
  if [[ ${#EXACT_TASKS[@]} -gt 0 ]]; then
    task_slug="$(sanitize_job_fragment "$(join_by "-" "${EXACT_TASKS[@]}")")"
    task_slug="${task_slug:0:48}"
    JOB_NAME="${dataset_slug}-${agent_slug}-${mode_slug}-${task_slug}"
  else
    JOB_NAME="${dataset_slug}-${agent_slug}-${mode_slug}-$(date +%Y%m%d-%H%M%S)"
  fi
fi

PROVIDER_CONFIG_PATH="${HOME}/.lash/config.json"
if [[ "${AGENT}" == "lash" && -f "${HOME}/.lash/config.json" ]]; then
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    if [[ -n "${LASH_PROVIDER_KIND}" ]]; then
      python3 - "${HOME}/.lash/config.json" "${LASH_PROVIDER_KIND}" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
provider = sys.argv[2]

data = json.loads(source.read_text())
providers = data.get("providers")
if not isinstance(providers, dict) or provider not in providers:
    available = ", ".join(sorted(providers)) if isinstance(providers, dict) else "<none>"
    raise SystemExit(
        f"error: provider `{provider}` is not configured in {source}; available: {available}"
    )
PY
    fi
  else
    provider_config_dir="${RESULTS_DIR}/provider-configs"
    mkdir -p "${provider_config_dir}"
    PROVIDER_CONFIG_PATH="$(cd -- "${provider_config_dir}" && pwd)/${JOB_NAME}.json"
    python3 - "${HOME}/.lash/config.json" "${PROVIDER_CONFIG_PATH}" "${LASH_PROVIDER_KIND}" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
provider = sys.argv[3]

data = json.loads(source.read_text())
if provider:
    providers = data.get("providers")
    if not isinstance(providers, dict) or provider not in providers:
        available = ", ".join(sorted(providers)) if isinstance(providers, dict) else "<none>"
        raise SystemExit(
            f"error: provider `{provider}` is not configured in {source}; available: {available}"
        )
    data["active_provider"] = provider

# Terminal Bench should be hermetic. Strip web-search credentials from the
# run-local config so `search_web` / `fetch_url` are not registered even when
# the user's normal Lash config has Tavily enabled.
auxiliary = data.get("auxiliary_secrets")
if isinstance(auxiliary, dict):
    auxiliary.pop("tavily_api_key", None)
    if not auxiliary:
        data.pop("auxiliary_secrets", None)
target.write_text(json.dumps(data, indent=2) + "\n")
PY
    export LASH_BENCH_CONFIG="${PROVIDER_CONFIG_PATH}"
  fi
fi

if [[ "${REUSE_COMPLETED}" -eq 1 ]]; then
  REUSE_PROVIDER_KIND="${LASH_PROVIDER_KIND}"
  if [[ "${AGENT}" == "lash" && -z "${REUSE_PROVIDER_KIND}" && -f "${PROVIDER_CONFIG_PATH}" ]]; then
    REUSE_PROVIDER_KIND="$(python3 - "${PROVIDER_CONFIG_PATH}" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text())
except Exception:
    print("")
else:
    value = data.get("active_provider")
    print(value if isinstance(value, str) else "")
PY
)"
  fi

  reuse_plan_dir="${RESULTS_DIR}/reuse-plans"
  mkdir -p "${reuse_plan_dir}"
  REUSE_PLAN_PATH="$(cd -- "${reuse_plan_dir}" && pwd)/${JOB_NAME}.json"
  REUSE_PLAN_CMD=(
    python3 "${SCRIPT_DIR}/terminalbench_reuse.py"
    plan
    --results-dir "${RESULTS_DIR}"
    --plan-path "${REUSE_PLAN_PATH}"
    --agent "${AGENT}"
    --dataset "${DATASET}"
    --execution-mode "${RUN_EXECUTION_MODE}"
    --harbor-env "${ENV_BACKEND}"
    --attempts "${ATTEMPTS}"
    --timeout-multiplier "${TIMEOUT_MULT}"
  )
  if [[ -n "${MODEL}" ]]; then
    REUSE_PLAN_CMD+=(--requested-model "${MODEL}")
  fi
  if [[ -n "${VARIANT}" ]]; then
    REUSE_PLAN_CMD+=(--variant "${VARIANT}")
  fi
  if [[ -n "${CONTEXT_APPROACH}" ]]; then
    REUSE_PLAN_CMD+=(--context-approach "${CONTEXT_APPROACH}")
  fi
  if [[ -n "${REUSE_PROVIDER_KIND}" ]]; then
    REUSE_PLAN_CMD+=(--provider-kind "${REUSE_PROVIDER_KIND}")
  fi
  if [[ -n "${CODEX_AGENT_VERSION}" ]]; then
    REUSE_PLAN_CMD+=(--agent-version "${CODEX_AGENT_VERSION}")
  fi
  for arg in "${EXTRA_ARGS[@]}"; do
    REUSE_PLAN_CMD+=("--extra-arg=${arg}")
  done
  for task_name in "${EXACT_TASKS[@]}"; do
    REUSE_PLAN_CMD+=(--requested-task "$(strip_terminalbench_task_prefix "${task_name}")")
  done
  for source in "${REUSE_SOURCES[@]}"; do
    REUSE_PLAN_CMD+=(--reuse-from "${source}")
  done

  mapfile -t REUSE_EXCLUDE_TASKS < <("${REUSE_PLAN_CMD[@]}")
  if [[ ${#REUSE_EXCLUDE_TASKS[@]} -gt 0 ]]; then
    echo "==> Reusing completed attempts for ${#REUSE_EXCLUDE_TASKS[@]} task(s): ${REUSE_EXCLUDE_TASKS[*]}"
    if [[ ${#EXACT_TASKS[@]} -gt 0 ]]; then
      requested_reuse_csv="$(
        for task_name in "${EXACT_TASKS[@]}"; do
          strip_terminalbench_task_prefix "${task_name}"
          printf '\n'
        done | sort -u | paste -sd, -
      )"
      reusable_csv="$(printf '%s\n' "${REUSE_EXCLUDE_TASKS[@]}" | sort -u | paste -sd, -)"
      if [[ "${requested_reuse_csv}" == "${reusable_csv}" ]]; then
        SKIP_HARBOR=1
      fi
    fi
  else
    echo "==> Reuse requested, but no completed matching task attempts were found."
  fi
fi

CMD=(
  harbor run
  --dataset "${DATASET}"
  --env "${ENV_BACKEND}"
  --jobs-dir "${JOBS_DIR}"
  --n-concurrent "${N_CONCURRENT}"
  --n-attempts "${ATTEMPTS}"
  --timeout-multiplier "${TIMEOUT_MULT}"
  --job-name "${JOB_NAME}"
)

if [[ -n "${REGISTRY_URL}" ]]; then
  CMD+=(--registry-url "${REGISTRY_URL}")
fi

if [[ "${AGENT}" == "lash" ]]; then
  CMD+=(--agent scripts.harbor_lash_agent:LashAgent)
elif [[ "${AGENT}" == "opencode" ]]; then
  CMD+=(--agent scripts.harbor_opencode_agent:BenchOpenCodeAgent)
elif [[ "${AGENT}" == "codex" ]]; then
  CMD+=(--agent codex)
fi

CMD+=(--agent-include-logs "**/*")
CMD+=(--verifier-include-logs "**/*")

if [[ "${AGENT}" == "codex" ]]; then
  CMD+=(--agent-kwarg "reasoning_effort=${VARIANT}")
  if [[ -n "${CODEX_AGENT_VERSION}" ]]; then
    CMD+=(--agent-kwarg "version=${CODEX_AGENT_VERSION}")
  fi
fi

if [[ -n "${MODEL}" ]]; then
  CMD+=(--model "${MODEL}")
fi

if [[ "${DELETE_AFTER_RUN}" -eq 0 ]]; then
  CMD+=(--no-delete)
fi

if [[ "${DEBUG}" -eq 1 ]]; then
  CMD+=(--debug)
fi

for pattern in "${TASK_PATTERNS[@]}"; do
  CMD+=(--include-task-name "$(harbor_task_filter_name "${pattern}")")
done

for task_name in "${EXACT_TASKS[@]}"; do
  CMD+=(--include-task-name "$(harbor_task_filter_name "${task_name}")")
done

for pattern in "${EXCLUDE_PATTERNS[@]}"; do
  CMD+=(--exclude-task-name "${pattern}")
done

for task_name in "${REUSE_EXCLUDE_TASKS[@]}"; do
  CMD+=(--exclude-task-name "$(harbor_task_filter_name "${task_name}")")
done

if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  CMD+=("${EXTRA_ARGS[@]}")
fi

if [[ "${SKIP_HARBOR}" -eq 1 ]]; then
  echo "==> Harbor run will be skipped: all requested exact tasks are covered by reusable completed attempts."
else
  echo "==> Running: ${CMD[*]}"
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  exit 0
fi

set +e
if [[ "${SKIP_HARBOR}" -eq 1 ]]; then
  echo "==> Skipping Harbor run: all requested exact tasks are covered by reusable completed attempts."
  mkdir -p "${JOBS_DIR}/${JOB_NAME}"
  HARBOR_RC=0
else
  "${CMD[@]}"
  HARBOR_RC=$?
fi
set -e

JOB_DIR="${JOBS_DIR}/${JOB_NAME}"
if [[ -d "${JOB_DIR}" ]]; then
  if [[ "${REUSE_COMPLETED}" -eq 1 && -n "${REUSE_PLAN_PATH}" && -f "${REUSE_PLAN_PATH}" ]]; then
    python3 "${SCRIPT_DIR}/terminalbench_reuse.py" \
      merge \
      --plan-path "${REUSE_PLAN_PATH}" \
      --target-job-dir "${JOB_DIR}" || true
  fi

  validate_exact_task_execution "${JOB_DIR}"

  EXPORT_CMD=(
    python3 "${SCRIPT_DIR}/export_terminalbench_results.py"
    "${JOB_DIR}"
    --results-dir "${RESULTS_DIR}"
    --agent "${AGENT}"
    --dataset "${DATASET}"
    --execution-mode "${RUN_EXECUTION_MODE}"
    --harbor-env "${ENV_BACKEND}"
    --n-concurrent "${N_CONCURRENT}"
    --attempts "${ATTEMPTS}"
    --timeout-multiplier "${TIMEOUT_MULT}"
  )

  if [[ -n "${REGISTRY_URL}" ]]; then
    EXPORT_CMD+=(--registry-url "${REGISTRY_URL}")
  fi
  if [[ -n "${TASK_PRESET}" ]]; then
    EXPORT_CMD+=(--preset "${TASK_PRESET}")
  fi
  if [[ -n "${BINARY_PATH}" ]]; then
    EXPORT_CMD+=(--binary-path "${BINARY_PATH}")
  fi
  if [[ "${AGENT}" == "lash" && -f "${PROVIDER_CONFIG_PATH}" ]]; then
    EXPORT_CMD+=(--provider-config "${PROVIDER_CONFIG_PATH}")
  fi
  if [[ -n "${MODEL}" ]]; then
    EXPORT_CMD+=(--requested-model "${MODEL}")
  fi
  if [[ -n "${VARIANT}" ]]; then
    EXPORT_CMD+=(--variant "${VARIANT}")
  fi
  if [[ -n "${CODEX_AGENT_VERSION}" ]]; then
    EXPORT_CMD+=(--agent-version "${CODEX_AGENT_VERSION}")
  fi
  if [[ -n "${CONTEXT_APPROACH}" ]]; then
    EXPORT_CMD+=(--context-approach "${CONTEXT_APPROACH}")
  fi
  if [[ "${DELETE_AFTER_RUN}" -eq 1 ]]; then
    EXPORT_CMD+=(--delete-after-run)
  fi
  if [[ "${DEBUG}" -eq 1 ]]; then
    EXPORT_CMD+=(--debug)
  fi
  for pattern in "${TASK_PATTERNS[@]}"; do
    EXPORT_CMD+=(--task-pattern "${pattern}")
  done
  for task_name in "${EXACT_TASKS[@]}"; do
    EXPORT_CMD+=(--exact-task "${task_name}")
  done
  for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    EXPORT_CMD+=(--exclude-pattern "${pattern}")
  done
  for arg in "${EXTRA_ARGS[@]}"; do
    EXPORT_CMD+=("--extra-arg=${arg}")
  done

  "${EXPORT_CMD[@]}" || true
  python3 "${SCRIPT_DIR}/summarize_terminalbench.py" "${JOB_DIR}" || true
  echo
  echo "Structured results: ${RESULTS_DIR}"
  echo "Browse them with: python3 ${SCRIPT_DIR}/bench_ui.py --results-dir ${RESULTS_DIR}"
fi
exit "${HARBOR_RC}"

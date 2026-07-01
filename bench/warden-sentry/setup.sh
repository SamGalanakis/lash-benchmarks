#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
STATE_DIR="${REPO_ROOT}/.benchmarks/warden-sentry"
WORKSPACE_DIR="${STATE_DIR}/workspace"
CORPUS_JSON="${STATE_DIR}/sentry-vulnerability-corpus.json"
CORPUS_URL="${CORPUS_URL:-https://raw.githubusercontent.com/getsentry/warden/main/packages/docs/src/data/benchmarking/sentry-vulnerability-corpus.json}"

mkdir -p "${STATE_DIR}/runs" "${WORKSPACE_DIR}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to download the Warden Sentry vulnerability corpus" >&2
  exit 1
fi

echo "Downloading Warden Sentry vulnerability corpus"
curl -fsSL "${CORPUS_URL}" -o "${CORPUS_JSON}.tmp"
python3 - "${CORPUS_JSON}.tmp" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    corpus = json.load(fh)

findings = corpus.get("findings") or []
if corpus.get("id") != "sentry-vulnerability-corpus":
    raise SystemExit(f"unexpected corpus id: {corpus.get('id')!r}")
if not findings:
    raise SystemExit("corpus has no findings")
for finding in findings:
    for key in ("id", "repository", "sha", "summary", "code"):
        if key not in finding:
            raise SystemExit(f"finding missing {key}: {finding!r}")
    code = finding["code"]
    if not code.get("path"):
        raise SystemExit(f"finding missing code.path: {finding['id']}")
print(f"validated {len(findings)} corpus findings")
PY
mv "${CORPUS_JSON}.tmp" "${CORPUS_JSON}"

echo
echo "Warden Sentry benchmark state ready under ${STATE_DIR}"
echo "  corpus:    ${CORPUS_JSON}"
echo "  workspace: ${WORKSPACE_DIR}"
echo
echo "List one runnable task:"
echo "  bench/warden-sentry/run.sh --dry-run --finding-id sentry-vuln-001"

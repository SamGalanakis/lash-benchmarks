#![recursion_limit = "256"]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use clap::{Parser, ValueEnum};
use lash::direct::{DirectJsonSchema, DirectLlmClient, DirectRequest};
use lash::persistence::RuntimePersistence;
use lash::plugins::ToolOutputBudgetPluginFactory;
use lash::provider::{LlmResponse, ProviderHandle};
use lash::rlm::{RlmProtocolPluginConfig, RlmProtocolPluginFactory, RlmTurnBuilderExt};
use lash::tools::ToolProvider;
use lash::usage::{SessionUsageReport, TokenUsage};
use lash::{
    LashCore, LashSession, ModelSpec, PluginStack, TurnActivity, TurnActivitySink, TurnEvent,
    TurnFinish, TurnInput, TurnOutcome, TurnStop,
};
use lash_core::plugin::{PluginSpec, StaticPluginFactory};
use lash_plugin_observational_memory::ObservationalMemoryPluginFactory;
use lash_search_tools::grep_provider;
use lash_sqlite_store::Store;
use lash_standard_plugins::{
    StandardContextApproach, rolling_history::RollingHistoryPluginFactory,
};
use lash_tools::files::{glob_provider, read_file_provider};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const STATE_ROOT: &str = ".benchmarks/warden-sentry";
const DEFAULT_CORPUS: &str = ".benchmarks/warden-sentry/sentry-vulnerability-corpus.json";
const DEFAULT_REPOSITORY: &str = "getsentry/sentry";
const DEFAULT_MAX_TURNS: usize = 100;
const DEFAULT_MAX_CONTEXT_TOKENS: usize = 1_000_000;
const DEFAULT_MAX_TASK_PROVIDER_TOTAL_TOKENS: u64 = 1_000_000;
const DEFAULT_BATCH_SIZE: usize = 1;
const DEFAULT_DOCKER_IMAGE: &str = "lash-benchmarks/warden-sentry-runner:ubuntu24.04";
const DEFAULT_EXECUTION_MODE: &str = "standard";
const DEFAULT_CONTEXT_APPROACH: &str = "rolling_history";
const BENCHMARK_NAME: &str = "warden-sentry";
const TARGET_MODE: &str = "all-corpus-files-by-sha";
const BENCHMARK_SKILL: &str = "focused-security-review";
const REPORT_ON: &str = "low";
const MIN_CONFIDENCE: &str = "low";
const SEMANTIC_SCORING_ARTIFACT: &str = "semantic-scoring.json";
const SEMANTIC_SCORING_SUMMARY_ARTIFACT: &str = "semantic-scoring-summary.md";
const RAW_PREDICTIONS_ARTIFACT: &str = "predictions.jsonl";
const WARDEN_FINAL_JSONL_ARTIFACT: &str = "warden-final.jsonl";
const POST_PROCESS_DIR: &str = "post-processing";
const POST_PROCESS_SUMMARY_ARTIFACT: &str = "post-processing/summary.json";
const POST_PROCESS_EVENTS_ARTIFACT: &str = "post-processing/events.jsonl";
const REPRODUCIBILITY_MANIFEST_ARTIFACT: &str = "post-processing/reproducibility-manifest.json";
const SOURCE_SNAPSHOT_ARTIFACT: &str = "post-processing/runner-source-snapshot.jsonl";
const UPSTREAM_BRIDGE_PROBE_ARTIFACT: &str = "post-processing/upstream-bridge-probe.json";
const VALIDATION_ARTIFACT: &str = "post-processing/validation.json";
const RAW_PRE_FINALIZATION_STALE_CLASS: &str = "raw-pre-finalization";
const STALE_FINALIZED_PRE_REPROCESS_CLASS: &str = "stale-finalized-pre-reprocess";
const EXPECTED_WARDEN_SENTRY_CHUNKS: usize = 156;
const EXPECTED_WARDEN_SENTRY_SUMMARY_RECORDS: usize = 1;
const WARDEN_CONTEXT_LINES: usize = 20;
const WARDEN_MAX_GAP_LINES: usize = 30;
const WARDEN_MAX_CHUNK_SIZE: usize = 8_000;
const DEFAULT_POST_PROCESS_BATCH_SIZE: usize = 4;
const DEFAULT_POST_PROCESS_MAX_OUTPUT_TOKENS: usize = 4096;
const DEFAULT_SCORE_MAX_OUTPUT_TOKENS: usize = 1024;
const AGENT_SEMANTIC_MATCH_PASS: &str = "agent-semantic-match-pass";
const POST_PROCESSING_METHOD: &str =
    "upstream_warden_sdk_chunk_dedupe_apply_merge_groups_lash_verify_merge_synthesis";
const CHILD_CONTAINER_RUN_DIR: &str = "/work/run";
const CHILD_CONTAINER_REPO_DIR: &str = "/work/repo";
const CHILD_CONTAINER_LASH_HOME: &str = "/work/secrets/lash";
const CHILD_CONTAINER_BIN: &str = "/usr/local/bin/bench-warden-sentry";
const DELETE_LASH_CONFIG_ENV: &str = "WARDEN_SENTRY_DELETE_LASH_CONFIG_AFTER_LOAD";

static GIT_WORKTREE_MUTEX: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));
static PROCESS_CWD_MUTEX: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

const SECURITY_REVIEW_PROMPT: &str = concat!(
    "You are running a focused security-review benchmark on a historical checkout of getsentry/sentry.\n\n",
    "Rules:\n",
    "1. Review only the Warden hunk named below. You may inspect nearby definitions, callers, permissions, models, and tests only when needed to understand reachability and impact.\n",
    "2. Report exploitable security or tenant-isolation vulnerabilities. Do not report style, refactors, missing tests, generic hardening, or speculative issues without a concrete attack path.\n",
    "3. Return a single JSON object and no surrounding prose. The shape is: {\"findings\":[{\"title\":\"...\",\"severity\":\"low|medium|high\",\"confidence\":\"low|medium|high\",\"path\":\"...\",\"start_line\":123,\"description\":\"...\",\"evidence\":\"...\",\"recommendation\":\"...\"}]}.\n",
    "4. If you find no qualifying issue, return {\"findings\":[]}.\n",
    "5. Every finding's `path` must be the target file and `start_line` must be inside the hunk line range. If the root cause is in surrounding code, anchor the finding to the nearest relevant line inside the hunk and explain the trace in `evidence`.\n",
    "6. Inspect the repository directly with read_file, grep, and glob. Use glob before guessing adjacent paths.\n",
);

const WARDEN_FINDING_ID_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

#[derive(Parser, Debug, Clone)]
#[command(name = "bench-warden-sentry")]
#[command(about = "Run Lash on Warden's Sentry vulnerability corpus.")]
struct Args {
    /// Warden Sentry vulnerability corpus JSON.
    #[arg(long, default_value = DEFAULT_CORPUS)]
    corpus: PathBuf,

    /// Shared workspace for the Sentry bare mirror and task worktrees.
    #[arg(long)]
    workspace_root: Option<PathBuf>,

    /// Run identifier; used as the output dir name under
    /// `.benchmarks/warden-sentry/runs/`.
    #[arg(long)]
    run_id: Option<String>,

    /// Explicit output directory. Defaults to
    /// `.benchmarks/warden-sentry/runs/<run_id>`.
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Resume a previous run by skipping task ids already present in
    /// `predictions.jsonl`.
    #[arg(long)]
    resume: bool,

    /// Run only these generated task ids. Use `--dry-run` to list ids.
    #[arg(long)]
    task_id: Vec<String>,

    /// Run tasks containing these corpus finding ids, such as
    /// `sentry-vuln-001`.
    #[arg(long)]
    finding_id: Vec<String>,

    /// Run tasks for these corpus SHAs.
    #[arg(long)]
    sha: Vec<String>,

    /// Run only target files matching these exact corpus paths.
    #[arg(long)]
    target_path: Vec<String>,

    #[arg(long)]
    limit: Option<usize>,

    #[arg(long, default_value_t = 0)]
    offset: usize,

    /// Model slug. If omitted, falls back to `~/.lash/config.json`'s active
    /// provider default.
    #[arg(long)]
    model: Option<String>,

    /// Reasoning effort variant, passed to Lash's model spec when supported.
    #[arg(long)]
    variant: Option<String>,

    /// Override the provider key from `~/.lash/config.json`.
    #[arg(long)]
    provider_id: Option<String>,

    #[arg(long, default_value = DEFAULT_EXECUTION_MODE, value_parser = ["standard", "rlm"])]
    execution_mode: String,

    #[arg(long, value_parser = ["rolling_history", "observational_memory"])]
    standard_context_approach: Option<String>,

    #[arg(long, default_value_t = DEFAULT_MAX_TURNS)]
    max_turns: usize,

    #[arg(long, default_value_t = DEFAULT_MAX_CONTEXT_TOKENS)]
    max_context_tokens: usize,

    /// Per-task provider token budget, counted as input + output. Use 0 to disable.
    #[arg(long, default_value_t = DEFAULT_MAX_TASK_PROVIDER_TOTAL_TOKENS)]
    max_task_provider_total_tokens: u64,

    #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
    batch_size: usize,

    /// Stop scheduling and remove active Docker children after the first task
    /// error or non-completed task result.
    #[arg(long)]
    fail_fast: bool,

    /// Child isolation mode. Docker is required for trusted benchmark runs;
    /// host-unsafe is only for local debugging.
    #[arg(long, value_enum, default_value_t = ChildIsolation::Docker)]
    isolation: ChildIsolation,

    /// Docker image used for isolated child tasks. Built automatically if
    /// missing.
    #[arg(long, default_value = DEFAULT_DOCKER_IMAGE)]
    docker_image: String,

    /// Score an existing run directory and update its summary.json.
    #[arg(long)]
    score_run_dir: Option<PathBuf>,

    /// Maximum number of semantic-match calls to run concurrently.
    #[arg(long, default_value_t = 8)]
    score_batch_size: usize,

    /// Maximum output tokens for each semantic-match call.
    #[arg(long, default_value_t = DEFAULT_SCORE_MAX_OUTPUT_TOKENS)]
    score_max_output_tokens: usize,

    /// Post-process an existing run with upstream Warden SDK deterministic
    /// steps, Lash verification/synthesis, and finalized JSONL output.
    #[arg(long)]
    post_process_run_dir: Option<PathBuf>,

    /// Validate a finalized run directory's Warden-comparable artifact invariants.
    #[arg(long)]
    validate_run_dir: Option<PathBuf>,

    /// Maximum output tokens for each post-processing verifier/merge call.
    #[arg(long, default_value_t = DEFAULT_POST_PROCESS_MAX_OUTPUT_TOKENS)]
    post_process_max_output_tokens: usize,

    /// Maximum number of verifier calls to run concurrently.
    #[arg(long, default_value_t = DEFAULT_POST_PROCESS_BATCH_SIZE)]
    post_process_batch_size: usize,

    /// Keep per-task Sentry worktrees after the run for debugging.
    #[arg(long)]
    keep_worktrees: bool,

    /// Estimated non-cached input price in USD per 1M tokens.
    #[arg(long, env = "WARDEN_SENTRY_INPUT_COST_PER_MTOK")]
    input_cost_per_mtok: Option<f64>,

    /// Estimated output price in USD per 1M tokens.
    #[arg(long, env = "WARDEN_SENTRY_OUTPUT_COST_PER_MTOK")]
    output_cost_per_mtok: Option<f64>,

    /// Estimated cached-input read price in USD per 1M tokens.
    #[arg(long, env = "WARDEN_SENTRY_CACHED_INPUT_COST_PER_MTOK")]
    cached_input_cost_per_mtok: Option<f64>,

    /// Estimated reasoning-token price in USD per 1M tokens, when billed separately.
    #[arg(long, env = "WARDEN_SENTRY_REASONING_COST_PER_MTOK")]
    reasoning_cost_per_mtok: Option<f64>,

    /// Print selected tasks and exit without requiring provider credentials.
    #[arg(long)]
    dry_run: bool,

    /// Internal child mode used by the parent to isolate process CWD per task.
    #[arg(long, hide = true)]
    single_task: Option<String>,

    /// Internal child mode: sanitized task spec with no corpus findings.
    #[arg(long, hide = true)]
    task_spec: Option<PathBuf>,

    /// Internal child mode: already materialized checkout to use as CWD.
    #[arg(long, hide = true)]
    prepared_repo: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum ChildIsolation {
    Docker,
    HostUnsafe,
}

impl ChildIsolation {
    fn label(self) -> &'static str {
        match self {
            ChildIsolation::Docker => "docker",
            ChildIsolation::HostUnsafe => "host-unsafe",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Corpus {
    id: String,
    title: String,
    description: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    findings: Vec<CorpusFinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CorpusFinding {
    id: String,
    repository: String,
    sha: String,
    summary: String,
    code: CorpusCode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CorpusCode {
    path: String,
    lines: Option<String>,
    language: Option<String>,
    snippet: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WardenTask {
    task_id: String,
    repository: String,
    sha: String,
    target_path: String,
    chunk: WardenChunk,
    findings: Vec<CorpusFinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AgentTaskSpec {
    task_id: String,
    repository: String,
    sha: String,
    target_path: String,
    chunk: WardenChunk,
}

impl From<&WardenTask> for AgentTaskSpec {
    fn from(task: &WardenTask) -> Self {
        Self {
            task_id: task.task_id.clone(),
            repository: task.repository.clone(),
            sha: task.sha.clone(),
            target_path: task.target_path.clone(),
            chunk: task.chunk.clone(),
        }
    }
}

impl From<AgentTaskSpec> for WardenTask {
    fn from(task: AgentTaskSpec) -> Self {
        Self {
            task_id: task.task_id,
            repository: task.repository,
            sha: task.sha,
            target_path: task.target_path,
            chunk: task.chunk,
            findings: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WardenChunk {
    index: usize,
    start_line: usize,
    end_line: usize,
    old_start_line: usize,
    old_line_count: usize,
    new_line_count: usize,
    context_start_line: usize,
    context_end_line: usize,
    language: String,
    header: Option<String>,
    hunk_content: String,
    context_before: Vec<String>,
    context_after: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DiffHunk {
    old_start: usize,
    old_count: usize,
    new_start: usize,
    new_count: usize,
    header: Option<String>,
    content: String,
    lines: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
struct TokenTotals {
    /// Raw provider input tokens, including cache reads when the provider reports them.
    input: u64,
    output: u64,
    reasoning: u64,
    /// Backwards-compatible alias for cache-read input tokens in older rows.
    cache: u64,
    cache_read: u64,
    cache_creation: u64,
    non_cache_input: u64,
    provider_total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
struct PricingConfig {
    input_per_mtok_usd: Option<f64>,
    output_per_mtok_usd: Option<f64>,
    cached_input_per_mtok_usd: Option<f64>,
    reasoning_per_mtok_usd: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
struct CostTotals {
    status: String,
    analysis_usd: Option<f64>,
    auxiliary_usd: Option<f64>,
    total_usd: Option<f64>,
    pricing: PricingConfig,
}

impl PricingConfig {
    fn from_args(args: &Args) -> Self {
        Self {
            input_per_mtok_usd: args.input_cost_per_mtok,
            output_per_mtok_usd: args.output_cost_per_mtok,
            cached_input_per_mtok_usd: args.cached_input_cost_per_mtok,
            reasoning_per_mtok_usd: args.reasoning_cost_per_mtok,
        }
    }

    fn status(&self) -> &'static str {
        if self.input_per_mtok_usd.is_some() && self.output_per_mtok_usd.is_some() {
            "estimated"
        } else if self.input_per_mtok_usd.is_some()
            || self.output_per_mtok_usd.is_some()
            || self.cached_input_per_mtok_usd.is_some()
            || self.reasoning_per_mtok_usd.is_some()
        {
            "partial_pricing"
        } else {
            "not_configured"
        }
    }

    fn estimate(&self, tokens: &TokenTotals) -> CostTotals {
        let status = self.status().to_string();
        if status != "estimated" {
            return CostTotals {
                status,
                analysis_usd: None,
                auxiliary_usd: None,
                total_usd: None,
                pricing: self.clone(),
            };
        }

        let input_rate = self.input_per_mtok_usd.unwrap_or_default();
        let output_rate = self.output_per_mtok_usd.unwrap_or_default();
        let cached_rate = self.cached_input_per_mtok_usd.unwrap_or(input_rate);
        let reasoning_rate = self.reasoning_per_mtok_usd.unwrap_or(0.0);
        let analysis = dollars(tokens.non_cache_input, input_rate)
            + dollars(tokens.cache_read, cached_rate)
            + dollars(tokens.output, output_rate)
            + dollars(tokens.reasoning, reasoning_rate);

        CostTotals {
            status,
            analysis_usd: Some(round_usd(analysis)),
            auxiliary_usd: Some(0.0),
            total_usd: Some(round_usd(analysis)),
            pricing: self.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
struct TaskResult {
    task_id: String,
    repository: String,
    sha: String,
    target_path: String,
    chunk_index: usize,
    chunk_start_line: usize,
    chunk_end_line: usize,
    chunk_context_start_line: usize,
    chunk_context_end_line: usize,
    chunk_line_count: usize,
    chunk_language: String,
    chunk_header: Option<String>,
    corpus_finding_ids: Vec<String>,
    corpus_summaries: Vec<String>,
    model: String,
    provider_kind: String,
    execution_mode_label: String,
    status: String,
    failure_reason: Option<String>,
    assistant_text: String,
    parsed_response: Option<serde_json::Value>,
    iterations: u64,
    llm_calls: u64,
    tool_calls: u64,
    tool_breakdown: BTreeMap<String, u64>,
    tokens: TokenTotals,
    input_tokens: u64,
    output_tokens: u64,
    reasoning_tokens: u64,
    cached_input_tokens: u64,
    cache_creation_input_tokens: u64,
    non_cache_input_tokens: u64,
    provider_total_tokens: u64,
    cost: CostTotals,
    analysis_cost_usd: Option<f64>,
    auxiliary_cost_usd: Option<f64>,
    cost_usd: Option<f64>,
    pricing_status: String,
    findings_total: u64,
    unfiltered_findings_total: u64,
    dropped_out_of_range_findings: u64,
    findings_by_severity: BTreeMap<String, u64>,
    findings_by_confidence: BTreeMap<String, u64>,
    trace_jsonl: String,
    events_jsonl: String,
    turn_status: String,
    done_reason: String,
    started_at: String,
    finished_at: String,
    duration_ms: u64,
    elapsed_seconds: f64,
    checkout_seconds: f64,
    turn_seconds: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct WardenLocation {
    path: String,
    start_line: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct WardenFinding {
    id: String,
    severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<String>,
    title: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<WardenLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    additional_locations: Option<Vec<WardenLocation>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
struct WardenUsageStats {
    input_tokens: u64,
    output_tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    cached_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_creation_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_creation_5m_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_creation_1h_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    web_search_requests: Option<u64>,
    #[serde(rename = "costUSD")]
    cost_usd: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct WardenUsageBreakdownEntry {
    usage: WardenUsageStats,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    models: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtimes: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct WardenUsageBreakdown {
    #[serde(skip_serializing_if = "Option::is_none")]
    scan: Option<WardenUsageBreakdownEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auxiliary: Option<BTreeMap<String, WardenUsageBreakdownEntry>>,
    total: WardenUsageBreakdownEntry,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WardenRunMetadata {
    timestamp: String,
    duration_ms: u64,
    cwd: String,
    run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    head_sha: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WardenJsonlChunk {
    schema_version: u64,
    run: WardenRunMetadata,
    skill: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    chunk: WardenJsonlChunkInfo,
    status: String,
    findings: Vec<WardenFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage_breakdown: Option<WardenUsageBreakdown>,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<WardenSkillError>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WardenJsonlChunkInfo {
    file: String,
    index: usize,
    total: usize,
    line_range: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WardenSkillError {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WardenJsonlSummary {
    run: WardenRunMetadata,
    #[serde(rename = "type")]
    record_type: String,
    total_findings: usize,
    by_severity: BTreeMap<String, u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usage_breakdown: Option<WardenUsageBreakdown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_failed_hunks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_failed_extractions: Option<u64>,
}

#[derive(Clone, Debug)]
struct PostProcessFinding {
    finding: WardenFinding,
    origin: FindingOrigin,
}

#[derive(Clone, Debug)]
struct FindingOrigin {
    row_index: usize,
    finding_index: usize,
    task_id: String,
    sha: String,
    target_path: String,
    chunk_index: usize,
    chunk_start_line: usize,
    chunk_end_line: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingProcessingEventJson {
    stage: String,
    action: String,
    finding: WardenFinding,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replacement: Option<WardenFinding>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerificationVerdict {
    verdict: String,
    #[serde(default)]
    finding: Option<WardenFinding>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug)]
struct AuxiliaryUsageEntry {
    agent: String,
    usage: WardenUsageStats,
    model: Option<String>,
    runtime: Option<String>,
    row_index: Option<usize>,
}

#[derive(Default)]
struct PostProcessCounters {
    raw_findings: usize,
    normalized_findings: usize,
    invalid_findings: usize,
    dedupe_dropped: usize,
    verification_rejected: usize,
    verification_revised: usize,
    merge_absorbed: usize,
    verifier_errors: usize,
    merge_errors: usize,
}

struct PostProcessRunOutput {
    final_jsonl_artifact: String,
    summary_artifact: String,
    events_artifact: String,
    final_findings: Vec<PostProcessFinding>,
    counters: PostProcessCounters,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmittedFinding {
    index: usize,
    value: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct SemanticScoreRow {
    finding_id: String,
    verdict: String,
    matched_corpus_ids: Vec<String>,
    notes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ScoringUsageTotals {
    input_tokens: u64,
    output_tokens: u64,
    reasoning_tokens: u64,
    cached_input_tokens: u64,
    cache_creation_input_tokens: u64,
    cache_creation_5m_input_tokens: u64,
    cache_creation_1h_input_tokens: u64,
    web_search_requests: u64,
    provider_total_tokens: u64,
    cost_usd: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AgentSemanticMatchResponse {
    verdict: String,
    matched_corpus_ids: Vec<String>,
    notes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SemanticScoringResult {
    run_id: String,
    corpus_id: String,
    scoring: serde_json::Value,
    scores: Vec<SemanticScoreRow>,
}

#[derive(Clone, Debug)]
struct AgentScoringJob {
    index: usize,
    sha: String,
    task_id: String,
    target_path: String,
    finding_index: usize,
    finding_id: String,
    finding: serde_json::Value,
    candidates: Vec<CorpusFinding>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AgentScoringOutput {
    index: usize,
    scores: Vec<SemanticScoreRow>,
    usage: ScoringUsageTotals,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamDedupResponse {
    kept_indices: Vec<usize>,
    events: Vec<UpstreamFindingEventIndex>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamFindingEventIndex {
    stage: String,
    action: String,
    finding_index: usize,
    replacement_index: Option<usize>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamApplyMergeGroupsResponse {
    absorbed: Vec<UpstreamAbsorbedFinding>,
    replacements: Vec<UpstreamFindingReplacement>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamAbsorbedFinding {
    index: usize,
    replacement: Option<WardenFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamFindingReplacement {
    index: usize,
    finding: WardenFinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionMode {
    Standard,
    Rlm,
}

impl ExecutionMode {
    fn label(self) -> &'static str {
        match self {
            ExecutionMode::Standard => "standard",
            ExecutionMode::Rlm => "rlm",
        }
    }
}

fn model_spec(
    model: impl Into<String>,
    variant: Option<String>,
    max_context_tokens: usize,
    max_output_tokens: Option<usize>,
) -> Result<ModelSpec> {
    ModelSpec::from_token_limits(model, variant, max_context_tokens, max_output_tokens)
        .map_err(anyhow::Error::msg)
}

struct RunTaskContext<'a> {
    run_dir: &'a Path,
    workspace_root: Option<&'a Path>,
    prepared_repo: Option<&'a Path>,
    provider: &'a ProviderHandle,
    provider_kind: &'a str,
    args: &'a Args,
    model: &'a str,
    execution_mode: ExecutionMode,
    standard_context_approach: Option<&'a StandardContextApproach>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    let args = Args::parse();

    if args.post_process_run_dir.is_some() {
        run_post_process(args).await
    } else if args.validate_run_dir.is_some() {
        run_validate(args).await
    } else if args.score_run_dir.is_some() {
        run_score(args).await
    } else if args.single_task.is_some() {
        run_child(args).await
    } else {
        run_parent(args).await
    }
}

async fn run_parent(args: Args) -> Result<()> {
    let corpus = load_corpus(&args.corpus)?;
    let state_root = PathBuf::from(STATE_ROOT);
    fs::create_dir_all(&state_root).with_context(|| format!("create {}", state_root.display()))?;
    let workspace_root = args
        .workspace_root
        .clone()
        .unwrap_or_else(|| state_root.join("workspace"));
    fs::create_dir_all(&workspace_root)
        .with_context(|| format!("create {}", workspace_root.display()))?;
    let workspace_root = fs::canonicalize(&workspace_root)
        .with_context(|| format!("canonicalize {}", workspace_root.display()))?;
    let tasks = select_tasks(build_tasks(&corpus, &workspace_root)?, &args);
    if tasks.is_empty() {
        bail!("no Warden Sentry chunks selected");
    }

    let run_id = args
        .run_id
        .clone()
        .or_else(|| {
            args.output_dir
                .as_ref()
                .and_then(|path| path.file_name())
                .map(|name| name.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| Utc::now().format("%Y%m%dT%H%M%SZ").to_string());
    let run_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| state_root.join("runs").join(&run_id));
    fs::create_dir_all(&run_dir).with_context(|| format!("create {}", run_dir.display()))?;
    let run_dir = fs::canonicalize(&run_dir)
        .with_context(|| format!("canonicalize {}", run_dir.display()))?;
    fs::create_dir_all(run_dir.join("tasks"))
        .with_context(|| format!("create {}", run_dir.join("tasks").display()))?;
    write_target_lists(&run_dir, &tasks)?;
    let run_log_path = run_dir.join("run.log");
    let run_log = Arc::new(Mutex::new(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&run_log_path)
            .with_context(|| format!("open {}", run_log_path.display()))?,
    ));

    let predictions_path = run_dir.join("predictions.jsonl");
    let (completed_rows, resume_reconcile) = if args.resume {
        reconcile_resume_predictions(&run_dir, &predictions_path, &tasks)?
    } else {
        (BTreeMap::new(), ResumeReconcileStats::default())
    };
    let completed: BTreeSet<String> = completed_rows.keys().cloned().collect();
    let pending: Vec<WardenTask> = tasks
        .iter()
        .filter(|task| !completed.contains(&task.task_id))
        .cloned()
        .collect();

    log_run(&run_log, format!("Warden Sentry run_id={run_id}"))?;
    log_run(
        &run_log,
        format!("  corpus:           {}", args.corpus.display()),
    )?;
    log_run(&run_log, format!("  corpus-id:        {}", corpus.id))?;
    log_run(
        &run_log,
        format!("  corpus-updated:   {}", corpus.updated_at),
    )?;
    log_run(&run_log, format!("  selected:         {}", tasks.len()))?;
    log_run(&run_log, format!("  pending:          {}", pending.len()))?;
    if args.resume
        && (resume_reconcile.imported_completed_results > 0
            || resume_reconcile.removed_non_completed_rows > 0
            || resume_reconcile.rewrote_predictions)
    {
        log_run(
            &run_log,
            format!(
                "  resume-reconcile: imported_completed={} removed_non_completed={} rewrote_predictions={}",
                resume_reconcile.imported_completed_results,
                resume_reconcile.removed_non_completed_rows,
                resume_reconcile.rewrote_predictions
            ),
        )?;
    }
    log_run(
        &run_log,
        format!("  output:           {}", run_dir.display()),
    )?;
    log_run(
        &run_log,
        format!("  run-log:          {}", run_log_path.display()),
    )?;

    if args.dry_run {
        for task in &pending {
            log_run(
                &run_log,
                format!(
                    "  [dry-run] {} {} {}:{}-{} ({} known finding{})",
                    task.task_id,
                    &task.sha[..8],
                    task.target_path,
                    task.chunk.start_line,
                    task.chunk.end_line,
                    task.findings.len(),
                    if task.findings.len() == 1 { "" } else { "s" }
                ),
            )?;
        }
        return Ok(());
    }
    let (provider_kind, resolved_model) = if pending.is_empty() {
        let first_row = completed_rows.values().next();
        let provider_kind = first_row
            .map(|row| row.provider_kind.clone())
            .or_else(|| args.provider_id.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let resolved_model = args
            .model
            .clone()
            .or_else(|| first_row.map(|row| row.model.clone()))
            .unwrap_or_else(|| "unknown".to_string());
        (provider_kind, resolved_model)
    } else {
        let (_provider, provider_kind, resolved_model) = resolve_provider(&args)?;
        (provider_kind, resolved_model)
    };
    let execution_mode = parse_execution_mode(&args.execution_mode)?;
    let standard_context_approach = resolve_standard_context_approach(
        execution_mode,
        args.standard_context_approach.as_deref(),
    )?;
    let execution_mode_label = execution_mode.label().to_string();
    let standard_context_approach_label = standard_context_approach
        .as_ref()
        .map(standard_context_approach_label)
        .map(str::to_string);

    log_run(
        &run_log,
        format!("  model:            {resolved_model} (provider={provider_kind})"),
    )?;
    log_run(
        &run_log,
        format!(
            "  variant:          {}",
            args.variant.as_deref().unwrap_or("provider-default")
        ),
    )?;
    log_run(
        &run_log,
        format!("  execution-mode:   {execution_mode_label}"),
    )?;
    log_run(
        &run_log,
        format!("  isolation:        {}", args.isolation.label()),
    )?;
    if args.isolation == ChildIsolation::Docker && !pending.is_empty() {
        ensure_docker_image(&args.docker_image)?;
        log_run(
            &run_log,
            format!("  docker-image:     {}", args.docker_image),
        )?;
    }
    if let Some(label) = &standard_context_approach_label {
        log_run(&run_log, format!("  context-approach: {label}"))?;
    }
    log_run(&run_log, format!("  batch_size:       {}", args.batch_size))?;
    if pending.is_empty() {
        log_run(
            &run_log,
            "  resume:           predictions.jsonl already covers every selected task",
        )?;
    }

    let process_started_at = Utc::now();
    let existing_started_at = if args.resume {
        read_summary_started_at(&run_dir)?
    } else {
        None
    };
    let resumed_from_existing_started_at = existing_started_at.is_some();
    let started_at = existing_started_at.unwrap_or(process_started_at);
    let started_instant = Instant::now();
    let child_exe = std::env::current_exe().context("resolve current_exe")?;
    let semaphore = Arc::new(Semaphore::new(args.batch_size.max(1)));
    let args_shared = Arc::new(args.clone());
    let workspace_root_shared = Arc::new(workspace_root);
    let run_dir_shared = Arc::new(run_dir.clone());
    let predictions_path_shared = Arc::new(predictions_path.clone());
    let child_exe_shared = Arc::new(child_exe);
    let append_mutex = Arc::new(tokio::sync::Mutex::new(()));
    let total = pending.len();
    let mut join_set: JoinSet<(usize, String, Result<TaskResult>)> = JoinSet::new();

    for (index, task) in pending.into_iter().enumerate() {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .context("acquire benchmark slot")?;
        let args = args_shared.clone();
        let workspace_root = workspace_root_shared.clone();
        let run_dir = run_dir_shared.clone();
        let predictions_path = predictions_path_shared.clone();
        let child_exe = child_exe_shared.clone();
        let append_mutex = append_mutex.clone();
        let task_id = task.task_id.clone();
        join_set.spawn(async move {
            let _permit = permit;
            let result = match spawn_child(
                &child_exe,
                &run_dir,
                &workspace_root,
                args.as_ref(),
                &task,
            )
            .await
            {
                Ok(row) => {
                    let _guard = append_mutex.lock().await;
                    append_prediction(predictions_path.as_ref(), &row).map(|_| row)
                }
                Err(err) => Err(err),
            };
            (index, task_id, result)
        });
    }

    let mut indexed: Vec<(usize, TaskResult)> = Vec::new();
    let mut failures: Vec<(String, anyhow::Error)> = Vec::new();
    let mut abort_error: Option<anyhow::Error> = None;
    let mut finished = 0usize;
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    while !join_set.is_empty() {
        let joined = tokio::select! {
            _ = &mut interrupt => {
                let message = "interrupted; active benchmark children were cancelled";
                log_run(&run_log, message)?;
                join_set.abort_all();
                cleanup_active_children(&run_dir, &run_log, args_shared.keep_worktrees)?;
                abort_error = Some(anyhow::anyhow!(message));
                break;
            }
            joined = join_set.join_next() => joined,
        };
        let Some(joined) = joined else {
            break;
        };
        let (index, task_id, result) = match joined {
            Ok(v) => v,
            Err(err) => {
                join_set.abort_all();
                cleanup_active_children(&run_dir, &run_log, args_shared.keep_worktrees)?;
                return Err(anyhow::anyhow!("task runner panicked: {err}"));
            }
        };
        match result {
            Ok(row) => {
                finished += 1;
                log_run(
                    &run_log,
                    format!(
                        "  [{finished}/{total}] {} status={} findings_json={} t={:.1}s iters={}",
                        row.task_id,
                        row.status,
                        row.parsed_response.is_some(),
                        row.elapsed_seconds,
                        row.iterations
                    ),
                )?;
                let should_fail_fast = args_shared.fail_fast && row.status != "completed";
                if should_fail_fast {
                    let reason = row
                        .failure_reason
                        .clone()
                        .unwrap_or_else(|| format!("task finished with status {}", row.status));
                    abort_error = Some(anyhow::anyhow!(
                        "fail-fast after {}: {}",
                        row.task_id,
                        reason
                    ));
                }
                indexed.push((index, row));
                if abort_error.is_some() {
                    join_set.abort_all();
                    cleanup_active_children(&run_dir, &run_log, args_shared.keep_worktrees)?;
                    break;
                }
            }
            Err(err) => {
                finished += 1;
                log_run(&run_log, format!("  [{finished}/{total}] ERROR: {err:#}"))?;
                if args_shared.fail_fast {
                    abort_error = Some(anyhow::anyhow!("fail-fast after {task_id}: {err:#}"));
                }
                failures.push((task_id, err));
                if abort_error.is_some() {
                    join_set.abort_all();
                    cleanup_active_children(&run_dir, &run_log, args_shared.keep_worktrees)?;
                    break;
                }
            }
        }
    }

    indexed.sort_by_key(|(i, _)| *i);
    let mut result_rows = load_completed_results(&predictions_path)?;
    for (_, row) in indexed {
        result_rows.entry(row.task_id.clone()).or_insert(row);
    }
    let mut results: Vec<TaskResult> = result_rows
        .into_values()
        .filter(|row| tasks.iter().any(|task| task.task_id == row.task_id))
        .collect();
    let task_order = tasks
        .iter()
        .enumerate()
        .map(|(index, task)| (task.task_id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    results.sort_by_key(|row| {
        task_order
            .get(row.task_id.as_str())
            .copied()
            .unwrap_or(usize::MAX)
    });
    let finished_at = Utc::now();
    let process_duration_seconds = started_instant.elapsed().as_secs_f64();
    let duration_seconds = if resumed_from_existing_started_at {
        let resumed_wall_seconds =
            (finished_at - started_at).num_milliseconds().max(0) as f64 / 1000.0;
        resumed_wall_seconds.max(process_duration_seconds)
    } else {
        process_duration_seconds
    };
    let failed_tasks: Vec<(String, String)> = failures
        .iter()
        .map(|(id, err)| (id.clone(), format!("{err:#}")))
        .collect();
    write_run_summary(
        &run_dir,
        &corpus,
        &run_id,
        &resolved_model,
        args_shared.variant.as_deref(),
        &provider_kind,
        &execution_mode_label,
        standard_context_approach_label.as_deref(),
        &tasks,
        &results,
        &failed_tasks,
        args_shared.max_turns,
        args_shared.max_context_tokens,
        args_shared.max_task_provider_total_tokens,
        args_shared.isolation.label(),
        &args_shared.docker_image,
        &started_at.to_rfc3339(),
        &finished_at.to_rfc3339(),
        duration_seconds,
    )?;

    log_run(&run_log, "")?;
    log_run(&run_log, "Run summary:")?;
    log_run(
        &run_log,
        format!("  run_dir:          {}", run_dir.display()),
    )?;
    log_run(
        &run_log,
        format!("  predictions:      {}", predictions_path.display()),
    )?;
    log_run(&run_log, format!("  completed:        {}", results.len()))?;
    if !failures.is_empty() {
        log_run(&run_log, format!("  failures: {}", failures.len()))?;
        for (id, err) in &failures {
            log_run(&run_log, format!("    {id}: {err:#}"))?;
        }
    }
    log_run(
        &run_log,
        format!("  wall_clock:       {duration_seconds:.1}s"),
    )?;
    if abort_error.is_none() {
        let post_processed = post_process_existing_run(
            args_shared.as_ref(),
            &run_dir,
            workspace_root_shared.as_ref(),
        )
        .await?;
        log_run(&run_log, "")?;
        log_run(&run_log, "Warden post-processing:")?;
        log_run(
            &run_log,
            format!(
                "  finalized_jsonl:  {}",
                post_processed.final_jsonl_artifact
            ),
        )?;
        log_run(
            &run_log,
            format!("  events:           {}", post_processed.events_artifact),
        )?;
        log_run(
            &run_log,
            format!(
                "  findings:         raw={} normalized={} final={}",
                post_processed.counters.raw_findings,
                post_processed.counters.normalized_findings,
                post_processed.final_findings.len()
            ),
        )?;
    }
    if let Some(err) = abort_error {
        return Err(err);
    }
    Ok(())
}

async fn run_post_process(args: Args) -> Result<()> {
    if args.single_task.is_some() {
        bail!("--post-process-run-dir cannot be combined with --single-task");
    }
    if args.score_run_dir.is_some() {
        bail!("--post-process-run-dir cannot be combined with --score-run-dir");
    }
    if args.validate_run_dir.is_some() {
        bail!("--post-process-run-dir cannot be combined with --validate-run-dir");
    }
    if !args.task_id.is_empty()
        || !args.finding_id.is_empty()
        || !args.sha.is_empty()
        || !args.target_path.is_empty()
        || args.limit.is_some()
        || args.offset != 0
    {
        bail!(
            "--post-process-run-dir finalizes all predictions in the run directory; task selectors apply only to analysis runs"
        );
    }

    let run_dir = args
        .post_process_run_dir
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--post-process-run-dir is required"))?;
    let run_dir = fs::canonicalize(&run_dir)
        .with_context(|| format!("canonicalize {}", run_dir.display()))?;
    let state_root = PathBuf::from(STATE_ROOT);
    let workspace_root = args
        .workspace_root
        .clone()
        .unwrap_or_else(|| state_root.join("workspace"));
    fs::create_dir_all(&workspace_root)
        .with_context(|| format!("create {}", workspace_root.display()))?;
    let workspace_root = fs::canonicalize(&workspace_root)
        .with_context(|| format!("canonicalize {}", workspace_root.display()))?;

    let output = post_process_existing_run(&args, &run_dir, &workspace_root).await?;
    eprintln!("Warden post-processing complete:");
    eprintln!("  run_dir:          {}", run_dir.display());
    eprintln!("  finalized_jsonl:  {}", output.final_jsonl_artifact);
    eprintln!("  summary:          {}", output.summary_artifact);
    eprintln!("  events:           {}", output.events_artifact);
    eprintln!(
        "  findings:         raw={} normalized={} final={}",
        output.counters.raw_findings,
        output.counters.normalized_findings,
        output.final_findings.len()
    );
    Ok(())
}

async fn run_validate(args: Args) -> Result<()> {
    if args.single_task.is_some() {
        bail!("--validate-run-dir cannot be combined with --single-task");
    }
    if args.score_run_dir.is_some() {
        bail!("--validate-run-dir cannot be combined with --score-run-dir");
    }
    if args.post_process_run_dir.is_some() {
        bail!("--validate-run-dir cannot be combined with --post-process-run-dir");
    }
    if !args.task_id.is_empty()
        || !args.finding_id.is_empty()
        || !args.sha.is_empty()
        || !args.target_path.is_empty()
        || args.limit.is_some()
        || args.offset != 0
    {
        bail!(
            "--validate-run-dir validates all finalized artifacts in the run directory; task selectors apply only to analysis runs"
        );
    }

    let run_dir = args
        .validate_run_dir
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--validate-run-dir is required"))?;
    let run_dir = fs::canonicalize(&run_dir)
        .with_context(|| format!("canonicalize {}", run_dir.display()))?;
    let report = validate_finalized_run(&run_dir)?;
    fs::create_dir_all(run_dir.join(POST_PROCESS_DIR))
        .with_context(|| format!("create {}", run_dir.join(POST_PROCESS_DIR).display()))?;
    fs::write(
        run_dir.join(VALIDATION_ARTIFACT),
        serde_json::to_string_pretty(&report)?,
    )
    .with_context(|| format!("write {}", run_dir.join(VALIDATION_ARTIFACT).display()))?;
    if let Some(items) = report.get("failures").and_then(|value| value.as_array())
        && !items.is_empty()
    {
        let details = items
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        bail!("finalized run validation failed: {details}");
    }
    eprintln!("Warden finalized artifact validation complete:");
    eprintln!("  run_dir:          {}", run_dir.display());
    eprintln!("  artifact:         {VALIDATION_ARTIFACT}");
    eprintln!(
        "  chunks:           {}",
        report
            .get("chunkRecords")
            .and_then(|value| value.as_u64())
            .unwrap_or_default()
    );
    eprintln!(
        "  verifier_results: {}",
        report
            .get("verifierResultArtifacts")
            .and_then(|value| value.as_u64())
            .unwrap_or_default()
    );
    eprintln!(
        "  merge_files:      {}",
        report
            .get("mergeArtifacts")
            .and_then(|value| value.as_u64())
            .unwrap_or_default()
    );
    Ok(())
}

async fn post_process_existing_run(
    args: &Args,
    run_dir: &Path,
    workspace_root: &Path,
) -> Result<PostProcessRunOutput> {
    let predictions_path = run_dir.join("predictions.jsonl");
    let mut results = load_completed_results(&predictions_path)?
        .into_values()
        .collect::<Vec<_>>();
    if results.is_empty() {
        bail!("no predictions found in {}", predictions_path.display());
    }
    results.sort_by(|a, b| {
        a.sha
            .cmp(&b.sha)
            .then(a.target_path.cmp(&b.target_path))
            .then(a.chunk_start_line.cmp(&b.chunk_start_line))
            .then(a.chunk_end_line.cmp(&b.chunk_end_line))
            .then(a.task_id.cmp(&b.task_id))
    });

    let run_id = run_id_from_summary_or_dir(run_dir)?;
    let (provider_kind, resolved_model) = post_process_provider_identity(args, run_dir, &results)?;
    let non_comparable_scoring_artifacts = mark_existing_scoring_non_comparable(run_dir)?;
    let post_dir = run_dir.join(POST_PROCESS_DIR);
    if post_dir.exists() {
        fs::remove_dir_all(&post_dir).with_context(|| format!("remove {}", post_dir.display()))?;
    }
    fs::create_dir_all(&post_dir).with_context(|| format!("create {}", post_dir.display()))?;
    fs::create_dir_all(post_dir.join("verification"))
        .with_context(|| format!("create {}", post_dir.join("verification").display()))?;
    fs::create_dir_all(post_dir.join("merge"))
        .with_context(|| format!("create {}", post_dir.join("merge").display()))?;

    let mut events_file =
        File::create(run_dir.join(POST_PROCESS_EVENTS_ARTIFACT)).with_context(|| {
            format!(
                "create {}",
                run_dir.join(POST_PROCESS_EVENTS_ARTIFACT).display()
            )
        })?;
    let started_at = Utc::now();
    let started = Instant::now();
    let mut counters = PostProcessCounters::default();
    let mut used_ids = BTreeSet::new();
    let mut events = Vec::new();
    let mut auxiliary_entries = Vec::new();
    let mut final_findings = Vec::new();

    let mut rows_by_sha: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (row_index, result) in results.iter().enumerate() {
        rows_by_sha
            .entry(result.sha.clone())
            .or_default()
            .push(row_index);
    }

    for (sha, row_indices) in rows_by_sha {
        let mut shard_findings = Vec::new();
        for row_index in row_indices {
            shard_findings.extend(normalize_result_findings(
                &results[row_index],
                row_index,
                &mut used_ids,
                &mut counters,
            ));
        }

        let before_dedupe = shard_findings.len();
        let (deduped, dedupe_events) = deduplicate_with_upstream_warden(shard_findings)?;
        counters.dedupe_dropped += before_dedupe.saturating_sub(deduped.len());
        events.extend(dedupe_events);

        if deduped.is_empty() {
            continue;
        }

        let repo_dir = post_dir.join("worktrees").join(&sha[..8]).join("repo");
        checkout_sha(workspace_root, &repo_dir, DEFAULT_REPOSITORY, &sha)
            .with_context(|| format!("checkout {sha} for post-processing"))?;

        let verification_dir = post_dir.join("verification").join(&sha[..8]);
        fs::create_dir_all(&verification_dir)
            .with_context(|| format!("create {}", verification_dir.display()))?;
        let verification = verify_post_findings(
            args,
            &resolved_model,
            &provider_kind,
            &repo_dir,
            &verification_dir,
            deduped,
        )
        .await?;
        counters.verification_rejected += verification.rejected;
        counters.verification_revised += verification.revised;
        counters.verifier_errors += verification.errors;
        events.extend(verification.events);
        auxiliary_entries.extend(verification.usage);

        let merge = merge_post_findings(
            args,
            &resolved_model,
            &provider_kind,
            &repo_dir,
            &post_dir.join("merge").join(format!("{}.json", &sha[..8])),
            verification.findings,
        )
        .await?;
        counters.merge_absorbed += merge.absorbed;
        counters.merge_errors += merge.errors;
        events.extend(merge.events);
        auxiliary_entries.extend(merge.usage);
        final_findings.extend(merge.findings);

        let _ = remove_sha_worktree(workspace_root, DEFAULT_REPOSITORY, &repo_dir);
    }

    final_findings.sort_by(compare_post_finding_for_output);
    for event in &events {
        writeln!(events_file, "{}", serde_json::to_string(event)?).with_context(|| {
            format!(
                "write {}",
                run_dir.join(POST_PROCESS_EVENTS_ARTIFACT).display()
            )
        })?;
    }
    events_file.flush().with_context(|| {
        format!(
            "flush {}",
            run_dir.join(POST_PROCESS_EVENTS_ARTIFACT).display()
        )
    })?;

    let auxiliary_usage = aggregate_auxiliary_usage(&auxiliary_entries);
    let auxiliary_usage_attribution = aggregate_auxiliary_usage_attribution(&auxiliary_entries);
    let cost_summary = post_process_cost_summary(args, &results, &auxiliary_usage);
    let reproducibility_manifest = write_reproducibility_manifest(
        args,
        run_dir,
        &run_id,
        &resolved_model,
        &provider_kind,
        &cost_summary,
    )?;
    let final_jsonl_path = run_dir.join(WARDEN_FINAL_JSONL_ARTIFACT);
    write_warden_final_jsonl(
        &final_jsonl_path,
        &run_id,
        run_dir,
        &results,
        &final_findings,
        &auxiliary_entries,
        &resolved_model,
    )?;
    let verification_artifact_count =
        count_files_named(&post_dir.join("verification"), "result.json")?;
    let merge_artifact_count = count_json_files(&post_dir.join("merge"))?;

    let finished_at = Utc::now();
    let clean_state = reproducibility_manifest
        .get("runner")
        .and_then(|value| value.get("cleanState"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let clean_state_warning = reproducibility_manifest
        .get("runner")
        .and_then(|value| value.get("cleanStateWarning"))
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let post_summary = serde_json::json!({
        "status": if counters.verifier_errors == 0 && counters.merge_errors == 0 { "completed" } else { "completed_with_auxiliary_errors" },
        "runId": run_id,
        "startedAt": started_at.to_rfc3339(),
        "finishedAt": finished_at.to_rfc3339(),
        "durationMs": seconds_to_ms(started.elapsed().as_secs_f64()),
        "rawFindings": counters.raw_findings,
        "normalizedFindings": counters.normalized_findings,
        "invalidFindings": counters.invalid_findings,
        "dedupeDropped": counters.dedupe_dropped,
        "verificationRejected": counters.verification_rejected,
        "verificationRevised": counters.verification_revised,
        "verifierErrors": counters.verifier_errors,
        "mergeAbsorbed": counters.merge_absorbed,
        "mergeErrors": counters.merge_errors,
        "finalFindings": final_findings.len(),
        "verificationArtifactCount": verification_artifact_count,
        "mergeArtifactCount": merge_artifact_count,
        "analysisCostUSD": cost_summary.analysis_usd,
        "auxiliaryCostUSD": cost_summary.auxiliary_usd,
        "costUSD": cost_summary.total_usd,
        "pricingStatus": cost_summary.status,
        "pricing": cost_summary.pricing,
        "finalJsonlArtifact": WARDEN_FINAL_JSONL_ARTIFACT,
        "eventsArtifact": POST_PROCESS_EVENTS_ARTIFACT,
        "reproducibilityManifestArtifact": REPRODUCIBILITY_MANIFEST_ARTIFACT,
        "verificationArtifacts": "post-processing/verification/",
        "mergeArtifacts": "post-processing/merge/",
        "nonComparableScoringArtifacts": non_comparable_scoring_artifacts,
        "auxiliaryUsage": auxiliary_usage,
        "auxiliaryUsageAttribution": auxiliary_usage_attribution,
        "reproducibility": reproducibility_manifest,
        "cleanState": clean_state,
        "cleanStateWarning": clean_state_warning,
        "model": resolved_model,
        "providerKind": provider_kind,
        "method": POST_PROCESSING_METHOD,
    });
    fs::write(
        run_dir.join(POST_PROCESS_SUMMARY_ARTIFACT),
        serde_json::to_string_pretty(&post_summary)?,
    )
    .with_context(|| {
        format!(
            "write {}",
            run_dir.join(POST_PROCESS_SUMMARY_ARTIFACT).display()
        )
    })?;
    update_summary_post_processing(
        run_dir,
        &post_summary,
        &final_findings,
        &auxiliary_usage,
        &resolved_model,
        &provider_kind,
    )?;

    Ok(PostProcessRunOutput {
        final_jsonl_artifact: WARDEN_FINAL_JSONL_ARTIFACT.to_string(),
        summary_artifact: POST_PROCESS_SUMMARY_ARTIFACT.to_string(),
        events_artifact: POST_PROCESS_EVENTS_ARTIFACT.to_string(),
        final_findings,
        counters,
    })
}

struct VerificationOutput {
    findings: Vec<PostProcessFinding>,
    usage: Vec<AuxiliaryUsageEntry>,
    events: Vec<FindingProcessingEventJson>,
    rejected: usize,
    revised: usize,
    errors: usize,
}

async fn verify_post_findings(
    args: &Args,
    resolved_model: &str,
    provider_kind: &str,
    repo_dir: &Path,
    verification_dir: &Path,
    findings: Vec<PostProcessFinding>,
) -> Result<VerificationOutput> {
    if findings.is_empty() {
        return Ok(VerificationOutput {
            findings,
            usage: Vec::new(),
            events: Vec::new(),
            rejected: 0,
            revised: 0,
            errors: 0,
        });
    }

    let _cwd_guard = PROCESS_CWD_MUTEX.lock().await;
    let previous_cwd = std::env::current_dir().context("capture current directory")?;
    std::env::set_current_dir(repo_dir)
        .with_context(|| format!("cd into verifier repo {}", repo_dir.display()))?;
    let verification_result = verify_post_findings_in_current_repo(
        args,
        resolved_model,
        provider_kind,
        repo_dir,
        verification_dir,
        findings,
    )
    .await;
    let restore_result = std::env::set_current_dir(&previous_cwd)
        .with_context(|| format!("restore cwd {}", previous_cwd.display()));
    restore_result?;
    verification_result
}

async fn verify_post_findings_in_current_repo(
    args: &Args,
    resolved_model: &str,
    provider_kind: &str,
    repo_dir: &Path,
    verification_dir: &Path,
    findings: Vec<PostProcessFinding>,
) -> Result<VerificationOutput> {
    let concurrency = args.post_process_batch_size.max(1);
    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut join_set: JoinSet<Result<VerificationJobOutput>> = JoinSet::new();
    for (index, finding) in findings.into_iter().enumerate() {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .context("acquire verifier slot")?;
        let args = args.clone();
        let model = resolved_model.to_string();
        let provider_kind = provider_kind.to_string();
        let repo_dir = repo_dir.to_path_buf();
        let artifact_dir = verification_dir.join(format!(
            "{:04}-{}-{}",
            index + 1,
            finding.finding.id,
            safe_path_segment(&finding.origin.task_id)
        ));
        join_set.spawn(async move {
            let _permit = permit;
            verify_one_post_finding(
                args,
                model,
                provider_kind,
                repo_dir,
                artifact_dir,
                index,
                finding,
            )
            .await
        });
    }

    let mut outputs = Vec::new();
    while let Some(joined) = join_set.join_next().await {
        match joined {
            Ok(Ok(output)) => outputs.push(output),
            Ok(Err(err)) => {
                join_set.abort_all();
                return Err(err);
            }
            Err(err) => {
                join_set.abort_all();
                bail!("verification task panicked: {err}");
            }
        }
    }
    outputs.sort_by_key(|output| output.index);

    let mut kept = Vec::new();
    let mut usage = Vec::new();
    let mut events = Vec::new();
    let mut rejected = 0usize;
    let mut revised = 0usize;
    let mut errors = 0usize;
    for output in outputs {
        usage.extend(output.usage);
        events.extend(output.events);
        rejected += usize::from(output.rejected);
        revised += usize::from(output.revised);
        errors += usize::from(output.error);
        if let Some(finding) = output.finding {
            kept.push(finding);
        }
    }

    Ok(VerificationOutput {
        findings: kept,
        usage,
        events,
        rejected,
        revised,
        errors,
    })
}

struct VerificationJobOutput {
    index: usize,
    finding: Option<PostProcessFinding>,
    usage: Vec<AuxiliaryUsageEntry>,
    events: Vec<FindingProcessingEventJson>,
    rejected: bool,
    revised: bool,
    error: bool,
}

async fn verify_one_post_finding(
    args: Args,
    resolved_model: String,
    provider_kind: String,
    repo_dir: PathBuf,
    artifact_dir: PathBuf,
    index: usize,
    candidate: PostProcessFinding,
) -> Result<VerificationJobOutput> {
    fs::create_dir_all(&artifact_dir)
        .with_context(|| format!("create {}", artifact_dir.display()))?;
    let prompt = build_verification_prompt(&candidate.finding)?;
    fs::write(artifact_dir.join("prompt.txt"), &prompt)
        .with_context(|| format!("write {}", artifact_dir.join("prompt.txt").display()))?;
    let origin = serde_json::json!({
        "taskId": &candidate.origin.task_id,
        "sha": &candidate.origin.sha,
        "targetPath": &candidate.origin.target_path,
        "chunkIndex": candidate.origin.chunk_index,
        "chunkStartLine": candidate.origin.chunk_start_line,
        "chunkEndLine": candidate.origin.chunk_end_line,
    });
    fs::write(
        artifact_dir.join("candidate.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "finding": &candidate.finding,
            "origin": origin,
        }))?,
    )
    .with_context(|| format!("write {}", artifact_dir.join("candidate.json").display()))?;

    let turn_result =
        run_repo_aware_verification_turn(&args, &resolved_model, &artifact_dir, &prompt).await;
    let mut artifact = serde_json::json!({
        "finding": &candidate.finding,
        "origin": {
            "taskId": &candidate.origin.task_id,
            "sha": &candidate.origin.sha,
            "targetPath": &candidate.origin.target_path,
            "chunkIndex": candidate.origin.chunk_index,
            "chunkStartLine": candidate.origin.chunk_start_line,
            "chunkEndLine": candidate.origin.chunk_end_line,
        },
        "repoPath": &repo_dir,
        "promptArtifact": "prompt.txt",
        "eventsArtifact": "events.jsonl",
        "traceArtifact": "session.trace.jsonl",
        "sessionDbArtifact": "session.db",
        "runtime": "lash-standard-tools",
        "providerKind": provider_kind,
        "model": resolved_model,
    });

    let mut usage = Vec::new();
    let mut events = Vec::new();
    match turn_result {
        Ok(turn) => {
            let usage_stats = usage_stats_from_token_totals(&args, &turn.tokens);
            usage.push(AuxiliaryUsageEntry {
                agent: "verification".to_string(),
                usage: usage_stats.clone(),
                model: Some(resolved_model.clone()),
                runtime: Some("lash-standard-tools".to_string()),
                row_index: Some(candidate.origin.row_index),
            });
            artifact["response"] = serde_json::json!({
                "text": turn.assistant_text,
                "usage": usage_stats,
                "tokens": turn.tokens,
                "turnStatus": turn.turn_status,
                "doneReason": turn.done_reason,
                "iterations": turn.iterations,
                "llmCalls": turn.llm_calls,
                "toolBreakdown": turn.tool_breakdown,
            });
            let verdict = turn.verdict;
            artifact["verdict"] = serde_json::to_value(&verdict)?;
            let original = candidate.finding.clone();
            let next = apply_verification_verdict(&original, verdict.as_ref());
            let mut out = candidate;
            match next {
                None => {
                    events.push(FindingProcessingEventJson {
                        stage: "verification".to_string(),
                        action: "rejected".to_string(),
                        finding: original,
                        reason: verdict.and_then(|v| v.reason),
                        replacement: None,
                    });
                    fs::write(
                        artifact_dir.join("result.json"),
                        serde_json::to_string_pretty(&artifact)?,
                    )
                    .with_context(|| {
                        format!("write {}", artifact_dir.join("result.json").display())
                    })?;
                    Ok(VerificationJobOutput {
                        index,
                        finding: None,
                        usage,
                        events,
                        rejected: true,
                        revised: false,
                        error: false,
                    })
                }
                Some(revised_finding) => {
                    let revised = revised_finding != original;
                    if revised {
                        events.push(FindingProcessingEventJson {
                            stage: "verification".to_string(),
                            action: "revised".to_string(),
                            finding: original,
                            reason: verdict.and_then(|v| v.reason),
                            replacement: Some(revised_finding.clone()),
                        });
                    }
                    out.finding = revised_finding;
                    fs::write(
                        artifact_dir.join("result.json"),
                        serde_json::to_string_pretty(&artifact)?,
                    )
                    .with_context(|| {
                        format!("write {}", artifact_dir.join("result.json").display())
                    })?;
                    Ok(VerificationJobOutput {
                        index,
                        finding: Some(out),
                        usage,
                        events,
                        rejected: false,
                        revised,
                        error: false,
                    })
                }
            }
        }
        Err(err) => {
            artifact["error"] = serde_json::Value::String(err.to_string());
            fs::write(
                artifact_dir.join("result.json"),
                serde_json::to_string_pretty(&artifact)?,
            )
            .with_context(|| format!("write {}", artifact_dir.join("result.json").display()))?;
            Ok(VerificationJobOutput {
                index,
                finding: Some(candidate),
                usage,
                events,
                rejected: false,
                revised: false,
                error: true,
            })
        }
    }
}

struct VerificationTurnOutput {
    assistant_text: String,
    verdict: Option<VerificationVerdict>,
    tokens: TokenTotals,
    tool_breakdown: BTreeMap<String, u64>,
    turn_status: String,
    done_reason: String,
    iterations: u64,
    llm_calls: u64,
}

async fn run_repo_aware_verification_turn(
    args: &Args,
    resolved_model: &str,
    artifact_dir: &Path,
    prompt: &str,
) -> Result<VerificationTurnOutput> {
    let (provider, _, _) = resolve_provider(args)?;
    let store_path = artifact_dir.join("session.db");
    let trace_path = artifact_dir.join("session.trace.jsonl");
    let events_path = artifact_dir.join("events.jsonl");
    let store = Arc::new(
        Store::open(&store_path)
            .await
            .with_context(|| format!("open {}", store_path.display()))?,
    );

    let sink = Arc::new(InstanceEventSink::new(events_path.clone())?);
    let mut builder = LashCore::standard_builder()
        .provider(provider)
        .model(model_spec(
            resolved_model.to_string(),
            args.variant.clone(),
            args.max_context_tokens,
            None,
        )?)
        .max_turns(args.max_turns)
        .plugins(build_verification_plugin_stack());
    builder = builder.trace_jsonl_path(trace_path.clone());
    let core = builder
        .advanced()
        .runtime_host_config(lash::durability::RuntimeHostConfig::in_memory())
        .build()?;
    let session = core
        .session("verification")
        .store(store.clone() as Arc<dyn RuntimePersistence>)
        .open()
        .await?;
    let telemetry = run_turn_on_session_with_schema(
        &session,
        prompt,
        sink.as_ref(),
        Some(verification_response_schema()),
        0,
    )
    .await?;
    let assistant_text = sink
        .last_llm_response()
        .or_else(|| non_empty(&telemetry.assistant_safe_text))
        .unwrap_or_default();
    let verdict = terminal_json_value(&telemetry.outcome)
        .and_then(|value| serde_json::from_value::<VerificationVerdict>(value).ok())
        .or_else(|| parse_verification_response(&assistant_text));
    let tokens = aggregate_usage(&telemetry.usage);

    Ok(VerificationTurnOutput {
        assistant_text,
        verdict,
        tokens,
        tool_breakdown: sink.tool_breakdown(),
        turn_status: turn_status_label(&telemetry.outcome).to_string(),
        done_reason: done_reason_label(&telemetry.outcome).to_string(),
        iterations: sink.iteration_count() as u64,
        llm_calls: sink.llm_response_count(),
    })
}

struct MergeOutput {
    findings: Vec<PostProcessFinding>,
    usage: Vec<AuxiliaryUsageEntry>,
    events: Vec<FindingProcessingEventJson>,
    absorbed: usize,
    errors: usize,
}

async fn merge_post_findings(
    args: &Args,
    resolved_model: &str,
    provider_kind: &str,
    repo_dir: &Path,
    artifact_path: &Path,
    findings: Vec<PostProcessFinding>,
) -> Result<MergeOutput> {
    let located_original_indices = findings
        .iter()
        .enumerate()
        .filter_map(|(index, finding)| finding.finding.location.is_some().then_some(index))
        .collect::<Vec<_>>();
    let with_locations = located_original_indices
        .iter()
        .map(|index| findings[*index].clone())
        .collect::<Vec<_>>();
    if with_locations.len() < 2 {
        return Ok(MergeOutput {
            findings,
            usage: Vec::new(),
            events: Vec::new(),
            absorbed: 0,
            errors: 0,
        });
    }

    let prompt = build_merge_prompt(&with_locations, repo_dir)?;
    let request = build_merge_request(args, resolved_model, prompt.clone());
    let (provider, _, _) = resolve_provider(args)?;
    let mut client = DirectLlmClient::new(provider);
    let response = client.complete(request).await;
    let mut artifact = serde_json::json!({
        "prompt": prompt,
        "findings": with_locations.iter().map(|finding| &finding.finding).collect::<Vec<_>>(),
        "indexedFindings": located_original_indices.iter().enumerate().map(|(merge_index, original_index)| {
            serde_json::json!({
                "mergeIndex": merge_index + 1,
                "originalIndex": original_index,
                "finding": &findings[*original_index].finding,
            })
        }).collect::<Vec<_>>(),
    });

    let mut usage = Vec::new();
    match response {
        Ok(response) => {
            let usage_stats = usage_stats_from_response(args, &response);
            usage.push(AuxiliaryUsageEntry {
                agent: "merge".to_string(),
                usage: usage_stats.clone(),
                model: Some(resolved_model.to_string()),
                runtime: Some("lash-direct-llm".to_string()),
                row_index: findings.first().map(|finding| finding.origin.row_index),
            });
            artifact["response"] = serde_json::json!({
                "text": response.full_text,
                "usage": usage_stats,
            });
            let groups = parse_merge_groups_response(&response.full_text).unwrap_or_default();
            artifact["groups"] = serde_json::json!(groups);
            let (merged, events, absorbed, upstream_apply) =
                apply_merge_groups_with_upstream_warden(
                    findings,
                    &located_original_indices,
                    &groups,
                )
                .with_context(|| "apply upstream Warden merge groups")?;
            artifact["upstreamApplyMergeGroups"] = upstream_apply;
            fs::write(artifact_path, serde_json::to_string_pretty(&artifact)?)
                .with_context(|| format!("write {}", artifact_path.display()))?;
            Ok(MergeOutput {
                findings: merged,
                usage,
                events,
                absorbed,
                errors: 0,
            })
        }
        Err(err) => {
            artifact["error"] = serde_json::Value::String(err.to_string());
            fs::write(artifact_path, serde_json::to_string_pretty(&artifact)?)
                .with_context(|| format!("write {}", artifact_path.display()))?;
            let _ = provider_kind;
            Ok(MergeOutput {
                findings,
                usage,
                events: Vec::new(),
                absorbed: 0,
                errors: 1,
            })
        }
    }
}

fn normalize_result_findings(
    result: &TaskResult,
    row_index: usize,
    used_ids: &mut BTreeSet<String>,
    counters: &mut PostProcessCounters,
) -> Vec<PostProcessFinding> {
    let mut out = Vec::new();
    for (finding_index, value) in finding_values(&result.parsed_response)
        .into_iter()
        .enumerate()
    {
        counters.raw_findings += 1;
        match normalize_raw_finding_to_warden(result, value, finding_index, used_ids) {
            Some(finding) => {
                counters.normalized_findings += 1;
                out.push(PostProcessFinding {
                    finding,
                    origin: FindingOrigin {
                        row_index,
                        finding_index,
                        task_id: result.task_id.clone(),
                        sha: result.sha.clone(),
                        target_path: result.target_path.clone(),
                        chunk_index: result.chunk_index,
                        chunk_start_line: result.chunk_start_line,
                        chunk_end_line: result.chunk_end_line,
                    },
                });
            }
            None => counters.invalid_findings += 1,
        }
    }
    out
}

fn normalize_raw_finding_to_warden(
    result: &TaskResult,
    value: &serde_json::Value,
    finding_index: usize,
    used_ids: &mut BTreeSet<String>,
) -> Option<WardenFinding> {
    let title = string_field(value, &["title"])?.trim().to_string();
    let description = string_field(value, &["description", "summary"])
        .unwrap_or("")
        .trim()
        .to_string();
    if title.is_empty() || description.is_empty() {
        return None;
    }
    let severity = normalize_warden_severity(string_field(value, &["severity"])?)?;
    let confidence = string_field(value, &["confidence"]).and_then(normalize_warden_confidence);
    let mut description = description;
    if let Some(recommendation) = string_field(value, &["recommendation", "fix"]) {
        let recommendation = recommendation.trim();
        if !recommendation.is_empty() {
            description.push_str("\n\nRecommendation: ");
            description.push_str(recommendation);
        }
    }
    let verification = string_field(value, &["verification", "evidence"])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let location = normalize_raw_location(value, &result.target_path);
    if let Some(location) = &location
        && (location.start_line < result.chunk_start_line as u64
            || location.start_line > result.chunk_end_line as u64)
    {
        return None;
    }
    let additional_locations = normalize_raw_additional_locations(value, &result.target_path);
    let seed = format!(
        "{}:{}:{}:{}:{}",
        result.sha,
        result.target_path,
        finding_index,
        title,
        location
            .as_ref()
            .map(|loc| loc.start_line.to_string())
            .unwrap_or_default()
    );
    let id = unique_warden_finding_id(&seed, used_ids);
    Some(WardenFinding {
        id,
        severity,
        confidence,
        title,
        description,
        verification,
        location,
        additional_locations,
        elapsed_ms: Some(result.duration_ms as f64),
    })
}

fn string_field<'a>(value: &'a serde_json::Value, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| value.get(*name)?.as_str())
}

fn normalize_warden_severity(raw: &str) -> Option<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" | "high" => Some("high".to_string()),
        "medium" => Some("medium".to_string()),
        "info" | "low" => Some("low".to_string()),
        _ => None,
    }
}

fn normalize_warden_confidence(raw: &str) -> Option<String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "high" => Some("high".to_string()),
        "medium" => Some("medium".to_string()),
        "low" => Some("low".to_string()),
        _ => None,
    }
}

fn normalize_raw_location(value: &serde_json::Value, target_path: &str) -> Option<WardenLocation> {
    let start_line = finding_start_line(value)?;
    let end_line = value
        .get("end_line")
        .or_else(|| value.get("endLine"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            value
                .get("location")
                .and_then(|location| location.get("endLine").or_else(|| location.get("end_line")))
                .and_then(|v| v.as_u64())
        });
    Some(WardenLocation {
        path: target_path.to_string(),
        start_line,
        end_line: end_line.filter(|end| *end >= start_line),
    })
}

fn normalize_raw_additional_locations(
    value: &serde_json::Value,
    target_path: &str,
) -> Option<Vec<WardenLocation>> {
    let raw_locations = value
        .get("additionalLocations")
        .or_else(|| value.get("additional_locations"))
        .and_then(|v| v.as_array())?;
    let locations = raw_locations
        .iter()
        .filter_map(|value| {
            let start_line = value
                .get("startLine")
                .or_else(|| value.get("start_line"))
                .and_then(|v| v.as_u64())?;
            let path = value
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or(target_path)
                .to_string();
            let end_line = value
                .get("endLine")
                .or_else(|| value.get("end_line"))
                .and_then(|v| v.as_u64())
                .filter(|end| *end >= start_line);
            Some(WardenLocation {
                path,
                start_line,
                end_line,
            })
        })
        .collect::<Vec<_>>();
    (!locations.is_empty()).then_some(locations)
}

fn unique_warden_finding_id(seed: &str, used_ids: &mut BTreeSet<String>) -> String {
    for attempt in 0..1000u64 {
        let candidate = warden_finding_id_from_seed(&format!("{seed}:{attempt}"));
        if used_ids.insert(candidate.clone()) {
            return candidate;
        }
    }
    let fallback = format!("LSH-{:03}", used_ids.len() + 1);
    used_ids.insert(fallback.clone());
    fallback
}

fn warden_finding_id_from_seed(seed: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in seed.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let mut raw = String::new();
    for round in 0..6 {
        let index = (hash % WARDEN_FINDING_ID_ALPHABET.len() as u64) as usize;
        raw.push(WARDEN_FINDING_ID_ALPHABET[index] as char);
        hash = hash.rotate_left(11) ^ (round as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15);
    }
    format!("{}-{}", &raw[..3], &raw[3..])
}

fn deduplicate_with_upstream_warden(
    findings: Vec<PostProcessFinding>,
) -> Result<(Vec<PostProcessFinding>, Vec<FindingProcessingEventJson>)> {
    let output = run_upstream_warden_bridge(serde_json::json!({
        "mode": "deduplicateFindings",
        "findings": findings.iter().map(|finding| &finding.finding).collect::<Vec<_>>(),
    }))
    .with_context(|| "run upstream Warden deduplicateFindings")?;
    let response: UpstreamDedupResponse =
        serde_json::from_value(output).with_context(|| "parse upstream Warden dedupe response")?;
    let mut kept = Vec::with_capacity(response.kept_indices.len());
    for index in response.kept_indices {
        let finding = findings.get(index).cloned().ok_or_else(|| {
            anyhow::anyhow!("upstream Warden dedupe returned invalid kept index {index}")
        })?;
        kept.push(finding);
    }
    let mut events = Vec::new();
    for event in response.events {
        let finding = findings.get(event.finding_index).ok_or_else(|| {
            anyhow::anyhow!(
                "upstream Warden dedupe returned invalid event finding index {}",
                event.finding_index
            )
        })?;
        let replacement = event
            .replacement_index
            .and_then(|index| findings.get(index))
            .map(|finding| finding.finding.clone());
        events.push(FindingProcessingEventJson {
            stage: event.stage,
            action: event.action,
            finding: finding.finding.clone(),
            reason: event.reason,
            replacement,
        });
    }
    Ok((kept, events))
}

fn build_verification_prompt(finding: &WardenFinding) -> Result<String> {
    Ok(format!(
        concat!(
            "<role>\n",
            "You are Warden's finding verifier. You validate one candidate finding at a time.\n",
            "Your job is to deeply trace the code, look for mitigations and intent, then keep, revise, or reject the candidate.\n",
            "</role>\n\n",
            "<tools>\n",
            "Use read-only repository tools to inspect the checkout. Read the reported file and use grep/glob to trace callers, imports, wrappers, guards, validators, and related code.\n",
            "</tools>\n\n",
            "<repository>\n",
            "The current working directory is the Sentry checkout being verified. Candidate location paths are relative to this checkout.\n",
            "</repository>\n\n",
            "<skill_instructions>\n",
            "The candidate was produced for this skill. Use these criteria as the only scope for verification:\n\n",
            "{skill}\n",
            "</skill_instructions>\n\n",
            "<verification_stance>\n",
            "- Keep findings only when the issue is still real after tracing.\n",
            "- Revise findings when the issue is real but the severity, confidence, title, description, or evidence trace needs a narrower scope.\n",
            "- Reject findings when the path is mitigated, unreachable, intentional, outside skill scope, or lacks a concrete code-level violation of the skill criteria.\n",
            "- Do not reject solely because broader repository invariants or caller behavior are incomplete in the inspected context. If the changed code shows a concrete source, boundary, and sink with no verified mitigation, keep or revise the finding.\n",
            "- When reachability or impact is plausible but not fully proven, keep the finding and revise severity, confidence, or scope instead of rejecting it.\n",
            "</verification_stance>\n\n",
            "<evidence>\n",
            "For revised findings, write the `verification` field as evidence for the public Evidence block: 2-5 short Markdown bullets tracing the concrete code path, guard, condition, or behavior that makes the finding real. Use function/file names when useful. Do not use checklist labels, generic reasoning, or restate the description.\n",
            "</evidence>\n\n",
            "<candidate_finding>\n",
            "{finding}\n",
            "</candidate_finding>\n\n",
            "<task>\n",
            "Verify this candidate. Return keep, revise, or reject.\n",
            "</task>\n\n",
            "<output_format>\n",
            "Return only valid JSON. Do not include markdown, prose, code fences, or explanations.\n\n",
            "{{\"verdict\":\"keep|revise|reject\",\"finding\":{{...}},\"reason\":\"short reason\"}}\n\n",
            "Use \"finding\" only for verdict \"revise\". For revised findings, return the complete Warden finding object and keep the original id.\n",
            "</output_format>"
        ),
        skill = SECURITY_REVIEW_PROMPT,
        finding = serde_json::to_string_pretty(finding)?,
    ))
}

fn verification_response_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["verdict", "finding", "reason"],
        "properties": {
            "verdict": { "type": "string", "enum": ["keep", "revise", "reject"] },
            "finding": {
                "anyOf": [
                    warden_finding_json_schema(),
                    { "type": "null" }
                ]
            },
            "reason": { "type": "string" }
        }
    })
}

fn warden_finding_json_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": true,
        "required": ["id", "severity", "title", "description"],
        "properties": {
            "id": { "type": "string" },
            "severity": { "type": "string", "enum": ["high", "medium", "low"] },
            "confidence": { "type": "string", "enum": ["high", "medium", "low"] },
            "title": { "type": "string" },
            "description": { "type": "string" },
            "verification": { "type": "string" },
            "location": {
                "type": "object",
                "additionalProperties": false,
                "required": ["path", "startLine"],
                "properties": {
                    "path": { "type": "string" },
                    "startLine": { "type": "integer", "minimum": 1 },
                    "endLine": { "type": "integer", "minimum": 1 }
                }
            },
            "additionalLocations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["path", "startLine"],
                    "properties": {
                        "path": { "type": "string" },
                        "startLine": { "type": "integer", "minimum": 1 },
                        "endLine": { "type": "integer", "minimum": 1 }
                    }
                }
            },
            "elapsedMs": { "type": "number", "minimum": 0 }
        }
    })
}

fn parse_verification_response(text: &str) -> Option<VerificationVerdict> {
    serde_json::from_str::<VerificationVerdict>(text.trim())
        .ok()
        .or_else(|| {
            parse_assistant_json(text)
                .and_then(|value| serde_json::from_value::<VerificationVerdict>(value).ok())
        })
}

fn apply_verification_verdict(
    original: &WardenFinding,
    verdict: Option<&VerificationVerdict>,
) -> Option<WardenFinding> {
    let Some(verdict) = verdict else {
        return Some(original.clone());
    };
    match verdict.verdict.trim().to_ascii_lowercase().as_str() {
        "keep" => Some(original.clone()),
        "reject" => None,
        "revise" => {
            let Some(mut revised) = verdict.finding.clone() else {
                return Some(original.clone());
            };
            revised.id = original.id.clone();
            revised.location = original.location.clone();
            revised.additional_locations = original.additional_locations.clone();
            revised.elapsed_ms = original.elapsed_ms;
            if is_valid_warden_finding(&revised) {
                Some(revised)
            } else {
                Some(original.clone())
            }
        }
        _ => Some(original.clone()),
    }
}

fn is_valid_warden_finding(finding: &WardenFinding) -> bool {
    matches!(finding.severity.as_str(), "high" | "medium" | "low")
        && finding
            .confidence
            .as_deref()
            .map(|confidence| matches!(confidence, "high" | "medium" | "low"))
            .unwrap_or(true)
        && !finding.id.trim().is_empty()
        && !finding.title.trim().is_empty()
        && !finding.description.trim().is_empty()
}

fn build_merge_prompt(findings: &[PostProcessFinding], repo_dir: &Path) -> Result<String> {
    let mut indexed = Vec::new();
    for (index, finding) in findings.iter().enumerate() {
        let loc = finding.finding.location.as_ref();
        let snippet = loc
            .map(|loc| read_repo_snippet(repo_dir, &loc.path, loc.start_line, 3))
            .unwrap_or_default();
        let location = loc
            .map(format_merge_location)
            .unwrap_or_else(|| "general".to_string());
        let mut text = format!(
            "{}. [{}] \"{}\" - {}",
            index + 1,
            location,
            finding.finding.title,
            finding.finding.description
        );
        if !snippet.is_empty() {
            text.push_str("\n   Code: ");
            text.push_str(&snippet.split('\n').collect::<Vec<_>>().join("\n   "));
        }
        indexed.push(text);
    }
    Ok(format!(
        concat!(
            "<task>\n",
            "Identify which of these code review findings describe the SAME underlying issue appearing at different locations. Group them by shared root cause.\n",
            "</task>\n\n",
            "<findings>\n",
            "{}\n",
            "</findings>\n\n",
            "<output_format>\n",
            "Return only valid JSON. Do not include markdown, prose, code fences, or explanations.\n\n",
            "Return a JSON array of arrays, where each inner array contains the 1-based indices of findings about the same issue.\n",
            "Singletons should not appear. Return [] if no findings describe the same issue.\n",
            "</output_format>"
        ),
        indexed.join("\n")
    ))
}

fn build_merge_request(args: &Args, model: &str, prompt: String) -> DirectRequest {
    let schema = DirectJsonSchema {
        name: "warden_cross_location_merge".to_string(),
        schema: merge_groups_response_schema().into(),
        strict: true,
    };
    let mut request = DirectRequest::json_schema(model.to_string(), prompt, schema);
    request.model_variant = args.variant.clone();
    let _ = args.post_process_max_output_tokens;
    request
}

fn merge_groups_response_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "array",
        "items": {
            "type": "array",
            "items": { "type": "integer", "minimum": 1 }
        }
    })
}

fn parse_merge_groups_response(text: &str) -> Option<Vec<Vec<usize>>> {
    serde_json::from_str::<Vec<Vec<usize>>>(text.trim())
        .ok()
        .or_else(|| parse_assistant_json(text).and_then(|value| serde_json::from_value(value).ok()))
}

fn apply_merge_groups_with_upstream_warden(
    findings: Vec<PostProcessFinding>,
    located_original_indices: &[usize],
    groups: &[Vec<usize>],
) -> Result<(
    Vec<PostProcessFinding>,
    Vec<FindingProcessingEventJson>,
    usize,
    serde_json::Value,
)> {
    let located_findings = located_original_indices
        .iter()
        .map(|index| &findings[*index].finding)
        .collect::<Vec<_>>();
    let output = run_upstream_warden_bridge(serde_json::json!({
        "mode": "applyMergeGroups",
        "findings": located_findings,
        "groups": groups,
    }))
    .with_context(|| "run upstream Warden applyMergeGroups")?;
    let response: UpstreamApplyMergeGroupsResponse = serde_json::from_value(output.clone())
        .with_context(|| "parse upstream Warden applyMergeGroups response")?;

    let mut absorbed_original_indices = BTreeSet::new();
    let mut events = Vec::new();
    for absorbed in response.absorbed {
        let original_index = *located_original_indices
            .get(absorbed.index)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "upstream Warden applyMergeGroups returned invalid absorbed index {}",
                    absorbed.index
                )
            })?;
        absorbed_original_indices.insert(original_index);
        events.push(FindingProcessingEventJson {
            stage: "merge".to_string(),
            action: "merged".to_string(),
            finding: findings[original_index].finding.clone(),
            reason: Some("same root cause at another location".to_string()),
            replacement: absorbed.replacement,
        });
    }

    let mut replacements = BTreeMap::new();
    for replacement in response.replacements {
        let original_index = *located_original_indices
            .get(replacement.index)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "upstream Warden applyMergeGroups returned invalid replacement index {}",
                    replacement.index
                )
            })?;
        replacements.insert(original_index, replacement.finding);
    }

    let absorbed_count = absorbed_original_indices.len();
    let merged = findings
        .into_iter()
        .enumerate()
        .filter_map(|(index, finding)| {
            if absorbed_original_indices.contains(&index) {
                None
            } else {
                let finding = replacements
                    .remove(&index)
                    .map(|replacement| PostProcessFinding {
                        finding: replacement,
                        origin: finding.origin.clone(),
                    })
                    .unwrap_or(finding);
                Some(finding)
            }
        })
        .collect::<Vec<_>>();
    Ok((merged, events, absorbed_count, output))
}

fn compare_post_finding_for_output(a: &PostProcessFinding, b: &PostProcessFinding) -> Ordering {
    a.origin
        .sha
        .cmp(&b.origin.sha)
        .then(a.origin.target_path.cmp(&b.origin.target_path))
        .then(finding_line(&a.finding).cmp(&finding_line(&b.finding)))
        .then(a.origin.finding_index.cmp(&b.origin.finding_index))
}

fn finding_line(finding: &WardenFinding) -> u64 {
    finding
        .location
        .as_ref()
        .map(|loc| loc.end_line.unwrap_or(loc.start_line))
        .unwrap_or(0)
}

#[cfg(test)]
fn format_location(location: &WardenLocation) -> String {
    match location.end_line {
        Some(end_line) if end_line != location.start_line => {
            format!("{}:{}-{}", location.path, location.start_line, end_line)
        }
        _ => format!("{}:{}", location.path, location.start_line),
    }
}

fn format_merge_location(location: &WardenLocation) -> String {
    match location.end_line {
        Some(end_line) => format!("{}:{}-{}", location.path, location.start_line, end_line),
        None => format!("{}:{}", location.path, finding_line_from_location(location)),
    }
}

fn finding_line_from_location(location: &WardenLocation) -> u64 {
    location.end_line.unwrap_or(location.start_line)
}

fn read_repo_snippet(
    repo_dir: &Path,
    file_path: &str,
    start_line: u64,
    context_lines: usize,
) -> String {
    let full_path = repo_dir.join(file_path);
    let Ok(content) = fs::read_to_string(&full_path) else {
        return String::new();
    };
    let lines = content.split('\n').collect::<Vec<_>>();
    let start = start_line
        .saturating_sub(1)
        .saturating_sub(context_lines as u64) as usize;
    let end = (start_line as usize + context_lines).min(lines.len());
    if start >= end {
        return String::new();
    }
    lines[start..end].join("\n")
}

fn usage_stats_from_response(args: &Args, response: &LlmResponse) -> WardenUsageStats {
    let input = response.usage.input_tokens.max(0) as u64;
    let output = response.usage.output_tokens.max(0) as u64;
    let cache_read = response.usage.cache_read_input_tokens.max(0) as u64;
    let reasoning = response.usage.reasoning_output_tokens.max(0) as u64;
    let tokens = TokenTotals {
        input,
        output,
        reasoning,
        cache: cache_read,
        cache_read,
        cache_creation: 0,
        non_cache_input: input.saturating_sub(cache_read),
        provider_total: input + output,
    };
    usage_stats_from_token_totals(args, &tokens)
}

fn usage_stats_from_token_totals(args: &Args, tokens: &TokenTotals) -> WardenUsageStats {
    let cost = PricingConfig::from_args(args).estimate(tokens);
    WardenUsageStats {
        input_tokens: tokens.input,
        output_tokens: tokens.output,
        cached_input_tokens: (tokens.cache_read > 0).then_some(tokens.cache_read),
        cache_creation_input_tokens: (tokens.cache_creation > 0).then_some(tokens.cache_creation),
        cache_creation_5m_input_tokens: None,
        cache_creation_1h_input_tokens: None,
        web_search_requests: None,
        cost_usd: cost.total_usd.unwrap_or(0.0),
    }
}

fn usage_stats_from_task_result(result: &TaskResult) -> WardenUsageStats {
    WardenUsageStats {
        input_tokens: result.input_tokens,
        output_tokens: result.output_tokens,
        cached_input_tokens: (result.cached_input_tokens > 0).then_some(result.cached_input_tokens),
        cache_creation_input_tokens: (result.cache_creation_input_tokens > 0)
            .then_some(result.cache_creation_input_tokens),
        cache_creation_5m_input_tokens: None,
        cache_creation_1h_input_tokens: None,
        web_search_requests: None,
        cost_usd: result.analysis_cost_usd.unwrap_or(0.0),
    }
}

fn usage_stats_have_value(usage: &WardenUsageStats) -> bool {
    usage.input_tokens > 0
        || usage.output_tokens > 0
        || usage.cached_input_tokens.unwrap_or(0) > 0
        || usage.cache_creation_input_tokens.unwrap_or(0) > 0
        || usage.cache_creation_5m_input_tokens.unwrap_or(0) > 0
        || usage.cache_creation_1h_input_tokens.unwrap_or(0) > 0
        || usage.web_search_requests.unwrap_or(0) > 0
        || usage.cost_usd > 0.0
}

fn add_warden_usage(a: &mut WardenUsageStats, b: &WardenUsageStats) {
    a.input_tokens += b.input_tokens;
    a.output_tokens += b.output_tokens;
    a.cost_usd = round_usd(a.cost_usd + b.cost_usd);
    if a.cached_input_tokens.is_some() || b.cached_input_tokens.is_some() {
        a.cached_input_tokens =
            Some(a.cached_input_tokens.unwrap_or(0) + b.cached_input_tokens.unwrap_or(0));
    }
    if a.cache_creation_input_tokens.is_some() || b.cache_creation_input_tokens.is_some() {
        a.cache_creation_input_tokens = Some(
            a.cache_creation_input_tokens.unwrap_or(0) + b.cache_creation_input_tokens.unwrap_or(0),
        );
    }
    if a.cache_creation_5m_input_tokens.is_some() || b.cache_creation_5m_input_tokens.is_some() {
        a.cache_creation_5m_input_tokens = Some(
            a.cache_creation_5m_input_tokens.unwrap_or(0)
                + b.cache_creation_5m_input_tokens.unwrap_or(0),
        );
    }
    if a.cache_creation_1h_input_tokens.is_some() || b.cache_creation_1h_input_tokens.is_some() {
        a.cache_creation_1h_input_tokens = Some(
            a.cache_creation_1h_input_tokens.unwrap_or(0)
                + b.cache_creation_1h_input_tokens.unwrap_or(0),
        );
    }
    if a.web_search_requests.is_some() || b.web_search_requests.is_some() {
        a.web_search_requests =
            Some(a.web_search_requests.unwrap_or(0) + b.web_search_requests.unwrap_or(0));
    }
}

fn aggregate_auxiliary_usage(
    entries: &[AuxiliaryUsageEntry],
) -> BTreeMap<String, WardenUsageStats> {
    let mut map = BTreeMap::<String, WardenUsageStats>::new();
    for entry in entries {
        let target = map.entry(entry.agent.clone()).or_default();
        add_warden_usage(target, &entry.usage);
    }
    map.retain(|_, usage| usage_stats_have_value(usage));
    map
}

fn aggregate_auxiliary_usage_attribution(
    entries: &[AuxiliaryUsageEntry],
) -> BTreeMap<String, serde_json::Value> {
    let mut by_agent: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for entry in entries {
        let (models, runtimes) = by_agent.entry(entry.agent.clone()).or_default();
        if let Some(model) = &entry.model {
            models.insert(model.clone());
        }
        if let Some(runtime) = &entry.runtime {
            runtimes.insert(runtime.clone());
        }
    }
    by_agent
        .into_iter()
        .filter_map(|(agent, (models, runtimes))| {
            let mut value = serde_json::Map::new();
            insert_attribution_values(&mut value, "model", "models", models);
            insert_attribution_values(&mut value, "runtime", "runtimes", runtimes);
            (!value.is_empty()).then_some((agent, serde_json::Value::Object(value)))
        })
        .collect()
}

fn insert_attribution_values(
    value: &mut serde_json::Map<String, serde_json::Value>,
    single_key: &str,
    plural_key: &str,
    values: BTreeSet<String>,
) {
    match values.len() {
        0 => {}
        1 => {
            value.insert(
                single_key.to_string(),
                serde_json::Value::String(values.into_iter().next().unwrap_or_default()),
            );
        }
        _ => {
            value.insert(
                plural_key.to_string(),
                serde_json::Value::Array(
                    values
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect::<Vec<_>>(),
                ),
            );
        }
    }
}

fn build_warden_usage_breakdown(
    scan: Option<WardenUsageStats>,
    auxiliary: BTreeMap<String, WardenUsageStats>,
    scan_model: Option<&str>,
    scan_runtime: Option<&str>,
    auxiliary_attribution: BTreeMap<String, serde_json::Value>,
) -> Option<WardenUsageBreakdown> {
    let scan_entry = scan
        .filter(usage_stats_have_value)
        .map(|usage| WardenUsageBreakdownEntry {
            usage,
            model: scan_model.map(str::to_string),
            models: None,
            runtime: scan_runtime.map(str::to_string),
            runtimes: None,
        });
    let auxiliary_entries = auxiliary
        .into_iter()
        .filter(|(_, usage)| usage_stats_have_value(usage))
        .map(|(agent, usage)| {
            let attribution = auxiliary_attribution.get(&agent);
            (
                agent,
                WardenUsageBreakdownEntry {
                    usage,
                    model: attribution
                        .and_then(|value| value.get("model"))
                        .and_then(|value| value.as_str())
                        .map(str::to_string),
                    models: attribution
                        .and_then(|value| value.get("models"))
                        .and_then(|value| value.as_array())
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|value| value.as_str().map(str::to_string))
                                .collect::<Vec<_>>()
                        })
                        .filter(|values| !values.is_empty()),
                    runtime: attribution
                        .and_then(|value| value.get("runtime"))
                        .and_then(|value| value.as_str())
                        .map(str::to_string),
                    runtimes: attribution
                        .and_then(|value| value.get("runtimes"))
                        .and_then(|value| value.as_array())
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|value| value.as_str().map(str::to_string))
                                .collect::<Vec<_>>()
                        })
                        .filter(|values| !values.is_empty()),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    if scan_entry.is_none() && auxiliary_entries.is_empty() {
        return None;
    }

    let mut total_usage = WardenUsageStats::default();
    if let Some(scan) = &scan_entry {
        add_warden_usage(&mut total_usage, &scan.usage);
    }
    for entry in auxiliary_entries.values() {
        add_warden_usage(&mut total_usage, &entry.usage);
    }
    let mut models = BTreeSet::new();
    let mut runtimes = BTreeSet::new();
    collect_breakdown_attribution(scan_entry.as_ref(), &mut models, &mut runtimes);
    for entry in auxiliary_entries.values() {
        collect_breakdown_attribution(Some(entry), &mut models, &mut runtimes);
    }
    Some(WardenUsageBreakdown {
        scan: scan_entry,
        auxiliary: (!auxiliary_entries.is_empty()).then_some(auxiliary_entries),
        total: WardenUsageBreakdownEntry {
            usage: total_usage,
            model: (models.len() == 1).then(|| models.iter().next().cloned().unwrap_or_default()),
            models: (models.len() > 1).then(|| models.iter().cloned().collect()),
            runtime: (runtimes.len() == 1)
                .then(|| runtimes.iter().next().cloned().unwrap_or_default()),
            runtimes: (runtimes.len() > 1).then(|| runtimes.iter().cloned().collect()),
        },
    })
}

fn collect_breakdown_attribution(
    entry: Option<&WardenUsageBreakdownEntry>,
    models: &mut BTreeSet<String>,
    runtimes: &mut BTreeSet<String>,
) {
    if let Some(entry) = entry {
        if let Some(model) = &entry.model {
            models.insert(model.clone());
        }
        for model in entry.models.clone().unwrap_or_default() {
            models.insert(model);
        }
        if let Some(runtime) = &entry.runtime {
            runtimes.insert(runtime.clone());
        }
        for runtime in entry.runtimes.clone().unwrap_or_default() {
            runtimes.insert(runtime);
        }
    }
}

fn write_warden_final_jsonl(
    path: &Path,
    run_id: &str,
    run_dir: &Path,
    results: &[TaskResult],
    final_findings: &[PostProcessFinding],
    auxiliary_entries: &[AuxiliaryUsageEntry],
    model: &str,
) -> Result<()> {
    let mut chunk_totals: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for result in results {
        *chunk_totals
            .entry((result.sha.as_str(), result.target_path.as_str()))
            .or_insert(0) += 1;
    }
    let mut findings_by_row: BTreeMap<usize, Vec<WardenFinding>> = BTreeMap::new();
    for finding in final_findings {
        findings_by_row
            .entry(finding.origin.row_index)
            .or_default()
            .push(finding.finding.clone());
    }
    for findings in findings_by_row.values_mut() {
        findings.sort_by(|a, b| finding_line(a).cmp(&finding_line(b)).then(a.id.cmp(&b.id)));
    }
    let mut auxiliary_by_row: BTreeMap<usize, Vec<AuxiliaryUsageEntry>> = BTreeMap::new();
    for entry in auxiliary_entries {
        if let Some(row_index) = entry.row_index {
            auxiliary_by_row
                .entry(row_index)
                .or_default()
                .push(entry.clone());
        }
    }
    let mut lines = Vec::new();
    let timestamp = Utc::now().to_rfc3339();
    for (row_index, result) in results.iter().enumerate() {
        let row_auxiliary = auxiliary_by_row.remove(&row_index).unwrap_or_default();
        let auxiliary_usage = aggregate_auxiliary_usage(&row_auxiliary);
        let auxiliary_attribution = aggregate_auxiliary_usage_attribution(&row_auxiliary);
        let usage_breakdown = build_warden_usage_breakdown(
            Some(usage_stats_from_task_result(result)),
            auxiliary_usage,
            Some(model),
            Some("lash"),
            auxiliary_attribution,
        );
        let status = if result.status == "completed" {
            "ok"
        } else {
            "error"
        };
        let record = WardenJsonlChunk {
            schema_version: 1,
            run: WardenRunMetadata {
                timestamp: timestamp.clone(),
                duration_ms: result.duration_ms,
                cwd: run_dir.display().to_string(),
                run_id: run_id.to_string(),
                model: Some(model.to_string()),
                head_sha: Some(result.sha.clone()),
            },
            skill: BENCHMARK_SKILL.to_string(),
            model: Some(model.to_string()),
            chunk: WardenJsonlChunkInfo {
                file: result.target_path.clone(),
                index: result.chunk_index,
                total: *chunk_totals
                    .get(&(result.sha.as_str(), result.target_path.as_str()))
                    .unwrap_or(&1),
                line_range: format!("{}-{}", result.chunk_start_line, result.chunk_end_line),
            },
            status: status.to_string(),
            findings: findings_by_row.remove(&row_index).unwrap_or_default(),
            usage_breakdown,
            duration_ms: result.duration_ms,
            error: (status == "error").then(|| WardenSkillError {
                code: warden_error_code_for_result(result).to_string(),
                message: result
                    .failure_reason
                    .clone()
                    .unwrap_or_else(|| format!("task status {}", result.status)),
                timestamp: Some(result.finished_at.clone()),
            }),
        };
        lines.push(serde_json::to_string(&record)?);
    }

    let total_scan = results
        .iter()
        .fold(WardenUsageStats::default(), |mut acc, result| {
            add_warden_usage(&mut acc, &usage_stats_from_task_result(result));
            acc
        });
    let auxiliary_usage = aggregate_auxiliary_usage(auxiliary_entries);
    let auxiliary_attribution = aggregate_auxiliary_usage_attribution(auxiliary_entries);
    let summary_usage_breakdown = build_warden_usage_breakdown(
        Some(total_scan),
        auxiliary_usage,
        Some(model),
        Some("lash"),
        auxiliary_attribution,
    );
    let selected_shas = results
        .iter()
        .map(|result| result.sha.as_str())
        .collect::<BTreeSet<_>>();
    let duration_ms = summary_duration_ms(run_dir)
        .unwrap_or_else(|| results.iter().map(|result| result.duration_ms).sum::<u64>());
    let failed = results
        .iter()
        .filter(|result| result.status != "completed")
        .count() as u64;
    let summary = WardenJsonlSummary {
        run: WardenRunMetadata {
            timestamp,
            duration_ms,
            cwd: run_dir.display().to_string(),
            run_id: run_id.to_string(),
            model: Some(model.to_string()),
            head_sha: (selected_shas.len() == 1).then(|| {
                selected_shas
                    .iter()
                    .next()
                    .copied()
                    .unwrap_or_default()
                    .to_string()
            }),
        },
        record_type: "summary".to_string(),
        total_findings: final_findings.len(),
        by_severity: count_warden_findings_by_severity(final_findings.iter().map(|f| &f.finding)),
        usage_breakdown: summary_usage_breakdown,
        total_failed_hunks: (failed > 0).then_some(failed),
        total_failed_extractions: None,
    };
    lines.push(serde_json::to_string(&summary)?);
    fs::write(path, lines.join("\n") + "\n")
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn summary_duration_ms(run_dir: &Path) -> Option<u64> {
    let raw = fs::read_to_string(run_dir.join("summary.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    value.get("durationMs").and_then(|value| value.as_u64())
}

fn mark_existing_scoring_non_comparable(run_dir: &Path) -> Result<Vec<String>> {
    let stale_at = Utc::now().to_rfc3339();
    let scoring_source = run_dir.join(SEMANTIC_SCORING_ARTIFACT);
    let mut stale_artifacts = BTreeSet::new();
    let mut stale_class = RAW_PRE_FINALIZATION_STALE_CLASS.to_string();
    if scoring_source.exists() {
        stale_class = classify_scoring_stale_class(&scoring_source);
        let target_name =
            unique_artifact_name(run_dir, &format!("semantic-scoring.{stale_class}.json"));
        let target = run_dir.join(&target_name);
        fs::rename(&scoring_source, &target).with_context(|| {
            format!(
                "rename {} -> {}",
                scoring_source.display(),
                target.display()
            )
        })?;
        rewrite_stale_scoring_json(&target, &stale_class, &stale_at)?;
        stale_artifacts.insert(target_name);
    }

    let summary_source = run_dir.join(SEMANTIC_SCORING_SUMMARY_ARTIFACT);
    if summary_source.exists() {
        let target_name = unique_artifact_name(
            run_dir,
            &format!("semantic-scoring-summary.{stale_class}.md"),
        );
        let target = run_dir.join(&target_name);
        fs::rename(&summary_source, &target).with_context(|| {
            format!(
                "rename {} -> {}",
                summary_source.display(),
                target.display()
            )
        })?;
        rewrite_stale_scoring_markdown(&target, &stale_class, &stale_at)?;
        stale_artifacts.insert(target_name);
    }

    normalize_existing_stale_scoring_artifacts(run_dir, &stale_at, &mut stale_artifacts)?;
    Ok(stale_artifacts.into_iter().collect())
}

fn classify_scoring_stale_class(path: &Path) -> String {
    if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
        if let Some(class) = stale_class_from_artifact_name(name) {
            return class.to_string();
        }
    }
    let scoring = fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
    let input_state = scoring
        .as_ref()
        .and_then(|value| json_str(value, &["scoring", "inputState"]));
    let input_artifact = scoring
        .as_ref()
        .and_then(|value| json_str(value, &["scoring", "inputArtifact"]));
    if input_state == Some("finalized") || input_artifact == Some(WARDEN_FINAL_JSONL_ARTIFACT) {
        STALE_FINALIZED_PRE_REPROCESS_CLASS.to_string()
    } else {
        RAW_PRE_FINALIZATION_STALE_CLASS.to_string()
    }
}

fn stale_class_from_artifact_name(name: &str) -> Option<&'static str> {
    if name.contains(RAW_PRE_FINALIZATION_STALE_CLASS) {
        Some(RAW_PRE_FINALIZATION_STALE_CLASS)
    } else if name.contains(STALE_FINALIZED_PRE_REPROCESS_CLASS) {
        Some(STALE_FINALIZED_PRE_REPROCESS_CLASS)
    } else {
        None
    }
}

fn unique_artifact_name(run_dir: &Path, preferred: &str) -> String {
    if !run_dir.join(preferred).exists() {
        return preferred.to_string();
    }
    let Some(dot) = preferred.rfind('.') else {
        for index in 2.. {
            let candidate = format!("{preferred}-{index}");
            if !run_dir.join(&candidate).exists() {
                return candidate;
            }
        }
        unreachable!();
    };
    let (stem, extension) = preferred.split_at(dot);
    for index in 2.. {
        let candidate = format!("{stem}-{index}{extension}");
        if !run_dir.join(&candidate).exists() {
            return candidate;
        }
    }
    unreachable!();
}

fn normalize_existing_stale_scoring_artifacts(
    run_dir: &Path,
    stale_at: &str,
    stale_artifacts: &mut BTreeSet<String>,
) -> Result<()> {
    for entry in fs::read_dir(run_dir).with_context(|| format!("read {}", run_dir.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", run_dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name == SEMANTIC_SCORING_ARTIFACT || name == SEMANTIC_SCORING_SUMMARY_ARTIFACT {
            continue;
        }
        if name.starts_with("semantic-scoring.") && name.ends_with(".json") && name.contains("pre-")
        {
            let class = classify_scoring_stale_class(&path);
            rewrite_stale_scoring_json(&path, &class, stale_at)?;
            stale_artifacts.insert(name.to_string());
        } else if name.starts_with("semantic-scoring-summary.")
            && name.ends_with(".md")
            && name.contains("pre-")
        {
            let class =
                stale_class_from_artifact_name(name).unwrap_or(RAW_PRE_FINALIZATION_STALE_CLASS);
            rewrite_stale_scoring_markdown(&path, class, stale_at)?;
            stale_artifacts.insert(name.to_string());
        }
    }
    Ok(())
}

fn rewrite_stale_scoring_json(path: &Path, stale_class: &str, stale_at: &str) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    let Some(root) = value.as_object_mut() else {
        return Ok(());
    };
    let scoring = root
        .entry("scoring".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let Some(scoring_obj) = scoring.as_object_mut() else {
        return Ok(());
    };
    let already_stale =
        scoring_obj.get("status").and_then(|value| value.as_str()) == Some("stale_non_comparable");

    let mut previous_status = if already_stale {
        scoring_obj
            .get("previousStatus")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    } else {
        scoring_obj
            .get("status")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    let mut previous_input_state = if already_stale {
        scoring_obj
            .get("previousInputState")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    } else {
        scoring_obj
            .get("inputState")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    let mut previous_input_artifact = if already_stale {
        scoring_obj
            .get("previousInputArtifact")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    } else {
        scoring_obj
            .get("inputArtifact")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    let mut previous_warden_comparable = if already_stale {
        scoring_obj
            .get("previousWardenComparable")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    } else {
        scoring_obj
            .get("wardenComparable")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };

    let stale_reason = if stale_class == RAW_PRE_FINALIZATION_STALE_CLASS {
        previous_input_state = serde_json::Value::String("raw".to_string());
        previous_input_artifact = serde_json::Value::String(RAW_PREDICTIONS_ARTIFACT.to_string());
        previous_warden_comparable = serde_json::Value::Bool(false);
        "Score was produced before Warden post-processing finalized the run; it is not upstream-comparable."
    } else {
        if previous_input_state.is_null()
            || previous_input_state.as_str() == Some("stale")
            || previous_input_state.as_str() == Some("raw")
        {
            previous_input_state = serde_json::Value::String("finalized".to_string());
        }
        if previous_input_artifact.is_null()
            || previous_input_artifact.as_str() == Some(RAW_PREDICTIONS_ARTIFACT)
        {
            previous_input_artifact =
                serde_json::Value::String(WARDEN_FINAL_JSONL_ARTIFACT.to_string());
        }
        "Post-processing was rerun after this score was produced; score input no longer names the current finalized artifact."
    };
    if previous_status.is_null() {
        previous_status = serde_json::Value::String("unknown".to_string());
    }

    scoring_obj.insert(
        "status".to_string(),
        serde_json::Value::String("stale_non_comparable".to_string()),
    );
    scoring_obj.insert("stale".to_string(), serde_json::Value::Bool(true));
    scoring_obj.insert("nonComparable".to_string(), serde_json::Value::Bool(true));
    scoring_obj.insert(
        "staleClass".to_string(),
        serde_json::Value::String(stale_class.to_string()),
    );
    scoring_obj.insert(
        "staleAt".to_string(),
        serde_json::Value::String(stale_at.to_string()),
    );
    scoring_obj.insert(
        "staleReason".to_string(),
        serde_json::Value::String(stale_reason.to_string()),
    );
    scoring_obj.insert("previousStatus".to_string(), previous_status);
    scoring_obj.insert("previousInputState".to_string(), previous_input_state);
    scoring_obj.insert("previousInputArtifact".to_string(), previous_input_artifact);
    scoring_obj.insert(
        "previousWardenComparable".to_string(),
        previous_warden_comparable,
    );
    scoring_obj.insert(
        "inputState".to_string(),
        serde_json::Value::String("stale".to_string()),
    );
    scoring_obj.insert("inputArtifact".to_string(), serde_json::Value::Null);
    scoring_obj.insert(
        "wardenComparable".to_string(),
        serde_json::Value::Bool(false),
    );
    scoring_obj.insert(
        "supersededBy".to_string(),
        serde_json::Value::String(WARDEN_FINAL_JSONL_ARTIFACT.to_string()),
    );
    fs::write(path, serde_json::to_string_pretty(&value)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn rewrite_stale_scoring_markdown(path: &Path, stale_class: &str, stale_at: &str) -> Result<()> {
    let raw = fs::read_to_string(path).unwrap_or_default();
    let marker = format!(
        "<!-- warden-sentry-stale-score staleClass=\"{stale_class}\" staleAt=\"{stale_at}\" nonComparable=\"true\" -->"
    );
    if raw.starts_with("<!-- warden-sentry-stale-score") {
        let rest = raw.split_once('\n').map(|(_, rest)| rest).unwrap_or("");
        fs::write(path, format!("{marker}\n{rest}"))
            .with_context(|| format!("write {}", path.display()))?;
        return Ok(());
    }
    let note = format!(
        "{marker}\n\n> Stale non-comparable score artifact retained for audit. Post-processing was rerun after this score was produced.\n\n"
    );
    fs::write(path, format!("{note}{raw}")).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn write_upstream_bridge_probe(run_dir: &Path) -> Result<serde_json::Value> {
    let probe = upstream_bridge_probe();
    let path = run_dir.join(UPSTREAM_BRIDGE_PROBE_ARTIFACT);
    fs::write(&path, serde_json::to_string_pretty(&probe)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(probe)
}

fn upstream_bridge_probe() -> serde_json::Value {
    run_upstream_bridge_probe_process().unwrap_or_else(|| upstream_bridge_probe_direct())
}

fn run_upstream_bridge_probe_process() -> Option<serde_json::Value> {
    let node = command_path("node")?;
    let script_path = std::env::temp_dir().join(format!(
        "warden-sentry-upstream-bridge-probe-{}.mjs",
        std::process::id()
    ));
    let script = r#"
import fs from 'node:fs';
import path from 'node:path';

const refRoot = '/tmp/ref-warden';
const packageRoot = path.join(refRoot, 'packages/warden');
const srcRoot = path.join(packageRoot, 'src');
const localTsx = path.join(refRoot, 'node_modules/.bin/tsx');
const nodeModules = path.join(refRoot, 'node_modules');
const wardenDist = path.join(packageRoot, 'dist/index.js');
const wardenDiffCoalesce = path.join(packageRoot, 'dist/diff/coalesce.js');
const wardenDiffParser = path.join(packageRoot, 'dist/diff/parser.js');
const wardenSdkExtract = path.join(packageRoot, 'dist/sdk/extract.js');
const result = {
  checkedAt: new Date().toISOString(),
  refRoot,
  packageRoot,
  node: process.version,
  srcExists: fs.existsSync(srcRoot),
  packageJsonExists: fs.existsSync(path.join(packageRoot, 'package.json')),
  nodeModulesExists: fs.existsSync(nodeModules),
  localTsxExists: fs.existsSync(localTsx),
  wardenDistExists: fs.existsSync(wardenDist),
  wardenDiffCoalesceExists: fs.existsSync(wardenDiffCoalesce),
  wardenDiffParserExists: fs.existsSync(wardenDiffParser),
  wardenSdkExtractExists: fs.existsSync(wardenSdkExtract),
  canExecuteTypeScript: false,
  blocker: null,
};
if (!result.srcExists || !result.packageJsonExists) {
  result.blocker = 'missing upstream Warden source checkout at /tmp/ref-warden/packages/warden';
} else if (!result.nodeModulesExists) {
  result.blocker = 'missing /tmp/ref-warden/node_modules; refusing package-manager install in Rust harness tests';
} else if (!result.localTsxExists) {
  result.blocker = 'missing local tsx binary in /tmp/ref-warden/node_modules/.bin/tsx';
} else if (!result.wardenDistExists) {
  result.blocker = 'missing built upstream Warden dist at /tmp/ref-warden/packages/warden/dist/index.js';
} else if (!result.wardenDiffCoalesceExists || !result.wardenDiffParserExists || !result.wardenSdkExtractExists) {
  result.blocker = 'missing required upstream Warden dist modules for chunking/post-processing bridge';
} else {
  result.canExecuteTypeScript = true;
}
console.log(JSON.stringify(result));
"#;
    fs::write(&script_path, script).ok()?;
    let output = Command::new(node).arg(&script_path).output().ok()?;
    let _ = fs::remove_file(&script_path);
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

fn upstream_bridge_probe_direct() -> serde_json::Value {
    let ref_root = Path::new("/tmp/ref-warden");
    let package_root = ref_root.join("packages/warden");
    let src_root = package_root.join("src");
    let node_modules = ref_root.join("node_modules");
    let local_tsx = node_modules.join(".bin/tsx");
    let warden_dist = package_root.join("dist/index.js");
    let warden_diff_coalesce = package_root.join("dist/diff/coalesce.js");
    let warden_diff_parser = package_root.join("dist/diff/parser.js");
    let warden_sdk_extract = package_root.join("dist/sdk/extract.js");
    let blocker = if command_path("node").is_none() {
        "missing node executable"
    } else if !src_root.exists() || !package_root.join("package.json").exists() {
        "missing upstream Warden source checkout at /tmp/ref-warden/packages/warden"
    } else if !node_modules.exists() {
        "missing /tmp/ref-warden/node_modules; refusing package-manager install in Rust harness tests"
    } else if !local_tsx.exists() {
        "missing local tsx binary in /tmp/ref-warden/node_modules/.bin/tsx"
    } else if !warden_dist.exists() {
        "missing built upstream Warden dist at /tmp/ref-warden/packages/warden/dist/index.js"
    } else if !warden_diff_coalesce.exists()
        || !warden_diff_parser.exists()
        || !warden_sdk_extract.exists()
    {
        "missing required upstream Warden dist modules for chunking/post-processing bridge"
    } else {
        ""
    };
    serde_json::json!({
        "checkedAt": Utc::now().to_rfc3339(),
        "refRoot": ref_root.display().to_string(),
        "packageRoot": package_root.display().to_string(),
        "node": command_path("node"),
        "srcExists": src_root.exists(),
        "packageJsonExists": package_root.join("package.json").exists(),
        "nodeModulesExists": node_modules.exists(),
        "localTsxExists": local_tsx.exists(),
        "wardenDistExists": warden_dist.exists(),
        "wardenDiffCoalesceExists": warden_diff_coalesce.exists(),
        "wardenDiffParserExists": warden_diff_parser.exists(),
        "wardenSdkExtractExists": warden_sdk_extract.exists(),
        "canExecuteTypeScript": blocker.is_empty(),
        "blocker": if blocker.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(blocker.to_string()) },
    })
}

fn run_upstream_warden_bridge(request: serde_json::Value) -> Result<serde_json::Value> {
    let probe = upstream_bridge_probe_direct();
    if probe
        .get("canExecuteTypeScript")
        .and_then(|value| value.as_bool())
        != Some(true)
    {
        bail!(
            "upstream Warden bridge is unavailable: {}",
            probe
                .get("blocker")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown blocker")
        );
    }
    let node = command_path("node").ok_or_else(|| anyhow::anyhow!("missing node executable"))?;
    let script_path = std::env::temp_dir().join(format!(
        "warden-sentry-upstream-bridge-{}-{}.mjs",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    fs::write(&script_path, upstream_warden_bridge_script())
        .with_context(|| format!("write {}", script_path.display()))?;
    let mut child = Command::new(node)
        .arg(&script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| "spawn upstream Warden bridge")?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("open upstream Warden bridge stdin"))?;
        stdin
            .write_all(serde_json::to_string(&request)?.as_bytes())
            .with_context(|| "write upstream Warden bridge request")?;
    }
    let output = child
        .wait_with_output()
        .with_context(|| "wait for upstream Warden bridge")?;
    let _ = fs::remove_file(&script_path);
    if !output.status.success() {
        bail!(
            "upstream Warden bridge failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| "parse upstream Warden bridge output")
}

fn upstream_warden_bridge_script() -> &'static str {
    r#"
import fs from 'node:fs';
import { parsePatch } from '/tmp/ref-warden/packages/warden/dist/diff/parser.js';
import { splitLargeHunks, coalesceHunks } from '/tmp/ref-warden/packages/warden/dist/diff/coalesce.js';
import { deduplicateFindings, applyMergeGroups } from '/tmp/ref-warden/packages/warden/dist/sdk/extract.js';

function createPatchFromContent(content) {
  const lines = content.split('\n');
  const lineCount = lines.length;
  if (lineCount === 0 || (lineCount === 1 && lines[0] === '')) {
    return '@@ -0,0 +0,0 @@\n';
  }
  return [`@@ -0,0 +1,${lineCount} @@`, ...lines.map((line) => `+${line}`)].join('\n');
}

function attachIndex(finding, index) {
  Object.defineProperty(finding, '__wardenBenchIndex', {
    value: index,
    enumerable: false,
    configurable: false,
  });
  return finding;
}

function stripHidden(value) {
  if (value === undefined) {
    return undefined;
  }
  return JSON.parse(JSON.stringify(value));
}

function sameLocation(a, b) {
  return Boolean(a && b && `${a.path}:${a.startLine}:${a.endLine ?? ''}` === `${b.path}:${b.startLine}:${b.endLine ?? ''}`);
}

function replacementForAbsorbed(finding, replacements) {
  for (const replacement of replacements.values()) {
    if (replacement.additionalLocations?.some((loc) => sameLocation(loc, finding.location))) {
      return replacement;
    }
  }
  return undefined;
}

const input = JSON.parse(fs.readFileSync(0, 'utf8'));

if (input.mode === 'chunkFile') {
  const hunks = parsePatch(createPatchFromContent(input.content));
  const split = splitLargeHunks(hunks, { maxChunkSize: input.maxChunkSize });
  const coalesced = coalesceHunks(split, {
    maxGapLines: input.maxGapLines,
    maxChunkSize: input.maxChunkSize,
  });
  console.log(JSON.stringify({ hunks: coalesced }));
} else if (input.mode === 'deduplicateFindings') {
  const findings = input.findings.map((finding, index) => attachIndex({ ...finding }, index));
  const events = [];
  const kept = deduplicateFindings(findings, (event) => {
    events.push({
      stage: event.stage,
      action: event.action,
      findingIndex: event.finding?.__wardenBenchIndex,
      replacementIndex: event.replacement?.__wardenBenchIndex,
      reason: event.reason,
    });
  });
  console.log(JSON.stringify({
    keptIndices: kept.map((finding) => finding.__wardenBenchIndex),
    events,
  }));
} else if (input.mode === 'applyMergeGroups') {
  const findings = input.findings.map((finding, index) => attachIndex({ ...finding }, index));
  const { absorbed, replacements } = applyMergeGroups(findings, input.groups);
  console.log(JSON.stringify({
    absorbed: findings
      .filter((finding) => absorbed.has(finding))
      .map((finding) => ({
        index: finding.__wardenBenchIndex,
        replacement: stripHidden(replacementForAbsorbed(finding, replacements)),
      })),
    replacements: [...replacements.entries()].map(([finding, replacement]) => ({
      index: finding.__wardenBenchIndex,
      finding: stripHidden(replacement),
    })),
  }));
} else {
  throw new Error(`unknown upstream Warden bridge mode: ${input.mode}`);
}
"#
}

fn command_path(program: &str) -> Option<String> {
    let output = Command::new("sh")
        .args(["-c", &format!("command -v {program}")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn post_process_cost_summary(
    args: &Args,
    results: &[TaskResult],
    auxiliary_usage: &BTreeMap<String, WardenUsageStats>,
) -> CostTotals {
    let result_refs = results.iter().collect::<Vec<_>>();
    let mut totals = sum_costs(&result_refs);
    let auxiliary_pricing = PricingConfig::from_args(args);
    let auxiliary_status = auxiliary_pricing.status();
    let auxiliary_sum = round_usd(
        auxiliary_usage
            .values()
            .map(|usage| usage.cost_usd)
            .sum::<f64>(),
    );
    let auxiliary_effectively_priced =
        auxiliary_usage.is_empty() || auxiliary_status == "estimated" || auxiliary_sum > 0.0;
    let auxiliary_usd = if auxiliary_effectively_priced {
        Some(auxiliary_sum)
    } else {
        None
    };
    let total_usd = match (totals.analysis_usd, auxiliary_usd) {
        (Some(analysis), Some(auxiliary)) => Some(round_usd(analysis + auxiliary)),
        _ => None,
    };

    totals.auxiliary_usd = auxiliary_usd;
    totals.total_usd = total_usd;
    if auxiliary_status != "not_configured" {
        totals.pricing = auxiliary_pricing;
    }
    totals.status = if totals.analysis_usd.is_some() && auxiliary_effectively_priced {
        "estimated".to_string()
    } else if totals.analysis_usd.is_some() || totals.auxiliary_usd.is_some() {
        "partial_pricing".to_string()
    } else if totals.status.is_empty() {
        "not_configured".to_string()
    } else {
        totals.status
    };
    totals
}

fn write_reproducibility_manifest(
    args: &Args,
    run_dir: &Path,
    run_id: &str,
    model: &str,
    provider_kind: &str,
    cost_summary: &CostTotals,
) -> Result<serde_json::Value> {
    let summary = fs::read_to_string(run_dir.join("summary.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
    let docker_image = summary
        .as_ref()
        .and_then(|summary| summary.get("dockerImage"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| Some(args.docker_image.clone()));
    let docker_image_digest_value = docker_image.as_deref().and_then(docker_image_digest);
    let runner_source_root = Path::new("bench/warden-sentry");
    let source_snapshot = write_source_snapshot(run_dir, runner_source_root)?;
    let git_status = git_status_porcelain_for_path(runner_source_root);
    let git_dirty = git_status
        .as_ref()
        .map(|status| !status.trim().is_empty())
        .or_else(|| git_dirty_for_path(runner_source_root));
    let clean_state = git_dirty.map(|dirty| !dirty);
    let clean_state_warning = (git_dirty == Some(true)).then_some(
        "runner source tree has uncommitted or untracked changes; wardenComparable reflects artifact invariants, not a clean git checkout",
    );
    let upstream_bridge_probe = write_upstream_bridge_probe(run_dir)?;
    let manifest = serde_json::json!({
        "schemaVersion": 1,
        "generatedAt": Utc::now().to_rfc3339(),
        "runId": run_id,
        "benchmark": BENCHMARK_NAME,
        "repository": DEFAULT_REPOSITORY,
        "targetMode": TARGET_MODE,
        "postProcessingMethod": POST_PROCESSING_METHOD,
        "runner": {
            "gitSha": git_stdout(None, &["rev-parse", "HEAD"]),
            "gitDirty": git_dirty,
            "cleanState": clean_state,
            "cleanStateWarning": clean_state_warning,
            "gitStatusPorcelain": git_status,
            "gitDiffSha256": git_diff_sha256_for_path(runner_source_root),
            "sourceTreePath": runner_source_root.display().to_string(),
            "sourceTreeSha256": source_snapshot.sha256.clone(),
            "sourceTreeFileCount": source_snapshot.file_count,
            "sourceSnapshotArtifact": SOURCE_SNAPSHOT_ARTIFACT,
            "sourceSnapshotSha256": source_snapshot.sha256.clone(),
            "binaryPath": std::env::current_exe().ok().map(|path| path.display().to_string()),
            "binarySha256": std::env::current_exe().ok().and_then(|path| sha256_hex_file(&path)),
            "packageVersion": env!("CARGO_PKG_VERSION"),
        },
        "corpus": {
            "path": args.corpus.display().to_string(),
            "sha256": sha256_hex_file(&args.corpus),
        },
        "upstreamWarden": {
            "path": "/tmp/ref-warden",
            "gitSha": git_stdout(Some(Path::new("/tmp/ref-warden")), &["rev-parse", "HEAD"]),
        },
        "model": {
            "providerKind": provider_kind,
            "name": model,
            "variant": args.variant.as_deref(),
        },
        "promptsAndSchemas": {
            "analysisPromptSha256": sha256_hex_bytes(SECURITY_REVIEW_PROMPT.as_bytes()),
            "findingsResponseSchemaSha256": sha256_hex_json(&findings_response_schema()),
            "verificationResponseSchemaSha256": sha256_hex_json(&verification_response_schema()),
            "mergeGroupsResponseSchemaSha256": sha256_hex_json(&merge_groups_response_schema()),
            "agentSemanticMatchResponseSchemaSha256": sha256_hex_json(&agent_semantic_match_schema()),
        },
        "docker": {
            "image": docker_image,
            "imageDigest": docker_image_digest_value,
        },
        "upstreamBridgeProbe": upstream_bridge_probe,
        "cost": cost_summary,
        "artifacts": {
            "finalJsonl": WARDEN_FINAL_JSONL_ARTIFACT,
            "postProcessingSummary": POST_PROCESS_SUMMARY_ARTIFACT,
            "postProcessingEvents": POST_PROCESS_EVENTS_ARTIFACT,
            "sourceSnapshot": SOURCE_SNAPSHOT_ARTIFACT,
            "upstreamBridgeProbe": UPSTREAM_BRIDGE_PROBE_ARTIFACT,
        },
    });
    let path = run_dir.join(REPRODUCIBILITY_MANIFEST_ARTIFACT);
    fs::write(&path, serde_json::to_string_pretty(&manifest)?)
        .with_context(|| format!("write {}", path.display()))?;
    Ok(manifest)
}

fn git_stdout(cwd: Option<&Path>, args: &[&str]) -> Option<String> {
    let mut command = Command::new("git");
    if let Some(cwd) = cwd {
        if !cwd.exists() {
            return None;
        }
        command.current_dir(cwd);
    }
    command.args(args);
    command_stdout_optional(&mut command)
}

fn git_dirty_for_path(path: &Path) -> Option<bool> {
    let output = Command::new("git")
        .args(["status", "--porcelain", "--"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn git_status_porcelain_for_path(path: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["status", "--porcelain", "--"])
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_diff_sha256_for_path(path: &Path) -> Option<String> {
    let mut command = Command::new("git");
    command.args(["diff", "--binary", "--"]).arg(path);
    let bytes = command_stdout_bytes_optional(&mut command)?;
    sha256_hex_bytes(&bytes)
}

fn docker_image_digest(image: &str) -> Option<String> {
    let digests = {
        let mut command = Command::new("docker");
        command.args([
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            image,
        ]);
        command_stdout_optional(&mut command)
            .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
            .and_then(|values| values.into_iter().next())
    };
    if digests.is_some() {
        return digests;
    }

    let mut command = Command::new("docker");
    command.args(["image", "inspect", "--format", "{{.Id}}", image]);
    command_stdout_optional(&mut command)
}

fn command_stdout_optional(command: &mut Command) -> Option<String> {
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn command_stdout_bytes_optional(command: &mut Command) -> Option<Vec<u8>> {
    let output = command.output().ok()?;
    output.status.success().then_some(output.stdout)
}

#[derive(Clone, Debug)]
struct DirectoryTreeHash {
    sha256: String,
    file_count: usize,
}

fn write_source_snapshot(run_dir: &Path, root: &Path) -> Result<DirectoryTreeHash> {
    let mut files = Vec::new();
    collect_hashable_files(root, &mut files)?;
    files.sort();
    let mut lines = Vec::new();
    lines.push(serde_json::to_string(&serde_json::json!({
        "type": "manifest",
        "schemaVersion": 1,
        "root": root.display().to_string(),
        "fileCount": files.len(),
        "encoding": "hex",
    }))?);
    for path in &files {
        let relative = path
            .strip_prefix(root)
            .with_context(|| format!("strip {} from {}", root.display(), path.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        lines.push(serde_json::to_string(&serde_json::json!({
            "type": "file",
            "path": relative,
            "sha256": sha256_hex_bytes(&bytes),
            "bytesHex": hex_encode(&bytes),
        }))?);
    }
    let content = lines.join("\n") + "\n";
    let path = run_dir.join(SOURCE_SNAPSHOT_ARTIFACT);
    fs::write(&path, &content).with_context(|| format!("write {}", path.display()))?;
    Ok(DirectoryTreeHash {
        sha256: sha256_hex_bytes(content.as_bytes()).unwrap_or_default(),
        file_count: files.len(),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn collect_hashable_files(root: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("file type {}", path.display()))?;
        if file_type.is_dir() {
            let name = entry.file_name();
            if name == "target" || name == "node_modules" || name == ".git" {
                continue;
            }
            collect_hashable_files(&path, out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn count_files_named(root: &Path, file_name: &str) -> Result<usize> {
    let mut count = 0usize;
    count_files_recursive(
        root,
        &mut |path| path.file_name().and_then(|name| name.to_str()) == Some(file_name),
        &mut count,
    )?;
    Ok(count)
}

fn count_json_files(root: &Path) -> Result<usize> {
    let mut count = 0usize;
    count_files_recursive(
        root,
        &mut |path| path.extension().and_then(|extension| extension.to_str()) == Some("json"),
        &mut count,
    )?;
    Ok(count)
}

fn count_files_recursive(
    root: &Path,
    predicate: &mut dyn FnMut(&Path) -> bool,
    count: &mut usize,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .with_context(|| format!("file type {}", path.display()))?;
        if file_type.is_dir() {
            count_files_recursive(&path, predicate, count)?;
        } else if file_type.is_file() && predicate(&path) {
            *count += 1;
        }
    }
    Ok(())
}

fn sha256_hex_file(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    sha256_hex_bytes(&bytes)
}

fn sha256_hex_json(value: &serde_json::Value) -> Option<String> {
    let bytes = serde_json::to_vec(value).ok()?;
    sha256_hex_bytes(&bytes)
}

fn sha256_hex_bytes(bytes: &[u8]) -> Option<String> {
    hash_bytes_with_command("sha256sum", &[], bytes)
        .or_else(|| hash_bytes_with_command("openssl", &["dgst", "-sha256", "-r"], bytes))
}

fn hash_bytes_with_command(program: &str, args: &[&str], bytes: &[u8]) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        stdin.write_all(bytes).ok()?;
    }
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .map(str::to_string)
        .filter(|value| value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
}

fn warden_error_code_for_result(result: &TaskResult) -> &'static str {
    match result.done_reason.as_str() {
        "max_turns" => "max_turns",
        "cancelled" => "aborted",
        "provider_error" => "provider_unavailable",
        _ => "unknown",
    }
}

fn count_warden_findings_by_severity<'a>(
    findings: impl Iterator<Item = &'a WardenFinding>,
) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::from([
        ("high".to_string(), 0),
        ("medium".to_string(), 0),
        ("low".to_string(), 0),
    ]);
    for finding in findings {
        if let Some(count) = out.get_mut(finding.severity.as_str()) {
            *count += 1;
        }
    }
    out
}

fn validate_finalized_run(run_dir: &Path) -> Result<serde_json::Value> {
    let mut failures = Vec::new();
    let summary_path = run_dir.join("summary.json");
    let post_summary_path = run_dir.join(POST_PROCESS_SUMMARY_ARTIFACT);
    let final_jsonl_path = run_dir.join(WARDEN_FINAL_JSONL_ARTIFACT);
    let summary = read_json_file(&summary_path)?;
    let post_summary = read_json_file(&post_summary_path)?;
    let final_jsonl = fs::read_to_string(&final_jsonl_path)
        .with_context(|| format!("read {}", final_jsonl_path.display()))?;

    let mut chunk_records = 0usize;
    let mut summary_records = 0usize;
    let mut final_summary = None;
    for (line_index, line) in final_jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value = match serde_json::from_str::<serde_json::Value>(line) {
            Ok(value) => value,
            Err(err) => {
                failures.push(format!(
                    "warden-final.jsonl line {} is invalid JSON: {err}",
                    line_index + 1
                ));
                continue;
            }
        };
        if value.get("type").and_then(|value| value.as_str()) == Some("summary") {
            summary_records += 1;
            match serde_json::from_value::<WardenJsonlSummary>(value.clone()) {
                Ok(parsed) => final_summary = Some((value, parsed)),
                Err(err) => failures.push(format!(
                    "warden-final.jsonl line {} is not a valid Warden summary record: {err}",
                    line_index + 1
                )),
            }
        } else {
            chunk_records += 1;
            if let Err(err) = serde_json::from_value::<WardenJsonlChunk>(value) {
                failures.push(format!(
                    "warden-final.jsonl line {} is not a valid Warden chunk record: {err}",
                    line_index + 1
                ));
            }
        }
    }

    check_usize(
        &mut failures,
        "chunk record count",
        chunk_records,
        EXPECTED_WARDEN_SENTRY_CHUNKS,
    );
    check_usize(
        &mut failures,
        "summary record count",
        summary_records,
        EXPECTED_WARDEN_SENTRY_SUMMARY_RECORDS,
    );

    let verifier_result_count =
        count_files_named(&run_dir.join("post-processing/verification"), "result.json")?;
    let merge_artifact_count = count_json_files(&run_dir.join("post-processing/merge"))?;
    let expected_verifier_results = json_usize(&post_summary, &["normalizedFindings"])
        .unwrap_or_default()
        .saturating_sub(json_usize(&post_summary, &["dedupeDropped"]).unwrap_or_default());
    check_usize(
        &mut failures,
        "verifier result artifact count",
        verifier_result_count,
        expected_verifier_results,
    );
    if let Some(expected) = json_usize(&post_summary, &["verificationArtifactCount"]) {
        check_usize(
            &mut failures,
            "post summary verificationArtifactCount",
            verifier_result_count,
            expected,
        );
    }
    if let Some(expected) = json_usize(&post_summary, &["mergeArtifactCount"]) {
        check_usize(
            &mut failures,
            "post summary mergeArtifactCount",
            merge_artifact_count,
            expected,
        );
    }

    if summary
        .get("wardenComparable")
        .and_then(|value| value.as_bool())
        != Some(true)
    {
        failures.push("summary.json wardenComparable is not true".to_string());
    }
    if !run_dir.join(SEMANTIC_SCORING_ARTIFACT).exists() {
        if summary
            .get("scoring")
            .and_then(|value| value.get("inputArtifact"))
            .and_then(|value| value.as_str())
            != Some(WARDEN_FINAL_JSONL_ARTIFACT)
        {
            failures
                .push("summary.json scoring.inputArtifact is not warden-final.jsonl".to_string());
        }
        if summary
            .get("scoring")
            .and_then(|value| value.get("wardenComparableRequired"))
            .and_then(|value| value.as_bool())
            != Some(true)
        {
            failures.push("summary.json scoring.wardenComparableRequired is not true".to_string());
        }
    }

    validate_renamed_stale_scores(run_dir, &summary, &post_summary, &mut failures)?;
    let post_final = json_usize(&post_summary, &["finalFindings"]).unwrap_or_default();
    validate_semantic_scoring_artifact(run_dir, &summary, post_final, &mut failures)?;

    if let Some((final_summary_value, parsed_summary)) = &final_summary {
        check_usize(
            &mut failures,
            "final summary totalFindings",
            parsed_summary.total_findings,
            post_final,
        );
        if let Some(summary_final) = json_usize(&summary, &["summary", "finalFindingsTotal"]) {
            check_usize(
                &mut failures,
                "summary finalFindingsTotal",
                summary_final,
                post_final,
            );
        }
        check_cost_consistency(
            &mut failures,
            "total cost",
            &[
                json_f64(&summary, &["summary", "costUSD"]),
                json_f64(&post_summary, &["costUSD"]),
                json_f64(
                    final_summary_value,
                    &["usageBreakdown", "total", "usage", "costUSD"],
                ),
            ],
        );
        check_cost_consistency(
            &mut failures,
            "auxiliary cost",
            &[
                json_f64(&summary, &["summary", "auxiliaryCostUSD"]),
                json_f64(&post_summary, &["auxiliaryCostUSD"]),
                final_summary_auxiliary_cost(final_summary_value),
            ],
        );
    } else {
        failures
            .push("warden-final.jsonl did not contain a valid trailing summary record".to_string());
    }

    Ok(serde_json::json!({
        "status": if failures.is_empty() { "passed" } else { "failed" },
        "checkedAt": Utc::now().to_rfc3339(),
        "runDir": run_dir.display().to_string(),
        "chunkRecords": chunk_records,
        "expectedChunkRecords": EXPECTED_WARDEN_SENTRY_CHUNKS,
        "summaryRecords": summary_records,
        "expectedSummaryRecords": EXPECTED_WARDEN_SENTRY_SUMMARY_RECORDS,
        "verifierResultArtifacts": verifier_result_count,
        "expectedVerifierResultArtifacts": expected_verifier_results,
        "mergeArtifacts": merge_artifact_count,
        "expectedMergeArtifacts": json_usize(&post_summary, &["mergeArtifactCount"]),
        "finalFindings": json_usize(&post_summary, &["finalFindings"]),
        "wardenComparable": summary.get("wardenComparable").cloned().unwrap_or(serde_json::Value::Null),
        "comparisonState": summary.get("comparisonState").cloned().unwrap_or(serde_json::Value::Null),
        "scoring": summary.get("scoring").cloned().unwrap_or(serde_json::Value::Null),
        "costs": {
            "summaryCostUSD": json_f64(&summary, &["summary", "costUSD"]),
            "postProcessingCostUSD": json_f64(&post_summary, &["costUSD"]),
            "finalJsonlCostUSD": final_summary
                .as_ref()
                .and_then(|(value, _)| json_f64(value, &["usageBreakdown", "total", "usage", "costUSD"])),
            "summaryAuxiliaryCostUSD": json_f64(&summary, &["summary", "auxiliaryCostUSD"]),
            "postProcessingAuxiliaryCostUSD": json_f64(&post_summary, &["auxiliaryCostUSD"]),
            "finalJsonlAuxiliaryCostUSD": final_summary
                .as_ref()
                .and_then(|(value, _)| final_summary_auxiliary_cost(value)),
        },
        "failures": failures,
    }))
}

fn read_json_file(path: &Path) -> Result<serde_json::Value> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn validate_renamed_stale_scores(
    run_dir: &Path,
    summary: &serde_json::Value,
    post_summary: &serde_json::Value,
    failures: &mut Vec<String>,
) -> Result<()> {
    let listed = post_summary
        .get("nonComparableScoringArtifacts")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .chain(
            summary
                .get("scoring")
                .and_then(|value| value.get("nonComparablePreviousArtifacts"))
                .and_then(|value| value.as_array())
                .into_iter()
                .flatten(),
        )
        .filter_map(|value| value.as_str())
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    for entry in fs::read_dir(run_dir).with_context(|| format!("read {}", run_dir.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", run_dir.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(artifact) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if artifact == SEMANTIC_SCORING_ARTIFACT || artifact == SEMANTIC_SCORING_SUMMARY_ARTIFACT {
            continue;
        }
        let is_stale_scoring = artifact.starts_with("semantic-scoring.")
            && artifact.ends_with(".json")
            && artifact.contains("pre-");
        let is_stale_summary = artifact.starts_with("semantic-scoring-summary.")
            && artifact.ends_with(".md")
            && artifact.contains("pre-");
        if (is_stale_scoring || is_stale_summary) && !listed.contains(artifact) {
            failures.push(format!(
                "{artifact} exists but is not listed as non-comparable stale scoring"
            ));
        }
        if is_stale_scoring {
            validate_stale_scoring_json(&path, artifact, failures)?;
        } else if is_stale_summary {
            let raw = fs::read_to_string(&path).unwrap_or_default();
            if !raw.starts_with("<!-- warden-sentry-stale-score") {
                failures.push(format!(
                    "{artifact} missing stale non-comparable markdown marker"
                ));
            }
        }
    }
    for artifact in &listed {
        if !run_dir.join(artifact).exists() {
            failures.push(format!(
                "listed stale scoring artifact does not exist: {artifact}"
            ));
        }
    }
    Ok(())
}

fn validate_stale_scoring_json(
    path: &Path,
    artifact: &str,
    failures: &mut Vec<String>,
) -> Result<()> {
    let stale = read_json_file(path)?;
    let scoring = stale.get("scoring").unwrap_or(&serde_json::Value::Null);
    if json_str(scoring, &["status"]) != Some("stale_non_comparable") {
        failures.push(format!(
            "{artifact} scoring.status is not stale_non_comparable"
        ));
    }
    if scoring
        .get("nonComparable")
        .and_then(|value| value.as_bool())
        != Some(true)
    {
        failures.push(format!("{artifact} scoring.nonComparable is not true"));
    }
    if scoring
        .get("wardenComparable")
        .and_then(|value| value.as_bool())
        != Some(false)
    {
        failures.push(format!("{artifact} scoring.wardenComparable is not false"));
    }
    if scoring.get("previousInputState").is_none() || scoring.get("previousInputArtifact").is_none()
    {
        failures.push(format!(
            "{artifact} missing previous input state/artifact metadata"
        ));
    }
    if artifact.contains("raw-pre-finalization")
        && (json_str(scoring, &["previousInputState"]) == Some("finalized")
            || json_str(scoring, &["previousInputArtifact"]) == Some(WARDEN_FINAL_JSONL_ARTIFACT))
    {
        failures.push(format!(
            "{artifact} is named raw-pre-finalization but previous input was finalized"
        ));
    }
    Ok(())
}

fn validate_semantic_scoring_artifact(
    run_dir: &Path,
    summary: &serde_json::Value,
    final_findings: usize,
    failures: &mut Vec<String>,
) -> Result<()> {
    let path = run_dir.join(SEMANTIC_SCORING_ARTIFACT);
    if !path.exists() {
        return Ok(());
    }
    let scoring = read_json_file(&path)?;
    let artifact_scoring = scoring.get("scoring").unwrap_or(&serde_json::Value::Null);
    let summary_scoring = summary.get("scoring").unwrap_or(&serde_json::Value::Null);
    if json_str(artifact_scoring, &["reviewer"]) != Some(AGENT_SEMANTIC_MATCH_PASS) {
        failures.push(
            "semantic-scoring.json scoring.reviewer is not agent-semantic-match-pass".to_string(),
        );
    }
    for key in ["reviewer", "scoredAt", "notes"] {
        if artifact_scoring.get(key) != summary_scoring.get(key) {
            failures.push(format!(
                "semantic-scoring.json scoring.{key} does not match summary.json"
            ));
        }
    }
    for key in [
        "knownFound",
        "knownFindingCount",
        "knownMissed",
        "knownPartial",
    ] {
        if json_usize(artifact_scoring, &[key]) != json_usize(summary_scoring, &[key]) {
            failures.push(format!(
                "semantic-scoring.json scoring.{key} does not match summary.json"
            ));
        }
    }
    for key in ["knownFoundRate"] {
        let a = json_f64(artifact_scoring, &[key]);
        let b = json_f64(summary_scoring, &[key]);
        if a.zip(b).map(|(a, b)| (a - b).abs() <= 0.000001) != Some(true) {
            failures.push(format!(
                "semantic-scoring.json scoring.{key} does not match summary.json"
            ));
        }
    }
    if scoring
        .get("scores")
        .and_then(|value| value.as_array())
        .map(Vec::len)
        != Some(final_findings)
    {
        failures.push(
            "semantic-scoring.json scores length does not equal finalized finding count"
                .to_string(),
        );
    }
    Ok(())
}

fn check_usize(failures: &mut Vec<String>, label: &str, actual: usize, expected: usize) {
    if actual != expected {
        failures.push(format!("{label} expected {expected}, got {actual}"));
    }
}

fn check_cost_consistency(failures: &mut Vec<String>, label: &str, values: &[Option<f64>]) {
    let present = values.iter().copied().flatten().collect::<Vec<_>>();
    if present.len() != values.len() {
        failures.push(format!(
            "{label} is missing on one or more finalized artifacts"
        ));
        return;
    }
    let Some(first) = present.first().copied() else {
        return;
    };
    for value in present.iter().skip(1) {
        if (first - value).abs() > 0.000001 {
            failures.push(format!("{label} mismatch across artifacts: {present:?}"));
            return;
        }
    }
}

fn final_summary_auxiliary_cost(summary: &serde_json::Value) -> Option<f64> {
    let usage_breakdown = summary.get("usageBreakdown")?;
    let Some(auxiliary) = usage_breakdown
        .get("auxiliary")
        .and_then(|value| value.as_object())
    else {
        return Some(0.0);
    };
    Some(round_usd(
        auxiliary
            .values()
            .filter_map(|entry| json_f64(entry, &["usage", "costUSD"]))
            .sum::<f64>(),
    ))
}

fn json_usize(value: &serde_json::Value, path: &[&str]) -> Option<usize> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_u64().map(|value| value as usize)
}

fn json_f64(value: &serde_json::Value, path: &[&str]) -> Option<f64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_f64()
}

fn json_str<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn update_summary_post_processing(
    run_dir: &Path,
    post_summary: &serde_json::Value,
    final_findings: &[PostProcessFinding],
    auxiliary_usage: &BTreeMap<String, WardenUsageStats>,
    model: &str,
    provider_kind: &str,
) -> Result<()> {
    let summary_path = run_dir.join("summary.json");
    let raw = fs::read_to_string(&summary_path)
        .with_context(|| format!("read {}", summary_path.display()))?;
    let mut summary: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", summary_path.display()))?;
    let Some(map) = summary.as_object_mut() else {
        bail!("{} does not contain a JSON object", summary_path.display());
    };
    map.insert("postProcessing".to_string(), post_summary.clone());
    map.insert(
        "findingVerification".to_string(),
        serde_json::json!({
            "enabled": true,
            "status": post_summary.get("status").cloned().unwrap_or_else(|| serde_json::json!("completed")),
            "method": "lash_repo_aware_tool_pass",
            "artifact": POST_PROCESS_SUMMARY_ARTIFACT,
            "eventsArtifact": POST_PROCESS_EVENTS_ARTIFACT,
            "artifacts": "post-processing/verification/",
            "model": model,
            "providerKind": provider_kind,
        }),
    );
    map.insert(
        "verificationEnabled".to_string(),
        serde_json::Value::Bool(true),
    );
    map.insert(
        "finalJsonlArtifact".to_string(),
        serde_json::Value::String(WARDEN_FINAL_JSONL_ARTIFACT.to_string()),
    );
    map.insert(
        "reproducibilityManifestArtifact".to_string(),
        serde_json::Value::String(REPRODUCIBILITY_MANIFEST_ARTIFACT.to_string()),
    );
    if let Some(clean_state) = post_summary.get("cleanState") {
        map.insert("cleanState".to_string(), clean_state.clone());
    }
    if let Some(clean_state_warning) = post_summary.get("cleanStateWarning") {
        if clean_state_warning.is_null() {
            map.remove("cleanStateWarning");
        } else {
            map.insert("cleanStateWarning".to_string(), clean_state_warning.clone());
        }
    }
    map.insert(
        "wardenComparable".to_string(),
        serde_json::Value::Bool(
            post_summary.get("status").and_then(|v| v.as_str()) == Some("completed"),
        ),
    );
    map.insert(
        "comparisonState".to_string(),
        serde_json::Value::String(
            if post_summary.get("status").and_then(|v| v.as_str()) == Some("completed") {
                "finalized-unscored"
            } else {
                "finalized-with-auxiliary-errors"
            }
            .to_string(),
        ),
    );
    let mut scoring = serde_json::json!({
        "status": "unscored",
        "inputState": "finalized",
        "inputArtifact": WARDEN_FINAL_JSONL_ARTIFACT,
        "wardenComparableRequired": true,
        "notes": "Post-processing changed the score input; run --score-run-dir after finalization.",
    });
    if let Some(moved) = post_summary.get("nonComparableScoringArtifacts")
        && moved
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    {
        scoring["nonComparablePreviousArtifacts"] = moved.clone();
    }
    map.insert("scoring".to_string(), scoring);
    if let Some(summary_obj) = map
        .get_mut("summary")
        .and_then(|value| value.as_object_mut())
    {
        if !summary_obj.contains_key("rawFindingsTotal") {
            if let Some(raw_total) = summary_obj.get("findingsTotal").cloned() {
                summary_obj.insert("rawFindingsTotal".to_string(), raw_total);
            }
            if let Some(raw_severity) = summary_obj.get("findingsBySeverity").cloned() {
                summary_obj.insert("rawFindingsBySeverity".to_string(), raw_severity);
            }
            if let Some(raw_confidence) = summary_obj.get("findingsByConfidence").cloned() {
                summary_obj.insert("rawFindingsByConfidence".to_string(), raw_confidence);
            }
        }
        summary_obj.insert(
            "findingsTotal".to_string(),
            serde_json::json!(final_findings.len()),
        );
        summary_obj.insert(
            "finalFindingsTotal".to_string(),
            serde_json::json!(final_findings.len()),
        );
        summary_obj.insert(
            "findingsBySeverity".to_string(),
            serde_json::to_value(count_warden_findings_by_severity(
                final_findings.iter().map(|finding| &finding.finding),
            ))?,
        );
        summary_obj.insert(
            "findingsByConfidence".to_string(),
            serde_json::to_value(count_warden_findings_by_confidence(
                final_findings.iter().map(|finding| &finding.finding),
            ))?,
        );
        summary_obj.insert(
            "auxiliaryUsage".to_string(),
            serde_json::to_value(auxiliary_usage)?,
        );
        copy_post_summary_field(summary_obj, post_summary, "analysisCostUSD");
        copy_post_summary_field(summary_obj, post_summary, "auxiliaryCostUSD");
        copy_post_summary_field(summary_obj, post_summary, "costUSD");
        copy_post_summary_field(summary_obj, post_summary, "pricingStatus");
        copy_post_summary_field(summary_obj, post_summary, "pricing");
    }
    fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)
        .with_context(|| format!("write {}", summary_path.display()))?;
    Ok(())
}

fn copy_post_summary_field(
    summary_obj: &mut serde_json::Map<String, serde_json::Value>,
    post_summary: &serde_json::Value,
    field: &str,
) {
    if let Some(value) = post_summary.get(field) {
        summary_obj.insert(field.to_string(), value.clone());
    }
}

fn count_warden_findings_by_confidence<'a>(
    findings: impl Iterator<Item = &'a WardenFinding>,
) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for finding in findings {
        let confidence = finding.confidence.as_deref().unwrap_or("unspecified");
        *out.entry(confidence.to_string()).or_insert(0) += 1;
    }
    out
}

fn post_process_provider_identity(
    args: &Args,
    run_dir: &Path,
    results: &[TaskResult],
) -> Result<(String, String)> {
    if args.model.is_some() || args.provider_id.is_some() {
        let (_provider, provider_kind, resolved_model) = resolve_provider(args)?;
        return Ok((provider_kind, resolved_model));
    }

    let summary = fs::read_to_string(run_dir.join("summary.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok());
    let provider_kind = results
        .first()
        .map(|row| row.provider_kind.clone())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            summary
                .as_ref()
                .and_then(|summary| {
                    summary
                        .get("providerKind")
                        .or_else(|| summary.get("provider_kind"))
                })
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());
    let model = results
        .first()
        .map(|row| row.model.clone())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            summary
                .as_ref()
                .and_then(|summary| summary.get("model"))
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());
    Ok((provider_kind, model))
}

fn checkout_sha(workspace_root: &Path, repo_dir: &Path, repository: &str, sha: &str) -> Result<()> {
    let bare_dir = workspace_root.join(bare_repo_dirname(repository));
    ensure_bare_clone(&bare_dir, repository)?;
    ensure_commit_present(&bare_dir, sha)?;
    let _ = run_git(
        &bare_dir,
        &[
            "worktree",
            "remove",
            "--force",
            &repo_dir.display().to_string(),
        ],
    );
    let _ = run_git(&bare_dir, &["worktree", "prune"]);
    if repo_dir.exists() {
        fs::remove_dir_all(repo_dir).with_context(|| format!("remove {}", repo_dir.display()))?;
    }
    fs::create_dir_all(repo_dir.parent().unwrap_or(Path::new(".")))
        .with_context(|| format!("create parent of {}", repo_dir.display()))?;
    run_git(
        &bare_dir,
        &[
            "worktree",
            "add",
            "--detach",
            "-f",
            &repo_dir.display().to_string(),
            sha,
        ],
    )
    .with_context(|| format!("git worktree add {sha}"))?;
    Ok(())
}

fn remove_sha_worktree(workspace_root: &Path, repository: &str, repo_dir: &Path) -> Result<()> {
    let bare_dir = workspace_root.join(bare_repo_dirname(repository));
    if !repo_dir.exists() {
        return Ok(());
    }
    let _ = run_git(
        &bare_dir,
        &[
            "worktree",
            "remove",
            "--force",
            &repo_dir.display().to_string(),
        ],
    );
    if repo_dir.exists() {
        fs::remove_dir_all(repo_dir).ok();
    }
    let _ = run_git(&bare_dir, &["worktree", "prune"]);
    Ok(())
}

async fn run_score(args: Args) -> Result<()> {
    if args.single_task.is_some() {
        bail!("--score-run-dir cannot be combined with --single-task");
    }
    if !args.task_id.is_empty()
        || !args.finding_id.is_empty()
        || !args.sha.is_empty()
        || !args.target_path.is_empty()
        || args.limit.is_some()
        || args.offset != 0
    {
        bail!(
            "--score-run-dir scores all predictions in the run directory; task selectors apply only to analysis runs"
        );
    }
    let run_dir = args
        .score_run_dir
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--score-run-dir is required"))?;
    let run_dir = fs::canonicalize(&run_dir)
        .with_context(|| format!("canonicalize {}", run_dir.display()))?;
    let predictions_path = run_dir.join("predictions.jsonl");
    let corpus = load_corpus(&args.corpus)?;
    let mut results = load_completed_results(&predictions_path)?
        .into_values()
        .collect::<Vec<_>>();
    if results.is_empty() {
        bail!("no predictions found in {}", predictions_path.display());
    }
    results.sort_by(|a, b| a.task_id.cmp(&b.task_id));
    let finalized_jsonl_path = run_dir.join(WARDEN_FINAL_JSONL_ARTIFACT);
    if !finalized_jsonl_path.exists() {
        bail!(
            "semantic scoring requires finalized Warden post-processing; run --post-process-run-dir {} first",
            run_dir.display()
        );
    }
    ensure_warden_comparable_marker(&run_dir)?;
    apply_finalized_findings_to_results(&mut results, &finalized_jsonl_path)?;

    let selected_corpus_ids = selected_corpus_ids_for_results(&corpus, &results);
    let corpus_by_sha = corpus_by_sha(&corpus);
    let corpus_id_to_sha = corpus_id_to_short_sha(&corpus);
    let run_id = run_id_from_summary_or_dir(&run_dir)?;
    let (_provider, _provider_kind, resolved_model) = resolve_provider(&args)?;
    let score_batch_size = args.score_batch_size.max(1);
    let all_jobs = build_agent_scoring_jobs(&results, &corpus_by_sha);
    let jobs_total = all_jobs.len();
    let progress_artifact = semantic_scoring_progress_artifact();
    let progress_path = run_dir.join(&progress_artifact);
    let completed_outputs = load_scoring_progress(&progress_path)?;
    let completed_indexes = completed_outputs.keys().copied().collect::<BTreeSet<_>>();
    let mut outputs = completed_outputs.into_values().collect::<Vec<_>>();
    let resumed_jobs = outputs.len();
    let jobs = all_jobs
        .into_iter()
        .filter(|job| !completed_indexes.contains(&job.index))
        .collect::<Vec<_>>();
    eprintln!(
        "Semantic scoring run_id={run_id} tasks={} emitted_findings={jobs_total} resumed={} remaining={} score_batch_size={score_batch_size} reviewer={}",
        results.len(),
        resumed_jobs,
        jobs.len(),
        AGENT_SEMANTIC_MATCH_PASS
    );

    let semaphore = Arc::new(Semaphore::new(score_batch_size));
    let mut join_set: JoinSet<Result<AgentScoringOutput>> = JoinSet::new();

    for job in jobs {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .context("acquire semantic scoring slot")?;
        let job_args = args.clone();
        let job_model = resolved_model.clone();
        join_set.spawn(async move {
            let _permit = permit;
            score_one_agent_semantic_match(job_args, job_model, job).await
        });
        while join_set.len() >= score_batch_size {
            collect_next_scoring_output(&mut join_set, &mut outputs, jobs_total, &progress_path)
                .await?;
        }
    }

    while !join_set.is_empty() {
        collect_next_scoring_output(&mut join_set, &mut outputs, jobs_total, &progress_path)
            .await?;
    }
    outputs.sort_by_key(|output| output.index);

    let mut scores = Vec::new();
    let mut usage = ScoringUsageTotals::default();
    for output in outputs {
        merge_scoring_usage(&mut usage, &output.usage);
        scores.extend(output.scores);
    }

    let matched_ids = scores
        .iter()
        .flat_map(|row| row.matched_corpus_ids.iter().cloned())
        .filter(|id| selected_corpus_ids.contains(id))
        .collect::<BTreeSet<_>>();
    let known_total = selected_corpus_ids.len();
    let known_found = matched_ids.len();
    let known_missed = known_total.saturating_sub(known_found);
    let known_found_rate = ratio4(known_found, known_total);
    let missed_ids = selected_corpus_ids
        .iter()
        .filter(|id| !matched_ids.contains(*id))
        .cloned()
        .collect::<Vec<_>>();
    let scoring = serde_json::json!({
        "reviewer": AGENT_SEMANTIC_MATCH_PASS,
        "scoredAt": Utc::now().date_naive().to_string(),
        "knownFindingCount": known_total,
        "knownFound": known_found,
        "knownMissed": known_missed,
        "knownPartial": 0,
        "knownFoundRate": known_found_rate,
        "notes": "Agent-verified semantic matches. A finding counts when it identifies the same bug in roughly the same location as an existing corpus finding. Same-file findings about different bugs do not count."
    });
    let artifact = SemanticScoringResult {
        run_id: run_id.clone(),
        corpus_id: corpus.id.clone(),
        scoring: scoring.clone(),
        scores: scores.clone(),
    };

    let artifact_path = run_dir.join(SEMANTIC_SCORING_ARTIFACT);
    fs::write(&artifact_path, serde_json::to_string_pretty(&artifact)?)
        .with_context(|| format!("write {}", artifact_path.display()))?;
    let markdown_path = run_dir.join(SEMANTIC_SCORING_SUMMARY_ARTIFACT);
    fs::write(
        &markdown_path,
        semantic_scoring_markdown(&run_id, &scoring, &scores, &missed_ids, &corpus_id_to_sha),
    )
    .with_context(|| format!("write {}", markdown_path.display()))?;
    update_summary_scoring(&run_dir, scoring)?;

    eprintln!("Semantic scoring complete:");
    eprintln!("  run_dir:          {}", run_dir.display());
    eprintln!("  scores:           {}", artifact_path.display());
    eprintln!("  summary:          {}", markdown_path.display());
    eprintln!(
        "  known_found:      {known_found}/{known_total} ({:.2}%)",
        known_found_rate * 100.0
    );
    eprintln!("  emitted_scored:   {}", scores.len());
    eprintln!(
        "  score_tokens:     input={} output={} reasoning={} cache_read={}",
        usage.input_tokens, usage.output_tokens, usage.reasoning_tokens, usage.cached_input_tokens
    );
    eprintln!("  progress:         {}", progress_path.display());
    Ok(())
}

async fn collect_next_scoring_output(
    join_set: &mut JoinSet<Result<AgentScoringOutput>>,
    outputs: &mut Vec<AgentScoringOutput>,
    total: usize,
    progress_path: &Path,
) -> Result<()> {
    let Some(joined) = join_set.join_next().await else {
        return Ok(());
    };
    match joined {
        Ok(Ok(output)) => {
            append_scoring_progress(progress_path, &output)?;
            outputs.push(output);
            eprintln!(
                "Semantic scoring progress: {}/{} match jobs completed",
                outputs.len(),
                total
            );
            Ok(())
        }
        Ok(Err(err)) => {
            join_set.abort_all();
            bail!("{err:#}");
        }
        Err(err) => {
            join_set.abort_all();
            bail!("semantic scoring task panicked: {err}");
        }
    }
}

fn semantic_scoring_progress_artifact() -> String {
    format!("semantic-scoring.{AGENT_SEMANTIC_MATCH_PASS}.progress.jsonl")
}

fn load_scoring_progress(path: &Path) -> Result<BTreeMap<usize, AgentScoringOutput>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut outputs = BTreeMap::new();
    for (line_index, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let output = serde_json::from_str::<AgentScoringOutput>(line).with_context(|| {
            format!(
                "parse {} line {} as scoring progress",
                path.display(),
                line_index + 1
            )
        })?;
        outputs.insert(output.index, output);
    }
    Ok(outputs)
}

fn append_scoring_progress(path: &Path, output: &AgentScoringOutput) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(output)?)
        .with_context(|| format!("append {}", path.display()))?;
    file.flush()
        .with_context(|| format!("flush {}", path.display()))?;
    Ok(())
}

async fn score_one_agent_semantic_match(
    args: Args,
    resolved_model: String,
    job: AgentScoringJob,
) -> Result<AgentScoringOutput> {
    let prompt = build_agent_semantic_match_prompt(&job)?;
    let request = build_agent_semantic_match_request(&args, &resolved_model, prompt);
    let (provider, _, _) = resolve_provider(&args)?;
    let mut client = DirectLlmClient::new(provider);
    let response = client
        .complete(request)
        .await
        .with_context(|| format!("agent semantic match failed for {}", job.finding_id))?;

    let mut usage = ScoringUsageTotals::default();
    add_scoring_usage(&mut usage, &response);
    let match_response: AgentSemanticMatchResponse =
        serde_json::from_str(response.full_text.trim()).with_context(|| {
            format!("parse agent semantic match response for {}", job.finding_id)
        })?;
    let score = score_row_from_agent_match(&job, match_response)?;

    Ok(AgentScoringOutput {
        index: job.index,
        scores: vec![score],
        usage,
    })
}

fn score_row_from_agent_match(
    job: &AgentScoringJob,
    match_response: AgentSemanticMatchResponse,
) -> Result<SemanticScoreRow> {
    let candidate_ids = candidate_subset_for_job(job)
        .into_iter()
        .map(|finding| finding.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut invalid_ids = Vec::new();
    let mut matched_corpus_ids = BTreeSet::new();
    for id in match_response.matched_corpus_ids {
        if candidate_ids.contains(id.as_str()) {
            matched_corpus_ids.insert(id);
        } else {
            invalid_ids.push(id);
        }
    }
    if !invalid_ids.is_empty() {
        bail!(
            "agent semantic match for {} returned ids outside presented candidates: {}",
            job.finding_id,
            invalid_ids.join(", ")
        );
    }
    let matched_corpus_ids = matched_corpus_ids.into_iter().collect::<Vec<_>>();
    let verdict = normalize_agent_match_verdict(&match_response.verdict, &matched_corpus_ids);
    if match_response
        .verdict
        .trim()
        .eq_ignore_ascii_case("known-found")
        && matched_corpus_ids.is_empty()
    {
        bail!(
            "agent semantic match marked {} known-found without matchedCorpusIds",
            job.finding_id
        );
    }
    if verdict == "not-known" && !matched_corpus_ids.is_empty() {
        bail!(
            "agent semantic match marked {} not-known but returned matchedCorpusIds",
            job.finding_id
        );
    }
    Ok(SemanticScoreRow {
        finding_id: job.finding_id.clone(),
        verdict,
        matched_corpus_ids,
        notes: truncate_str(&match_response.notes, 500),
    })
}

fn normalize_agent_match_verdict(raw: &str, matched_corpus_ids: &[String]) -> String {
    let raw = raw.trim().to_ascii_lowercase().replace('_', "-");
    if raw == "known-found" && !matched_corpus_ids.is_empty() {
        "known-found".to_string()
    } else {
        "not-known".to_string()
    }
}

fn add_scoring_usage(totals: &mut ScoringUsageTotals, response: &LlmResponse) {
    totals.input_tokens += response.usage.input_tokens.max(0) as u64;
    totals.output_tokens += response.usage.output_tokens.max(0) as u64;
    totals.reasoning_tokens += response.usage.reasoning_output_tokens.max(0) as u64;
    totals.cached_input_tokens += response.usage.cache_read_input_tokens.max(0) as u64;
    totals.provider_total_tokens = totals.input_tokens + totals.output_tokens;
}

async fn run_child(args: Args) -> Result<()> {
    let task_id = args
        .single_task
        .clone()
        .expect("single_task required in child mode");
    let run_dir = args
        .output_dir
        .clone()
        .ok_or_else(|| anyhow::anyhow!("child requires --output-dir"))?;
    let workspace_root = args.workspace_root.clone();

    let task = if let Some(task_spec) = &args.task_spec {
        let raw = fs::read_to_string(task_spec)
            .with_context(|| format!("read {}", task_spec.display()))?;
        let task: AgentTaskSpec =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", task_spec.display()))?;
        if task.task_id != task_id {
            bail!(
                "task spec {} contains {}, expected {}",
                task_spec.display(),
                task.task_id,
                task_id
            );
        }
        WardenTask::from(task)
    } else {
        let workspace_root = workspace_root.as_ref().ok_or_else(|| {
            anyhow::anyhow!("child requires --workspace-root without --task-spec")
        })?;
        let corpus = load_corpus(&args.corpus)?;
        build_tasks(&corpus, workspace_root)?
            .into_iter()
            .find(|task| task.task_id == task_id)
            .ok_or_else(|| anyhow::anyhow!("task {task_id} not in corpus"))?
    };
    let (provider, provider_kind, resolved_model) = resolve_provider(&args)?;
    delete_lash_config_after_provider_load()?;
    let execution_mode = parse_execution_mode(&args.execution_mode)?;
    let standard_context_approach = resolve_standard_context_approach(
        execution_mode,
        args.standard_context_approach.as_deref(),
    )?;

    let result = run_task(
        RunTaskContext {
            run_dir: &run_dir,
            workspace_root: workspace_root.as_deref(),
            prepared_repo: args.prepared_repo.as_deref(),
            provider: &provider,
            provider_kind: &provider_kind,
            args: &args,
            model: &resolved_model,
            execution_mode,
            standard_context_approach: standard_context_approach.as_ref(),
        },
        &task,
    )
    .await
    .with_context(|| format!("run {task_id}"))?;

    eprintln!(
        "child[{}] status={} iters={} t={:.1}s",
        result.task_id, result.status, result.iterations, result.elapsed_seconds
    );
    Ok(())
}

async fn spawn_child(
    child_exe: &Path,
    run_dir: &Path,
    workspace_root: &Path,
    args: &Args,
    task: &WardenTask,
) -> Result<TaskResult> {
    match args.isolation {
        ChildIsolation::Docker => {
            spawn_docker_child(child_exe, run_dir, workspace_root, args, task).await
        }
        ChildIsolation::HostUnsafe => {
            spawn_host_child(child_exe, run_dir, workspace_root, args, task).await
        }
    }
}

async fn spawn_host_child(
    child_exe: &Path,
    run_dir: &Path,
    workspace_root: &Path,
    args: &Args,
    task: &WardenTask,
) -> Result<TaskResult> {
    let task_dir = run_dir.join("tasks").join(&task.task_id);
    fs::create_dir_all(&task_dir).with_context(|| format!("create {}", task_dir.display()))?;
    let task_spec = write_agent_task_spec(&task_dir, task)?;

    let mut cmd = tokio::process::Command::new(child_exe);
    cmd.arg("--single-task").arg(&task.task_id);
    cmd.arg("--task-spec").arg(&task_spec);
    cmd.arg("--workspace-root").arg(workspace_root);
    cmd.arg("--output-dir").arg(run_dir);
    if let Some(variant) = args.variant.as_deref() {
        cmd.arg("--variant").arg(variant);
    }
    cmd.arg("--execution-mode").arg(&args.execution_mode);
    if let Some(approach) = &args.standard_context_approach {
        cmd.arg("--standard-context-approach").arg(approach);
    }
    cmd.arg("--max-turns").arg(args.max_turns.to_string());
    cmd.arg("--max-context-tokens")
        .arg(args.max_context_tokens.to_string());
    cmd.arg("--max-task-provider-total-tokens")
        .arg(args.max_task_provider_total_tokens.to_string());
    if args.keep_worktrees {
        cmd.arg("--keep-worktrees");
    }
    if let Some(model) = args.model.as_deref() {
        cmd.arg("--model").arg(model);
    }
    if let Some(provider_id) = args.provider_id.as_deref() {
        cmd.arg("--provider-id").arg(provider_id);
    }
    if let Some(rate) = args.input_cost_per_mtok {
        cmd.arg("--input-cost-per-mtok").arg(rate.to_string());
    }
    if let Some(rate) = args.output_cost_per_mtok {
        cmd.arg("--output-cost-per-mtok").arg(rate.to_string());
    }
    if let Some(rate) = args.cached_input_cost_per_mtok {
        cmd.arg("--cached-input-cost-per-mtok")
            .arg(rate.to_string());
    }
    if let Some(rate) = args.reasoning_cost_per_mtok {
        cmd.arg("--reasoning-cost-per-mtok").arg(rate.to_string());
    }
    let stdout_path = task_dir.join("child.stdout.log");
    let stdout_file = std::fs::File::create(&stdout_path)
        .with_context(|| format!("create {}", stdout_path.display()))?;
    cmd.stdout(std::process::Stdio::from(stdout_file));
    let stderr_path = task_dir.join("child.stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path)
        .with_context(|| format!("create {}", stderr_path.display()))?;
    cmd.stderr(std::process::Stdio::from(stderr_file));
    cmd.kill_on_drop(true);

    let status = cmd
        .status()
        .await
        .with_context(|| format!("spawn child for {}", task.task_id))?;
    if !status.success() {
        let tail = read_tail(&stderr_path, 80).unwrap_or_default();
        bail!(
            "child exited with {} - last stderr lines:\n{}",
            status,
            tail
        );
    }

    let result_path = task_dir.join("result.json");
    let raw = fs::read_to_string(&result_path)
        .with_context(|| format!("read {}", result_path.display()))?;
    let result: TaskResult =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", result_path.display()))?;
    Ok(result)
}

async fn spawn_docker_child(
    child_exe: &Path,
    run_dir: &Path,
    workspace_root: &Path,
    args: &Args,
    task: &WardenTask,
) -> Result<TaskResult> {
    let task_dir = run_dir.join("tasks").join(&task.task_id);
    fs::create_dir_all(&task_dir).with_context(|| format!("create {}", task_dir.display()))?;
    let _task_spec = write_agent_task_spec(&task_dir, task)?;

    let worktree_dir = run_dir
        .join("docker-worktrees")
        .join(&task.task_id)
        .join("repo");
    let checkout_guard = GIT_WORKTREE_MUTEX.lock().await;
    checkout_task(workspace_root, &worktree_dir, task)
        .with_context(|| format!("checkout {} for docker", task.task_id))?;
    drop(checkout_guard);

    let secrets_dir = prepare_docker_lash_home(run_dir, task)?;
    let secrets_parent = secrets_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| secrets_dir.clone());
    let stderr_path = task_dir.join("child.stderr.log");
    let stderr_file = std::fs::File::create(&stderr_path)
        .with_context(|| format!("create {}", stderr_path.display()))?;

    let task_container_dir = format!("{CHILD_CONTAINER_RUN_DIR}/tasks/{}", task.task_id);
    let task_spec_container = format!("{task_container_dir}/task.json");
    let (uid, gid) = current_uid_gid()?;
    let mut cmd = tokio::process::Command::new("docker");
    cmd.arg("run")
        .arg("--rm")
        .arg("--read-only")
        .arg("--cap-drop")
        .arg("ALL")
        .arg("--security-opt")
        .arg("no-new-privileges")
        .arg("--pids-limit")
        .arg("256")
        .arg("--label")
        .arg("org.lash.benchmark=warden-sentry")
        .arg("--label")
        .arg(format!(
            "org.lash.benchmark.run-id={}",
            docker_run_label(run_dir)
        ))
        .arg("--label")
        .arg(format!("org.lash.benchmark.task-id={}", task.task_id))
        .arg("--tmpfs")
        .arg("/tmp:rw,exec,nosuid,mode=1777,size=1g")
        .arg("--user")
        .arg(format!("{uid}:{gid}"))
        .arg("-e")
        .arg(format!("LASH_HOME={CHILD_CONTAINER_LASH_HOME}"))
        .arg("-e")
        .arg("HOME=/tmp")
        .arg("-e")
        .arg(format!("{DELETE_LASH_CONFIG_ENV}=1"))
        .arg("-v")
        .arg(format!("{}:{CHILD_CONTAINER_BIN}:ro", child_exe.display()))
        .arg("-v")
        .arg(format!(
            "{}:{CHILD_CONTAINER_REPO_DIR}:ro",
            worktree_dir.display()
        ))
        .arg("-v")
        .arg(format!("{}:{task_container_dir}:rw", task_dir.display()))
        .arg("-v")
        .arg(format!(
            "{}:{CHILD_CONTAINER_LASH_HOME}:rw",
            secrets_dir.display()
        ))
        .arg("-w")
        .arg(CHILD_CONTAINER_REPO_DIR)
        .arg(&args.docker_image)
        .arg(CHILD_CONTAINER_BIN)
        .arg("--single-task")
        .arg(&task.task_id)
        .arg("--task-spec")
        .arg(&task_spec_container)
        .arg("--prepared-repo")
        .arg(CHILD_CONTAINER_REPO_DIR)
        .arg("--output-dir")
        .arg(CHILD_CONTAINER_RUN_DIR);
    append_child_common_args(&mut cmd, args);
    let stdout_path = task_dir.join("child.stdout.log");
    let stdout_file = std::fs::File::create(&stdout_path)
        .with_context(|| format!("create {}", stdout_path.display()))?;
    cmd.stdout(std::process::Stdio::from(stdout_file));
    cmd.stderr(std::process::Stdio::from(stderr_file));
    cmd.kill_on_drop(true);

    let status_result = cmd
        .status()
        .await
        .with_context(|| format!("spawn docker child for {}", task.task_id));

    fs::remove_dir_all(&secrets_parent).ok();
    let status = status_result?;
    if !args.keep_worktrees {
        let _ = remove_worktree(workspace_root, task, &worktree_dir);
        if let Some(task_worktree_parent) = worktree_dir.parent() {
            fs::remove_dir(task_worktree_parent).ok();
        }
    }

    if !status.success() {
        let tail = read_tail(&stderr_path, 120).unwrap_or_default();
        bail!(
            "docker child exited with {} - last stderr lines:\n{}",
            status,
            tail
        );
    }

    let result_path = task_dir.join("result.json");
    let raw = fs::read_to_string(&result_path)
        .with_context(|| format!("read {}", result_path.display()))?;
    let result: TaskResult =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", result_path.display()))?;
    Ok(result)
}

fn append_child_common_args(cmd: &mut tokio::process::Command, args: &Args) {
    if let Some(variant) = args.variant.as_deref() {
        cmd.arg("--variant").arg(variant);
    }
    cmd.arg("--execution-mode").arg(&args.execution_mode);
    if let Some(approach) = &args.standard_context_approach {
        cmd.arg("--standard-context-approach").arg(approach);
    }
    cmd.arg("--max-turns").arg(args.max_turns.to_string());
    cmd.arg("--max-context-tokens")
        .arg(args.max_context_tokens.to_string());
    cmd.arg("--max-task-provider-total-tokens")
        .arg(args.max_task_provider_total_tokens.to_string());
    if args.keep_worktrees {
        cmd.arg("--keep-worktrees");
    }
    if let Some(model) = args.model.as_deref() {
        cmd.arg("--model").arg(model);
    }
    if let Some(provider_id) = args.provider_id.as_deref() {
        cmd.arg("--provider-id").arg(provider_id);
    }
    if let Some(rate) = args.input_cost_per_mtok {
        cmd.arg("--input-cost-per-mtok").arg(rate.to_string());
    }
    if let Some(rate) = args.output_cost_per_mtok {
        cmd.arg("--output-cost-per-mtok").arg(rate.to_string());
    }
    if let Some(rate) = args.cached_input_cost_per_mtok {
        cmd.arg("--cached-input-cost-per-mtok")
            .arg(rate.to_string());
    }
    if let Some(rate) = args.reasoning_cost_per_mtok {
        cmd.arg("--reasoning-cost-per-mtok").arg(rate.to_string());
    }
}

fn cleanup_active_children(
    run_dir: &Path,
    run_log: &Arc<Mutex<File>>,
    keep_worktrees: bool,
) -> Result<()> {
    let removed = cleanup_active_docker_children(run_dir)?;
    if removed > 0 {
        log_run(
            run_log,
            format!("  cleanup: removed {removed} active Docker child container(s)"),
        )?;
    }
    fs::remove_dir_all(run_dir.join("docker-secrets")).ok();
    if !keep_worktrees {
        fs::remove_dir_all(run_dir.join("docker-worktrees")).ok();
    }
    Ok(())
}

fn cleanup_active_docker_children(run_dir: &Path) -> Result<usize> {
    let run_label = format!("org.lash.benchmark.run-id={}", docker_run_label(run_dir));
    let output = Command::new("docker")
        .arg("ps")
        .arg("-aq")
        .arg("--filter")
        .arg("label=org.lash.benchmark=warden-sentry")
        .arg("--filter")
        .arg(format!("label={run_label}"))
        .output();
    let output = match output {
        Ok(output) => output,
        Err(_) => return Ok(0),
    };
    if !output.status.success() {
        return Ok(0);
    }
    let ids = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Ok(0);
    }

    let status = Command::new("docker")
        .arg("rm")
        .arg("-f")
        .args(&ids)
        .status()
        .with_context(|| "spawn docker rm -f for active benchmark children")?;
    if !status.success() {
        bail!("docker rm -f failed with {status}");
    }
    Ok(ids.len())
}

fn docker_run_label(run_dir: &Path) -> String {
    run_dir
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| safe_path_segment(&run_dir.display().to_string()))
}

fn write_agent_task_spec(task_dir: &Path, task: &WardenTask) -> Result<PathBuf> {
    let path = task_dir.join("task.json");
    fs::write(
        &path,
        serde_json::to_string_pretty(&AgentTaskSpec::from(task))?,
    )
    .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

fn prepare_docker_lash_home(run_dir: &Path, task: &WardenTask) -> Result<PathBuf> {
    let secrets_dir = run_dir
        .join("docker-secrets")
        .join(&task.task_id)
        .join("lash");
    if secrets_dir.exists() {
        fs::remove_dir_all(&secrets_dir)
            .with_context(|| format!("remove {}", secrets_dir.display()))?;
    }
    fs::create_dir_all(&secrets_dir)
        .with_context(|| format!("create {}", secrets_dir.display()))?;
    let source = bench_common::lash_home().join("config.json");
    let dest = secrets_dir.join("config.json");
    fs::copy(&source, &dest)
        .with_context(|| format!("copy {} -> {}", source.display(), dest.display()))?;
    Ok(secrets_dir)
}

fn delete_lash_config_after_provider_load() -> Result<()> {
    if std::env::var_os(DELETE_LASH_CONFIG_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return Ok(());
    }
    let config_path = bench_common::lash_home().join("config.json");
    if config_path.exists() {
        fs::remove_file(&config_path)
            .with_context(|| format!("remove {}", config_path.display()))?;
    }
    Ok(())
}

fn ensure_docker_image(image: &str) -> Result<()> {
    let inspect = Command::new("docker")
        .args(["image", "inspect", image])
        .output()
        .with_context(|| "spawn docker image inspect")?;
    if inspect.status.success() {
        return Ok(());
    }

    let bench_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("resolve bench/warden-sentry directory"))?
        .to_path_buf();
    let dockerfile = bench_dir.join("Dockerfile");
    eprintln!(
        "  docker-build:     {} from {}",
        image,
        dockerfile.display()
    );
    let output = Command::new("docker")
        .args(["build", "-t", image, "-f"])
        .arg(&dockerfile)
        .arg(&bench_dir)
        .output()
        .with_context(|| "spawn docker build")?;
    if !output.status.success() {
        bail!(
            "docker build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn current_uid_gid() -> Result<(String, String)> {
    let uid = command_stdout("id", &["-u"])?;
    let gid = command_stdout("id", &["-g"])?;
    Ok((uid.trim().to_string(), gid.trim().to_string()))
}

fn command_stdout(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("spawn {program} {args:?}"))?;
    if !output.status.success() {
        bail!(
            "{program} {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn run_task(ctx: RunTaskContext<'_>, task: &WardenTask) -> Result<TaskResult> {
    let RunTaskContext {
        run_dir,
        workspace_root,
        prepared_repo,
        provider,
        provider_kind,
        args,
        model,
        execution_mode,
        standard_context_approach,
    } = ctx;
    let started_at = Utc::now();
    let started_instant = Instant::now();

    let task_dir = run_dir.join("tasks").join(&task.task_id);
    fs::create_dir_all(&task_dir).with_context(|| format!("create {}", task_dir.display()))?;

    let checkout_started = Instant::now();
    let repo_dir = if let Some(prepared_repo) = prepared_repo {
        let repo_dir = fs::canonicalize(prepared_repo)
            .with_context(|| format!("canonicalize {}", prepared_repo.display()))?;
        let target = repo_dir.join(&task.target_path);
        if !target.exists() {
            bail!("target file {} missing in prepared repo", task.target_path);
        }
        repo_dir
    } else {
        let repo_dir = fs::canonicalize(&task_dir)
            .with_context(|| format!("canonicalize {}", task_dir.display()))?
            .join("repo");
        let workspace_root = workspace_root.ok_or_else(|| {
            anyhow::anyhow!("run_task requires workspace_root without prepared_repo")
        })?;
        checkout_task(workspace_root, &repo_dir, task)
            .with_context(|| format!("checkout {}", task.task_id))?;
        repo_dir
    };
    let checkout_seconds = checkout_started.elapsed().as_secs_f64();

    let prompt = build_prompt(task);
    fs::write(task_dir.join("prompt.txt"), &prompt)
        .with_context(|| format!("write {}", task_dir.join("prompt.txt").display()))?;
    fs::write(
        task_dir.join("task.json"),
        serde_json::to_string_pretty(&AgentTaskSpec::from(task))?,
    )
    .with_context(|| format!("write {}", task_dir.join("task.json").display()))?;

    let store_path = task_dir.join("session.db");
    let trace_path = task_dir.join("session.trace.jsonl");
    let events_path = task_dir.join("events.jsonl");
    let store = Arc::new(
        Store::open(&store_path)
            .await
            .with_context(|| format!("open {}", store_path.display()))?,
    );

    std::env::set_current_dir(&repo_dir)
        .with_context(|| format!("cd into {}", repo_dir.display()))?;
    let sink = Arc::new(InstanceEventSink::new(events_path.clone())?);
    let turn_started = Instant::now();
    let telemetry = match execution_mode {
        ExecutionMode::Standard => {
            let mut builder = LashCore::standard_builder()
                .provider(provider.clone())
                .model(model_spec(
                    model.to_string(),
                    args.variant.clone(),
                    args.max_context_tokens,
                    None,
                )?)
                .max_turns(args.max_turns)
                .plugins(build_standard_plugin_stack(
                    standard_context_approach.cloned(),
                ));
            builder = builder.trace_jsonl_path(trace_path.clone());
            let core = builder
                .advanced()
                .runtime_host_config(lash::durability::RuntimeHostConfig::in_memory())
                .build()?;
            let session = core
                .session("root")
                .store(store.clone() as Arc<dyn RuntimePersistence>)
                .open()
                .await?;
            run_turn_on_session(
                &session,
                &prompt,
                sink.as_ref(),
                false,
                args.max_task_provider_total_tokens,
            )
            .await?
        }
        ExecutionMode::Rlm => {
            let rlm_factory = RlmProtocolPluginFactory::new(
                RlmProtocolPluginConfig::default(),
                Arc::new(lash_lashlang_runtime::InMemoryLashlangArtifactStore::new()),
            );
            let mut builder = LashCore::rlm_builder(rlm_factory)
                .provider(provider.clone())
                .model(model_spec(
                    model.to_string(),
                    args.variant.clone(),
                    args.max_context_tokens,
                    None,
                )?)
                .max_turns(args.max_turns)
                .plugins(build_rlm_plugin_stack());
            builder = builder.trace_jsonl_path(trace_path.clone());
            let core = builder
                .advanced()
                .runtime_host_config(lash::durability::RuntimeHostConfig::in_memory())
                .build()?;
            let session = core
                .session("root")
                .store(store.clone() as Arc<dyn RuntimePersistence>)
                .open()
                .await?;
            run_turn_on_session(
                &session,
                &prompt,
                sink.as_ref(),
                true,
                args.max_task_provider_total_tokens,
            )
            .await?
        }
    };

    let turn_seconds = turn_started.elapsed().as_secs_f64();
    let turn_status = turn_status_label(&telemetry.outcome);
    let done_reason = done_reason_label(&telemetry.outcome);
    let status = if turn_completed(&telemetry.outcome) {
        "completed"
    } else {
        "error"
    };
    let assistant_text = sink
        .last_llm_response()
        .or_else(|| non_empty(&telemetry.assistant_safe_text))
        .unwrap_or_default();
    let parsed_response_raw =
        terminal_json_value(&telemetry.outcome).or_else(|| parse_assistant_json(&assistant_text));
    let unfiltered_findings_total = findings_total(&parsed_response_raw);
    let (parsed_response, dropped_out_of_range_findings) =
        filter_parsed_response_to_chunk(parsed_response_raw, task);
    let failure_reason = telemetry.first_error.or_else(|| sink.last_error());
    let tool_breakdown = sink.tool_breakdown();
    let tool_calls = tool_breakdown.values().copied().sum::<u64>();
    let tokens = aggregate_usage(&telemetry.usage);
    let cost = PricingConfig::from_args(args).estimate(&tokens);
    let findings_total = findings_total(&parsed_response);
    let findings_by_severity = finding_breakdown(&parsed_response, "severity");
    let findings_by_confidence = finding_breakdown(&parsed_response, "confidence");
    let finished_at = Utc::now();
    let elapsed_seconds = started_instant.elapsed().as_secs_f64();

    let result = TaskResult {
        task_id: task.task_id.clone(),
        repository: task.repository.clone(),
        sha: task.sha.clone(),
        target_path: task.target_path.clone(),
        chunk_index: task.chunk.index,
        chunk_start_line: task.chunk.start_line,
        chunk_end_line: task.chunk.end_line,
        chunk_context_start_line: task.chunk.context_start_line,
        chunk_context_end_line: task.chunk.context_end_line,
        chunk_line_count: task.chunk.new_line_count,
        chunk_language: task.chunk.language.clone(),
        chunk_header: task.chunk.header.clone(),
        corpus_finding_ids: Vec::new(),
        corpus_summaries: Vec::new(),
        model: model.to_string(),
        provider_kind: provider_kind.to_string(),
        execution_mode_label: execution_mode.label().to_string(),
        status: status.to_string(),
        failure_reason,
        assistant_text,
        parsed_response,
        iterations: sink.iteration_count() as u64,
        llm_calls: sink.llm_response_count(),
        tool_calls,
        tool_breakdown,
        input_tokens: tokens.input,
        output_tokens: tokens.output,
        reasoning_tokens: tokens.reasoning,
        cached_input_tokens: tokens.cache_read,
        cache_creation_input_tokens: tokens.cache_creation,
        non_cache_input_tokens: tokens.non_cache_input,
        provider_total_tokens: tokens.provider_total,
        analysis_cost_usd: cost.analysis_usd,
        auxiliary_cost_usd: cost.auxiliary_usd,
        cost_usd: cost.total_usd,
        pricing_status: cost.status.clone(),
        cost,
        findings_total,
        unfiltered_findings_total,
        dropped_out_of_range_findings,
        findings_by_severity,
        findings_by_confidence,
        trace_jsonl: format!("tasks/{}/session.trace.jsonl", task.task_id),
        events_jsonl: format!("tasks/{}/events.jsonl", task.task_id),
        tokens,
        turn_status: turn_status.to_string(),
        done_reason: done_reason.to_string(),
        started_at: started_at.to_rfc3339(),
        finished_at: finished_at.to_rfc3339(),
        duration_ms: seconds_to_ms(elapsed_seconds),
        elapsed_seconds,
        checkout_seconds,
        turn_seconds,
    };

    fs::write(
        task_dir.join("result.json"),
        serde_json::to_string_pretty(&result)?,
    )
    .with_context(|| format!("write {}", task_dir.join("result.json").display()))?;

    if !args.keep_worktrees && prepared_repo.is_none() {
        if let Some(workspace_root) = workspace_root {
            let _ = remove_worktree(workspace_root, task, &repo_dir);
        }
    }

    Ok(result)
}

struct TurnTelemetry {
    outcome: TurnOutcome,
    assistant_safe_text: String,
    first_error: Option<String>,
    usage: SessionUsageReport,
}

async fn run_turn_on_session(
    session: &LashSession,
    prompt: &str,
    sink: &InstanceEventSink,
    require_structured_finish: bool,
    max_task_provider_total_tokens: u64,
) -> Result<TurnTelemetry> {
    let schema = require_structured_finish.then(findings_response_schema);
    run_turn_on_session_with_schema(
        session,
        prompt,
        sink,
        schema,
        max_task_provider_total_tokens,
    )
    .await
}

async fn run_turn_on_session_with_schema(
    session: &LashSession,
    prompt: &str,
    sink: &InstanceEventSink,
    finish_schema: Option<serde_json::Value>,
    max_task_provider_total_tokens: u64,
) -> Result<TurnTelemetry> {
    let cancel = tokio_util::sync::CancellationToken::new();
    sink.set_token_budget(max_task_provider_total_tokens, cancel.clone());
    let before_usage = session.usage_report();
    let mut turn = session.turn(TurnInput::text(prompt.to_string()));
    if let Some(schema) = finish_schema {
        turn = turn.require_finish_schema(schema)?;
    }
    let result = turn
        .cancel(cancel)
        .stream_to(sink)
        .await
        .context("run Warden Sentry task")?;
    let after_usage = session.usage_report();
    let usage = lash::usage::diff_usage_reports(&before_usage, &after_usage)
        .map(|rows| SessionUsageReport::from_entries(&rows))
        .map_err(anyhow::Error::msg)
        .context("diff usage reports")?;

    Ok(TurnTelemetry {
        outcome: result.outcome.clone(),
        assistant_safe_text: result.assistant_output.safe_text.clone(),
        first_error: result.errors.first().map(|e| e.message.clone()),
        usage,
    })
}

fn findings_response_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["findings"],
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "title",
                        "severity",
                        "confidence",
                        "path",
                        "start_line",
                        "description",
                        "evidence",
                        "recommendation"
                    ],
                    "properties": {
                        "title": { "type": "string" },
                        "severity": {
                            "type": "string",
                            "enum": ["low", "medium", "high"]
                        },
                        "confidence": {
                            "type": "string",
                            "enum": ["low", "medium", "high"]
                        },
                        "path": { "type": "string" },
                        "start_line": {
                            "type": "integer",
                            "minimum": 1
                        },
                        "description": { "type": "string" },
                        "evidence": { "type": "string" },
                        "recommendation": { "type": "string" }
                    }
                }
            }
        }
    })
}

fn load_corpus(path: &Path) -> Result<Corpus> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let corpus: Corpus =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    if corpus.findings.is_empty() {
        bail!("corpus {} has no findings", path.display());
    }
    Ok(corpus)
}

fn build_tasks(corpus: &Corpus, workspace_root: &Path) -> Result<Vec<WardenTask>> {
    let mut grouped: BTreeMap<(String, String, String), Vec<CorpusFinding>> = BTreeMap::new();
    for finding in &corpus.findings {
        if finding.repository != DEFAULT_REPOSITORY {
            bail!(
                "unsupported corpus repository {} for {}",
                finding.repository,
                finding.id
            );
        }
        grouped
            .entry((
                finding.repository.clone(),
                finding.sha.clone(),
                finding.code.path.clone(),
            ))
            .or_default()
            .push(finding.clone());
    }

    let mut tasks = Vec::new();
    for ((repository, sha, target_path), findings) in grouped {
        let bare_dir = workspace_root.join(bare_repo_dirname(&repository));
        ensure_bare_clone(&bare_dir, &repository)?;
        ensure_commit_present(&bare_dir, &sha)?;
        let content = read_file_at_commit(&bare_dir, &sha, &target_path)
            .with_context(|| format!("read {target_path} at {sha}"))?;
        let chunks = build_warden_chunks(&target_path, &content)?;
        for chunk in chunks {
            let chunk_findings = findings
                .iter()
                .filter(|finding| finding_overlaps_chunk(finding, &chunk))
                .cloned()
                .collect::<Vec<_>>();
            let task_id = format!(
                "{}-{}-l{}-{}",
                &sha[..8],
                safe_path_segment(&target_path),
                chunk.start_line,
                chunk.end_line
            );
            tasks.push(WardenTask {
                task_id,
                repository: repository.clone(),
                sha: sha.clone(),
                target_path: target_path.clone(),
                chunk,
                findings: chunk_findings,
            });
        }
    }
    Ok(tasks)
}

fn finding_overlaps_chunk(finding: &CorpusFinding, chunk: &WardenChunk) -> bool {
    let Some((start, end)) = parse_corpus_line_range(finding.code.lines.as_deref()) else {
        return true;
    };
    start <= chunk.end_line && end >= chunk.start_line
}

fn parse_corpus_line_range(raw: Option<&str>) -> Option<(usize, usize)> {
    static LINE_NUMBER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+").unwrap());
    let raw = raw?;
    let numbers = LINE_NUMBER_RE
        .find_iter(raw)
        .filter_map(|m| m.as_str().parse::<usize>().ok())
        .collect::<Vec<_>>();
    let start = *numbers.first()?;
    let end = *numbers.last().unwrap_or(&start);
    Some((start.min(end), start.max(end)))
}

fn select_tasks(mut tasks: Vec<WardenTask>, args: &Args) -> Vec<WardenTask> {
    if !args.task_id.is_empty() {
        let wanted: BTreeSet<&str> = args.task_id.iter().map(String::as_str).collect();
        tasks.retain(|task| wanted.contains(task.task_id.as_str()));
    }
    if !args.finding_id.is_empty() {
        let wanted: BTreeSet<&str> = args.finding_id.iter().map(String::as_str).collect();
        tasks.retain(|task| {
            task.findings
                .iter()
                .any(|finding| wanted.contains(finding.id.as_str()))
        });
    }
    if !args.sha.is_empty() {
        let wanted: BTreeSet<&str> = args.sha.iter().map(String::as_str).collect();
        tasks.retain(|task| wanted.contains(task.sha.as_str()));
    }
    if !args.target_path.is_empty() {
        let wanted: BTreeSet<&str> = args.target_path.iter().map(String::as_str).collect();
        tasks.retain(|task| wanted.contains(task.target_path.as_str()));
    }
    if args.offset > 0 {
        tasks = tasks.into_iter().skip(args.offset).collect();
    }
    if let Some(limit) = args.limit {
        tasks.truncate(limit);
    }
    tasks
}

fn build_prompt(task: &WardenTask) -> String {
    format!(
        "{SECURITY_REVIEW_PROMPT}\n## Benchmark target\n\nRepository: {repository}\nCommit: {sha}\nTarget file: {target_path}\nHunk line range: {start_line}-{end_line}\n\n{hunk}\n\nStart by reading `{target_path}` from the current working directory if you need more context. Report only findings anchored to lines {start_line}-{end_line} in `{target_path}`.\n",
        repository = task.repository,
        sha = task.sha,
        target_path = task.target_path,
        start_line = task.chunk.start_line,
        end_line = task.chunk.end_line,
        hunk = format_hunk_for_analysis(task),
    )
}

fn format_hunk_for_analysis(task: &WardenTask) -> String {
    let chunk = &task.chunk;
    let mut lines = Vec::new();
    lines.push(format!("## File: {}", task.target_path));
    lines.push(format!("## Language: {}", chunk.language));
    lines.push(format!(
        "## Hunk: lines {}-{}",
        chunk.start_line, chunk.end_line
    ));
    if let Some(header) = &chunk.header {
        lines.push(format!("## Scope: {header}"));
    }
    lines.push(String::new());
    if !chunk.context_before.is_empty() {
        lines.push(format!(
            "### Context Before (lines {}-{})",
            chunk.context_start_line,
            chunk.start_line.saturating_sub(1)
        ));
        lines.push(format!("```{}", chunk.language));
        lines.push(chunk.context_before.join("\n"));
        lines.push("```".to_string());
        lines.push(String::new());
    }
    lines.push("### Changes".to_string());
    lines.push("```diff".to_string());
    lines.push(chunk.hunk_content.clone());
    lines.push("```".to_string());
    lines.push(String::new());
    if !chunk.context_after.is_empty() {
        let after_start = chunk.start_line + chunk.new_line_count;
        let after_end = after_start + chunk.context_after.len() - 1;
        lines.push(format!(
            "### Context After (lines {after_start}-{after_end})"
        ));
        lines.push(format!("```{}", chunk.language));
        lines.push(chunk.context_after.join("\n"));
        lines.push("```".to_string());
    }
    lines.join("\n")
}

fn build_warden_chunks(filename: &str, content: &str) -> Result<Vec<WardenChunk>> {
    let file_lines = content.split('\n').map(str::to_string).collect::<Vec<_>>();
    let output = run_upstream_warden_bridge(serde_json::json!({
        "mode": "chunkFile",
        "filename": filename,
        "content": content,
        "maxGapLines": WARDEN_MAX_GAP_LINES,
        "maxChunkSize": WARDEN_MAX_CHUNK_SIZE,
    }))
    .with_context(|| format!("run upstream Warden chunk bridge for {filename}"))?;
    let hunks = serde_json::from_value::<Vec<DiffHunk>>(
        output
            .get("hunks")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("upstream Warden chunk bridge omitted hunks"))?,
    )
    .with_context(|| format!("parse upstream Warden hunks for {filename}"))?;
    if hunks.is_empty()
        || hunks
            .iter()
            .all(|hunk| hunk.new_count == 0 && hunk.old_count == 0)
    {
        bail!("{filename} produced no analyzable Warden hunks");
    }
    Ok(hunks
        .into_iter()
        .enumerate()
        .map(|(index, hunk)| expand_hunk_context(filename, &file_lines, hunk, index + 1))
        .collect())
}

fn expand_hunk_context(
    filename: &str,
    file_lines: &[String],
    hunk: DiffHunk,
    index: usize,
) -> WardenChunk {
    let start_line = hunk.new_start;
    let end_line = hunk.new_start + hunk.new_count - 1;
    let context_start_line = start_line.saturating_sub(WARDEN_CONTEXT_LINES).max(1);
    let context_end_line = end_line + WARDEN_CONTEXT_LINES;
    let context_before =
        read_line_range(file_lines, context_start_line, start_line.saturating_sub(1));
    let context_after = read_line_range(file_lines, start_line + hunk.new_count, context_end_line);
    let context_end_line = if context_after.is_empty() {
        end_line
    } else {
        start_line + hunk.new_count + context_after.len() - 1
    };
    WardenChunk {
        index,
        start_line,
        end_line,
        old_start_line: hunk.old_start,
        old_line_count: hunk.old_count,
        new_line_count: hunk.new_count,
        context_start_line,
        context_end_line,
        language: detect_language(filename),
        header: hunk.header,
        hunk_content: hunk.content,
        context_before,
        context_after,
    }
}

fn read_line_range(file_lines: &[String], start_line: usize, end_line: usize) -> Vec<String> {
    if start_line == 0 || end_line < start_line || file_lines.is_empty() {
        return Vec::new();
    }
    let start = start_line.saturating_sub(1);
    let end = end_line.min(file_lines.len());
    if start >= end {
        return Vec::new();
    }
    file_lines[start..end].to_vec()
}

fn detect_language(filename: &str) -> String {
    match filename
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "ts" | "tsx" => "typescript",
        "js" | "jsx" => "javascript",
        "py" => "python",
        "rb" => "ruby",
        "go" => "go",
        "rs" => "rust",
        "java" => "java",
        "kt" => "kotlin",
        "cs" => "csharp",
        "cpp" | "hpp" => "cpp",
        "c" | "h" => "c",
        "swift" => "swift",
        "php" => "php",
        "sh" | "bash" | "zsh" => "bash",
        "yml" | "yaml" => "yaml",
        "json" => "json",
        "toml" => "toml",
        "md" => "markdown",
        "sql" => "sql",
        "html" => "html",
        "css" => "css",
        "scss" => "scss",
        "less" => "less",
        other => other,
    }
    .to_string()
}

fn corpus_by_sha(corpus: &Corpus) -> BTreeMap<String, Vec<CorpusFinding>> {
    let mut out: BTreeMap<String, Vec<CorpusFinding>> = BTreeMap::new();
    for finding in &corpus.findings {
        out.entry(finding.sha.clone())
            .or_default()
            .push(finding.clone());
    }
    out
}

fn selected_corpus_ids_for_results(corpus: &Corpus, results: &[TaskResult]) -> BTreeSet<String> {
    results
        .iter()
        .flat_map(|result| {
            corpus
                .findings
                .iter()
                .filter(move |finding| finding_matches_result_chunk(finding, result))
                .map(|finding| finding.id.clone())
        })
        .collect()
}

fn finding_matches_result_chunk(finding: &CorpusFinding, result: &TaskResult) -> bool {
    if finding.repository != result.repository
        || finding.sha != result.sha
        || finding.code.path != result.target_path
    {
        return false;
    }
    let Some((start, end)) = parse_corpus_line_range(finding.code.lines.as_deref()) else {
        return true;
    };
    start <= result.chunk_end_line && end >= result.chunk_start_line
}

fn corpus_id_to_short_sha(corpus: &Corpus) -> BTreeMap<String, String> {
    corpus
        .findings
        .iter()
        .map(|finding| (finding.id.clone(), finding.sha[..8].to_string()))
        .collect()
}

fn run_id_from_summary_or_dir(run_dir: &Path) -> Result<String> {
    let summary_path = run_dir.join("summary.json");
    if summary_path.exists() {
        let raw = fs::read_to_string(&summary_path)
            .with_context(|| format!("read {}", summary_path.display()))?;
        let summary: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse {}", summary_path.display()))?;
        if let Some(run_id) = summary
            .get("runId")
            .or_else(|| summary.get("run_id"))
            .and_then(|v| v.as_str())
        {
            return Ok(run_id.to_string());
        }
    }
    Ok(run_dir
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown-run".to_string()))
}

fn ensure_warden_comparable_marker(run_dir: &Path) -> Result<()> {
    let summary_path = run_dir.join("summary.json");
    let raw = fs::read_to_string(&summary_path)
        .with_context(|| format!("read {}", summary_path.display()))?;
    let summary: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", summary_path.display()))?;
    if summary
        .get("wardenComparable")
        .and_then(|value| value.as_bool())
        == Some(true)
    {
        return Ok(());
    }
    bail!(
        "semantic scoring requires summary.json wardenComparable=true; rerun --post-process-run-dir {} and verify post-processing completed without auxiliary errors",
        run_dir.display()
    )
}

fn read_summary_started_at(run_dir: &Path) -> Result<Option<DateTime<Utc>>> {
    let summary_path = run_dir.join("summary.json");
    if !summary_path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&summary_path)
        .with_context(|| format!("read {}", summary_path.display()))?;
    let summary: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", summary_path.display()))?;
    let Some(raw_started_at) = summary
        .get("startedAt")
        .or_else(|| summary.get("started_at"))
        .and_then(|value| value.as_str())
    else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(raw_started_at)
        .with_context(|| format!("parse startedAt from {}", summary_path.display()))?
        .with_timezone(&Utc);
    Ok(Some(parsed))
}

fn emitted_findings(result: &TaskResult) -> Vec<EmittedFinding> {
    finding_values(&result.parsed_response)
        .into_iter()
        .enumerate()
        .map(|(index, value)| EmittedFinding {
            index,
            value: truncate_json_strings(value, 2_000),
        })
        .collect()
}

fn build_agent_scoring_jobs(
    results: &[TaskResult],
    corpus_by_sha: &BTreeMap<String, Vec<CorpusFinding>>,
) -> Vec<AgentScoringJob> {
    let mut jobs = Vec::new();
    for result in results {
        let candidates = corpus_by_sha.get(&result.sha).cloned().unwrap_or_default();
        for finding in emitted_findings(result) {
            let finding_id = finding_id_from_value(&finding.value)
                .unwrap_or_else(|| format!("{}#{}", result.task_id, finding.index + 1));
            jobs.push(AgentScoringJob {
                index: jobs.len(),
                sha: result.sha.clone(),
                task_id: result.task_id.clone(),
                target_path: result.target_path.clone(),
                finding_index: finding.index,
                finding_id,
                finding: finding.value,
                candidates: candidates.clone(),
            });
        }
    }
    jobs
}

fn finding_id_from_value(value: &serde_json::Value) -> Option<String> {
    value
        .get("id")
        .and_then(|value| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
}

fn apply_finalized_findings_to_results(
    results: &mut [TaskResult],
    jsonl_path: &Path,
) -> Result<()> {
    let raw =
        fs::read_to_string(jsonl_path).with_context(|| format!("read {}", jsonl_path.display()))?;
    let mut finalized: BTreeMap<(String, String, String, usize), Vec<WardenFinding>> =
        BTreeMap::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let value: serde_json::Value = serde_json::from_str(line)
            .with_context(|| format!("parse {}", jsonl_path.display()))?;
        if value.get("type").and_then(|value| value.as_str()) == Some("summary") {
            continue;
        }
        if value.get("schemaVersion").and_then(|value| value.as_u64()) != Some(1) {
            continue;
        }
        let record: WardenJsonlChunk = serde_json::from_value(value)
            .with_context(|| format!("parse chunk record from {}", jsonl_path.display()))?;
        let sha = record.run.head_sha.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "{} chunk record for {} lacks run.headSha",
                jsonl_path.display(),
                record.chunk.file
            )
        })?;
        finalized.insert(
            (
                sha,
                record.chunk.file,
                record.chunk.line_range,
                record.chunk.index,
            ),
            record.findings,
        );
    }

    for result in results {
        let key = (
            result.sha.clone(),
            result.target_path.clone(),
            format!("{}-{}", result.chunk_start_line, result.chunk_end_line),
            result.chunk_index,
        );
        let findings = finalized.remove(&key).ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no finalized chunk for {} {}:{}-{}",
                jsonl_path.display(),
                &result.sha[..8],
                result.target_path,
                result.chunk_start_line,
                result.chunk_end_line
            )
        })?;
        result.parsed_response = Some(serde_json::json!({ "findings": findings }));
        result.findings_total = findings_total(&result.parsed_response);
        result.findings_by_severity = finding_breakdown(&result.parsed_response, "severity");
        result.findings_by_confidence = finding_breakdown(&result.parsed_response, "confidence");
    }
    Ok(())
}

fn build_agent_semantic_match_prompt(job: &AgentScoringJob) -> Result<String> {
    let candidates = candidate_subset_for_job(job)
        .into_iter()
        .map(agent_corpus_candidate_value)
        .collect::<Vec<_>>();
    let candidates_json = serde_json::to_string_pretty(&candidates)?;
    let finding_json = serde_json::to_string_pretty(&job.finding)?;
    Ok(format!(
        concat!(
            "You are performing Warden's Sentry vulnerability corpus agent-semantic-match-pass.\n",
            "This is the same semantic scoring rule used in the published corpus benchmark results.\n\n",
            "Score one finalized emitted finding against existing corpus findings from the same commit.\n\n",
            "Rules:\n",
            "- Return known-found only if the emitted finding identifies the same vulnerability/root cause in roughly the same code location as one or more corpus candidates.\n",
            "- Same file but a different bug is not-known.\n",
            "- A broad finding may match multiple corpus ids only when it explicitly covers the shared root cause or explicit additional locations.\n",
            "- Ignore severity/confidence differences unless they prove the finding is about a different issue.\n",
            "- Do not award credit for generic hardening, style issues, or speculative risks.\n",
            "- matchedCorpusIds must contain only ids from the provided candidates.\n\n",
            "Commit SHA: {sha}\n",
            "Finding id: {finding_id}\n",
            "Finding origin: task={task_id}, path={target_path}, findingIndex={finding_index}\n\n",
            "Finalized emitted finding:\n",
            "{finding_json}\n\n",
            "Candidate corpus findings:\n",
            "{candidates_json}\n\n",
            "Return only JSON with: verdict, matchedCorpusIds, notes."
        ),
        sha = job.sha,
        finding_id = job.finding_id,
        task_id = job.task_id,
        target_path = job.target_path,
        finding_index = job.finding_index,
        finding_json = finding_json,
        candidates_json = candidates_json,
    ))
}

fn build_agent_semantic_match_request(args: &Args, model: &str, prompt: String) -> DirectRequest {
    let schema = DirectJsonSchema {
        name: "warden_agent_semantic_match_pass".to_string(),
        schema: agent_semantic_match_schema().into(),
        strict: true,
    };
    let mut request = DirectRequest::json_schema(model.to_string(), prompt, schema);
    request.model_variant = args.variant.clone();
    let _ = args.score_max_output_tokens;
    request
}

fn agent_semantic_match_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["verdict", "matchedCorpusIds", "notes"],
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["known-found", "not-known"]
            },
            "matchedCorpusIds": {
                "type": "array",
                "items": {"type": "string"}
            },
            "notes": {
                "type": "string"
            }
        }
    })
}

fn candidate_subset_for_job(job: &AgentScoringJob) -> Vec<&CorpusFinding> {
    let paths = finding_paths(&job.finding, &job.target_path);
    let filtered = job
        .candidates
        .iter()
        .filter(|candidate| paths.contains(&candidate.code.path))
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        job.candidates.iter().collect()
    } else {
        filtered
    }
}

fn finding_paths(finding: &serde_json::Value, fallback_path: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::from([fallback_path.to_string()]);
    if let Some(path) = finding
        .get("location")
        .and_then(|location| location.get("path"))
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
    {
        paths.insert(path.to_string());
    }
    if let Some(locations) = finding
        .get("additionalLocations")
        .and_then(|value| value.as_array())
    {
        for location in locations {
            if let Some(path) = location
                .get("path")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
            {
                paths.insert(path.to_string());
            }
        }
    }
    paths
}

fn agent_corpus_candidate_value(finding: &CorpusFinding) -> serde_json::Value {
    serde_json::json!({
        "id": finding.id.clone(),
        "summary": finding.summary.clone(),
        "path": finding.code.path.clone(),
        "lines": finding.code.lines.clone(),
        "language": finding.code.language.clone(),
        "snippet": finding.code.snippet.as_deref().map(|snippet| truncate_str(snippet, 600)),
    })
}

fn merge_scoring_usage(totals: &mut ScoringUsageTotals, other: &ScoringUsageTotals) {
    totals.input_tokens += other.input_tokens;
    totals.output_tokens += other.output_tokens;
    totals.reasoning_tokens += other.reasoning_tokens;
    totals.cached_input_tokens += other.cached_input_tokens;
    totals.cache_creation_input_tokens += other.cache_creation_input_tokens;
    totals.cache_creation_5m_input_tokens += other.cache_creation_5m_input_tokens;
    totals.cache_creation_1h_input_tokens += other.cache_creation_1h_input_tokens;
    totals.web_search_requests += other.web_search_requests;
    totals.provider_total_tokens = totals.input_tokens + totals.output_tokens;
    totals.cost_usd = round_usd(totals.cost_usd + other.cost_usd);
}

fn ratio4(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        ((numerator as f64 / denominator as f64) * 10_000.0).round() / 10_000.0
    }
}

fn update_summary_scoring(run_dir: &Path, scoring: serde_json::Value) -> Result<()> {
    let summary_path = run_dir.join("summary.json");
    let raw = fs::read_to_string(&summary_path)
        .with_context(|| format!("read {}", summary_path.display()))?;
    let mut summary: serde_json::Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", summary_path.display()))?;
    let Some(map) = summary.as_object_mut() else {
        bail!("{} does not contain a JSON object", summary_path.display());
    };
    map.insert("scoring".to_string(), scoring);
    map.insert(
        "comparisonState".to_string(),
        serde_json::Value::String("finalized-scored".to_string()),
    );
    fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)
        .with_context(|| format!("write {}", summary_path.display()))?;
    Ok(())
}

fn semantic_scoring_markdown(
    run_id: &str,
    scoring: &serde_json::Value,
    scores: &[SemanticScoreRow],
    missed_ids: &[String],
    corpus_id_to_sha: &BTreeMap<String, String>,
) -> String {
    let known_total = scoring
        .get("knownFindingCount")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    let known_found = scoring
        .get("knownFound")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    let known_found_rate = scoring
        .get("knownFoundRate")
        .and_then(|v| v.as_f64())
        .unwrap_or_default();
    let known_found_entries = scores
        .iter()
        .filter(|score| score.verdict == "known-found")
        .count();
    let not_known_entries = scores.len().saturating_sub(known_found_entries);

    let mut found_by_sha: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for id in scores
        .iter()
        .flat_map(|score| score.matched_corpus_ids.iter())
    {
        if let Some(sha) = corpus_id_to_sha.get(id) {
            found_by_sha
                .entry(sha.clone())
                .or_default()
                .insert(id.clone());
        }
    }
    let mut missed_by_sha: BTreeMap<String, u64> = BTreeMap::new();
    for id in missed_ids {
        if let Some(sha) = corpus_id_to_sha.get(id) {
            *missed_by_sha.entry(sha.clone()).or_insert(0) += 1;
        }
    }

    let mut out = String::new();
    out.push_str("# Semantic Scoring Summary\n\n");
    out.push_str(&format!("Run: `{run_id}`\n\n"));
    out.push_str("Scoring rule: Warden-style semantic match. A finding counts only when it identifies the same bug in roughly the same code location as a corpus finding.\n\n");
    out.push_str("## Headline\n\n");
    out.push_str("| Metric | Value |\n|---|---:|\n");
    out.push_str(&format!("| Emitted findings scored | {} |\n", scores.len()));
    out.push_str(&format!(
        "| Known-found score entries | {known_found_entries} |\n"
    ));
    out.push_str(&format!(
        "| Not-known score entries | {not_known_entries} |\n"
    ));
    out.push_str(&format!(
        "| Unique corpus findings found | {known_found} / {known_total} |\n"
    ));
    out.push_str(&format!(
        "| Known found rate | {:.2}% |\n",
        known_found_rate * 100.0
    ));

    out.push_str("\n## By Commit\n\n");
    out.push_str("| Commit | Found | Missed | Total |\n|---|---:|---:|---:|\n");
    let shas = found_by_sha
        .keys()
        .chain(missed_by_sha.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for sha in shas {
        let found = found_by_sha.get(&sha).map(BTreeSet::len).unwrap_or(0) as u64;
        let missed = missed_by_sha.get(&sha).copied().unwrap_or(0);
        out.push_str(&format!(
            "| `{sha}` | {found} | {missed} | {} |\n",
            found + missed
        ));
    }

    out.push_str("\n## Missed Corpus IDs\n\n");
    if missed_ids.is_empty() {
        out.push_str("(none)\n");
    } else {
        out.push_str(
            &missed_ids
                .iter()
                .map(|id| format!("`{id}`"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push('\n');
    }

    out.push_str("\n## Not-Known Emitted Findings\n\n");
    let not_known = scores
        .iter()
        .filter(|score| score.verdict == "not-known")
        .collect::<Vec<_>>();
    if not_known.is_empty() {
        out.push_str("(none)\n");
    } else {
        for score in not_known {
            out.push_str(&format!("- `{}`: {}\n", score.finding_id, score.notes));
        }
    }
    out
}

fn truncate_json_strings(value: &serde_json::Value, max_chars: usize) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(truncate_str(s, max_chars)),
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|value| truncate_json_strings(value, max_chars))
                .collect(),
        ),
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), truncate_json_strings(value, max_chars)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn truncate_str(value: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= max_chars {
            out.push_str("...");
            return out;
        }
        out.push(ch);
    }
    out
}

fn checkout_task(workspace_root: &Path, repo_dir: &Path, task: &WardenTask) -> Result<()> {
    let bare_dir = workspace_root.join(bare_repo_dirname(&task.repository));
    ensure_bare_clone(&bare_dir, &task.repository)?;
    ensure_commit_present(&bare_dir, &task.sha)?;
    let _ = run_git(
        &bare_dir,
        &[
            "worktree",
            "remove",
            "--force",
            &repo_dir.display().to_string(),
        ],
    );
    let _ = run_git(&bare_dir, &["worktree", "prune"]);
    if repo_dir.exists() {
        fs::remove_dir_all(repo_dir).with_context(|| format!("remove {}", repo_dir.display()))?;
    }
    fs::create_dir_all(repo_dir.parent().unwrap_or(Path::new(".")))
        .with_context(|| format!("create parent of {}", repo_dir.display()))?;
    run_git(
        &bare_dir,
        &[
            "worktree",
            "add",
            "--detach",
            "-f",
            &repo_dir.display().to_string(),
            &task.sha,
        ],
    )
    .with_context(|| format!("git worktree add {}", task.sha))?;

    let target = repo_dir.join(&task.target_path);
    if !target.exists() {
        bail!("target file {} missing in {}", task.target_path, task.sha);
    }
    Ok(())
}

fn remove_worktree(workspace_root: &Path, task: &WardenTask, repo_dir: &Path) -> Result<()> {
    let bare_dir = workspace_root.join(bare_repo_dirname(&task.repository));
    if !repo_dir.exists() {
        return Ok(());
    }
    let _ = run_git(
        &bare_dir,
        &[
            "worktree",
            "remove",
            "--force",
            &repo_dir.display().to_string(),
        ],
    );
    if repo_dir.exists() {
        fs::remove_dir_all(repo_dir).ok();
    }
    let _ = run_git(&bare_dir, &["worktree", "prune"]);
    Ok(())
}

fn ensure_bare_clone(bare_dir: &Path, repo: &str) -> Result<()> {
    if bare_dir.join("HEAD").exists() {
        return Ok(());
    }
    fs::create_dir_all(bare_dir.parent().unwrap_or(Path::new(".")))
        .with_context(|| format!("create parent of {}", bare_dir.display()))?;
    let url = format!("https://github.com/{repo}.git");
    eprintln!("  cloning {url} -> {}", bare_dir.display());
    run_git(
        Path::new("."),
        &[
            "clone",
            "--bare",
            "--filter=blob:none",
            &url,
            &bare_dir.display().to_string(),
        ],
    )
    .with_context(|| format!("git clone {url}"))?;
    Ok(())
}

fn ensure_commit_present(bare_dir: &Path, sha: &str) -> Result<()> {
    if run_git(bare_dir, &["cat-file", "-e", &format!("{sha}^{{commit}}")]).is_ok() {
        return Ok(());
    }
    run_git(bare_dir, &["fetch", "--filter=blob:none", "origin", sha])
        .or_else(|_| run_git(bare_dir, &["fetch", "--filter=blob:none", "origin"]))
        .with_context(|| format!("fetch {sha}"))?;
    run_git(bare_dir, &["cat-file", "-e", &format!("{sha}^{{commit}}")])
        .with_context(|| format!("commit {sha} still missing after fetch"))?;
    Ok(())
}

fn read_file_at_commit(bare_dir: &Path, sha: &str, target_path: &str) -> Result<String> {
    run_git(bare_dir, &["show", &format!("{sha}:{target_path}")])
}

fn bare_repo_dirname(repo: &str) -> String {
    format!("{}.git", repo.replace('/', "__"))
}

fn run_git(cwd: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("spawn git {args:?} in {}", cwd.display()))?;
    if !output.status.success() {
        bail!(
            "git {args:?} in {} failed: {}",
            cwd.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn build_standard_plugin_stack(
    standard_context_approach: Option<StandardContextApproach>,
) -> PluginStack {
    let mut stack = warden_read_only_repo_tool_stack();
    push_standard_context_tools(&mut stack, standard_context_approach);
    stack
}

fn build_verification_plugin_stack() -> PluginStack {
    let mut stack = warden_read_only_repo_tool_stack();
    push_standard_context_tools(
        &mut stack,
        Some(StandardContextApproach::RollingHistory(Default::default())),
    );
    stack
}

fn build_rlm_plugin_stack() -> PluginStack {
    warden_read_only_repo_tool_stack()
}

fn warden_read_only_repo_tool_stack() -> PluginStack {
    let mut stack = PluginStack::new();
    stack.push(Arc::new(ToolOutputBudgetPluginFactory::default()));
    push_read_only_repo_tools(&mut stack);
    stack
}

fn push_standard_context_tools(
    stack: &mut PluginStack,
    standard_context_approach: Option<StandardContextApproach>,
) {
    match standard_context_approach {
        Some(StandardContextApproach::RollingHistory(config)) => {
            stack.push(Arc::new(RollingHistoryPluginFactory::new(config)));
        }
        Some(StandardContextApproach::ObservationalMemory(config)) => {
            stack.push(Arc::new(ObservationalMemoryPluginFactory::new(config)));
        }
        None => {}
    }
}

fn push_read_only_repo_tools(stack: &mut PluginStack) {
    stack.push(Arc::new(StaticPluginFactory::new(
        "read_file",
        PluginSpec::new()
            .with_tool_provider(Arc::new(read_file_provider()) as Arc<dyn ToolProvider>),
    )));
    stack.push(Arc::new(StaticPluginFactory::new(
        "glob",
        PluginSpec::new().with_tool_provider(Arc::new(glob_provider()) as Arc<dyn ToolProvider>),
    )));
    stack.push(Arc::new(StaticPluginFactory::new(
        "grep",
        PluginSpec::new().with_tool_provider(Arc::new(grep_provider()) as Arc<dyn ToolProvider>),
    )));
}

fn resolve_provider(args: &Args) -> Result<(ProviderHandle, String, String)> {
    let provider = bench_common::load_provider(args.provider_id.as_deref())?;
    let kind = provider.kind().to_string();
    let model = args
        .model
        .clone()
        .unwrap_or_else(|| bench_common::default_model_for_provider(provider.kind()).to_string());
    Ok((provider, kind, model))
}

fn parse_execution_mode(raw: &str) -> Result<ExecutionMode> {
    match raw {
        "rlm" => Ok(ExecutionMode::Rlm),
        "standard" => Ok(ExecutionMode::Standard),
        other => bail!("unsupported execution mode `{other}`"),
    }
}

fn parse_standard_context_approach(raw: &str) -> Result<StandardContextApproach> {
    match raw {
        "rolling_history" => Ok(StandardContextApproach::RollingHistory(Default::default())),
        "observational_memory" => Ok(StandardContextApproach::ObservationalMemory(
            Default::default(),
        )),
        other => bail!("unsupported context approach `{other}`"),
    }
}

fn resolve_standard_context_approach(
    execution_mode: ExecutionMode,
    raw: Option<&str>,
) -> Result<Option<StandardContextApproach>> {
    if execution_mode == ExecutionMode::Standard {
        return parse_standard_context_approach(raw.unwrap_or(DEFAULT_CONTEXT_APPROACH)).map(Some);
    }
    if raw.is_some() {
        bail!("--standard-context-approach only applies to --execution-mode standard");
    }
    Ok(None)
}

fn standard_context_approach_label(approach: &StandardContextApproach) -> &'static str {
    match approach {
        StandardContextApproach::RollingHistory(_) => "rolling_history",
        StandardContextApproach::ObservationalMemory(_) => "observational_memory",
    }
}

fn turn_completed(outcome: &TurnOutcome) -> bool {
    matches!(
        outcome,
        TurnOutcome::Finished(_) | TurnOutcome::AgentFrameSwitch { .. }
    )
}

fn turn_status_label(outcome: &TurnOutcome) -> &'static str {
    match outcome {
        TurnOutcome::Finished(_) | TurnOutcome::AgentFrameSwitch { .. } => "completed",
        TurnOutcome::Stopped(TurnStop::Cancelled) => "interrupted",
        TurnOutcome::Stopped(_) => "failed",
    }
}

fn done_reason_label(outcome: &TurnOutcome) -> &'static str {
    match outcome {
        TurnOutcome::Finished(TurnFinish::AssistantMessage { .. }) => "assistant_message",
        TurnOutcome::Finished(TurnFinish::FinalValue { .. }) => "final_value",
        TurnOutcome::Finished(TurnFinish::ToolValue { .. }) => "tool_value",
        TurnOutcome::AgentFrameSwitch { .. } => "agent_frame_switch",
        TurnOutcome::Stopped(TurnStop::Cancelled) => "cancelled",
        TurnOutcome::Stopped(TurnStop::Incomplete) => "incomplete",
        TurnOutcome::Stopped(TurnStop::InvalidInput) => "invalid_input",
        TurnOutcome::Stopped(TurnStop::MaxTurns) => "max_turns",
        TurnOutcome::Stopped(TurnStop::ToolFailure) => "tool_failure",
        TurnOutcome::Stopped(TurnStop::ProviderError) => "provider_error",
        TurnOutcome::Stopped(TurnStop::PluginAbort) => "plugin_abort",
        TurnOutcome::Stopped(TurnStop::RuntimeError) => "runtime_error",
        TurnOutcome::Stopped(TurnStop::SubmittedError { .. }) => "submitted_error",
        TurnOutcome::Stopped(TurnStop::ToolError { .. }) => "tool_error",
    }
}

fn terminal_json_value(outcome: &TurnOutcome) -> Option<serde_json::Value> {
    match outcome {
        TurnOutcome::Finished(TurnFinish::FinalValue { value })
        | TurnOutcome::Finished(TurnFinish::ToolValue { value, .. }) => Some(value.clone()),
        _ => None,
    }
}

fn aggregate_usage(report: &SessionUsageReport) -> TokenTotals {
    let mut out = TokenTotals::default();
    for row in &report.by_source_model {
        out.input += row.usage.usage.input_tokens.max(0) as u64;
        out.output += row.usage.usage.output_tokens.max(0) as u64;
        out.cache_read += row.usage.usage.cache_read_input_tokens.max(0) as u64;
        out.reasoning += row.usage.usage.reasoning_output_tokens.max(0) as u64;
    }
    out.cache = out.cache_read;
    out.non_cache_input = out.input.saturating_sub(out.cache_read);
    out.provider_total = out.input + out.output;
    out
}

fn sum_tokens<'a>(tokens: impl Iterator<Item = &'a TokenTotals>) -> TokenTotals {
    let mut out = TokenTotals::default();
    for row in tokens {
        out.input += row.input;
        out.output += row.output;
        out.reasoning += row.reasoning;
        out.cache += row.cache;
        out.cache_read += row.cache_read;
        out.cache_creation += row.cache_creation;
        out.non_cache_input += row.non_cache_input;
        out.provider_total += row.provider_total;
    }
    out
}

fn dollars(tokens: u64, per_mtok_usd: f64) -> f64 {
    tokens as f64 * per_mtok_usd / 1_000_000.0
}

fn round_usd(value: f64) -> f64 {
    (value * 1_000_000.0).round() / 1_000_000.0
}

fn seconds_to_ms(seconds: f64) -> u64 {
    (seconds.max(0.0) * 1000.0).round() as u64
}

fn findings_total(parsed: &Option<serde_json::Value>) -> u64 {
    finding_values(parsed).len() as u64
}

fn filter_parsed_response_to_chunk(
    parsed: Option<serde_json::Value>,
    task: &WardenTask,
) -> (Option<serde_json::Value>, u64) {
    let Some(value) = parsed else {
        return (None, 0);
    };
    match value {
        serde_json::Value::Object(mut map) => {
            let Some(serde_json::Value::Array(findings)) = map.remove("findings") else {
                return (Some(serde_json::Value::Object(map)), 0);
            };
            let original_len = findings.len();
            let filtered = findings
                .into_iter()
                .filter_map(|finding| normalize_and_filter_finding(finding, task))
                .collect::<Vec<_>>();
            let dropped = original_len.saturating_sub(filtered.len()) as u64;
            map.insert("findings".to_string(), serde_json::Value::Array(filtered));
            (Some(serde_json::Value::Object(map)), dropped)
        }
        serde_json::Value::Array(findings) => {
            let original_len = findings.len();
            let filtered = findings
                .into_iter()
                .filter_map(|finding| normalize_and_filter_finding(finding, task))
                .collect::<Vec<_>>();
            let dropped = original_len.saturating_sub(filtered.len()) as u64;
            (Some(serde_json::Value::Array(filtered)), dropped)
        }
        other => (Some(other), 0),
    }
}

fn normalize_and_filter_finding(
    mut finding: serde_json::Value,
    task: &WardenTask,
) -> Option<serde_json::Value> {
    normalize_finding_path(&mut finding, &task.target_path);
    normalize_finding_severity(&mut finding);
    let Some(start_line) = finding_start_line(&finding) else {
        return Some(finding);
    };
    (start_line >= task.chunk.start_line as u64 && start_line <= task.chunk.end_line as u64)
        .then_some(finding)
}

fn normalize_finding_severity(finding: &mut serde_json::Value) {
    if let Some(map) = finding.as_object_mut() {
        let Some(raw) = map.get("severity").and_then(|value| value.as_str()) else {
            return;
        };
        let normalized = match raw.trim().to_ascii_lowercase().as_str() {
            "low" => "low",
            "medium" => "medium",
            "critical" | "high" => "high",
            _ => "unspecified",
        };
        map.insert(
            "severity".to_string(),
            serde_json::Value::String(normalized.to_string()),
        );
    }
}

fn normalize_finding_path(finding: &mut serde_json::Value, target_path: &str) {
    if let Some(map) = finding.as_object_mut() {
        map.insert(
            "path".to_string(),
            serde_json::Value::String(target_path.to_string()),
        );
        if let Some(location) = map.get_mut("location").and_then(|v| v.as_object_mut()) {
            location.insert(
                "path".to_string(),
                serde_json::Value::String(target_path.to_string()),
            );
        }
    }
}

fn finding_start_line(finding: &serde_json::Value) -> Option<u64> {
    finding
        .get("start_line")
        .or_else(|| finding.get("startLine"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            finding
                .get("location")
                .and_then(|location| {
                    location
                        .get("startLine")
                        .or_else(|| location.get("start_line"))
                })
                .and_then(|v| v.as_u64())
        })
}

fn finding_breakdown(parsed: &Option<serde_json::Value>, field: &str) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for finding in finding_values(parsed) {
        let label = finding
            .get(field)
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unspecified".to_string());
        *out.entry(label).or_insert(0) += 1;
    }
    out
}

fn finding_values(parsed: &Option<serde_json::Value>) -> Vec<&serde_json::Value> {
    match parsed {
        Some(serde_json::Value::Object(map)) => map
            .get("findings")
            .and_then(|v| v.as_array())
            .map(|values| values.iter().collect())
            .unwrap_or_default(),
        Some(serde_json::Value::Array(values)) => values.iter().collect(),
        _ => Vec::new(),
    }
}

fn merge_counts(into: &mut BTreeMap<String, u64>, counts: &BTreeMap<String, u64>) {
    for (key, value) in counts {
        *into.entry(key.clone()).or_insert(0) += value;
    }
}

fn sum_costs(results: &[&TaskResult]) -> CostTotals {
    let pricing = results
        .first()
        .map(|result| result.cost.pricing.clone())
        .unwrap_or_default();
    let statuses: BTreeSet<&str> = results
        .iter()
        .map(|result| result.cost.status.as_str())
        .collect();
    let status = if statuses.len() == 1 {
        statuses
            .iter()
            .next()
            .copied()
            .unwrap_or("not_configured")
            .to_string()
    } else if statuses.is_empty() {
        "not_configured".to_string()
    } else {
        "mixed".to_string()
    };

    CostTotals {
        status,
        analysis_usd: sum_optional_usd(results.iter().map(|result| result.analysis_cost_usd)),
        auxiliary_usd: sum_optional_usd(results.iter().map(|result| result.auxiliary_cost_usd)),
        total_usd: sum_optional_usd(results.iter().map(|result| result.cost_usd)),
        pricing,
    }
}

fn sum_optional_usd(values: impl Iterator<Item = Option<f64>>) -> Option<f64> {
    let mut total = 0.0;
    let mut seen = false;
    for value in values {
        let value = value?;
        seen = true;
        total += value;
    }
    seen.then(|| round_usd(total))
}

fn percentile_ms(values: &[u64], percentile: f64) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = ((sorted.len() - 1) as f64 * percentile).round() as usize;
    sorted.get(rank).copied()
}

fn timing_stats_json(values: &[u64]) -> serde_json::Value {
    let total_ms = values.iter().sum::<u64>();
    serde_json::json!({
        "count": values.len(),
        "totalMs": total_ms,
        "minMs": values.iter().min().copied(),
        "p50Ms": percentile_ms(values, 0.50),
        "p75Ms": percentile_ms(values, 0.75),
        "p90Ms": percentile_ms(values, 0.90),
        "p95Ms": percentile_ms(values, 0.95),
        "maxMs": values.iter().max().copied(),
    })
}

fn parse_assistant_json(text: &str) -> Option<serde_json::Value> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text.trim()) {
        return Some(value);
    }
    for fenced in fenced_json_blocks(text) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&fenced) {
            return Some(value);
        }
    }
    let trimmed = text.trim();
    for (open, close) in [('{', '}'), ('[', ']')] {
        if let (Some(start), Some(end)) = (trimmed.find(open), trimmed.rfind(close)) {
            if end > start
                && let Ok(value) = serde_json::from_str::<serde_json::Value>(&trimmed[start..=end])
            {
                return Some(value);
            }
        }
    }
    None
}

fn fenced_json_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if !in_block && (trimmed.starts_with("```json") || trimmed.starts_with("```")) {
            in_block = true;
            current.clear();
            continue;
        }
        if in_block && trimmed.starts_with("```") {
            if !current.trim().is_empty() {
                out.push(current.trim().to_string());
            }
            in_block = false;
            continue;
        }
        if in_block {
            current.push_str(line);
            current.push('\n');
        }
    }
    out
}

fn non_empty(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn safe_path_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('-');
        }
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    out.trim_matches('-').chars().take(120).collect()
}

fn write_target_lists(run_dir: &Path, tasks: &[WardenTask]) -> Result<()> {
    let targets_dir = run_dir.join("targets");
    fs::create_dir_all(&targets_dir)
        .with_context(|| format!("create {}", targets_dir.display()))?;
    let mut by_sha: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for task in tasks {
        by_sha
            .entry(task.sha.clone())
            .or_default()
            .insert(task.target_path.clone());
    }
    for (sha, paths) in by_sha {
        let path = targets_dir.join(format!("targets-{}.txt", &sha[..8]));
        fs::write(
            &path,
            paths.into_iter().collect::<Vec<_>>().join("\n") + "\n",
        )
        .with_context(|| format!("write {}", path.display()))?;
    }
    Ok(())
}

fn load_completed_results(path: &Path) -> Result<BTreeMap<String, TaskResult>> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut out = BTreeMap::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let mut row: TaskResult = serde_json::from_str(line)
            .with_context(|| format!("parse row from {}", path.display()))?;
        normalize_task_result(&mut row);
        if !row.task_id.is_empty() {
            let task_id = row.task_id.clone();
            if out.insert(task_id.clone(), row).is_some() {
                bail!(
                    "{} contains duplicate task row for {}",
                    path.display(),
                    task_id
                );
            }
        }
    }
    Ok(out)
}

#[derive(Default)]
struct ResumeReconcileStats {
    imported_completed_results: usize,
    removed_non_completed_rows: usize,
    rewrote_predictions: bool,
}

fn reconcile_resume_predictions(
    run_dir: &Path,
    predictions_path: &Path,
    tasks: &[WardenTask],
) -> Result<(BTreeMap<String, TaskResult>, ResumeReconcileStats)> {
    let mut rows = load_completed_results(predictions_path)?;
    let selected_task_ids = tasks
        .iter()
        .map(|task| task.task_id.as_str())
        .collect::<BTreeSet<_>>();
    rows.retain(|task_id, _| selected_task_ids.contains(task_id.as_str()));

    let mut stats = ResumeReconcileStats::default();
    let before_retain = rows.len();
    rows.retain(|_, row| row.status == "completed");
    stats.removed_non_completed_rows = before_retain.saturating_sub(rows.len());

    for task in tasks {
        if rows.contains_key(&task.task_id) {
            continue;
        }
        let result_path = run_dir
            .join("tasks")
            .join(&task.task_id)
            .join("result.json");
        if !result_path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&result_path)
            .with_context(|| format!("read {}", result_path.display()))?;
        let mut row: TaskResult = serde_json::from_str(&raw)
            .with_context(|| format!("parse {}", result_path.display()))?;
        normalize_task_result(&mut row);
        if row.status == "completed" {
            rows.insert(task.task_id.clone(), row);
            stats.imported_completed_results += 1;
        }
    }

    if stats.imported_completed_results > 0 || stats.removed_non_completed_rows > 0 {
        rewrite_predictions(predictions_path, tasks, &rows)?;
        stats.rewrote_predictions = true;
    }

    Ok((rows, stats))
}

fn rewrite_predictions(
    path: &Path,
    tasks: &[WardenTask],
    rows: &BTreeMap<String, TaskResult>,
) -> Result<()> {
    let tmp_path = path.with_extension("jsonl.tmp");
    {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .with_context(|| format!("open {}", tmp_path.display()))?;
        for task in tasks {
            if let Some(row) = rows.get(&task.task_id) {
                writeln!(file, "{}", serde_json::to_string(row)?)
                    .with_context(|| format!("write {}", tmp_path.display()))?;
            }
        }
        file.flush()
            .with_context(|| format!("flush {}", tmp_path.display()))?;
    }
    fs::rename(&tmp_path, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

fn normalize_task_result(row: &mut TaskResult) {
    if row.tokens.cache_read == 0 && row.tokens.cache > 0 {
        row.tokens.cache_read = row.tokens.cache;
    }
    row.tokens.cache = row.tokens.cache_read;
    if row.tokens.non_cache_input == 0 {
        row.tokens.non_cache_input = row.tokens.input.saturating_sub(row.tokens.cache_read);
    }
    if row.tokens.provider_total == 0 {
        row.tokens.provider_total = row.tokens.input + row.tokens.output;
    }

    if row.input_tokens == 0 {
        row.input_tokens = row.tokens.input;
    }
    if row.output_tokens == 0 {
        row.output_tokens = row.tokens.output;
    }
    if row.reasoning_tokens == 0 {
        row.reasoning_tokens = row.tokens.reasoning;
    }
    if row.cached_input_tokens == 0 {
        row.cached_input_tokens = row.tokens.cache_read;
    }
    if row.cache_creation_input_tokens == 0 {
        row.cache_creation_input_tokens = row.tokens.cache_creation;
    }
    if row.non_cache_input_tokens == 0 {
        row.non_cache_input_tokens = row.tokens.non_cache_input;
    }
    if row.provider_total_tokens == 0 {
        row.provider_total_tokens = row.tokens.provider_total;
    }

    if row.cost.status.is_empty() {
        row.cost.status = "not_configured".to_string();
    }
    if row.pricing_status.is_empty() {
        row.pricing_status = row.cost.status.clone();
    }
    if row.duration_ms == 0 && row.elapsed_seconds > 0.0 {
        row.duration_ms = seconds_to_ms(row.elapsed_seconds);
    }
    if row.findings_total == 0 {
        row.findings_total = findings_total(&row.parsed_response);
    }
    if row.unfiltered_findings_total == 0 {
        row.unfiltered_findings_total = row.findings_total + row.dropped_out_of_range_findings;
    }
    if row.chunk_line_count == 0 && row.chunk_end_line >= row.chunk_start_line {
        row.chunk_line_count = row.chunk_end_line - row.chunk_start_line + 1;
    }
    if row.findings_by_severity.is_empty() {
        row.findings_by_severity = finding_breakdown(&row.parsed_response, "severity");
    }
    if row.findings_by_confidence.is_empty() {
        row.findings_by_confidence = finding_breakdown(&row.parsed_response, "confidence");
    }
    if row.trace_jsonl.is_empty() && !row.task_id.is_empty() {
        row.trace_jsonl = format!("tasks/{}/session.trace.jsonl", row.task_id);
    }
    if row.events_jsonl.is_empty() && !row.task_id.is_empty() {
        row.events_jsonl = format!("tasks/{}/events.jsonl", row.task_id);
    }
}

fn append_prediction(path: &Path, row: &TaskResult) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(row)?)
        .with_context(|| format!("append {}", path.display()))?;
    Ok(())
}

fn log_run(log: &Arc<Mutex<File>>, line: impl AsRef<str>) -> Result<()> {
    let line = line.as_ref();
    eprintln!("{line}");
    let mut file = log
        .lock()
        .map_err(|_| anyhow::anyhow!("run log mutex poisoned"))?;
    writeln!(file, "{line}").context("write run log")?;
    file.flush().context("flush run log")?;
    Ok(())
}

fn write_run_summary(
    run_dir: &Path,
    corpus: &Corpus,
    run_id: &str,
    model: &str,
    variant: Option<&str>,
    provider_kind: &str,
    execution_mode: &str,
    standard_context_approach: Option<&str>,
    selected_tasks: &[WardenTask],
    results: &[TaskResult],
    failed_tasks: &[(String, String)],
    max_turns: usize,
    max_context_tokens: usize,
    max_task_provider_total_tokens: u64,
    child_isolation: &str,
    docker_image: &str,
    started_at: &str,
    finished_at: &str,
    duration_seconds: f64,
) -> Result<()> {
    let summary = run_summary_value(
        corpus,
        run_id,
        model,
        variant,
        provider_kind,
        execution_mode,
        standard_context_approach,
        selected_tasks,
        results,
        failed_tasks,
        max_turns,
        max_context_tokens,
        max_task_provider_total_tokens,
        child_isolation,
        docker_image,
        started_at,
        finished_at,
        duration_seconds,
    );
    fs::write(
        run_dir.join("summary.json"),
        serde_json::to_string_pretty(&summary)?,
    )
    .with_context(|| format!("write {}", run_dir.join("summary.json").display()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_summary_value(
    corpus: &Corpus,
    run_id: &str,
    model: &str,
    variant: Option<&str>,
    provider_kind: &str,
    execution_mode: &str,
    standard_context_approach: Option<&str>,
    selected_tasks: &[WardenTask],
    results: &[TaskResult],
    failed_tasks: &[(String, String)],
    max_turns: usize,
    max_context_tokens: usize,
    max_task_provider_total_tokens: u64,
    child_isolation: &str,
    docker_image: &str,
    started_at: &str,
    finished_at: &str,
    duration_seconds: f64,
) -> serde_json::Value {
    let selected_shas: BTreeSet<&str> = selected_tasks
        .iter()
        .map(|task| task.sha.as_str())
        .collect();
    let selected_target_files: BTreeSet<(String, String)> = selected_tasks
        .iter()
        .map(|task| (task.sha.clone(), task.target_path.clone()))
        .collect();
    let result_target_files: BTreeSet<(String, String)> = results
        .iter()
        .map(|result| (result.sha.clone(), result.target_path.clone()))
        .collect();
    let selected_corpus_findings = selected_tasks
        .iter()
        .flat_map(|task| task.findings.iter().map(|finding| finding.id.clone()))
        .collect::<BTreeSet<_>>()
        .len();
    let completed_rows = results.len();
    let succeeded_rows = results
        .iter()
        .filter(|result| result.status == "completed")
        .count();
    let failed_rows = results.len().saturating_sub(succeeded_rows);
    let failed_count = failed_rows + failed_tasks.len();
    let token_totals = sum_tokens(results.iter().map(|result| &result.tokens));
    let result_refs = results.iter().collect::<Vec<_>>();
    let cost_totals = sum_costs(&result_refs);
    let mut findings_by_severity = BTreeMap::new();
    let mut findings_by_confidence = BTreeMap::new();
    let findings_total = results
        .iter()
        .map(|result| result.findings_total)
        .sum::<u64>();
    let unfiltered_findings_total = results
        .iter()
        .map(|result| result.unfiltered_findings_total)
        .sum::<u64>();
    let dropped_out_of_range_findings = results
        .iter()
        .map(|result| result.dropped_out_of_range_findings)
        .sum::<u64>();
    for result in results {
        merge_counts(&mut findings_by_severity, &result.findings_by_severity);
        merge_counts(&mut findings_by_confidence, &result.findings_by_confidence);
    }

    let task_duration_ms = results
        .iter()
        .map(|result| result.duration_ms)
        .collect::<Vec<_>>();
    let measured_wall_duration_ms = seconds_to_ms(duration_seconds);
    let task_duration_floor_ms = task_duration_ms.iter().max().copied().unwrap_or(0);
    let duration_ms = measured_wall_duration_ms.max(task_duration_floor_ms);
    let duration_seconds = duration_ms as f64 / 1000.0;
    let wall_duration_source = if measured_wall_duration_ms >= task_duration_floor_ms {
        "measured_parent_wall_clock"
    } else {
        "reconstructed_task_duration_floor"
    };
    let turn_duration_ms = results
        .iter()
        .map(|result| seconds_to_ms(result.turn_seconds))
        .collect::<Vec<_>>();
    let checkout_duration_ms = results
        .iter()
        .map(|result| seconds_to_ms(result.checkout_seconds))
        .collect::<Vec<_>>();

    let mut tasks_by_sha: BTreeMap<&str, Vec<&WardenTask>> = BTreeMap::new();
    for task in selected_tasks {
        tasks_by_sha.entry(&task.sha).or_default().push(task);
    }
    let mut results_by_sha: BTreeMap<&str, Vec<&TaskResult>> = BTreeMap::new();
    for result in results {
        results_by_sha.entry(&result.sha).or_default().push(result);
    }
    let task_sha_by_id = selected_tasks
        .iter()
        .map(|task| (task.task_id.as_str(), task.sha.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut failed_by_sha: BTreeMap<&str, u64> = BTreeMap::new();
    for (task_id, _) in failed_tasks {
        if let Some(sha) = task_sha_by_id.get(task_id.as_str()) {
            *failed_by_sha.entry(*sha).or_insert(0) += 1;
        }
    }

    let shards = tasks_by_sha
        .iter()
        .map(|(sha, tasks)| {
            let sha_value = *sha;
            let shard_results = results_by_sha.get(sha_value).cloned().unwrap_or_default();
            let shard_tokens = sum_tokens(shard_results.iter().map(|result| &result.tokens));
            let shard_cost = sum_costs(&shard_results);
            let mut shard_findings_by_severity = BTreeMap::new();
            let mut shard_findings_by_confidence = BTreeMap::new();
            let shard_findings_total = shard_results
                .iter()
                .map(|result| result.findings_total)
                .sum::<u64>();
            let shard_unfiltered_findings_total = shard_results
                .iter()
                .map(|result| result.unfiltered_findings_total)
                .sum::<u64>();
            let shard_dropped_out_of_range_findings = shard_results
                .iter()
                .map(|result| result.dropped_out_of_range_findings)
                .sum::<u64>();
            for result in &shard_results {
                merge_counts(
                    &mut shard_findings_by_severity,
                    &result.findings_by_severity,
                );
                merge_counts(
                    &mut shard_findings_by_confidence,
                    &result.findings_by_confidence,
                );
            }
            let shard_target_paths = tasks
                .iter()
                .map(|task| task.target_path.clone())
                .collect::<BTreeSet<_>>();
            let shard_target_file_count = shard_target_paths.len();
            let shard_result_target_paths = shard_results
                .iter()
                .map(|result| result.target_path.clone())
                .collect::<BTreeSet<_>>();
            let shard_files_analyzed = shard_result_target_paths.len();
            let shard_corpus_finding_count = tasks
                .iter()
                .flat_map(|task| task.findings.iter().map(|finding| finding.id.clone()))
                .collect::<BTreeSet<_>>()
                .len();
            let shard_succeeded = shard_results
                .iter()
                .filter(|result| result.status == "completed")
                .count();
            let shard_failed_rows = shard_results.len().saturating_sub(shard_succeeded);
            let shard_failed =
                shard_failed_rows + failed_by_sha.get(sha_value).copied().unwrap_or(0) as usize;
            let shard_duration_ms = shard_results
                .iter()
                .map(|result| result.duration_ms)
                .sum::<u64>();

            serde_json::json!({
                "sha": sha_value,
                "shortSha": &sha_value[..8],
                "repository": tasks.first().map(|task| task.repository.as_str()).unwrap_or(DEFAULT_REPOSITORY),
                "targetList": format!("targets/targets-{}.txt", &sha_value[..8]),
                "targetPaths": shard_target_paths,
                "corpusFindingCount": shard_corpus_finding_count,
                "targetFileCount": shard_target_file_count,
                "filesAnalyzed": shard_files_analyzed,
                "chunksTotal": tasks.len(),
                "chunksAnalyzed": shard_results.len(),
                "chunksSucceeded": shard_succeeded,
                "chunksFailed": shard_failed,
                "findingsTotal": shard_findings_total,
                "unfilteredFindingsTotal": shard_unfiltered_findings_total,
                "droppedOutOfRangeFindings": shard_dropped_out_of_range_findings,
                "findingsBySeverity": shard_findings_by_severity,
                "findingsByConfidence": shard_findings_by_confidence,
                "durationMs": shard_duration_ms,
                "inputTokens": shard_tokens.input,
                "outputTokens": shard_tokens.output,
                "reasoningTokens": shard_tokens.reasoning,
                "cacheReadInputTokens": shard_tokens.cache_read,
                "cacheCreationInputTokens": shard_tokens.cache_creation,
                "nonCacheInputTokens": shard_tokens.non_cache_input,
                "providerTotalTokens": shard_tokens.provider_total,
                "analysisCostUSD": shard_cost.analysis_usd,
                "auxiliaryCostUSD": shard_cost.auxiliary_usd,
                "costUSD": shard_cost.total_usd,
                "pricingStatus": shard_cost.status,
                "rawJsonlArtifact": "predictions.jsonl",
                "traceArtifacts": shard_results.iter().map(|result| result.trace_jsonl.clone()).collect::<Vec<_>>(),
                "eventArtifacts": shard_results.iter().map(|result| result.events_jsonl.clone()).collect::<Vec<_>>(),
                "childStdoutArtifacts": shard_results.iter().map(|result| format!("tasks/{}/child.stdout.log", result.task_id)).collect::<Vec<_>>(),
                "childStderrArtifacts": shard_results.iter().map(|result| format!("tasks/{}/child.stderr.log", result.task_id)).collect::<Vec<_>>(),
                "promptArtifacts": shard_results.iter().map(|result| format!("tasks/{}/prompt.txt", result.task_id)).collect::<Vec<_>>(),
                "taskSpecArtifacts": shard_results.iter().map(|result| format!("tasks/{}/task.json", result.task_id)).collect::<Vec<_>>(),
                "resultArtifacts": shard_results.iter().map(|result| format!("tasks/{}/result.json", result.task_id)).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

    let result_summaries = results
        .iter()
        .map(|result| {
            serde_json::json!({
                "task_id": result.task_id,
                "taskId": result.task_id,
                "sha": result.sha,
                "target_path": result.target_path,
                "targetPath": result.target_path,
                "chunkIndex": result.chunk_index,
                "chunkStartLine": result.chunk_start_line,
                "chunkEndLine": result.chunk_end_line,
                "chunkContextStartLine": result.chunk_context_start_line,
                "chunkContextEndLine": result.chunk_context_end_line,
                "chunkLineCount": result.chunk_line_count,
                "chunkLanguage": result.chunk_language,
                "chunkHeader": result.chunk_header,
                "corpus_finding_ids": result.corpus_finding_ids,
                "corpusFindingIds": result.corpus_finding_ids,
                "status": result.status,
                "turn_status": result.turn_status,
                "turnStatus": result.turn_status,
                "done_reason": result.done_reason,
                "doneReason": result.done_reason,
                "elapsed_seconds": result.elapsed_seconds,
                "durationMs": result.duration_ms,
                "parsed_response": result.parsed_response.is_some(),
                "parsedResponse": result.parsed_response.is_some(),
                "findingsTotal": result.findings_total,
                "unfilteredFindingsTotal": result.unfiltered_findings_total,
                "droppedOutOfRangeFindings": result.dropped_out_of_range_findings,
                "findingsBySeverity": result.findings_by_severity,
                "findingsByConfidence": result.findings_by_confidence,
                "inputTokens": result.input_tokens,
                "outputTokens": result.output_tokens,
                "reasoningTokens": result.reasoning_tokens,
                "cacheReadInputTokens": result.cached_input_tokens,
                "cacheCreationInputTokens": result.cache_creation_input_tokens,
                "nonCacheInputTokens": result.non_cache_input_tokens,
                "providerTotalTokens": result.provider_total_tokens,
                "analysisCostUSD": result.analysis_cost_usd,
                "auxiliaryCostUSD": result.auxiliary_cost_usd,
                "costUSD": result.cost_usd,
                "pricingStatus": result.pricing_status,
                "traceArtifact": result.trace_jsonl,
                "eventsArtifact": result.events_jsonl,
                "childStdoutArtifact": format!("tasks/{}/child.stdout.log", result.task_id),
                "childStderrArtifact": format!("tasks/{}/child.stderr.log", result.task_id),
                "promptArtifact": format!("tasks/{}/prompt.txt", result.task_id),
                "taskSpecArtifact": format!("tasks/{}/task.json", result.task_id),
                "resultArtifact": format!("tasks/{}/result.json", result.task_id),
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "run_id": run_id,
        "runId": run_id,
        "benchmark": BENCHMARK_NAME,
        "corpus_id": corpus.id,
        "corpusId": corpus.id,
        "corpus_title": corpus.title,
        "corpusTitle": corpus.title,
        "corpus_updated_at": corpus.updated_at,
        "corpusUpdatedAt": corpus.updated_at,
        "repository": DEFAULT_REPOSITORY,
        "runtime": "lash",
        "runtimeVersion": env!("CARGO_PKG_VERSION"),
        "skill": BENCHMARK_SKILL,
        "targetMode": TARGET_MODE,
        "model": model,
        "variant": variant,
        "reasoningLevel": variant.unwrap_or("provider-default"),
        "provider_kind": provider_kind,
        "providerKind": provider_kind,
        "execution_mode": execution_mode,
        "executionMode": execution_mode,
        "standard_context_approach": standard_context_approach,
        "standardContextApproach": standard_context_approach,
        "childIsolation": child_isolation,
        "isolation": child_isolation,
        "dockerImage": if child_isolation == ChildIsolation::Docker.label() {
            serde_json::Value::String(docker_image.to_string())
        } else {
            serde_json::Value::Null
        },
        "maxTurns": max_turns,
        "maxContextTokens": max_context_tokens,
        "maxTaskProviderTotalTokens": max_task_provider_total_tokens,
        "reportOn": REPORT_ON,
        "minConfidence": MIN_CONFIDENCE,
        "verificationEnabled": false,
        "wardenComparable": false,
        "comparisonState": "raw-unfinalized",
        "started_at": started_at,
        "startedAt": started_at,
        "finished_at": finished_at,
        "finishedAt": finished_at,
        "duration_seconds": duration_seconds,
        "durationMs": duration_ms,
        "shardCount": selected_shas.len(),
        "tasks_selected": selected_tasks.len(),
        "tasksSelected": selected_tasks.len(),
        "tasks_completed": completed_rows,
        "tasksCompleted": completed_rows,
        "tasks_succeeded": succeeded_rows,
        "tasksSucceeded": succeeded_rows,
        "tasks_failed": failed_count,
        "tasksFailed": failed_count,
        "rawJsonlArtifact": "predictions.jsonl",
        "rawArtifactsReviewStatus": "local_unreviewed",
        "runLogArtifact": "run.log",
        "targetListArtifacts": selected_shas.iter().map(|sha| {
            let sha = *sha;
            format!("targets/targets-{}.txt", &sha[..8])
        }).collect::<Vec<_>>(),
        "traceCapture": {
            "enabled": true,
            "coverage": "per-task",
            "format": "jsonl",
            "artifacts": results.iter().map(|result| result.trace_jsonl.clone()).collect::<Vec<_>>(),
        },
        "artifactPersistence": {
            "mode": "run-directory-bind-mount",
            "runLog": "run.log",
            "rawPredictions": "predictions.jsonl",
            "perTaskArtifacts": [
                "prompt.txt",
                "task.json",
                "session.db",
                "session.trace.jsonl",
                "events.jsonl",
                "child.stdout.log",
                "child.stderr.log",
                "result.json"
            ],
            "note": "Docker children bind-mount only the per-task artifact directory as writable; container removal does not remove these files."
        },
        "findingVerification": {
            "enabled": false,
            "status": "not_configured",
        },
        "summary": {
            "corpusFindingCount": selected_corpus_findings,
            "targetFileCount": selected_target_files.len(),
            "filesTargeted": selected_target_files.len(),
            "filesAnalyzed": result_target_files.len(),
            "chunksTotal": selected_tasks.len(),
            "chunksAnalyzed": completed_rows,
            "chunksSucceeded": succeeded_rows,
            "chunksFailed": failed_count,
            "findingsTotal": findings_total,
            "unfilteredFindingsTotal": unfiltered_findings_total,
            "droppedOutOfRangeFindings": dropped_out_of_range_findings,
            "findingsBySeverity": findings_by_severity,
            "findingsByConfidence": findings_by_confidence,
            "inputTokens": token_totals.input,
            "outputTokens": token_totals.output,
            "reasoningTokens": token_totals.reasoning,
            "cacheReadInputTokens": token_totals.cache_read,
            "cacheCreationInputTokens": token_totals.cache_creation,
            "nonCacheInputTokens": token_totals.non_cache_input,
            "providerTotalTokens": token_totals.provider_total,
            "analysisCostUSD": cost_totals.analysis_usd,
            "auxiliaryCostUSD": cost_totals.auxiliary_usd,
            "costUSD": cost_totals.total_usd,
            "pricingStatus": cost_totals.status,
            "pricing": cost_totals.pricing,
        },
        "timing": {
            "wallDurationMs": duration_ms,
            "wallDurationSource": wall_duration_source,
            "taskDurationMs": timing_stats_json(&task_duration_ms),
            "turnDurationMs": timing_stats_json(&turn_duration_ms),
            "checkoutDurationMs": timing_stats_json(&checkout_duration_ms),
        },
        "scoring": {
            "status": "unscored",
            "knownFindingCount": selected_corpus_findings,
            "knownFound": null,
            "knownMissed": null,
            "knownPartial": null,
            "knownFoundRate": null,
        },
        "failedTasks": failed_tasks.iter().map(|(task_id, error)| {
            serde_json::json!({
                "taskId": task_id,
                "error": error,
            })
        }).collect::<Vec<_>>(),
        "shards": shards,
        "results": result_summaries,
    })
}

fn read_tail(path: &Path, max_lines: usize) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let lines: Vec<&str> = raw.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    Some(lines[start..].join("\n"))
}

struct InstanceEventSink {
    file: Mutex<File>,
    last_llm_response: Mutex<Option<String>>,
    current_response: Mutex<String>,
    iterations: Mutex<BTreeSet<usize>>,
    last_error: Mutex<Option<String>>,
    llm_response_count: Mutex<u64>,
    tool_breakdown: Mutex<BTreeMap<String, u64>>,
    live_usage: Mutex<TokenTotals>,
    token_budget: Mutex<Option<TokenBudgetGuard>>,
}

struct TokenBudgetGuard {
    max_provider_total_tokens: u64,
    cancel: tokio_util::sync::CancellationToken,
    tripped: bool,
}

impl InstanceEventSink {
    fn new(path: PathBuf) -> Result<Self> {
        let file = File::create(&path).with_context(|| format!("create {}", path.display()))?;
        Ok(Self {
            file: Mutex::new(file),
            last_llm_response: Mutex::new(None),
            current_response: Mutex::new(String::new()),
            iterations: Mutex::new(BTreeSet::new()),
            last_error: Mutex::new(None),
            llm_response_count: Mutex::new(0),
            tool_breakdown: Mutex::new(BTreeMap::new()),
            live_usage: Mutex::new(TokenTotals::default()),
            token_budget: Mutex::new(None),
        })
    }

    fn set_token_budget(
        &self,
        max_provider_total_tokens: u64,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        if max_provider_total_tokens == 0 {
            return;
        }
        if let Ok(mut guard) = self.token_budget.lock() {
            *guard = Some(TokenBudgetGuard {
                max_provider_total_tokens,
                cancel,
                tripped: false,
            });
        }
    }

    fn flush_current_response(&self) {
        let flushed = {
            let mut current = self
                .current_response
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if current.trim().is_empty() {
                None
            } else {
                Some(std::mem::take(&mut *current))
            }
        };
        if let Some(text) = flushed {
            if let Ok(mut last) = self.last_llm_response.lock() {
                *last = Some(text.trim().to_string());
            }
        }
    }

    fn last_llm_response(&self) -> Option<String> {
        self.flush_current_response();
        self.last_llm_response.lock().ok().and_then(|g| g.clone())
    }

    fn iteration_count(&self) -> usize {
        self.iterations.lock().map(|g| g.len()).unwrap_or(0)
    }

    fn llm_response_count(&self) -> u64 {
        *self
            .llm_response_count
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn tool_breakdown(&self) -> BTreeMap<String, u64> {
        self.tool_breakdown
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    fn last_error(&self) -> Option<String> {
        self.last_error.lock().ok().and_then(|g| g.clone())
    }

    fn record_usage(&self, usage: &TokenUsage) {
        let provider_total = {
            let mut totals = self.live_usage.lock().unwrap_or_else(|e| e.into_inner());
            totals.input += usage.input_tokens.max(0) as u64;
            totals.output += usage.output_tokens.max(0) as u64;
            totals.cache_read += usage.cache_read_input_tokens.max(0) as u64;
            totals.reasoning += usage.reasoning_output_tokens.max(0) as u64;
            totals.cache = totals.cache_read;
            totals.non_cache_input = totals.input.saturating_sub(totals.cache_read);
            totals.provider_total = totals.input + totals.output;
            totals.provider_total
        };
        if let Ok(mut budget) = self.token_budget.lock()
            && let Some(guard) = budget.as_mut()
            && !guard.tripped
            && provider_total > guard.max_provider_total_tokens
        {
            guard.tripped = true;
            let message = format!(
                "token budget exceeded: provider_total_tokens={} limit={}",
                provider_total, guard.max_provider_total_tokens
            );
            if let Ok(mut last) = self.last_error.lock() {
                *last = Some(message);
            }
            guard.cancel.cancel();
        }
    }
}

#[async_trait::async_trait]
impl TurnActivitySink for InstanceEventSink {
    async fn emit(&self, activity: TurnActivity) {
        match &activity.event {
            TurnEvent::ModelRequestStarted { protocol_iteration } => {
                self.flush_current_response();
                if let Ok(mut s) = self.iterations.lock() {
                    s.insert(*protocol_iteration);
                }
                if let Ok(mut count) = self.llm_response_count.lock() {
                    *count += 1;
                }
            }
            TurnEvent::AssistantProseDelta { text } => {
                if let Ok(mut current) = self.current_response.lock() {
                    current.push_str(text);
                }
            }
            TurnEvent::Error { message } => {
                if let Ok(mut last) = self.last_error.lock() {
                    *last = Some(message.clone());
                }
            }
            TurnEvent::ToolCallStarted { name, .. } => {
                if let Ok(mut map) = self.tool_breakdown.lock() {
                    *map.entry(name.clone()).or_insert(0) += 1;
                }
            }
            TurnEvent::Usage { usage, .. } | TurnEvent::ChildUsage { usage, .. } => {
                self.record_usage(usage);
            }
            _ => {}
        }
        if let Ok(line) = serde_json::to_string(&activity)
            && let Ok(mut file) = self.file.lock()
        {
            let _ = writeln!(file, "{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_names_for_stack(stack: PluginStack) -> Vec<String> {
        let mut factories = stack.into_factories();
        factories.push(Arc::new(
            lash_mode_standard::StandardProtocolPluginFactory::new(),
        ));
        let host = lash_core::PluginHost::new(factories);
        let session_id = "test".to_string();
        let session = host.build_session(session_id.clone(), None).unwrap();
        session
            .tool_catalog(&session_id)
            .unwrap()
            .into_iter()
            .filter_map(|tool| {
                tool.get("name")
                    .and_then(|name| name.as_str())
                    .map(str::to_string)
            })
            .collect()
    }

    fn sample_result() -> TaskResult {
        TaskResult {
            task_id: "task-1".to_string(),
            repository: DEFAULT_REPOSITORY.to_string(),
            sha: "788ba30f1aa42b00c02d64ed4b8b2515ff8ab8da".to_string(),
            target_path: "src/app.py".to_string(),
            chunk_index: 1,
            chunk_start_line: 10,
            chunk_end_line: 20,
            chunk_context_start_line: 1,
            chunk_context_end_line: 30,
            chunk_line_count: 11,
            chunk_language: "python".to_string(),
            status: "completed".to_string(),
            model: "test-model".to_string(),
            provider_kind: "test-provider".to_string(),
            execution_mode_label: "standard".to_string(),
            duration_ms: 123,
            input_tokens: 100,
            output_tokens: 20,
            tokens: TokenTotals {
                input: 100,
                output: 20,
                non_cache_input: 100,
                provider_total: 120,
                ..Default::default()
            },
            cost: CostTotals {
                status: "estimated".to_string(),
                analysis_usd: Some(0.001),
                auxiliary_usd: Some(0.0),
                total_usd: Some(0.001),
                pricing: PricingConfig::default(),
            },
            analysis_cost_usd: Some(0.001),
            cost_usd: Some(0.001),
            finished_at: "2026-07-01T00:00:00Z".to_string(),
            ..Default::default()
        }
    }

    fn finding(
        id: &str,
        severity: &str,
        confidence: Option<&str>,
        path: &str,
        line: u64,
    ) -> WardenFinding {
        WardenFinding {
            id: id.to_string(),
            severity: severity.to_string(),
            confidence: confidence.map(str::to_string),
            title: "Issue".to_string(),
            description: "Description".to_string(),
            verification: None,
            location: Some(WardenLocation {
                path: path.to_string(),
                start_line: line,
                end_line: None,
            }),
            additional_locations: None,
            elapsed_ms: None,
        }
    }

    fn post_finding(id: &str, severity: &str, path: &str, line: u64) -> PostProcessFinding {
        PostProcessFinding {
            finding: finding(id, severity, Some("low"), path, line),
            origin: FindingOrigin {
                row_index: 0,
                finding_index: 0,
                task_id: format!("task-{id}"),
                sha: "sha".to_string(),
                target_path: path.to_string(),
                chunk_index: 1,
                chunk_start_line: 1,
                chunk_end_line: 100,
            },
        }
    }

    fn post_finding_without_location(id: &str) -> PostProcessFinding {
        let mut finding = post_finding(id, "medium", "src/general.py", 1);
        finding.finding.location = None;
        finding
    }

    fn upstream_bridge_available() -> bool {
        upstream_bridge_probe_direct()
            .get("canExecuteTypeScript")
            .and_then(|value| value.as_bool())
            == Some(true)
    }

    fn upstream_bridge_reason() -> String {
        let probe = upstream_bridge_probe();
        probe
            .get("blocker")
            .and_then(|value| value.as_str())
            .unwrap_or("upstream Warden bridge is executable")
            .to_string()
    }

    fn run_upstream_differential_bridge_fixture() -> serde_json::Value {
        let probe = upstream_bridge_probe();
        if probe
            .get("canExecuteTypeScript")
            .and_then(|value| value.as_bool())
            != Some(true)
        {
            return serde_json::json!({
                "executed": false,
                "probe": probe,
            });
        }

        let node = match command_path("node") {
            Some(node) => node,
            None => {
                return serde_json::json!({"executed": false, "probe": probe, "blocker": "missing node executable"});
            }
        };
        let upstream_extract = Path::new("/tmp/ref-warden/packages/warden/dist/sdk/extract.js");
        if !upstream_extract.exists() {
            return serde_json::json!({
                "executed": false,
                "probe": probe,
                "blocker": "missing built upstream Warden dist at /tmp/ref-warden/packages/warden/dist/sdk/extract.js"
            });
        }
        let script_path = std::env::temp_dir().join(format!(
            "warden-sentry-upstream-differential-{}.mjs",
            std::process::id()
        ));
        let script = r#"
import { deduplicateFindings, applyMergeGroups } from '/tmp/ref-warden/packages/warden/dist/sdk/extract.js';

const findings = [
  {id:'FIX-001', severity:'high', confidence:'high', title:'Tenant bypass', description:'Unchecked organization slug reaches a lookup.', location:{path:'src/app.ts', startLine:10}},
  {id:'DUP-002', severity:'high', confidence:'high', title:'Tenant bypass', description:'Duplicate candidate.', location:{path:'src/app.ts', startLine:10}},
  {id:'OTH-004', severity:'medium', confidence:'medium', title:'Tenant bypass elsewhere', description:'Same unchecked slug reaches another lookup.', location:{path:'src/other.ts', startLine:30}},
  {id:'GEN-005', severity:'medium', confidence:'low', title:'Issue', description:'Description'},
];
const events = [];
const deduped = deduplicateFindings(findings, (event) => events.push({
  stage: event.stage,
  action: event.action,
  findingId: event.finding?.id,
  replacementId: event.replacement?.id,
  reason: event.reason,
}));
const withLocations = deduped.filter((finding) => finding.location);
const { absorbed, replacements } = applyMergeGroups(withLocations, [[1, 2]]);
for (const finding of absorbed) {
  const replacement = [...replacements.values()].find((candidate) =>
    candidate.additionalLocations?.some((loc) =>
      loc.path === finding.location?.path && loc.startLine === finding.location?.startLine
    )
  );
  events.push({stage:'merge', action:'merged', findingId:finding.id, replacementId:replacement?.id, reason:'same root cause at another location'});
}
const merged = deduped.filter((finding) => !absorbed.has(finding)).map((finding) => replacements.get(finding) ?? finding);
console.log(JSON.stringify({executed:true, finalFindings: merged, events}));
"#;
        if let Err(err) = fs::write(&script_path, script) {
            return serde_json::json!({"executed": false, "probe": probe, "blocker": err.to_string()});
        }
        let output = Command::new(node)
            .arg(&script_path)
            .current_dir("/tmp/ref-warden/packages/warden")
            .output();
        let _ = fs::remove_file(&script_path);
        match output {
            Ok(output) if output.status.success() => serde_json::from_slice(&output.stdout)
                .unwrap_or_else(|err| serde_json::json!({"executed": false, "probe": probe, "blocker": err.to_string()})),
            Ok(output) => serde_json::json!({
                "executed": false,
                "probe": probe,
                "blocker": String::from_utf8_lossy(&output.stderr).trim().to_string(),
            }),
            Err(err) => serde_json::json!({"executed": false, "probe": probe, "blocker": err.to_string()}),
        }
    }

    #[test]
    fn token_budget_guard_cancels_after_provider_total_limit() {
        let path = std::env::temp_dir().join(format!(
            "warden-sentry-token-budget-{}.jsonl",
            std::process::id()
        ));
        let sink = InstanceEventSink::new(path.clone()).expect("event sink");
        let cancel = tokio_util::sync::CancellationToken::new();
        sink.set_token_budget(100, cancel.clone());

        sink.record_usage(&TokenUsage {
            input_tokens: 90,
            output_tokens: 9,
            cache_read_input_tokens: 0,
            cache_write_input_tokens: 0,
            reasoning_output_tokens: 1000,
        });
        assert!(!cancel.is_cancelled());

        sink.record_usage(&TokenUsage {
            input_tokens: 2,
            output_tokens: 0,
            cache_read_input_tokens: 0,
            cache_write_input_tokens: 0,
            reasoning_output_tokens: 0,
        });
        assert!(cancel.is_cancelled());
        assert!(
            sink.last_error()
                .unwrap_or_default()
                .contains("token budget exceeded")
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn upstream_reference_files_cover_local_parity_fixtures_when_available() {
        let upstream = Path::new("/tmp/ref-warden/packages/warden/src");
        if !upstream.exists() {
            return;
        }

        let coalesce = fs::read_to_string(upstream.join("diff/coalesce.ts")).unwrap();
        assert!(coalesce.contains("DEFAULT_MAX_GAP_LINES = 30"));
        assert!(coalesce.contains("DEFAULT_MAX_CHUNK_SIZE = 8000"));

        let extract = fs::read_to_string(upstream.join("sdk/extract.ts")).unwrap();
        assert!(extract.contains("deduplicateFindings"));
        assert!(extract.contains("f.location?.startLine"));
        assert!(extract.contains("applyMergeGroups(withLocations"));

        let verify = fs::read_to_string(upstream.join("sdk/verify.ts")).unwrap();
        assert!(verify.contains("function applyVerdict"));
        assert!(verify.contains("revised.location = finding.location"));

        let jsonl = fs::read_to_string(upstream.join("cli/output/jsonl.ts")).unwrap();
        assert!(jsonl.contains("schemaVersion: z.literal(1)"));
        assert!(jsonl.contains("type: z.literal('summary')"));
    }

    #[test]
    fn chunking_uses_upstream_warden_bridge_when_available() {
        if !upstream_bridge_available() {
            return;
        }

        let content = (0..200)
            .map(|index| format!("const value{index} = \"\u{1F600}\";"))
            .collect::<Vec<_>>()
            .join("\n");
        let output = run_upstream_warden_bridge(serde_json::json!({
            "mode": "chunkFile",
            "filename": "src/app.ts",
            "content": content,
            "maxGapLines": WARDEN_MAX_GAP_LINES,
            "maxChunkSize": 200,
        }))
        .unwrap();
        let hunks = serde_json::from_value::<Vec<DiffHunk>>(output["hunks"].clone()).unwrap();

        assert!(!hunks.is_empty());
        assert!(hunks.iter().any(|hunk| hunk.content.contains("\u{1F600}")));
        assert!(hunks.iter().all(|hunk| hunk.new_count > 0));
    }

    #[test]
    fn differential_post_process_fixture_matches_upstream_contract_snapshot() {
        let bridge_reason = upstream_bridge_reason();
        let upstream_bridge = run_upstream_differential_bridge_fixture();
        if upstream_bridge
            .get("executed")
            .and_then(|value| value.as_bool())
            == Some(false)
        {
            assert!(
                bridge_reason.contains("missing /tmp/ref-warden/node_modules")
                    || bridge_reason.contains("missing upstream Warden source")
                    || bridge_reason.contains("missing node")
                    || bridge_reason.contains("missing local tsx")
                    || bridge_reason.contains("missing built upstream Warden dist"),
                "unexpected upstream bridge blocker: {bridge_reason}"
            );
            return;
        }

        let first = PostProcessFinding {
            finding: WardenFinding {
                id: "FIX-001".to_string(),
                severity: "high".to_string(),
                confidence: Some("high".to_string()),
                title: "Tenant bypass".to_string(),
                description: "Unchecked organization slug reaches a lookup.".to_string(),
                verification: None,
                location: Some(WardenLocation {
                    path: "src/app.ts".to_string(),
                    start_line: 10,
                    end_line: None,
                }),
                additional_locations: None,
                elapsed_ms: None,
            },
            origin: FindingOrigin {
                row_index: 0,
                finding_index: 0,
                task_id: "task-1".to_string(),
                sha: "sha".to_string(),
                target_path: "src/app.ts".to_string(),
                chunk_index: 1,
                chunk_start_line: 1,
                chunk_end_line: 100,
            },
        };
        let mut duplicate = first.clone();
        duplicate.finding.id = "DUP-002".to_string();
        duplicate.finding.description = "Duplicate candidate.".to_string();
        let rejected = PostProcessFinding {
            finding: WardenFinding {
                id: "REJ-003".to_string(),
                severity: "low".to_string(),
                confidence: Some("low".to_string()),
                title: "Mitigated debug path".to_string(),
                description: "Debug endpoint appears exposed.".to_string(),
                verification: None,
                location: Some(WardenLocation {
                    path: "src/debug.ts".to_string(),
                    start_line: 40,
                    end_line: None,
                }),
                additional_locations: None,
                elapsed_ms: None,
            },
            origin: first.origin.clone(),
        };
        let other = PostProcessFinding {
            finding: WardenFinding {
                id: "OTH-004".to_string(),
                severity: "medium".to_string(),
                confidence: Some("medium".to_string()),
                title: "Tenant bypass elsewhere".to_string(),
                description: "Same unchecked slug reaches another lookup.".to_string(),
                verification: None,
                location: Some(WardenLocation {
                    path: "src/other.ts".to_string(),
                    start_line: 30,
                    end_line: None,
                }),
                additional_locations: None,
                elapsed_ms: None,
            },
            origin: first.origin.clone(),
        };
        let general = post_finding_without_location("GEN-005");

        let (deduped, mut events) =
            deduplicate_with_upstream_warden(vec![first, duplicate, rejected, other, general])
                .unwrap();
        let mut verified = Vec::new();
        for mut candidate in deduped {
            let original = candidate.finding.clone();
            let verdict = match original.id.as_str() {
                "FIX-001" => {
                    let mut revised = original.clone();
                    revised.title = "Tenant bypass verified".to_string();
                    revised.description =
                        "Unchecked organization slug reaches tenant data.".to_string();
                    revised.verification =
                        Some("- slug reaches lookup\n- membership guard is missing".to_string());
                    revised.location = Some(WardenLocation {
                        path: "src/moved.ts".to_string(),
                        start_line: 99,
                        end_line: None,
                    });
                    Some(VerificationVerdict {
                        verdict: "revise".to_string(),
                        finding: Some(revised),
                        reason: Some("narrower verified path".to_string()),
                    })
                }
                "REJ-003" => Some(VerificationVerdict {
                    verdict: "reject".to_string(),
                    finding: None,
                    reason: Some("guarded by debug permission".to_string()),
                }),
                _ => Some(VerificationVerdict {
                    verdict: "keep".to_string(),
                    finding: None,
                    reason: None,
                }),
            };
            match apply_verification_verdict(&original, verdict.as_ref()) {
                None => events.push(FindingProcessingEventJson {
                    stage: "verification".to_string(),
                    action: "rejected".to_string(),
                    finding: original,
                    reason: verdict.and_then(|verdict| verdict.reason),
                    replacement: None,
                }),
                Some(next) => {
                    if next != original {
                        events.push(FindingProcessingEventJson {
                            stage: "verification".to_string(),
                            action: "revised".to_string(),
                            finding: original,
                            reason: verdict.and_then(|verdict| verdict.reason),
                            replacement: Some(next.clone()),
                        });
                    }
                    candidate.finding = next;
                    verified.push(candidate);
                }
            }
        }

        let located_original_indices = verified
            .iter()
            .enumerate()
            .filter_map(|(index, finding)| finding.finding.location.is_some().then_some(index))
            .collect::<Vec<_>>();
        let (merged, merge_events, absorbed, _) = apply_merge_groups_with_upstream_warden(
            verified,
            &located_original_indices,
            &[vec![1, 2]],
        )
        .unwrap();
        events.extend(merge_events);

        assert_eq!(absorbed, 1);
        let final_findings = merged
            .iter()
            .map(|finding| serde_json::to_value(&finding.finding).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            final_findings,
            vec![
                serde_json::json!({
                    "id": "FIX-001",
                    "severity": "high",
                    "confidence": "high",
                    "title": "Tenant bypass verified",
                    "description": "Unchecked organization slug reaches tenant data.",
                    "verification": "- slug reaches lookup\n- membership guard is missing",
                    "location": {"path": "src/app.ts", "startLine": 10},
                    "additionalLocations": [{"path": "src/other.ts", "startLine": 30}]
                }),
                serde_json::json!({
                    "id": "GEN-005",
                    "severity": "medium",
                    "confidence": "low",
                    "title": "Issue",
                    "description": "Description"
                }),
            ]
        );

        let event_contract = events
            .iter()
            .map(|event| {
                serde_json::json!({
                    "stage": event.stage,
                    "action": event.action,
                    "findingId": event.finding.id,
                    "replacementId": event.replacement.as_ref().map(|finding| finding.id.clone()),
                    "reason": event.reason,
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            event_contract,
            vec![
                serde_json::json!({"stage":"dedupe","action":"dropped","findingId":"DUP-002","replacementId":"FIX-001","reason":"duplicate title and location"}),
                serde_json::json!({"stage":"verification","action":"revised","findingId":"FIX-001","replacementId":"FIX-001","reason":"narrower verified path"}),
                serde_json::json!({"stage":"verification","action":"rejected","findingId":"REJ-003","replacementId":null,"reason":"guarded by debug permission"}),
                serde_json::json!({"stage":"merge","action":"merged","findingId":"OTH-004","replacementId":"FIX-001","reason":"same root cause at another location"}),
            ]
        );

        let usage_entries = vec![
            AuxiliaryUsageEntry {
                agent: "verification".to_string(),
                usage: WardenUsageStats {
                    input_tokens: 10,
                    output_tokens: 2,
                    cost_usd: 0.01,
                    ..Default::default()
                },
                model: Some("aux-model".to_string()),
                runtime: Some("claude".to_string()),
                row_index: Some(0),
            },
            AuxiliaryUsageEntry {
                agent: "merge".to_string(),
                usage: WardenUsageStats {
                    input_tokens: 4,
                    output_tokens: 1,
                    cost_usd: 0.004,
                    ..Default::default()
                },
                model: Some("synthesis-model".to_string()),
                runtime: Some("claude".to_string()),
                row_index: Some(0),
            },
        ];
        assert_eq!(
            serde_json::to_value(aggregate_auxiliary_usage(&usage_entries)).unwrap(),
            serde_json::json!({
                "merge": {"inputTokens": 4, "outputTokens": 1, "costUSD": 0.004},
                "verification": {"inputTokens": 10, "outputTokens": 2, "costUSD": 0.01}
            })
        );
        assert_eq!(
            serde_json::to_value(aggregate_auxiliary_usage_attribution(&usage_entries)).unwrap(),
            serde_json::json!({
                "merge": {"model": "synthesis-model", "runtime": "claude"},
                "verification": {"model": "aux-model", "runtime": "claude"}
            })
        );

        if upstream_bridge
            .get("executed")
            .and_then(|value| value.as_bool())
            == Some(true)
        {
            let upstream_final = upstream_bridge.get("finalFindings").unwrap();
            assert_eq!(
                upstream_final,
                &serde_json::json!([
                    {
                        "id": "FIX-001",
                        "severity": "high",
                        "confidence": "high",
                        "title": "Tenant bypass",
                        "description": "Unchecked organization slug reaches a lookup.",
                        "location": {"path": "src/app.ts", "startLine": 10},
                        "additionalLocations": [{"path": "src/other.ts", "startLine": 30}]
                    },
                    {
                        "id": "GEN-005",
                        "severity": "medium",
                        "confidence": "low",
                        "title": "Issue",
                        "description": "Description"
                    }
                ])
            );
            assert_eq!(
                upstream_bridge.get("events").unwrap(),
                &serde_json::json!([
                    {"stage":"dedupe","action":"dropped","findingId":"DUP-002","replacementId":"FIX-001","reason":"duplicate title and location"},
                    {"stage":"merge","action":"merged","findingId":"OTH-004","replacementId":"FIX-001","reason":"same root cause at another location"}
                ])
            );
        } else {
            assert!(
                upstream_bridge
                    .get("probe")
                    .and_then(|probe| probe.get("blocker"))
                    .and_then(|value| value.as_str())
                    .is_some()
            );
        }
    }

    #[test]
    fn verifier_prompt_snapshots_upstream_contract_and_lash_tool_mapping() {
        let finding = finding("ABC-123", "high", Some("high"), "src/app.ts", 10);
        let prompt = build_verification_prompt(&finding).unwrap();
        for required in [
            "You are Warden's finding verifier. You validate one candidate finding at a time.",
            "Keep findings only when the issue is still real after tracing.",
            "Do not reject solely because broader repository invariants or caller behavior are incomplete",
            "Do not use checklist labels",
            "Return only valid JSON. Do not include markdown, prose, code fences, or explanations.",
            "<candidate_finding>",
            "Verify this candidate. Return keep, revise, or reject.",
            "read_file",
            "glob",
            "grep",
        ] {
            assert!(
                prompt.contains(required),
                "missing prompt contract: {required}"
            );
        }
        for forbidden in ["Do not edit files.", "Do not spawn subagents"] {
            assert!(
                !prompt.contains(forbidden),
                "prompt should not mention unavailable tools: {forbidden}"
            );
        }

        let upstream = Path::new("/tmp/ref-warden/packages/warden/src/sdk/verify.ts");
        if upstream.exists() {
            let source = fs::read_to_string(upstream).unwrap();
            assert!(source.contains("Use read-only tools to inspect the repository. Read the reported file and use Grep/Glob"));
            assert!(source.contains("const VERIFICATION_CONCURRENCY = 4"));
            assert!(source.contains("revised.location = finding.location"));
        }
    }

    #[test]
    fn warden_repo_agents_expose_only_read_only_repo_tools() {
        for names in [
            tool_names_for_stack(build_standard_plugin_stack(Some(
                StandardContextApproach::RollingHistory(Default::default()),
            ))),
            tool_names_for_stack(build_verification_plugin_stack()),
            tool_names_for_stack(build_rlm_plugin_stack()),
        ] {
            for expected in ["batch", "read_file", "grep", "glob"] {
                assert!(
                    names.contains(&expected.to_string()),
                    "missing {expected}: {names:?}"
                );
            }
            for forbidden in [
                "exec_command",
                "start_command",
                "write_stdin",
                "list_process_handles",
                "edit",
                "write",
                "llm_query",
                "spawn_agent",
            ] {
                assert!(
                    !names.contains(&forbidden.to_string()),
                    "unexpected {forbidden}: {names:?}"
                );
            }
        }
    }

    #[test]
    fn normalizes_raw_harness_findings_to_warden_findings() {
        let mut result = sample_result();
        result.parsed_response = Some(serde_json::json!({
            "findings": [{
                "title": "Tenant bypass",
                "severity": "critical",
                "confidence": "HIGH",
                "path": "ignored.py",
                "start_line": 12,
                "description": "User-controlled org slug is trusted.",
                "evidence": "- line 12 trusts the slug",
                "recommendation": "Check membership before returning data."
            }]
        }));
        let mut used_ids = BTreeSet::new();
        let mut counters = PostProcessCounters::default();

        let findings = normalize_result_findings(&result, 0, &mut used_ids, &mut counters);

        assert_eq!(findings.len(), 1);
        let finding = &findings[0].finding;
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.confidence.as_deref(), Some("high"));
        assert_eq!(finding.location.as_ref().unwrap().path, "src/app.py");
        assert_eq!(finding.location.as_ref().unwrap().start_line, 12);
        assert!(
            finding
                .description
                .contains("Recommendation: Check membership")
        );
        assert_eq!(
            finding.verification.as_deref(),
            Some("- line 12 trusts the slug")
        );
        assert_eq!(finding.id.len(), 7);
        assert_eq!(counters.raw_findings, 1);
        assert_eq!(counters.normalized_findings, 1);
    }

    #[test]
    fn deduplicates_by_title_path_and_start_line() {
        if !upstream_bridge_available() {
            return;
        }

        let first = post_finding("AAA-111", "medium", "src/a.py", 10);
        let mut duplicate = post_finding("BBB-222", "high", "src/a.py", 10);
        duplicate.finding.title = first.finding.title.clone();
        duplicate.finding.location.as_mut().unwrap().end_line = Some(99);
        let mut different_start = post_finding("CCC-333", "high", "src/a.py", 11);
        different_start.finding.title = first.finding.title.clone();

        let (deduped, events) =
            deduplicate_with_upstream_warden(vec![first.clone(), duplicate, different_start])
                .unwrap();

        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].finding.id, first.finding.id);
        assert_eq!(deduped[1].finding.id, "CCC-333");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].stage, "dedupe");
        assert_eq!(events[0].action, "dropped");
        assert_eq!(events[0].replacement.as_ref().unwrap().id, first.finding.id);
    }

    #[test]
    fn applies_verifier_revisions_without_moving_validated_anchors() {
        let original = finding("ABC-123", "high", Some("high"), "src/app.py", 10);
        let revised = WardenFinding {
            id: "DIFFERENT".to_string(),
            severity: "medium".to_string(),
            confidence: Some("medium".to_string()),
            title: "Narrower issue".to_string(),
            description: "Narrower description".to_string(),
            verification: Some("Verified narrower path.".to_string()),
            location: Some(WardenLocation {
                path: "src/other.py".to_string(),
                start_line: 99,
                end_line: None,
            }),
            additional_locations: Some(vec![WardenLocation {
                path: "src/other.py".to_string(),
                start_line: 100,
                end_line: None,
            }]),
            elapsed_ms: Some(9.0),
        };
        let verdict = VerificationVerdict {
            verdict: "revise".to_string(),
            finding: Some(revised),
            reason: Some("impact is narrower".to_string()),
        };

        let applied = apply_verification_verdict(&original, Some(&verdict)).unwrap();

        assert_eq!(applied.id, "ABC-123");
        assert_eq!(applied.severity, "medium");
        assert_eq!(applied.confidence.as_deref(), Some("medium"));
        assert_eq!(applied.title, "Narrower issue");
        assert_eq!(applied.location, original.location);
        assert_eq!(applied.additional_locations, original.additional_locations);

        let reject = VerificationVerdict {
            verdict: "reject".to_string(),
            finding: None,
            reason: None,
        };
        assert!(apply_verification_verdict(&original, Some(&reject)).is_none());

        let invalid_revision = VerificationVerdict {
            verdict: "revise".to_string(),
            finding: Some(WardenFinding {
                id: "DIFFERENT".to_string(),
                severity: "critical".to_string(),
                confidence: Some("medium".to_string()),
                title: "Invalid severity".to_string(),
                description: "This should fall back to the original finding.".to_string(),
                verification: None,
                location: original.location.clone(),
                additional_locations: None,
                elapsed_ms: None,
            }),
            reason: Some("invalid payload".to_string()),
        };
        assert_eq!(
            apply_verification_verdict(&original, Some(&invalid_revision)).unwrap(),
            original
        );
        assert_eq!(
            apply_verification_verdict(&original, None).unwrap(),
            original
        );
    }

    #[test]
    fn applies_cross_location_merge_groups_with_warden_priority() {
        if !upstream_bridge_available() {
            return;
        }

        let low = post_finding("LOW-111", "low", "src/b.py", 20);
        let high = post_finding("HGH-222", "high", "src/a.py", 10);
        let other = post_finding("MED-333", "medium", "src/c.py", 30);

        let (merged, events, absorbed, _) = apply_merge_groups_with_upstream_warden(
            vec![low, high, other],
            &[0, 1, 2],
            &[vec![1, 2, 3]],
        )
        .unwrap();

        assert_eq!(absorbed, 2);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].finding.id, "HGH-222");
        assert_eq!(
            merged[0]
                .finding
                .additional_locations
                .as_ref()
                .unwrap()
                .iter()
                .map(format_location)
                .collect::<Vec<_>>(),
            vec!["src/c.py:30", "src/b.py:20"]
        );
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.stage == "merge"));
    }

    #[test]
    fn merge_groups_from_located_prompt_map_back_to_original_findings() {
        if !upstream_bridge_available() {
            return;
        }

        let general = post_finding_without_location("GEN-000");
        let low = post_finding("LOW-111", "low", "src/b.py", 20);
        let high = post_finding("HGH-222", "high", "src/a.py", 10);

        let (merged, events, absorbed, _) = apply_merge_groups_with_upstream_warden(
            vec![general, low, high],
            &[1, 2],
            &[vec![1, 2]],
        )
        .unwrap();

        assert_eq!(absorbed, 1);
        assert_eq!(events.len(), 1);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|finding| finding.finding.id == "GEN-000"));
        let winner = merged
            .iter()
            .find(|finding| finding.finding.id == "HGH-222")
            .unwrap();
        assert_eq!(
            winner
                .finding
                .additional_locations
                .as_ref()
                .unwrap()
                .iter()
                .map(format_location)
                .collect::<Vec<_>>(),
            vec!["src/b.py:20"]
        );
    }

    #[test]
    fn builds_usage_breakdown_with_matching_totals() {
        let scan = WardenUsageStats {
            input_tokens: 100,
            output_tokens: 10,
            cost_usd: 1.0,
            ..Default::default()
        };
        let mut auxiliary = BTreeMap::new();
        auxiliary.insert(
            "verification".to_string(),
            WardenUsageStats {
                input_tokens: 20,
                output_tokens: 2,
                cost_usd: 0.25,
                ..Default::default()
            },
        );
        let breakdown = build_warden_usage_breakdown(
            Some(scan),
            auxiliary,
            Some("scan-model"),
            Some("lash"),
            BTreeMap::from([(
                "verification".to_string(),
                serde_json::json!({"model": "aux-model", "runtime": "lash-direct-llm"}),
            )]),
        )
        .unwrap();

        assert_eq!(breakdown.total.usage.input_tokens, 120);
        assert_eq!(breakdown.total.usage.output_tokens, 12);
        assert!((breakdown.total.usage.cost_usd - 1.25).abs() < f64::EPSILON);
        assert_eq!(
            breakdown
                .auxiliary
                .as_ref()
                .unwrap()
                .get("verification")
                .unwrap()
                .model
                .as_deref(),
            Some("aux-model")
        );
        assert_eq!(
            breakdown.total.models.unwrap(),
            vec!["aux-model".to_string(), "scan-model".to_string()]
        );
    }

    #[test]
    fn summary_cost_accounting_matches_post_summary_and_final_jsonl() {
        let temp_dir = std::env::temp_dir().join(format!(
            "warden-sentry-cost-accounting-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(temp_dir.join(POST_PROCESS_DIR)).unwrap();
        fs::write(
            temp_dir.join("summary.json"),
            serde_json::json!({
                "runId": "cost-run",
                "durationMs": 123,
                "summary": {
                    "analysisCostUSD": 0.001,
                    "auxiliaryCostUSD": 0.0,
                    "costUSD": 0.001,
                    "pricingStatus": "estimated"
                }
            })
            .to_string(),
        )
        .unwrap();

        let args = Args::parse_from([
            "bench",
            "--dry-run",
            "--input-cost-per-mtok",
            "1",
            "--output-cost-per-mtok",
            "1",
        ]);
        let result = sample_result();
        let final_finding = post_finding("FIN-123", "high", "src/app.py", 12);
        let auxiliary_entries = vec![AuxiliaryUsageEntry {
            agent: "verification".to_string(),
            usage: WardenUsageStats {
                input_tokens: 20,
                output_tokens: 2,
                cost_usd: 0.125,
                ..Default::default()
            },
            model: Some("verifier-model".to_string()),
            runtime: Some("lash-standard-tools".to_string()),
            row_index: Some(0),
        }];
        let auxiliary_usage = aggregate_auxiliary_usage(&auxiliary_entries);
        let cost_summary =
            post_process_cost_summary(&args, std::slice::from_ref(&result), &auxiliary_usage);
        let post_summary = serde_json::json!({
            "status": "completed",
            "analysisCostUSD": cost_summary.analysis_usd,
            "auxiliaryCostUSD": cost_summary.auxiliary_usd,
            "costUSD": cost_summary.total_usd,
            "pricingStatus": cost_summary.status,
            "pricing": cost_summary.pricing,
            "nonComparableScoringArtifacts": [],
        });
        fs::write(
            temp_dir.join(POST_PROCESS_SUMMARY_ARTIFACT),
            serde_json::to_string_pretty(&post_summary).unwrap(),
        )
        .unwrap();

        let jsonl_path = temp_dir.join(WARDEN_FINAL_JSONL_ARTIFACT);
        write_warden_final_jsonl(
            &jsonl_path,
            "cost-run",
            &temp_dir,
            std::slice::from_ref(&result),
            std::slice::from_ref(&final_finding),
            &auxiliary_entries,
            "test-model",
        )
        .unwrap();
        update_summary_post_processing(
            &temp_dir,
            &post_summary,
            std::slice::from_ref(&final_finding),
            &auxiliary_usage,
            "test-model",
            "test-provider",
        )
        .unwrap();

        let summary: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(temp_dir.join("summary.json")).unwrap())
                .unwrap();
        assert_eq!(
            summary
                .get("summary")
                .and_then(|value| value.get("auxiliaryCostUSD"))
                .and_then(|value| value.as_f64()),
            Some(0.125)
        );
        assert_eq!(
            summary
                .get("summary")
                .and_then(|value| value.get("costUSD"))
                .and_then(|value| value.as_f64()),
            Some(0.126)
        );
        let post: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(temp_dir.join(POST_PROCESS_SUMMARY_ARTIFACT)).unwrap(),
        )
        .unwrap();
        assert_eq!(
            post.get("costUSD").and_then(|value| value.as_f64()),
            Some(0.126)
        );

        let lines = fs::read_to_string(&jsonl_path).unwrap();
        let summary_line = lines.lines().last().unwrap();
        let final_summary: WardenJsonlSummary = serde_json::from_str(summary_line).unwrap();
        assert_eq!(
            final_summary
                .usage_breakdown
                .as_ref()
                .unwrap()
                .total
                .usage
                .cost_usd,
            0.126
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn reproducibility_manifest_records_hashes_refs_model_and_artifacts() {
        let temp_dir = std::env::temp_dir().join(format!(
            "warden-sentry-manifest-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(temp_dir.join(POST_PROCESS_DIR)).unwrap();
        let corpus_path = temp_dir.join("corpus.json");
        fs::write(&corpus_path, r#"{"id":"test-corpus"}"#).unwrap();
        fs::write(
            temp_dir.join("summary.json"),
            serde_json::json!({
                "runId": "manifest-run",
                "durationMs": 1,
                "dockerImage": "missing-local-image-for-test"
            })
            .to_string(),
        )
        .unwrap();
        let args = Args::parse_from([
            "bench",
            "--dry-run",
            "--corpus",
            corpus_path.to_str().unwrap(),
            "--model",
            "test-model",
            "--variant",
            "high",
        ]);
        let cost = CostTotals {
            status: "estimated".to_string(),
            analysis_usd: Some(1.0),
            auxiliary_usd: Some(0.5),
            total_usd: Some(1.5),
            pricing: PricingConfig::default(),
        };

        let manifest = write_reproducibility_manifest(
            &args,
            &temp_dir,
            "manifest-run",
            "test-model",
            "codex",
            &cost,
        )
        .unwrap();

        assert!(temp_dir.join(REPRODUCIBILITY_MANIFEST_ARTIFACT).exists());
        assert!(temp_dir.join(SOURCE_SNAPSHOT_ARTIFACT).exists());
        assert!(temp_dir.join(UPSTREAM_BRIDGE_PROBE_ARTIFACT).exists());
        assert_eq!(
            manifest
                .get("schemaVersion")
                .and_then(|value| value.as_u64()),
            Some(1)
        );
        assert_eq!(
            manifest
                .get("model")
                .and_then(|value| value.get("variant"))
                .and_then(|value| value.as_str()),
            Some("high")
        );
        assert_eq!(
            manifest
                .get("artifacts")
                .and_then(|value| value.get("finalJsonl"))
                .and_then(|value| value.as_str()),
            Some(WARDEN_FINAL_JSONL_ARTIFACT)
        );
        assert_eq!(
            manifest
                .get("artifacts")
                .and_then(|value| value.get("sourceSnapshot"))
                .and_then(|value| value.as_str()),
            Some(SOURCE_SNAPSHOT_ARTIFACT)
        );
        assert_eq!(
            manifest
                .get("artifacts")
                .and_then(|value| value.get("upstreamBridgeProbe"))
                .and_then(|value| value.as_str()),
            Some(UPSTREAM_BRIDGE_PROBE_ARTIFACT)
        );
        let corpus_hash = manifest
            .get("corpus")
            .and_then(|value| value.get("sha256"))
            .and_then(|value| value.as_str())
            .unwrap();
        assert_eq!(corpus_hash.len(), 64);
        let analysis_prompt_hash = manifest
            .get("promptsAndSchemas")
            .and_then(|value| value.get("analysisPromptSha256"))
            .and_then(|value| value.as_str())
            .unwrap();
        assert_eq!(analysis_prompt_hash.len(), 64);
        let runner = manifest.get("runner").unwrap();
        assert_eq!(
            runner
                .get("sourceTreeSha256")
                .and_then(|value| value.as_str())
                .map(str::len),
            Some(64)
        );
        assert_eq!(
            runner
                .get("binarySha256")
                .and_then(|value| value.as_str())
                .map(str::len),
            Some(64)
        );
        assert!(runner.get("cleanState").is_some());
        assert_eq!(
            runner
                .get("sourceSnapshotArtifact")
                .and_then(|value| value.as_str()),
            Some(SOURCE_SNAPSHOT_ARTIFACT)
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn finalized_run_validator_accepts_complete_comparable_artifacts() {
        let temp_dir = std::env::temp_dir().join(format!(
            "warden-sentry-validator-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(temp_dir.join("post-processing/verification/sha")).unwrap();
        fs::create_dir_all(temp_dir.join("post-processing/merge")).unwrap();
        fs::write(
            temp_dir.join("post-processing/verification/sha/result.json"),
            "{}",
        )
        .unwrap();
        fs::write(temp_dir.join("post-processing/merge/sha.json"), "{}").unwrap();
        fs::write(
            temp_dir.join("semantic-scoring.raw-pre-finalization.json"),
            serde_json::json!({
                "scoring": {
                    "status": "stale_non_comparable",
                    "stale": true,
                    "nonComparable": true,
                    "staleClass": "raw-pre-finalization",
                    "staleAt": "2026-07-01T00:00:00Z",
                    "staleReason": "test stale raw score",
                    "previousStatus": "scored",
                    "previousInputState": "raw",
                    "previousInputArtifact": "predictions.jsonl",
                    "previousWardenComparable": false,
                    "inputState": "stale",
                    "inputArtifact": null,
                    "wardenComparable": false
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            temp_dir.join("semantic-scoring-summary.raw-pre-finalization.md"),
            "<!-- warden-sentry-stale-score staleClass=\"raw-pre-finalization\" staleAt=\"2026-07-01T00:00:00Z\" nonComparable=\"true\" -->\n\nraw",
        )
        .unwrap();
        fs::write(
            temp_dir.join(SEMANTIC_SCORING_ARTIFACT),
            serde_json::json!({
                "runId": "validation-run",
                "corpusId": "sentry-vulnerability-corpus",
                "scoring": {
                    "reviewer": AGENT_SEMANTIC_MATCH_PASS,
                    "scoredAt": "2026-07-01",
                    "knownFindingCount": 1,
                    "knownFound": 1,
                    "knownMissed": 0,
                    "knownPartial": 0,
                    "knownFoundRate": 1.0,
                    "notes": "Agent-verified semantic matches. A finding counts when it identifies the same bug in roughly the same location as an existing corpus finding. Same-file findings about different bugs do not count."
                },
                "scores": [{
                    "findingId": "FIN-123",
                    "matchedCorpusIds": ["sentry-vuln-001"],
                    "verdict": "known-found",
                    "notes": "same issue"
                }]
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            temp_dir.join("summary.json"),
            serde_json::json!({
                "runId": "validation-run",
                "durationMs": 1,
                "wardenComparable": true,
                "comparisonState": "finalized-scored",
                "summary": {
                    "finalFindingsTotal": 1,
                    "costUSD": 0.0,
                    "auxiliaryCostUSD": 0.0
                },
                "scoring": {
                    "reviewer": AGENT_SEMANTIC_MATCH_PASS,
                    "scoredAt": "2026-07-01",
                    "knownFindingCount": 1,
                    "knownFound": 1,
                    "knownMissed": 0,
                    "knownPartial": 0,
                    "knownFoundRate": 1.0,
                    "notes": "Agent-verified semantic matches. A finding counts when it identifies the same bug in roughly the same location as an existing corpus finding. Same-file findings about different bugs do not count.",
                    "nonComparablePreviousArtifacts": [
                        "semantic-scoring.raw-pre-finalization.json",
                        "semantic-scoring-summary.raw-pre-finalization.md"
                    ]
                }
            })
            .to_string(),
        )
        .unwrap();
        fs::write(
            temp_dir.join(POST_PROCESS_SUMMARY_ARTIFACT),
            serde_json::json!({
                "status": "completed",
                "normalizedFindings": 1,
                "dedupeDropped": 0,
                "finalFindings": 1,
                "verificationArtifactCount": 1,
                "mergeArtifactCount": 1,
                "costUSD": 0.0,
                "auxiliaryCostUSD": 0.0,
                "nonComparableScoringArtifacts": [
                    "semantic-scoring.raw-pre-finalization.json",
                    "semantic-scoring-summary.raw-pre-finalization.md"
                ]
            })
            .to_string(),
        )
        .unwrap();

        let mut results = Vec::new();
        for index in 0..EXPECTED_WARDEN_SENTRY_CHUNKS {
            let mut result = sample_result();
            result.task_id = format!("task-{index}");
            result.chunk_index = index + 1;
            result.chunk_start_line = index + 1;
            result.chunk_end_line = index + 1;
            result.analysis_cost_usd = Some(0.0);
            result.cost_usd = Some(0.0);
            result.cost.analysis_usd = Some(0.0);
            result.cost.total_usd = Some(0.0);
            results.push(result);
        }
        let final_finding = post_finding("FIN-123", "high", "src/app.py", 12);
        write_warden_final_jsonl(
            &temp_dir.join(WARDEN_FINAL_JSONL_ARTIFACT),
            "validation-run",
            &temp_dir,
            &results,
            std::slice::from_ref(&final_finding),
            &[],
            "test-model",
        )
        .unwrap();

        let report = validate_finalized_run(&temp_dir).unwrap();
        assert_eq!(
            report.get("status").and_then(|value| value.as_str()),
            Some("passed")
        );
        assert_eq!(
            report.get("chunkRecords").and_then(|value| value.as_u64()),
            Some(EXPECTED_WARDEN_SENTRY_CHUNKS as u64)
        );
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn finalized_jsonl_records_drive_scoring_inputs() {
        let temp_dir = std::env::temp_dir().join(format!(
            "warden-sentry-final-jsonl-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            temp_dir.join("summary.json"),
            serde_json::json!({"runId": "run-1", "durationMs": 123}).to_string(),
        )
        .unwrap();
        let mut raw_result = sample_result();
        raw_result.parsed_response = Some(serde_json::json!({
            "findings": [{"title": "Raw", "severity": "low"}]
        }));
        let final_finding = post_finding("FIN-123", "high", "src/app.py", 12);
        let jsonl_path = temp_dir.join(WARDEN_FINAL_JSONL_ARTIFACT);

        write_warden_final_jsonl(
            &jsonl_path,
            "run-1",
            &temp_dir,
            &[raw_result.clone()],
            std::slice::from_ref(&final_finding),
            &[],
            "test-model",
        )
        .unwrap();

        let content = fs::read_to_string(&jsonl_path).unwrap();
        let lines = content.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        for line in &lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            if value.get("type").and_then(|value| value.as_str()) == Some("summary") {
                let parsed: WardenJsonlSummary = serde_json::from_value(value).unwrap();
                assert_eq!(parsed.record_type, "summary");
            } else {
                let parsed: WardenJsonlChunk = serde_json::from_value(value).unwrap();
                assert_eq!(parsed.schema_version, 1);
            }
        }
        let chunk: WardenJsonlChunk = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(chunk.schema_version, 1);
        assert_eq!(chunk.findings[0].id, "FIN-123");
        let summary: WardenJsonlSummary = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(summary.total_findings, 1);

        let mut scoring_results = vec![raw_result];
        apply_finalized_findings_to_results(&mut scoring_results, &jsonl_path).unwrap();
        let emitted = emitted_findings(&scoring_results[0]);
        assert_eq!(emitted.len(), 1);
        assert_eq!(
            emitted[0].value.get("id").and_then(|v| v.as_str()),
            Some("FIN-123")
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn agent_semantic_match_jobs_score_finalized_findings_against_presented_candidates() {
        let sha = "788ba30f1aa42b00c02d64ed4b8b2515ff8ab8da".to_string();
        let empty_sha = "899ba30f1aa42b00c02d64ed4b8b2515ff8ab8da".to_string();
        let mut first = sample_result();
        first.task_id = "task-a".to_string();
        first.sha = sha.clone();
        first.target_path = "src/a.py".to_string();
        let mut first_finding = finding("F-A", "high", Some("high"), "src/a.py", 12);
        first_finding.additional_locations = Some(vec![WardenLocation {
            path: "src/b.py".to_string(),
            start_line: 18,
            end_line: None,
        }]);
        first.parsed_response = Some(serde_json::json!({
            "findings": [first_finding]
        }));

        let mut second = sample_result();
        second.task_id = "task-b".to_string();
        second.sha = sha.clone();
        second.target_path = "src/b.py".to_string();
        second.parsed_response = Some(serde_json::json!({
            "findings": [finding("F-B", "medium", Some("medium"), "src/b.py", 18)]
        }));

        let mut empty = sample_result();
        empty.task_id = "task-empty".to_string();
        empty.sha = empty_sha.clone();
        empty.target_path = "src/empty.py".to_string();
        empty.parsed_response = Some(serde_json::json!({"findings": []}));

        let candidates = vec![
            CorpusFinding {
                id: "CORPUS-A".to_string(),
                repository: DEFAULT_REPOSITORY.to_string(),
                sha: sha.clone(),
                summary: "first expected vulnerability".to_string(),
                code: CorpusCode {
                    path: "src/a.py".to_string(),
                    lines: Some("12".to_string()),
                    language: Some("python".to_string()),
                    snippet: None,
                },
            },
            CorpusFinding {
                id: "CORPUS-B".to_string(),
                repository: DEFAULT_REPOSITORY.to_string(),
                sha: sha.clone(),
                summary: "second expected vulnerability".to_string(),
                code: CorpusCode {
                    path: "src/b.py".to_string(),
                    lines: Some("18".to_string()),
                    language: Some("python".to_string()),
                    snippet: None,
                },
            },
            CorpusFinding {
                id: "CORPUS-C".to_string(),
                repository: DEFAULT_REPOSITORY.to_string(),
                sha: sha.clone(),
                summary: "third expected vulnerability".to_string(),
                code: CorpusCode {
                    path: "src/c.py".to_string(),
                    lines: Some("42".to_string()),
                    language: Some("python".to_string()),
                    snippet: None,
                },
            },
        ];
        let empty_candidates = vec![CorpusFinding {
            id: "CORPUS-EMPTY".to_string(),
            repository: DEFAULT_REPOSITORY.to_string(),
            sha: empty_sha.clone(),
            summary: "expected vulnerability with no emitted finding".to_string(),
            code: CorpusCode {
                path: "src/empty.py".to_string(),
                lines: Some("22".to_string()),
                language: Some("python".to_string()),
                snippet: None,
            },
        }];
        let corpus_by_sha = BTreeMap::from([
            (sha.clone(), candidates.clone()),
            (empty_sha.clone(), empty_candidates),
        ]);
        let jobs = build_agent_scoring_jobs(&[first, second, empty], &corpus_by_sha);

        assert_eq!(jobs.len(), 2);
        let first_job = jobs
            .iter()
            .find(|job| job.finding_id == "F-A")
            .expect("first emitted finding job");
        assert_eq!(first_job.sha, sha);
        assert_eq!(first_job.task_id, "task-a");
        assert_eq!(first_job.finding_index, 0);
        assert_eq!(first_job.candidates.len(), 3);
        assert_eq!(
            candidate_subset_for_job(first_job)
                .into_iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec!["CORPUS-A", "CORPUS-B"]
        );

        let request = build_agent_semantic_match_prompt(first_job).unwrap();
        assert!(request.contains("agent-semantic-match-pass"));
        assert!(request.contains("\"id\": \"CORPUS-A\""));
        assert!(request.contains("\"id\": \"CORPUS-B\""));
        assert!(!request.contains("\"id\": \"CORPUS-C\""));

        let row = score_row_from_agent_match(
            first_job,
            AgentSemanticMatchResponse {
                verdict: "known-found".to_string(),
                matched_corpus_ids: vec!["CORPUS-B".to_string()],
                notes: "same root cause at additional location".to_string(),
            },
        )
        .unwrap();
        assert_eq!(
            row,
            SemanticScoreRow {
                finding_id: "F-A".to_string(),
                verdict: "known-found".to_string(),
                matched_corpus_ids: vec!["CORPUS-B".to_string()],
                notes: "same root cause at additional location".to_string(),
            }
        );

        assert!(
            score_row_from_agent_match(
                first_job,
                AgentSemanticMatchResponse {
                    verdict: "known-found".to_string(),
                    matched_corpus_ids: vec!["CORPUS-C".to_string()],
                    notes: "invalid candidate".to_string(),
                },
            )
            .is_err()
        );
        assert!(
            score_row_from_agent_match(
                first_job,
                AgentSemanticMatchResponse {
                    verdict: "not-known".to_string(),
                    matched_corpus_ids: vec!["CORPUS-A".to_string()],
                    notes: "inconsistent".to_string(),
                },
            )
            .is_err()
        );
        assert!(
            score_row_from_agent_match(
                first_job,
                AgentSemanticMatchResponse {
                    verdict: "known-found".to_string(),
                    matched_corpus_ids: Vec::new(),
                    notes: "missing match".to_string(),
                },
            )
            .is_err()
        );

        let second_job = jobs
            .iter()
            .find(|job| job.finding_id == "F-B")
            .expect("second emitted finding job");
        assert_eq!(
            candidate_subset_for_job(second_job)
                .into_iter()
                .map(|finding| finding.id.as_str())
                .collect::<Vec<_>>(),
            vec!["CORPUS-B"]
        );
        let second_row = score_row_from_agent_match(
            second_job,
            AgentSemanticMatchResponse {
                verdict: "not-known".to_string(),
                matched_corpus_ids: Vec::new(),
                notes: "different issue".to_string(),
            },
        )
        .unwrap();
        assert_eq!(second_row.finding_id, "F-B");
        assert_eq!(second_row.verdict, "not-known");
        assert!(second_row.matched_corpus_ids.is_empty());
    }

    #[test]
    fn end_to_end_post_processing_golden_finalizes_and_scores_from_final_jsonl() {
        if !upstream_bridge_available() {
            return;
        }

        let temp_dir = std::env::temp_dir().join(format!(
            "warden-sentry-post-process-golden-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        fs::write(
            temp_dir.join("summary.json"),
            serde_json::json!({"runId": "golden-run", "durationMs": 250}).to_string(),
        )
        .unwrap();

        let mut first = sample_result();
        first.task_id = "task-1".to_string();
        first.chunk_index = 1;
        first.chunk_start_line = 10;
        first.chunk_end_line = 20;
        first.parsed_response = Some(serde_json::json!({
            "findings": [
                {
                    "title": "Tenant bypass",
                    "severity": "high",
                    "confidence": "high",
                    "start_line": 12,
                    "description": "Organization slug is trusted.",
                    "evidence": "Slug reaches lookup without membership guard.",
                    "recommendation": "Check membership."
                },
                {
                    "title": "Tenant bypass",
                    "severity": "medium",
                    "confidence": "low",
                    "start_line": 12,
                    "description": "Duplicate report for the same bug.",
                    "evidence": "Same path and line.",
                    "recommendation": "Check membership."
                },
                {
                    "title": "Mitigated debug path",
                    "severity": "low",
                    "confidence": "low",
                    "start_line": 13,
                    "description": "This path is actually guarded.",
                    "evidence": "The verifier should reject it.",
                    "recommendation": "No change."
                }
            ]
        }));

        let mut second = sample_result();
        second.task_id = "task-2".to_string();
        second.chunk_index = 2;
        second.chunk_start_line = 30;
        second.chunk_end_line = 40;
        second.parsed_response = Some(serde_json::json!({
            "findings": [{
                "title": "Tenant bypass elsewhere",
                "severity": "medium",
                "confidence": "medium",
                "start_line": 33,
                "description": "Same root cause appears in another endpoint.",
                "evidence": "The same unchecked slug reaches a lookup.",
                "recommendation": "Check membership."
            }]
        }));
        let results = vec![first.clone(), second.clone()];

        let mut counters = PostProcessCounters::default();
        let mut used_ids = BTreeSet::new();
        let mut normalized = Vec::new();
        for (row_index, result) in results.iter().enumerate() {
            normalized.extend(normalize_result_findings(
                result,
                row_index,
                &mut used_ids,
                &mut counters,
            ));
        }
        assert_eq!(counters.raw_findings, 4);
        assert_eq!(counters.normalized_findings, 4);

        let (deduped, mut events) = deduplicate_with_upstream_warden(normalized).unwrap();
        assert_eq!(deduped.len(), 3);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].stage, "dedupe");

        let mut verified = Vec::new();
        for mut candidate in deduped {
            let original = candidate.finding.clone();
            let verdict = if original.title == "Tenant bypass" {
                let mut revised = original.clone();
                revised.severity = "medium".to_string();
                revised.title = "Tenant bypass through organization slug".to_string();
                revised.description =
                    "Unchecked organization slug reaches a tenant scoped lookup.".to_string();
                revised.verification = Some(
                    "- endpoint accepts organization slug\n- lookup runs before membership verification"
                        .to_string(),
                );
                Some(VerificationVerdict {
                    verdict: "revise".to_string(),
                    finding: Some(revised),
                    reason: Some("impact is narrower than originally reported".to_string()),
                })
            } else if original.title == "Mitigated debug path" {
                Some(VerificationVerdict {
                    verdict: "reject".to_string(),
                    finding: None,
                    reason: Some("guarded by explicit debug permission".to_string()),
                })
            } else {
                Some(VerificationVerdict {
                    verdict: "keep".to_string(),
                    finding: None,
                    reason: Some("same issue remains reachable".to_string()),
                })
            };
            match apply_verification_verdict(&original, verdict.as_ref()) {
                None => events.push(FindingProcessingEventJson {
                    stage: "verification".to_string(),
                    action: "rejected".to_string(),
                    finding: original,
                    reason: verdict.and_then(|verdict| verdict.reason),
                    replacement: None,
                }),
                Some(next) => {
                    if next != original {
                        events.push(FindingProcessingEventJson {
                            stage: "verification".to_string(),
                            action: "revised".to_string(),
                            finding: original,
                            reason: verdict.and_then(|verdict| verdict.reason),
                            replacement: Some(next.clone()),
                        });
                    }
                    candidate.finding = next;
                    verified.push(candidate);
                }
            }
        }
        assert_eq!(verified.len(), 2);
        assert!(events.iter().any(|event| event.action == "revised"));
        assert!(events.iter().any(|event| event.action == "rejected"));

        let located_original_indices = verified
            .iter()
            .enumerate()
            .filter_map(|(index, finding)| finding.finding.location.is_some().then_some(index))
            .collect::<Vec<_>>();
        let (merged, merge_events, absorbed, _) = apply_merge_groups_with_upstream_warden(
            verified,
            &located_original_indices,
            &[vec![1, 2]],
        )
        .unwrap();
        events.extend(merge_events);
        assert_eq!(absorbed, 1);
        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged[0].finding.title,
            "Tenant bypass through organization slug"
        );
        assert_eq!(
            merged[0]
                .finding
                .additional_locations
                .as_ref()
                .unwrap()
                .iter()
                .map(format_location)
                .collect::<Vec<_>>(),
            vec!["src/app.py:33"]
        );
        assert!(events.iter().any(|event| event.stage == "merge"));

        let auxiliary_entries = vec![
            AuxiliaryUsageEntry {
                agent: "verification".to_string(),
                usage: WardenUsageStats {
                    input_tokens: 100,
                    output_tokens: 10,
                    cost_usd: 0.1,
                    ..Default::default()
                },
                model: Some("verifier-model".to_string()),
                runtime: Some("lash-standard-tools".to_string()),
                row_index: Some(0),
            },
            AuxiliaryUsageEntry {
                agent: "verification".to_string(),
                usage: WardenUsageStats {
                    input_tokens: 80,
                    output_tokens: 8,
                    cost_usd: 0.08,
                    ..Default::default()
                },
                model: Some("verifier-model".to_string()),
                runtime: Some("lash-standard-tools".to_string()),
                row_index: Some(1),
            },
            AuxiliaryUsageEntry {
                agent: "merge".to_string(),
                usage: WardenUsageStats {
                    input_tokens: 40,
                    output_tokens: 4,
                    cost_usd: 0.04,
                    ..Default::default()
                },
                model: Some("merge-model".to_string()),
                runtime: Some("lash-direct-llm".to_string()),
                row_index: Some(0),
            },
        ];
        let jsonl_path = temp_dir.join(WARDEN_FINAL_JSONL_ARTIFACT);
        write_warden_final_jsonl(
            &jsonl_path,
            "golden-run",
            &temp_dir,
            &results,
            &merged,
            &auxiliary_entries,
            "scan-model",
        )
        .unwrap();

        let content = fs::read_to_string(&jsonl_path).unwrap();
        let lines = content.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 3);
        let first_chunk: WardenJsonlChunk = serde_json::from_str(lines[0]).unwrap();
        let second_chunk: WardenJsonlChunk = serde_json::from_str(lines[1]).unwrap();
        let summary: WardenJsonlSummary = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(first_chunk.schema_version, 1);
        assert_eq!(first_chunk.chunk.file, "src/app.py");
        assert_eq!(first_chunk.findings.len(), 1);
        assert_eq!(second_chunk.findings.len(), 0);
        let first_aux = first_chunk
            .usage_breakdown
            .as_ref()
            .unwrap()
            .auxiliary
            .as_ref()
            .unwrap();
        assert!(first_aux.contains_key("verification"));
        assert!(first_aux.contains_key("merge"));
        let summary_aux = summary
            .usage_breakdown
            .as_ref()
            .unwrap()
            .auxiliary
            .as_ref()
            .unwrap();
        assert_eq!(
            summary_aux.get("verification").unwrap().usage.input_tokens,
            180
        );
        assert_eq!(summary.total_findings, 1);

        let mut scoring_results = results;
        apply_finalized_findings_to_results(&mut scoring_results, &jsonl_path).unwrap();
        let first_emitted = emitted_findings(&scoring_results[0]);
        let second_emitted = emitted_findings(&scoring_results[1]);
        assert_eq!(first_emitted.len(), 1);
        assert_eq!(second_emitted.len(), 0);
        assert_eq!(
            first_emitted[0]
                .value
                .get("title")
                .and_then(|value| value.as_str()),
            Some("Tenant bypass through organization slug")
        );
        assert_eq!(
            first_emitted[0]
                .value
                .get("additionalLocations")
                .and_then(|value| value.as_array())
                .map(Vec::len),
            Some(1)
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn target_lists_are_grouped_by_sha_and_deduplicated() {
        let temp_dir = std::env::temp_dir().join(format!(
            "warden-sentry-target-list-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&temp_dir);
        fs::create_dir_all(&temp_dir).unwrap();
        let chunk = WardenChunk {
            index: 1,
            start_line: 1,
            end_line: 1,
            old_start_line: 0,
            old_line_count: 0,
            new_line_count: 1,
            context_start_line: 1,
            context_end_line: 1,
            language: "python".to_string(),
            header: None,
            hunk_content: "@@ -0,0 +1,1 @@\n+x".to_string(),
            context_before: Vec::new(),
            context_after: Vec::new(),
        };
        let tasks = vec![
            WardenTask {
                task_id: "a".to_string(),
                repository: DEFAULT_REPOSITORY.to_string(),
                sha: "aaaaaaaa11111111".to_string(),
                target_path: "b.py".to_string(),
                chunk: chunk.clone(),
                findings: Vec::new(),
            },
            WardenTask {
                task_id: "b".to_string(),
                repository: DEFAULT_REPOSITORY.to_string(),
                sha: "aaaaaaaa11111111".to_string(),
                target_path: "a.py".to_string(),
                chunk,
                findings: Vec::new(),
            },
        ];

        write_target_lists(&temp_dir, &tasks).unwrap();

        let list =
            fs::read_to_string(temp_dir.join("targets").join("targets-aaaaaaaa.txt")).unwrap();
        assert_eq!(list, "a.py\nb.py\n");
        let _ = fs::remove_dir_all(&temp_dir);
    }
}

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use lash::rlm::RlmTurnBuilderExt;
use lash::{
    LashCore, ModelSpec, PluginStack, SessionSpec, TurnInput,
    persistence::{
        ProtocolEvent, RuntimePersistence, RuntimeSessionState, load_persisted_session_state,
    },
    prompt::{
        PromptBuiltin, PromptSlot, PromptTemplate, PromptTemplateEntry, PromptTemplateSection,
    },
    provider::ProviderHandle,
    tools::ToolDefinition,
    usage::{SessionUsageReport, diff_usage_reports},
};
use lash_core::{TestLocalProcessRegistry, TurnFinish, TurnOutcome, TurnStop};
use lash_llm_tools::LlmToolsPluginFactory;
use lash_plugin_process_controls::SessionProcessAdminPluginFactory;
use lash_protocol_rlm::RlmTurnInputExt;
use lash_rlm_types::RlmProtocolEvent;
use lash_sqlite_store::Store;
use lash_subagents::{CapabilityRegistry, StaticCapability, SubagentsPluginFactory};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_MAX_CONTEXT_TOKENS: usize = 1_000_000;
const DEFAULT_MAX_TURNS: usize = 30;
const CLBENCH_MEMORY_GUIDANCE: &str = concat!(
    "You are solving a continual-learning benchmark across repeated queries. ",
    "Use projected variables such as `diary`, `iteration`, `current_query`, and `current_feedback` ",
    "to preserve useful lessons between turns. Submit only the next action matching the requested schema."
);

#[derive(Parser, Debug)]
#[command(name = "bench-clbench-lash")]
#[command(about = "Run one Continual Learning Bench query through Lash RLM.")]
struct Args {
    #[arg(long)]
    request: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RunnerRequest {
    session_id: String,
    session_db: PathBuf,
    trace_path: Option<PathBuf>,
    model: String,
    provider_id: Option<String>,
    variant: Option<String>,
    max_context_tokens: Option<usize>,
    max_turns: Option<usize>,
    iteration: usize,
    prompt: String,
    feedback: Option<String>,
    response_schema: Value,
    init_diary: bool,
}

#[derive(Debug, Serialize)]
struct RunnerResponse {
    action: Value,
    session_id: String,
    status: String,
    done_reason: String,
    usage: Value,
    diagnostics: Value,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let request: RunnerRequest = serde_json::from_str(
        &fs::read_to_string(&args.request)
            .with_context(|| format!("read {}", args.request.display()))?,
    )
    .with_context(|| format!("parse {}", args.request.display()))?;

    let response = run_query(request).await?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

async fn run_query(request: RunnerRequest) -> Result<RunnerResponse> {
    if let Some(parent) = request.session_db.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    if let Some(trace_path) = &request.trace_path
        && let Some(parent) = trace_path.parent()
    {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let provider = resolve_provider(request.provider_id.as_deref())?;
    let model_spec = ModelSpec::from_token_limits(
        request.model.clone(),
        request.variant.clone(),
        request
            .max_context_tokens
            .unwrap_or(DEFAULT_MAX_CONTEXT_TOKENS),
        None,
    )
    .map_err(anyhow::Error::msg)?;
    let mut core_builder = LashCore::rlm_builder(lash::rlm::RlmProtocolPluginFactory::new(
        clbench_rlm_config(),
        Arc::new(lash::persistence::InMemoryLashlangArtifactStore::new()),
    ))
    .provider(provider)
    .model(model_spec)
    .max_turns(request.max_turns.unwrap_or(DEFAULT_MAX_TURNS))
    .store_factory(Arc::new(
        lash::persistence::InMemorySessionStoreFactory::new(),
    ))
    .process_registry(Arc::new(TestLocalProcessRegistry::default()))
    .process_env_store(Arc::new(
        lash::persistence::InMemoryProcessExecutionEnvStore::new(),
    ))
    .effect_host(Arc::new(lash::durability::InlineEffectHost::default()))
    .attachment_store(Arc::new(lash::persistence::InMemoryAttachmentStore::new()))
    .plugins(build_plugin_stack());
    if let Some(trace_path) = request.trace_path.clone() {
        core_builder = core_builder.trace_jsonl_path(trace_path);
    }
    let core = core_builder.build()?;

    let store = Arc::new(
        Store::open(&request.session_db)
            .await
            .with_context(|| format!("open {}", request.session_db.display()))?,
    );
    let mut state = load_persisted_session_state(store.as_ref())
        .await
        .context("load session state")?
        .unwrap_or_else(|| RuntimeSessionState {
            session_id: request.session_id.clone(),
            ..RuntimeSessionState::default()
        });
    if let Some(seed) = build_seed_event(&request) {
        state.session_graph.append_protocol_event(seed);
    }
    let session = core
        .session(request.session_id.clone())
        .store(store.clone() as Arc<dyn RuntimePersistence>)
        .open_with_state(state)
        .await
        .context("open clbench session")?;

    let mut turn_input = TurnInput::text(clbench_turn_text(&request))
        .rlm_project(build_projected_bindings(&request)?)?;
    turn_input.trace_turn_id = Some(format!("clbench-turn-{:04}", request.iteration));
    let before_usage = session.usage_report();
    let turn = session
        .turn(turn_input)
        .require_finish_schema(request.response_schema.clone())?
        .prompt_template(clbench_prompt_template(CLBENCH_MEMORY_GUIDANCE))
        .stream_to(&lash::runtime::NoopTurnActivitySink)
        .await
        .context("run clbench turn")?;
    let usage = diff_usage_reports(&before_usage, &session.usage_report())
        .map(|rows| SessionUsageReport::from_entries(&rows))
        .map_err(anyhow::Error::msg)
        .context("diff usage reports")?;

    let action = match &turn.outcome {
        TurnOutcome::Finished(TurnFinish::FinalValue { value })
        | TurnOutcome::Finished(TurnFinish::ToolValue { value, .. }) => value.clone(),
        other => bail!(
            "turn did not submit an action: status={} reason={} errors={:?} output={}",
            turn_status_label(other),
            done_reason_label(other),
            turn.errors,
            turn.assistant_output.safe_text
        ),
    };

    Ok(RunnerResponse {
        action,
        session_id: request.session_id,
        status: turn_status_label(&turn.outcome).to_string(),
        done_reason: done_reason_label(&turn.outcome).to_string(),
        usage: serde_json::to_value(&usage)?,
        diagnostics: json!({
            "assistant_output_chars": turn.assistant_output.safe_text.chars().count(),
            "tool_call_count": turn.tool_calls.len(),
            "error_count": turn.errors.len(),
            "followed_turn_count": 1,
            "handoff_count": usize::from(matches!(turn.outcome, TurnOutcome::AgentFrameSwitch { .. })),
        }),
    })
}

fn clbench_turn_text(request: &RunnerRequest) -> String {
    let mut text = String::from("Choose the next benchmark action.");
    text.push_str("\n\n=== CURRENT QUERY ===\n\n");
    text.push_str(&request.prompt);
    text.push_str("\n\n=== CURRENT FEEDBACK ===\n\n");
    match request.feedback.as_deref() {
        Some(feedback) if !feedback.trim().is_empty() => text.push_str(feedback),
        _ => text.push_str("null"),
    }
    text
}

fn clbench_rlm_config() -> lash_protocol_rlm::RlmProtocolPluginConfig {
    lash_protocol_rlm::RlmProtocolPluginConfig {
        prompt_features: lash_protocol_rlm::RlmPromptFeatures {
            images: false,
            ..lash_protocol_rlm::RlmPromptFeatures::default()
        },
        ..lash_protocol_rlm::RlmProtocolPluginConfig::default()
    }
}

fn clbench_prompt_template(memory_guidance: &str) -> PromptTemplate {
    PromptTemplate::new(vec![
        PromptTemplateSection::untitled(vec![PromptTemplateEntry::text(
            "You are being evaluated by Continual Learning Bench, which tests whether an agent improves from feedback across sequential task instances.",
        )]),
        PromptTemplateSection::titled(
            "Execution",
            vec![
                PromptTemplateEntry::builtin(PromptBuiltin::ExecutionInstructions),
                PromptTemplateEntry::slot(PromptSlot::Execution),
            ],
        ),
        PromptTemplateSection::titled(
            "Continual Memory",
            vec![PromptTemplateEntry::text(memory_guidance)],
        ),
        PromptTemplateSection::titled(
            "Guidance",
            vec![
                PromptTemplateEntry::slot(PromptSlot::Guidance),
                PromptTemplateEntry::slot(PromptSlot::ProjectInstructions),
            ],
        ),
        PromptTemplateSection::titled(
            "Environment",
            vec![
                PromptTemplateEntry::slot(PromptSlot::RuntimeContext),
                PromptTemplateEntry::slot(PromptSlot::Environment),
            ],
        ),
    ])
}

fn build_plugin_stack() -> PluginStack {
    let _clbench_tools = clbench_tool_definitions();
    let mut stack = lash::plugins::runtime_plugin_stack();
    stack.push(Arc::new(LlmToolsPluginFactory::default()));
    stack.push(Arc::new(
        SessionProcessAdminPluginFactory::without_cancel_process(),
    ));
    stack.push(Arc::new(
        SubagentsPluginFactory::new(Arc::new(CapabilityRegistry::new().with(Arc::new(
            StaticCapability::new("explore", SessionSpec::inherit()),
        ))))
        .with_session_spec(SessionSpec::inherit()),
    ));
    stack
}

fn clbench_tool_definitions() -> Vec<ToolDefinition> {
    let capabilities = vec!["explore".to_string()];
    vec![
        lash_llm_tools::llm_query_tool_definition(),
        lash_protocol_rlm::continue_as_tool_definition(),
        lash_plugin_process_controls::process_list_tool_definition(),
        lash_subagents::spawn_agent_tool_definition(&capabilities),
    ]
}

fn build_seed_event(request: &RunnerRequest) -> Option<ProtocolEvent> {
    let mut globals = serde_json::Map::new();
    if request.init_diary {
        globals.insert("diary".to_string(), Value::Array(Vec::new()));
    }
    (!globals.is_empty()).then(|| {
        lash_protocol_rlm::rlm_protocol_event(RlmProtocolEvent::RlmSeed(
            lash_rlm_types::RlmSeedPluginBody {
                globals,
                projected: Default::default(),
            },
        ))
    })
}

fn build_projected_bindings(
    request: &RunnerRequest,
) -> anyhow::Result<lash_protocol_rlm::RlmProjectedBindings> {
    Ok(lash_protocol_rlm::RlmProjectedBindings::new()
        .bind_json("iteration", json!(request.iteration))?
        .bind_json("current_query", json!(request.prompt))?
        .bind_json(
            "current_feedback".to_string(),
            request
                .feedback
                .as_ref()
                .map(|feedback| json!(feedback))
                .unwrap_or(Value::Null),
        )?)
}

fn resolve_provider(provider_id: Option<&str>) -> Result<ProviderHandle> {
    bench_common::load_provider(provider_id)
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
        TurnOutcome::Finished(TurnFinish::FinalValue { .. }) => "submitted_value",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn clbench_rlm_tool_surface_exposes_explicit_limited_tools() {
        let core = LashCore::rlm_builder(lash::rlm::RlmProtocolPluginFactory::new(
            clbench_rlm_config(),
            Arc::new(lash::persistence::InMemoryLashlangArtifactStore::new()),
        ))
        .model(
            ModelSpec::from_token_limits("mock-model", None, DEFAULT_MAX_CONTEXT_TOKENS, None)
                .expect("valid model spec"),
        )
        .store_factory(Arc::new(
            lash::persistence::InMemorySessionStoreFactory::new(),
        ))
        .process_registry(Arc::new(TestLocalProcessRegistry::default()))
        .process_env_store(Arc::new(
            lash::persistence::InMemoryProcessExecutionEnvStore::new(),
        ))
        .effect_host(Arc::new(lash::durability::InlineEffectHost::default()))
        .attachment_store(Arc::new(lash::persistence::InMemoryAttachmentStore::new()))
        .plugins(build_plugin_stack())
        .build()
        .expect("core");
        let session = core.session("root").open().await.expect("session");

        let mut ordinary_names = session
            .observe()
            .active_tool_manifests()
            .into_iter()
            .map(|tool| tool.name)
            .collect::<Vec<_>>();
        ordinary_names.sort();
        let mut benchmark_names = clbench_tool_definitions()
            .into_iter()
            .map(|tool| tool.name().to_string())
            .collect::<Vec<_>>();
        benchmark_names.sort();
        assert_eq!(
            ordinary_names,
            vec![
                "continue_as",
                "list_process_handles",
                "llm_query",
                "spawn_agent"
            ]
        );
        assert_eq!(
            benchmark_names,
            vec![
                "continue_as",
                "list_process_handles",
                "llm_query",
                "spawn_agent"
            ]
        );
        assert!(
            !benchmark_names
                .iter()
                .any(|name| name.as_str() == "cancel_process"),
            "CLBench installs process controls in locked-down list-only mode"
        );

        for denied in [
            "exec_command",
            "read_file",
            "grep",
            "search_web",
            "fetch_url",
            "apply_patch",
            "monitor",
        ] {
            assert!(
                !benchmark_names.iter().any(|name| name == denied),
                "{denied} must not be callable in CLBench"
            );
        }

        for expected in [
            "llm_query",
            "spawn_agent",
            "continue_as",
            "list_process_handles",
        ] {
            assert!(
                benchmark_names.iter().any(|name| name == expected),
                "{expected} must be documented in the RLM prompt"
            );
        }
    }
}

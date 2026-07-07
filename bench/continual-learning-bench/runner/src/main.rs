use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use clap::Parser;
use lash::plugins::ToolOutputBudgetPluginFactory;
use lash::{
    ModelSpec, SessionSpec, TurnFinish, TurnInput, TurnOutcome, TurnStop,
    plugins::{PluginFactory, PluginSession, PluginSpec, StaticPluginFactory},
    prompt::{
        PromptBuiltin, PromptSlot, PromptTemplate, PromptTemplateEntry, PromptTemplateSection,
    },
    provider::ProviderHandle,
    runtime::{
        EventSink, ExecutionScope, InlineRuntimeEffectController, LashRuntime, NoopEventSink,
        TurnContext,
    },
    tools::{
        ToolCall, ToolContract, ToolDefinition, ToolManifest, ToolProvider, ToolResult,
        ToolScheduling,
    },
    usage::{SessionUsageReport, TokenLedgerEntry},
};
use lash_cli::config::LashConfig;
use lash_core::{
    AgentFrameRun, AppendSessionNodesRequest, InputItem, PluginHost, RuntimePersistence,
    SessionAppendNode, SessionPolicy, SingleProviderResolver, TurnOptions,
};
use lash_llm_tools::LlmToolsPluginFactory;
use lash_mode_rlm::RlmTurnInputExt;
use lash_rlm_types::{RlmGlobalsPatchPluginBody, RlmProtocolEvent};
use lash_sqlite_store::Store;
use lash_subagents::{CapabilityRegistry, StaticCapability, SubagentsPluginFactory};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_MAX_CONTEXT_TOKENS: usize = 1_000_000;
const DEFAULT_MAX_TURNS: usize = 30;
const CLBENCH_MEMORY_GUIDANCE: &str = "Maintain and consult the persistent `diary` binding across Continual Learning Bench iterations. Treat feedback as authoritative, preserve durable facts that can help future queries, and base each finished action on the current query, current feedback, and accumulated diary state.";

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
    let max_context_tokens = request
        .max_context_tokens
        .unwrap_or(DEFAULT_MAX_CONTEXT_TOKENS);
    let model_spec = ModelSpec::from_token_limits(
        request.model.clone(),
        request.variant.clone(),
        max_context_tokens,
        None,
    )
    .map_err(anyhow::Error::msg)?;
    let policy = SessionPolicy {
        model: model_spec,
        provider_id: provider.kind().to_string(),
        max_turns: Some(request.max_turns.unwrap_or(DEFAULT_MAX_TURNS)),
        session_id: Some(request.session_id.clone()),
        ..SessionPolicy::default()
    };

    let store = Arc::new(
        Store::open(&request.session_db)
            .await
            .with_context(|| format!("open {}", request.session_db.display()))?,
    );
    let trace_sink = request.trace_path.clone().map(|path| {
        Arc::new(lash::tracing::JsonlTraceSink::new(path)) as Arc<dyn lash::tracing::TraceSink>
    });
    let plugin_session = build_plugin_session()?;
    let mut runtime = LashRuntime::builder()
        .with_session_id(request.session_id.clone())
        .with_policy(policy)
        .with_plugin_session(plugin_session)
        .with_store(store.clone() as Arc<dyn RuntimePersistence>)
        .with_provider_resolver(Arc::new(SingleProviderResolver::new(provider.clone())))
        .with_trace_sink(trace_sink)
        .with_prompt_template(clbench_prompt_template(CLBENCH_MEMORY_GUIDANCE))
        .build()
        .await
        .context("open runtime")?;

    if let Some(defaults) = build_globals_patch(&request) {
        runtime
            .append_session_nodes(AppendSessionNodesRequest {
                nodes: vec![SessionAppendNode::protocol_event(
                    lash_mode_rlm::rlm_protocol_event(RlmProtocolEvent::RlmGlobalsPatch(defaults)),
                )],
                requires_ancestor_node_id: None,
            })
            .await
            .context("bind clbench defaults")?;
    }

    let sink = NoopEventSink;
    let turn_id = format!("clbench-turn-{:04}", request.iteration);
    let followed = runtime
        .stream_turn_with_agent_frames(
            (TurnInput {
                items: vec![InputItem::Text {
                    text: clbench_turn_text(&request),
                }],
                image_blobs: Default::default(),
                protocol_turn_options: Some(lash_core::ProtocolTurnOptions::typed(
                    lash_rlm_types::RlmCreateExtras {
                        termination: lash_rlm_types::RlmTermination::FinishRequired {
                            schema: Some(request.response_schema.clone()),
                        },
                        final_answer_format: None,
                    },
                )?),
                trace_turn_id: Some(turn_id.clone()),
                protocol_extension: None,
                turn_context: TurnContext::default(),
            })
            .rlm_project(build_projected_bindings(&request)?)?,
            TurnOptions::new(
                tokio_util::sync::CancellationToken::new(),
                lash_core::ScopedEffectController::shared(
                    Arc::new(InlineRuntimeEffectController),
                    ExecutionScope::turn(request.session_id.clone(), turn_id),
                )?,
            )
            .with_events(&sink as &dyn EventSink),
        )
        .await
        .context("run clbench turn")?;
    let usage = usage_from_followed_turn(&followed);
    let turn = followed
        .final_turn()
        .context("handoff chain did not produce a turn")?;

    let action = match &turn.outcome {
        TurnOutcome::Finished(TurnFinish::FinalValue { value })
        | TurnOutcome::Finished(TurnFinish::ToolValue { value, .. }) => value.clone(),
        other => bail!(
            "turn did not finish with an action: status={} reason={} errors={:?} output={}",
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
            "followed_turn_count": followed.turns.len(),
            "handoff_count": followed.frame_switch_count(),
        }),
    })
}

fn usage_from_followed_turn(followed: &AgentFrameRun) -> SessionUsageReport {
    let entries = followed
        .turns
        .iter()
        .filter(|turn| {
            turn.token_usage.total() != 0 || turn.token_usage.cache_read_input_tokens != 0
        })
        .map(|turn| TokenLedgerEntry {
            source: "turn".to_string(),
            model: turn.state.policy.model.id.clone(),
            usage: turn.token_usage.clone(),
        })
        .collect::<Vec<_>>();
    SessionUsageReport::from_entries(&entries)
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

fn clbench_prompt_template(memory_guidance: &str) -> PromptTemplate {
    PromptTemplate::new(vec![
        PromptTemplateSection::untitled(vec![
            PromptTemplateEntry::builtin(PromptBuiltin::MainAgentIntro),
            PromptTemplateEntry::slot(PromptSlot::Intro),
        ]),
        PromptTemplateSection::titled(
            "Execution",
            vec![
                PromptTemplateEntry::builtin(PromptBuiltin::ExecutionInstructions),
                PromptTemplateEntry::slot(PromptSlot::Execution),
            ],
        ),
        PromptTemplateSection::titled(
            "Guidance",
            vec![
                PromptTemplateEntry::builtin(PromptBuiltin::CoreGuidance),
                PromptTemplateEntry::text(memory_guidance),
                PromptTemplateEntry::slot(PromptSlot::ProjectInstructions),
                PromptTemplateEntry::slot(PromptSlot::Guidance),
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

fn build_plugin_session() -> Result<Arc<PluginSession>> {
    let _clbench_tools = clbench_tool_definitions();
    let factories: Vec<Arc<dyn PluginFactory>> = vec![
        Arc::new(ToolOutputBudgetPluginFactory::default()),
        Arc::new(
            lash_mode_rlm::RlmProtocolPluginFactory::new(
                lash_mode_rlm::RlmProtocolPluginConfig {
                    prompt_features: lash_mode_rlm::RlmPromptFeatures {
                        images: false,
                        ..lash_mode_rlm::RlmPromptFeatures::default()
                    },
                    ..lash_mode_rlm::RlmProtocolPluginConfig::default()
                },
                Arc::new(lash_lashlang_runtime::InMemoryLashlangArtifactStore::new()),
            )
            .with_process_lifecycle(false),
        ),
        Arc::new(LlmToolsPluginFactory::default()),
        Arc::new(StaticPluginFactory::new(
            "clbench_async_handles",
            PluginSpec::new().with_tool_provider(Arc::new(ClbenchAsyncHandlesTool)),
        )),
        Arc::new(
            SubagentsPluginFactory::new(Arc::new(CapabilityRegistry::new().with(Arc::new(
                StaticCapability::new("explore", SessionSpec::inherit()),
            ))))
            .with_session_spec(SessionSpec::inherit()),
        ),
    ];
    PluginHost::new(factories)
        .build_session("root", None)
        .context("build plugin session")
}

struct ClbenchAsyncHandlesTool;

#[async_trait]
impl ToolProvider for ClbenchAsyncHandlesTool {
    fn tool_manifests(&self) -> Vec<ToolManifest> {
        vec![list_async_handles_tool_definition().manifest()]
    }

    fn resolve_contract(&self, name: &str) -> Option<Arc<ToolContract>> {
        (name == "list_async_handles")
            .then(|| Arc::new(list_async_handles_tool_definition().contract()))
    }

    async fn execute(&self, call: ToolCall<'_>) -> ToolResult {
        ToolResult::err_fmt(format_args!(
            "`{}` is handled by the RLM session runtime and cannot run directly",
            call.name
        ))
    }
}

fn clbench_tool_definitions() -> Vec<ToolDefinition> {
    let capabilities = vec!["explore".to_string()];
    vec![
        lash_llm_tools::llm_query_tool_definition(),
        lash_mode_rlm::continue_as_tool_definition(),
        clbench_list_async_handles_tool_definition(),
        lash_subagents::spawn_agent_tool_definition(&capabilities),
    ]
}

fn list_async_handles_tool_definition() -> ToolDefinition {
    clbench_list_async_handles_tool_definition()
}

fn clbench_list_async_handles_tool_definition() -> ToolDefinition {
    ToolDefinition::raw(
        "tool:list_async_handles",
        "list_async_handles",
        "List live lashlang async handles only. Returns `{ monitor: { monitor_id: handle }, subagent: { name: handle }, tool: { id: handle } }`; terminal, awaited, or cancelled handles are omitted. In CLBench, use this to rediscover live `start call` handles after a handoff or long-running fan-out.",
        ToolDefinition::default_input_schema(),
        json!({
            "type": "object",
            "properties": {
                "monitor": { "type": "object" },
                "subagent": { "type": "object" },
                "tool": { "type": "object" }
            },
            "required": ["monitor", "subagent", "tool"]
        }),
    )
    .with_examples(vec![r#"handles = (call list_async_handles {})?"#.into()])
    .with_scheduling(ToolScheduling::Parallel)
}

fn build_globals_patch(request: &RunnerRequest) -> Option<RlmGlobalsPatchPluginBody> {
    let mut set_default = serde_json::Map::new();
    if request.init_diary {
        set_default.insert("diary".to_string(), Value::Array(Vec::new()));
    }
    (!set_default.is_empty()).then_some(RlmGlobalsPatchPluginBody { set_default })
}

fn build_projected_bindings(
    request: &RunnerRequest,
) -> anyhow::Result<lash_mode_rlm::RlmProjectedBindings> {
    Ok(lash_mode_rlm::RlmProjectedBindings::new()
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
    let config_path = lash_home().join("config.json");
    let mut config = LashConfig::load(&config_path)
        .ok_or_else(|| anyhow::anyhow!("missing or invalid {}", config_path.display()))?;
    if let Some(provider_id) = provider_id {
        config
            .set_active_provider_kind(provider_id)
            .map_err(anyhow::Error::msg)?;
    }
    config.build_active_provider().map_err(anyhow::Error::msg)
}

fn lash_home() -> PathBuf {
    std::env::var_os("LASH_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".lash")))
        .unwrap_or_else(|| Path::new(".lash").to_path_buf())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clbench_rlm_tool_surface_exposes_explicit_limited_tools() {
        let session = build_plugin_session().expect("plugin session");
        let mut names = session
            .tool_catalog("root")
            .expect("tool catalog")
            .into_iter()
            .filter_map(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            })
            .collect::<Vec<_>>();
        names.sort();
        let mut child_names = clbench_tool_definitions()
            .into_iter()
            .map(|tool| tool.name().to_owned())
            .collect::<Vec<_>>();
        child_names.sort();
        assert_eq!(
            names,
            vec![
                "continue_as",
                "list_async_handles",
                "llm_query",
                "spawn_agent"
            ]
        );
        assert_eq!(
            child_names, names,
            "CLBench subagents use the same tools as the root agent"
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
                !names.iter().any(|name| name == denied),
                "{denied} must not be callable in CLBench"
            );
        }

        for expected in [
            "llm_query",
            "spawn_agent",
            "continue_as",
            "list_async_handles",
        ] {
            assert!(
                names.iter().any(|name| name == expected),
                "{expected} must be callable in CLBench"
            );
        }
        assert!(
            !names.iter().any(|name| name == "peer"),
            "CLBench must not advertise unavailable peer capability"
        );
    }
}

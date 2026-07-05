//! Shared helpers for the Lash benchmark runners.
//!
//! The runners build a [`ProviderHandle`] from the user's `~/.lash/config.json`
//! (the same file the `lash` CLI writes). The CLI's config loader lives in the
//! unpublished `lash-cli` crate, so this module reproduces the small slice the
//! benchmarks need — reading the active provider spec and materializing it with
//! the published provider factories.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use lash_core::{ProviderFactory, ProviderHandle, ProviderSpec};
use lash_provider_anthropic::AnthropicProviderFactory;
use lash_provider_codex::CodexProviderFactory;
use lash_provider_google::GoogleOAuthProviderFactory;
use lash_provider_openai::{OpenAiCompatibleProviderFactory, OpenAiProviderFactory};
use serde::Deserialize;

/// The slice of `~/.lash/config.json` the benchmarks read: the active provider
/// key and the provider specs. Unknown fields (theme, mcp servers, model
/// defaults, …) are ignored.
#[derive(Debug, Deserialize)]
struct LashConfig {
    active_provider: String,
    providers: BTreeMap<String, ProviderSpec>,
}

impl LashConfig {
    fn load(path: &Path) -> Option<Self> {
        let data = std::fs::read_to_string(path).ok()?;
        let config: Self = serde_json::from_str(&data).ok()?;
        config
            .providers
            .contains_key(&config.active_provider)
            .then_some(config)
    }
}

/// `~/.lash` (or `$LASH_HOME`).
pub fn lash_home() -> PathBuf {
    std::env::var_os("LASH_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".lash")))
        .unwrap_or_else(|| Path::new(".lash").to_path_buf())
}

/// Build a [`ProviderHandle`] from `~/.lash/config.json`. When `provider_id` is
/// `Some`, it may be either a provider key from the file or a provider kind
/// such as `codex`.
pub fn load_provider(provider_id: Option<&str>) -> Result<ProviderHandle> {
    let config_path = lash_home().join("config.json");
    let config = LashConfig::load(&config_path).ok_or_else(|| {
        anyhow!(
            "{} not found or invalid — set up a provider with the lash CLI (`lash --provider`) or re-login",
            config_path.display()
        )
    })?;
    let spec = config.resolve_provider_spec(provider_id).with_context(|| {
        format!(
            "provider `{}` not present in {} as a key or kind",
            provider_id.unwrap_or(&config.active_provider),
            config_path.display()
        )
    })?;
    materialize_provider_spec(spec)
}

impl LashConfig {
    fn resolve_provider_spec(&self, provider_id: Option<&str>) -> Option<&ProviderSpec> {
        let key_or_kind = provider_id.unwrap_or(&self.active_provider);
        self.providers.get(key_or_kind).or_else(|| {
            self.providers
                .values()
                .find(|spec| spec.kind == key_or_kind)
        })
    }
}

/// Materialize a [`ProviderSpec`] using the published provider factories. Mirrors
/// the kind dispatch the lash CLI performs.
pub fn materialize_provider_spec(spec: &ProviderSpec) -> Result<ProviderHandle> {
    let components = match spec.kind.as_str() {
        "anthropic" => AnthropicProviderFactory.deserialize(spec.config.clone()),
        "openai" => OpenAiProviderFactory.deserialize(spec.config.clone()),
        "openai-compatible" => OpenAiCompatibleProviderFactory.deserialize(spec.config.clone()),
        "codex" => CodexProviderFactory.deserialize(spec.config.clone()),
        "google_oauth" => GoogleOAuthProviderFactory.deserialize(spec.config.clone()),
        other => bail!("provider `{other}` is not supported by the benchmark runners"),
    }
    .map_err(|err| anyhow!(err))?;
    Ok(ProviderHandle::new(components))
}

/// Default model slug for a provider kind, used when `--model` is omitted.
pub fn default_model_for_provider(kind: &str) -> &'static str {
    match kind {
        "anthropic" => "claude-opus-4-7",
        "openai" => "gpt-5.4",
        "openai-compatible" => "anthropic/claude-sonnet-4.6",
        "codex" => "gpt-5.5",
        "google_oauth" => "gemini-3.1-pro-preview",
        _ => "mock-model",
    }
}

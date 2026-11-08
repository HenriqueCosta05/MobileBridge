//! Contract every instrumentation provider implements (ARC-003, ARC-008).
//!
//! The engine only knows this trait, so new providers are added by implementing it in an adapter crate
//! without modifying the core. Providers send observations through a bounded [`EventSink`]: when the
//! pipeline falls behind, `emit` waits, which pushes backpressure to the source instead of growing memory
//! (ARC-005, NFR-004).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::device::Capability;
use crate::event::Observation;
use crate::private_fs;
use crate::redact::Redactor;
use crate::session::ARTIFACTS_DIR;

#[async_trait]
pub trait Provider: Send + Sync {
    /// Stable identifier, used in event sources, session manifests and CLI selection.
    fn id(&self) -> &'static str;

    /// Checks whether the provider can run on the target device without collecting anything.
    async fn probe(&self) -> Capability;

    /// Collects until the source ends or `context.stop` fires.
    async fn run(&self, context: ProviderContext) -> Result<ProviderReport, ProviderError>;
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("{0}")]
    Source(String),
    #[error("the recording pipeline closed before the provider finished")]
    PipelineClosed,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Everything a running provider is given by the engine.
pub struct ProviderContext {
    pub sink: EventSink,
    pub stop: StopSignal,
    /// Directory where the provider stores raw artifacts. Paths in reports are relative to it.
    pub artifact_dir: PathBuf,
    /// The session's redaction rules, for text artifacts written outside the event pipeline.
    pub redactor: Redactor,
}

/// Bounded, provider-tagged channel into the recording pipeline.
#[derive(Clone)]
pub struct EventSink {
    provider: &'static str,
    sender: mpsc::Sender<SinkItem>,
}

pub(crate) struct SinkItem {
    pub provider: &'static str,
    pub observation: Observation,
}

impl EventSink {
    pub(crate) fn new(provider: &'static str, sender: mpsc::Sender<SinkItem>) -> Self {
        Self { provider, sender }
    }

    /// Sends an observation, waiting while the pipeline queue is full.
    pub async fn emit(&self, observation: Observation) -> Result<(), ProviderError> {
        self.sender
            .send(SinkItem {
                provider: self.provider,
                observation,
            })
            .await
            .map_err(|_| ProviderError::PipelineClosed)
    }
}

/// Cooperative stop request shared by all providers of a recording.
#[derive(Clone)]
pub struct StopSignal {
    receiver: watch::Receiver<bool>,
}

impl StopSignal {
    pub(crate) fn new(receiver: watch::Receiver<bool>) -> Self {
        Self { receiver }
    }

    /// Completes once a stop has been requested (immediately if it already was).
    pub async fn requested(&mut self) {
        // An error means the engine dropped the sender, which is also a reason to stop.
        let _ = self.receiver.wait_for(|stop| *stop).await;
    }
}

/// A provider together with the result of probing it.
pub struct ProbedProvider {
    pub provider: Arc<dyn Provider>,
    pub capability: Capability,
}

/// Probes providers concurrently. Each capability is identified by its provider's id, whatever id the
/// provider put in it, so capabilities and providers cannot be mismatched.
pub async fn probe_all(providers: Vec<Arc<dyn Provider>>) -> Vec<ProbedProvider> {
    let mut probes = JoinSet::new();
    let mut capabilities: Vec<Option<Capability>> = vec![None; providers.len()];
    let mut task_index = std::collections::HashMap::new();
    for (index, provider) in providers.iter().enumerate() {
        let provider = Arc::clone(provider);
        let handle = probes.spawn(async move { (index, provider.probe().await) });
        task_index.insert(handle.id(), index);
    }
    while let Some(joined) = probes.join_next_with_id().await {
        let (index, capability) = match joined {
            Ok((_, (index, capability))) => (index, capability),
            Err(error) => {
                let index = task_index.get(&error.id()).copied().unwrap_or_default();
                let failure =
                    Capability::unavailable("", "the capability check failed unexpectedly", None);
                (index, failure)
            }
        };
        capabilities[index] = Some(capability);
    }
    providers
        .into_iter()
        .zip(capabilities)
        .map(|(provider, capability)| {
            let mut capability = capability.unwrap_or_else(|| {
                Capability::unavailable("", "the capability check did not run", None)
            });
            capability.id = provider.id().to_string();
            ProbedProvider {
                provider,
                capability,
            }
        })
        .collect()
}

/// A raw artifact a provider saved for the session (EVT-003).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRef {
    /// Path relative to the session directory.
    pub path: String,
    pub provider: String,
    pub description: String,
    pub bytes: u64,
}

impl ArtifactRef {
    /// Writes an artifact with owner-only permissions and describes it.
    pub fn write(
        provider: &str,
        artifact_dir: &Path,
        file_name: &str,
        contents: &[u8],
        description: &str,
    ) -> std::io::Result<Self> {
        private_fs::write(&artifact_dir.join(file_name), contents)?;
        Ok(Self::new(
            provider,
            file_name,
            contents.len() as u64,
            description,
        ))
    }

    /// Describes a file another program placed in the artifact directory, restricting it to the owner.
    pub fn adopt(
        provider: &str,
        artifact_dir: &Path,
        file_name: &str,
        description: &str,
    ) -> std::io::Result<Self> {
        let path = artifact_dir.join(file_name);
        private_fs::restrict_to_owner(&path)?;
        let bytes = std::fs::metadata(&path)?.len();
        Ok(Self::new(provider, file_name, bytes, description))
    }

    fn new(provider: &str, file_name: &str, bytes: u64, description: &str) -> Self {
        Self {
            path: format!("{ARTIFACTS_DIR}/{file_name}"),
            provider: provider.to_string(),
            description: description.to_string(),
            bytes,
        }
    }
}

/// What a provider reports when it finishes normally.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderReport {
    pub artifacts: Vec<ArtifactRef>,
    /// Limitations or partial results the user should know about.
    pub notes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::CapabilityStatus;

    struct Probe {
        id: &'static str,
        panics: bool,
    }

    #[async_trait]
    impl Provider for Probe {
        fn id(&self) -> &'static str {
            self.id
        }

        async fn probe(&self) -> Capability {
            assert!(!self.panics, "probe bug");
            Capability::available("a-mistyped-id", "fine")
        }

        async fn run(&self, _context: ProviderContext) -> Result<ProviderReport, ProviderError> {
            Ok(ProviderReport::default())
        }
    }

    #[tokio::test]
    async fn probes_keep_provider_order_ids_and_report_panics() {
        let providers: Vec<Arc<dyn Provider>> = vec![
            Arc::new(Probe {
                id: "first",
                panics: false,
            }),
            Arc::new(Probe {
                id: "broken",
                panics: true,
            }),
        ];
        let probed = probe_all(providers).await;
        let ids: Vec<&str> = probed.iter().map(|p| p.capability.id.as_str()).collect();
        assert_eq!(ids, ["first", "broken"]);
        assert_eq!(probed[0].capability.status, CapabilityStatus::Available);
        assert_eq!(probed[1].capability.status, CapabilityStatus::Unavailable);
    }
}

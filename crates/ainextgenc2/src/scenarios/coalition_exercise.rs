//! FMN coalition exercise — config-driven HTTPS federation runner.

use mim_crypto::PkiMode;
use mim_transport::FederationConfig;

use crate::scenarios::allied_sensor_retrieval::{
    AlliedSensorRetrievalOutput, AlliedSensorRetrievalScenario,
};
use crate::MimStack;

/// Config-driven coalition exercise over HTTPS federation.
#[derive(Clone, Debug)]
pub struct CoalitionExerciseScenario {
    federation: FederationConfig,
}

impl CoalitionExerciseScenario {
    pub fn from_env() -> mim_transport::TransportResult<Self> {
        Ok(Self {
            federation: FederationConfig::from_env()?,
        })
    }

    pub fn with_federation(federation: FederationConfig) -> Self {
        Self { federation }
    }

    pub fn federation(&self) -> &FederationConfig {
        &self.federation
    }

    /// Production coalition exercise: `pki_env` + `MIM_NMB_TRUST` from environment.
    pub async fn run(&self, stack: &MimStack) -> mim_transport::TransportResult<AlliedSensorRetrievalOutput> {
        self.federation.apply_pki_env()?;
        self.run_with_mode(stack, PkiMode::Production).await
    }

    /// Lab coalition exercise using bundled conformance PKI (no environment variables).
    pub async fn run_lab(
        &self,
        stack: &MimStack,
    ) -> mim_transport::TransportResult<AlliedSensorRetrievalOutput> {
        self.run_with_mode(stack, PkiMode::Lab).await
    }

    async fn run_with_mode(
        &self,
        stack: &MimStack,
        mode: PkiMode,
    ) -> mim_transport::TransportResult<AlliedSensorRetrievalOutput> {
        AlliedSensorRetrievalScenario::demo()
            .run_coalition_exercise(stack, Some(&self.federation), mode)
            .await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn coalition_exercise_federation_config_loads() {
        let config_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../config/fmn-federation.toml");
        std::env::set_var("MIM_FEDERATION_CONFIG", &config_path);
        let scenario = CoalitionExerciseScenario::from_env().expect("config");
        assert_eq!(scenario.federation().local_node.id, "usa-national-c2");
    }
}

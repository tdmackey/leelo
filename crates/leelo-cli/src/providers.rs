use crate::{Result, read_bounded};
use leelo_envelope::NetworkBinding;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    providers: Vec<ProviderConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderConfig {
    provider_id: String,
    key_id: String,
    public_key: String,
    url: String,
    ca_file: PathBuf,
}

struct Identity {
    provider_id: [u8; 32],
    key_id: [u8; 32],
    public_key: [u8; 49],
}

/// Resolve trusted endpoint configuration without creating an enrollment.
pub(super) struct Providers {
    pub network: leelo_net::HttpsNetworkProvider,
    identities: Vec<Identity>,
}

fn unhex<const N: usize>(value: &str) -> Result<[u8; N]> {
    hex::decode(value)?
        .try_into()
        .map_err(|_| "wrong hex field length".into())
}

impl Providers {
    pub fn provider_ids(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.identities.iter().map(|identity| identity.provider_id)
    }

    pub fn read(path: &Path) -> Result<Self> {
        let config: Config = serde_json::from_slice(&read_bounded(path, 32 * 1024)?)?;
        if config.providers.is_empty() || config.providers.len() > 27 {
            return Err("configure 1..27 independent network providers".into());
        }
        let mut identities = Vec::new();
        let mut endpoints = Vec::new();
        for provider in config.providers {
            let provider_id = unhex(&provider.provider_id)?;
            let public_key = unhex(&provider.public_key)?;
            let key_id = unhex(&provider.key_id)?;
            if leelo_net::key_id(&public_key) != key_id {
                return Err("provider key ID does not match public key".into());
            }
            let ca = if provider.ca_file.is_absolute() {
                provider.ca_file
            } else {
                path.parent()
                    .unwrap_or(Path::new("."))
                    .join(provider.ca_file)
            };
            endpoints.push(leelo_net::Endpoint {
                provider_id,
                url: provider.url,
                ca_pem: read_bounded(&ca, 64 * 1024)?,
            });
            identities.push(Identity {
                provider_id,
                key_id,
                public_key,
            });
        }
        Ok(Self {
            network: leelo_net::HttpsNetworkProvider::new(endpoints)?,
            identities,
        })
    }

    /// Only enrollment creates new input seeds. Unlock and resume use the signed envelope.
    pub fn enrollment_bindings(&self) -> Result<Vec<NetworkBinding>> {
        self.identities
            .iter()
            .enumerate()
            .map(|(index, identity)| {
                Ok(NetworkBinding {
                    node_id: (index + 2) as u8,
                    provider_id: identity.provider_id,
                    key_id: identity.key_id,
                    public_key: identity.public_key,
                    input_seed: *leelo_crypto::random_bytes::<32>()?,
                })
            })
            .collect()
    }
}

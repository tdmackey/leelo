use crate::Outcome;
use leelo_envelope::NetworkBinding;
use leelo_net::{Endpoint, HttpsNetworkProvider};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: usize = 32 * 1024;
const MAX_TARGETS: usize = 27;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    providers: Vec<Provider>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provider {
    provider_id: String,
    key_id: String,
    public_key: String,
    url: String,
    ca_file: PathBuf,
}

pub(crate) struct Configured {
    pub network: HttpsNetworkProvider,
    pub binding: NetworkBinding,
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, Outcome> {
    // Operator-owned regular files only; never intentionally open a pipe or device.
    if !std::fs::metadata(path)
        .map_err(|_| Outcome::Configuration)?
        .is_file()
    {
        return Err(Outcome::Configuration);
    }
    let file = File::open(path).map_err(|_| Outcome::Configuration)?;
    if !file
        .metadata()
        .map_err(|_| Outcome::Configuration)?
        .is_file()
    {
        return Err(Outcome::Configuration);
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Outcome::Configuration)?;
    if bytes.len() > limit {
        return Err(Outcome::Configuration);
    }
    Ok(bytes)
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N], Outcome> {
    if text.len() != N * 2 {
        return Err(Outcome::Configuration);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| Outcome::Configuration)?;
    Ok(bytes)
}

pub(crate) fn read(path: &Path, target: u8) -> Result<Configured, Outcome> {
    let config: Config = serde_json::from_slice(&read_bounded(path, MAX_CONFIG_BYTES)?)
        .map_err(|_| Outcome::Configuration)?;
    if config.providers.is_empty()
        || config.providers.len() > MAX_TARGETS
        || target == 0
        || usize::from(target) > config.providers.len()
    {
        return Err(Outcome::Configuration);
    }
    let mut identities = BTreeSet::new();
    let mut selected = None;
    for (index, provider) in config.providers.into_iter().enumerate() {
        let provider_id = unhex(&provider.provider_id)?;
        let public_key = unhex(&provider.public_key)?;
        let key_id = unhex(&provider.key_id)?;
        if !identities.insert(provider_id) || leelo_net::key_id(&public_key) != key_id {
            return Err(Outcome::Configuration);
        }
        leelo_crypto::ServerPublicKey::from_bytes(public_key)
            .map_err(|_| Outcome::Configuration)?;
        if index + 1 != usize::from(target) {
            continue;
        }
        let ca_path = if provider.ca_file.is_absolute() {
            provider.ca_file
        } else {
            path.parent()
                .unwrap_or(Path::new("."))
                .join(provider.ca_file)
        };
        let ca_pem = read_bounded(&ca_path, leelo_net::MAX_CA_BYTES)?;
        let network = HttpsNetworkProvider::new(vec![Endpoint {
            provider_id,
            url: provider.url,
            ca_pem,
        }])
        .map_err(Outcome::from)?;
        selected = Some(Configured {
            network,
            binding: NetworkBinding {
                node_id: 1,
                provider_id,
                key_id,
                public_key,
                input_seed: [0; 32],
            },
        });
    }
    selected.ok_or(Outcome::Configuration)
}

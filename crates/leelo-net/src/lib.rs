#![forbid(unsafe_code)]
//! The operator configures this HTTPS transport. Network-bound messages have a fixed size.

use leelo_crypto::Evaluation;
use leelo_engine::NetworkProvider;
use leelo_envelope::NetworkBinding;
use reqwest::blocking::Client;
use reqwest::{Certificate, Url};
use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

pub mod wire;

pub const MAX_PROVIDERS: usize = 32;
pub const MAX_CA_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Configuration,
    DuplicateProvider,
    UnknownProvider,
    InvalidKeyId,
    Transport,
    RemoteFailure,
    Protocol,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid trusted network-provider configuration",
            Self::DuplicateProvider => "duplicate network provider identifier",
            Self::UnknownProvider => "network provider is not configured locally",
            Self::InvalidKeyId => "network binding key identifier does not match its public key",
            Self::Transport => "network provider TLS or transport failure",
            Self::RemoteFailure => "network provider refused evaluation",
            Self::Protocol => "invalid network provider response",
        })
    }
}
impl std::error::Error for Error {}

/// A trusted local operator supplies this configuration. A LUKS token cannot supply it.
/// `url` is an HTTPS origin. This crate supplies the evaluation path.
pub struct Endpoint {
    pub provider_id: [u8; 32],
    pub url: String,
    pub ca_pem: Vec<u8>,
}

struct ConfiguredEndpoint {
    url: Url,
    client: Client,
}

pub struct HttpsNetworkProvider {
    endpoints: BTreeMap<[u8; 32], ConfiguredEndpoint>,
}

pub fn key_id(public: &[u8; 49]) -> [u8; 32] {
    let digest = leelo_crypto::hash_context(public);
    let mut id = [0; 32];
    id.copy_from_slice(&digest[..32]);
    id
}

impl HttpsNetworkProvider {
    pub fn new(endpoints: Vec<Endpoint>) -> Result<Self, Error> {
        if endpoints.is_empty() || endpoints.len() > MAX_PROVIDERS {
            return Err(Error::Configuration);
        }
        let mut configured = BTreeMap::new();
        for endpoint in endpoints {
            if endpoint.url.len() > 2048 {
                return Err(Error::Configuration);
            }
            let mut url = Url::parse(&endpoint.url).map_err(|_| Error::Configuration)?;
            if url.scheme() != "https"
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || endpoint.ca_pem.is_empty()
                || endpoint.ca_pem.len() > MAX_CA_BYTES
            {
                return Err(Error::Configuration);
            }
            let roots =
                Certificate::from_pem_bundle(&endpoint.ca_pem).map_err(|_| Error::Configuration)?;
            if roots.is_empty() {
                return Err(Error::Configuration);
            }
            let mut builder = Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .tls_built_in_root_certs(false)
                .min_tls_version(reqwest::tls::Version::TLS_1_3)
                .max_tls_version(reqwest::tls::Version::TLS_1_3)
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(5))
                .pool_max_idle_per_host(0);
            for root in roots {
                builder = builder.add_root_certificate(root);
            }
            let client = builder.build().map_err(|_| Error::Configuration)?;
            url.set_path("/v1/evaluate");
            if configured
                .insert(endpoint.provider_id, ConfiguredEndpoint { url, client })
                .is_some()
            {
                return Err(Error::DuplicateProvider);
            }
        }
        Ok(Self {
            endpoints: configured,
        })
    }

    pub fn evaluate_binding(
        &self,
        binding: &NetworkBinding,
        blinded: &[u8; 49],
    ) -> Result<Evaluation, Error> {
        if binding.key_id != key_id(&binding.public_key) {
            return Err(Error::InvalidKeyId);
        }
        let endpoint = self
            .endpoints
            .get(&binding.provider_id)
            .ok_or(Error::UnknownProvider)?;
        let body = wire::encode_request(&binding.key_id, blinded);
        let response = endpoint
            .client
            .post(endpoint.url.clone())
            .header(reqwest::header::CONTENT_TYPE, wire::CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, wire::CONTENT_TYPE)
            .body(body.to_vec())
            .send()
            .map_err(|_| Error::Transport)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(Error::RemoteFailure);
        }
        if response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|x| x.to_str().ok())
            != Some(wire::CONTENT_TYPE)
            || response
                .headers()
                .get_all(reqwest::header::CONTENT_TYPE)
                .iter()
                .count()
                != 1
            || response
                .headers()
                .contains_key(reqwest::header::CONTENT_ENCODING)
            || response
                .content_length()
                .is_some_and(|len| len != wire::RESPONSE_BYTES as u64)
        {
            return Err(Error::Protocol);
        }
        let mut bytes = Vec::with_capacity(wire::RESPONSE_BYTES + 1);
        response
            .take((wire::RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Transport)?;
        wire::decode_response(&bytes).map_err(|_| Error::Protocol)
    }
}

impl NetworkProvider for HttpsNetworkProvider {
    fn evaluate(
        &mut self,
        binding: &NetworkBinding,
        blinded: &[u8; 49],
    ) -> Result<Evaluation, leelo_engine::Error> {
        self.evaluate_binding(binding, blinded)
            .map_err(|_| leelo_engine::Error::Provider("network-bound provider evaluation failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_untrusted_url_capabilities_before_io() {
        for url in [
            "http://host",
            "https://u:p@host",
            "https://host/path",
            "https://host/?q=1",
            "https://host/#f",
            "file:///tmp/key",
        ] {
            let endpoint = Endpoint {
                provider_id: [1; 32],
                url: url.into(),
                ca_pem: b"invalid".to_vec(),
            };
            assert!(HttpsNetworkProvider::new(vec![endpoint]).is_err());
        }
    }
}

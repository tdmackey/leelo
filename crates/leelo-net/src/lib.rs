#![forbid(unsafe_code)]
//! The operator configures this HTTPS transport. Network-bound messages have a fixed size.

mod dns;

use leelo_crypto::Evaluation;
use leelo_engine::{NetworkFailure, NetworkProvider};
use leelo_envelope::NetworkBinding;
use reqwest::Client;
use reqwest::{Certificate, Url};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub use leelo_protocol::{key_id, wire};

pub const MAX_PROVIDERS: usize = 32;
pub const MAX_CA_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Configuration,
    DuplicateProvider,
    UnknownProvider,
    InvalidKeyId,
    Transport,
    Timeout,
    Runtime,
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
            Self::Timeout => "network provider response deadline expired",
            Self::Runtime => "network provider requires a synchronous caller or its async adapter",
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

/// A monitoring result from the ordinary, certificate-validated HTTPS exchange.
/// The optional DER is the peer leaf certificate, never the configured trust root.
/// Callers must not include certificate bytes or protocol material in telemetry.
pub struct ObservedEvaluation {
    pub evaluation: Result<Evaluation, Error>,
    pub peer_certificate_der: Option<Vec<u8>>,
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
                // Async DNS permits request cancellation without a blocking NSS call.
                .dns_resolver(std::sync::Arc::new(dns::DnsResolver))
                .redirect(reqwest::redirect::Policy::none())
                .tls_built_in_root_certs(false)
                .tls_info(true)
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
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Error::Runtime);
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Runtime)?;
        runtime.block_on(self.evaluate_before(
            binding,
            blinded,
            Instant::now() + Duration::from_secs(5),
        ))
    }

    /// Run one bounded evaluation and expose the TLS peer certificate to a probe.
    /// Validation, DNS, protocol framing, and the five-second deadline are unchanged.
    pub fn evaluate_binding_observed(
        &self,
        binding: &NetworkBinding,
        blinded: &[u8; 49],
    ) -> ObservedEvaluation {
        let mut peer_certificate_der = None;
        let evaluation = (|| {
            if tokio::runtime::Handle::try_current().is_ok() {
                return Err(Error::Runtime);
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| Error::Runtime)?;
            runtime.block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    self.exchange(binding, blinded, Some(&mut peer_certificate_der)),
                )
                .await
                .map_err(|_| Error::Timeout)?
            })
        })();
        ObservedEvaluation {
            evaluation,
            peer_certificate_der,
        }
    }

    async fn evaluate_before(
        &self,
        binding: &NetworkBinding,
        blinded: &[u8; 49],
        deadline: Instant,
    ) -> Result<Evaluation, Error> {
        let deadline = deadline.min(Instant::now() + Duration::from_secs(5));
        tokio::time::timeout_at(deadline.into(), self.exchange(binding, blinded, None))
            .await
            .map_err(|_| Error::Timeout)?
    }

    async fn exchange(
        &self,
        binding: &NetworkBinding,
        blinded: &[u8; 49],
        peer_certificate_der: Option<&mut Option<Vec<u8>>>,
    ) -> Result<Evaluation, Error> {
        if binding.key_id != key_id(&binding.public_key) {
            return Err(Error::InvalidKeyId);
        }
        let endpoint = self
            .endpoints
            .get(&binding.provider_id)
            .ok_or(Error::UnknownProvider)?;
        let body = wire::encode_request(&binding.key_id, blinded);
        let mut response = endpoint
            .client
            .post(endpoint.url.clone())
            .header(reqwest::header::CONTENT_TYPE, wire::CONTENT_TYPE)
            .header(reqwest::header::ACCEPT, wire::CONTENT_TYPE)
            .body(body.to_vec())
            .send()
            .await
            .map_err(transport_error)?;
        if let Some(peer_certificate_der) = peer_certificate_der {
            *peer_certificate_der = response
                .extensions()
                .get::<reqwest::tls::TlsInfo>()
                .and_then(|info| info.peer_certificate())
                .filter(|der| der.len() <= MAX_CA_BYTES)
                .map(<[u8]>::to_vec);
        }
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
        while let Some(chunk) = response.chunk().await.map_err(transport_error)? {
            if bytes.len() + chunk.len() > wire::RESPONSE_BYTES {
                return Err(Error::Protocol);
            }
            bytes.extend_from_slice(&chunk);
        }
        wire::decode_response(&bytes).map_err(|_| Error::Protocol)
    }
}

impl NetworkProvider for HttpsNetworkProvider {
    async fn evaluate(
        &self,
        binding: &NetworkBinding,
        blinded: &[u8; 49],
        deadline: Instant,
    ) -> Result<Evaluation, NetworkFailure> {
        self.evaluate_before(binding, blinded, deadline)
            .await
            .map_err(|error| match error {
                Error::Configuration
                | Error::DuplicateProvider
                | Error::UnknownProvider
                | Error::InvalidKeyId
                | Error::Runtime => NetworkFailure::Configuration,
                Error::Transport => NetworkFailure::Unavailable,
                Error::Timeout => NetworkFailure::Timeout,
                Error::RemoteFailure => NetworkFailure::RemoteRejected,
                Error::Protocol => NetworkFailure::InvalidResponse,
            })
    }
}

fn transport_error(error: reqwest::Error) -> Error {
    if error.is_timeout() {
        Error::Timeout
    } else {
        Error::Transport
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

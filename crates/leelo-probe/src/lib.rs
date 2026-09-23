#![forbid(unsafe_code)]
//! One independent evaluation with a dedicated public test input. No disk or TPM access.

mod config;
mod output;

pub use output::write_textfile;

use leelo_crypto::ServerPublicKey;
use serde::Serialize;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use x509_cert::der::Decode;

/// This domain is deliberately separate from production envelope inputs.
const PROBE_INPUT: &[u8] = b"leelo/v1/independent-evaluation-probe\0nonproduction";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Configuration,
    Transport,
    Timeout,
    RemoteRejected,
    InvalidResponse,
    InvalidProof,
    Cryptography,
    Runtime,
}

impl Outcome {
    pub const ALL: [Self; 9] = [
        Self::Success,
        Self::Configuration,
        Self::Transport,
        Self::Timeout,
        Self::RemoteRejected,
        Self::InvalidResponse,
        Self::InvalidProof,
        Self::Cryptography,
        Self::Runtime,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Configuration => "configuration",
            Self::Transport => "transport",
            Self::Timeout => "timeout",
            Self::RemoteRejected => "remote_rejected",
            Self::InvalidResponse => "invalid_response",
            Self::InvalidProof => "invalid_proof",
            Self::Cryptography => "cryptography",
            Self::Runtime => "runtime",
        }
    }
}

impl From<leelo_net::Error> for Outcome {
    fn from(error: leelo_net::Error) -> Self {
        use leelo_net::Error;
        match error {
            Error::Configuration
            | Error::DuplicateProvider
            | Error::UnknownProvider
            | Error::InvalidKeyId => Self::Configuration,
            Error::Transport => Self::Transport,
            Error::Timeout => Self::Timeout,
            Error::RemoteFailure => Self::RemoteRejected,
            Error::Protocol => Self::InvalidResponse,
            Error::Runtime => Self::Runtime,
        }
    }
}

/// Allowlisted, fixed-size observation. No endpoint, identity, path, or crypto bytes.
#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub target: u8,
    pub outcome: Outcome,
    pub success: bool,
    pub collection_success: bool,
    pub clock_valid: bool,
    pub started_timestamp_seconds: u64,
    pub completed_timestamp_seconds: u64,
    pub duration_seconds: f64,
    pub certificate_not_after_timestamp_seconds: Option<u64>,
}

fn timestamp() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Select one provider by its one-based index in the ordinary provider configuration.
/// Every invocation samples a fresh blind. The finalized output is immediately dropped.
pub fn run(config_path: &Path, target: u8) -> Report {
    let started = timestamp();
    let clock = Instant::now();
    let mut certificate_not_after_timestamp_seconds = None;
    let result = (|| {
        let configured = config::read(config_path, target)?;
        let pin = ServerPublicKey::from_bytes(configured.binding.public_key)
            .map_err(|_| Outcome::Configuration)?;
        let (state, point) = leelo_crypto::blind(PROBE_INPUT).map_err(|_| Outcome::Cryptography)?;
        let observed = configured
            .network
            .evaluate_binding_observed(&configured.binding, &point);
        certificate_not_after_timestamp_seconds = observed
            .peer_certificate_der
            .as_deref()
            .and_then(certificate_expiry);
        let evaluation = observed.evaluation.map_err(Outcome::from)?;
        // Successful HTTP and well-formed framing are insufficient: verify the trusted pin.
        let output = state
            .finalize(&evaluation, &pin)
            .map_err(|error| match error {
                leelo_crypto::Error::InvalidEncoding => Outcome::InvalidResponse,
                leelo_crypto::Error::InvalidProof => Outcome::InvalidProof,
                _ => Outcome::Cryptography,
            })?;
        drop(output);
        Ok::<(), Outcome>(())
    })();
    let completed = timestamp();
    let outcome = result.err().unwrap_or(Outcome::Success);
    let clock_valid = started.zip(completed).is_some_and(|(a, b)| b >= a);
    Report {
        schema_version: 1,
        target,
        outcome,
        success: outcome == Outcome::Success,
        collection_success: clock_valid
            && (outcome != Outcome::Success || certificate_not_after_timestamp_seconds.is_some()),
        clock_valid,
        started_timestamp_seconds: started.unwrap_or(0),
        completed_timestamp_seconds: completed.unwrap_or(0),
        duration_seconds: clock.elapsed().as_secs_f64(),
        certificate_not_after_timestamp_seconds,
    }
}

fn certificate_expiry(der: &[u8]) -> Option<u64> {
    let certificate = x509_cert::Certificate::from_der(der).ok()?;
    Some(
        certificate
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
    )
}

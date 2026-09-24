//! This adapter uses TPM2-TSS to seal seeds with explicit SHA-256 PCR equality policies.
//!
//! The adapter implements network-bound mode. It rejects attested mode.
//! It does not implement signed PCR updates or NV rollback policies.
//! The core proof does not cover the TPM, firmware, TSS FFI, or this platform adapter.
#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::Tpm2Provider;

/// Builds for other operating systems supply an explicit unsupported platform adapter.
#[cfg(not(target_os = "linux"))]
pub struct Tpm2Provider;

#[cfg(not(target_os = "linux"))]
impl Tpm2Provider {
    pub fn new(_: &str) -> Result<Self, leelo_engine::Error> {
        Err(leelo_engine::Error::Provider("TPM2-TSS requires Linux"))
    }
    pub fn pcr_digest(&mut self, _: u32) -> Result<[u8; 32], leelo_engine::Error> {
        Err(leelo_engine::Error::Provider("TPM2-TSS requires Linux"))
    }
}

#[cfg(not(target_os = "linux"))]
impl leelo_engine::TpmProvider for Tpm2Provider {
    fn supports_mode(&self, _: leelo_policy::Mode) -> bool {
        false
    }
    fn seal(
        &mut self,
        _: &leelo_envelope::Descriptor,
        _: &[u8; 32],
    ) -> Result<leelo_envelope::TpmBlob, leelo_engine::Error> {
        Err(leelo_engine::Error::Provider("TPM2-TSS requires Linux"))
    }
    fn unseal(
        &mut self,
        _: &leelo_envelope::AuthenticatedEnvelope,
    ) -> Result<leelo_engine::UnsealedSeed, leelo_engine::Error> {
        Err(leelo_engine::Error::Provider("TPM2-TSS requires Linux"))
    }
}

use std::str::FromStr;

use leelo_engine::{Error, TpmAuthorization, TpmProvider, UnsealedSeed};
use leelo_envelope::{AuthenticatedEnvelope, Descriptor, TpmBlob};
use leelo_policy::Mode;
use sha2::{Digest as _, Sha256};
use tss_esapi::{
    Context, TctiNameConf,
    attributes::{ObjectAttributes, ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{CommandCode, SessionType},
    handles::{KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, EccPoint, KeyedHashScheme, PcrSelectionList, PcrSelectionListBuilder, PcrSlot,
        Private, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
        SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::{Marshall, UnMarshall},
};
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

/// Trusted boot or enrollment configuration supplies the settings for this adapter.
///
/// The adapter does not read ambient TCTI environment variables.
/// It does not accept `tcti` from an envelope.
/// Production callers usually select `device:/dev/tpmrm0`.
/// Software TPM transports support isolated tests. They do not provide hardware assurance.
/// The owner hierarchy must have empty authorization for this initial adapter.
/// The adapter never changes hierarchy authorization or creates persistent handles.
pub struct Tpm2Provider {
    tcti: TctiNameConf,
}

fn tss_error(operation: &'static str, error: tss_esapi::Error) -> Error {
    // Diagnostics contain no library objects, command parameters, or secret buffers.
    Error::Tpm {
        operation,
        detail: format!("{error:?}"),
    }
}

impl Tpm2Provider {
    /// Parse trusted transport configuration without issuing a TPM command.
    pub fn new(tcti: &str) -> Result<Self, Error> {
        let tcti = TctiNameConf::from_str(tcti).map_err(|error| tss_error("new", error))?;
        Ok(Self { tcti })
    }

    fn context(&self) -> Result<Context, Error> {
        Context::new(self.tcti.clone()).map_err(|error| tss_error("context", error))
    }

    /// Hash the selected SHA-256 PCR values in increasing PCR-index order.
    ///
    /// PCR update counters must agree across reads.
    /// This method produces a direct equality policy for the current state.
    /// It does not produce a signed update policy.
    pub fn pcr_digest(&mut self, mask: u32) -> Result<[u8; 32], Error> {
        validate_mask(mask)?;
        let mut context = self.context()?;
        let mut counter = None;
        let mut hash = Sha256::new();
        for index in 0..24 {
            if mask & (1 << index) == 0 {
                continue;
            }
            let selected = selection(1 << index)?;
            let (current, returned, digests) = context
                .pcr_read(selected.clone())
                .map_err(|error| tss_error("pcr_digest", error))?;
            if returned != selected
                || digests.value().len() != 1
                || digests.value()[0].value().len() != 32
            {
                return Err(Error::Provider("selected SHA256 PCR is unavailable"));
            }
            if counter.is_some_and(|previous| previous != current) {
                return Err(Error::Provider("PCR state changed during snapshot"));
            }
            counter = Some(current);
            hash.update(digests.value()[0].value());
        }
        Ok(hash.finalize().into())
    }
}

fn validate_mask(mask: u32) -> Result<(), Error> {
    if mask == 0 || mask & 0xff00_0000 != 0 {
        return Err(Error::Provider(
            "PCR selection must use SHA256 PCRs 0 through 23",
        ));
    }
    Ok(())
}

fn selection(mask: u32) -> Result<PcrSelectionList, Error> {
    validate_mask(mask)?;
    let slots: Result<Vec<_>, _> = (0..24)
        .filter(|index| mask & (1 << index) != 0)
        .map(|index| PcrSlot::try_from(1_u32 << index))
        .collect();
    PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &slots.map_err(|error| tss_error("selection", error))?,
        )
        .build()
        .map_err(|error| tss_error("selection", error))
}

fn sealed_attributes() -> Result<ObjectAttributes, Error> {
    ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_admin_with_policy(true)
        .with_user_with_auth(false)
        .with_sensitive_data_origin(false)
        .with_restricted(false)
        .with_decrypt(false)
        .with_sign_encrypt(false)
        .build()
        .map_err(|error| tss_error("sealed_attributes", error))
}

fn sealed_public(policy: Digest) -> Result<Public, Error> {
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(sealed_attributes()?)
        .with_auth_policy(policy)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .map_err(|error| tss_error("sealed_public", error))
}

fn parent_public() -> Result<Public, Error> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .build()
        .map_err(|error| tss_error("parent_public", error))?;
    let parameters = PublicEccParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        EccCurve::NistP256,
    )
    .build()
    .map_err(|error| tss_error("parent_public", error))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|error| tss_error("parent_public", error))
}

fn sha256_name(public: &Public) -> Result<Vec<u8>, Error> {
    if public.name_hashing_algorithm() != HashingAlgorithm::Sha256 {
        return Err(Error::Provider("TPM object Name must use SHA256"));
    }
    let bytes = public
        .marshall()
        .map_err(|error| tss_error("sha256_name", error))?;
    let mut name = vec![0x00, 0x0b]; // TPM_ALG_SHA256, big endian.
    name.extend_from_slice(&Sha256::digest(&bytes));
    Ok(name)
}

fn create_parent(context: &mut Context) -> Result<(KeyHandle, Vec<u8>), Error> {
    let template = parent_public()?;
    // The primary contains no supplied secret.
    // Subsequent commands that carry seeds use a session salted to this key.
    // Those commands never use password-only traffic.
    let result = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map_err(|error| tss_error("create_parent", error))?;
    let name = sha256_name(&result.out_public)?;
    if context
        .tr_get_name(result.key_handle.into())
        .map_err(|error| tss_error("create_parent", error))?
        .value()
        != name
    {
        return Err(Error::Provider("primary object Name mismatch"));
    }
    Ok((result.key_handle, name))
}

fn start_session(
    context: &mut Context,
    parent: Option<KeyHandle>,
    kind: SessionType,
) -> Result<AuthSession, Error> {
    context
        .start_auth_session(
            parent,
            None,
            None,
            kind,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|error| tss_error("start_session", error))?
        .ok_or(Error::Provider("TPM returned no session"))
}

fn set_protection(
    context: &mut Context,
    session: AuthSession,
    decrypt: bool,
    encrypt: bool,
) -> Result<(), Error> {
    let (attributes, mask) = SessionAttributesBuilder::new()
        .with_continue_session(true)
        .with_decrypt(decrypt)
        .with_encrypt(encrypt)
        .build();
    context
        .tr_sess_set_attributes(session, attributes, mask)
        .map_err(|error| tss_error("set_protection", error))
}

fn apply_policy(
    context: &mut Context,
    session: AuthSession,
    descriptor: &Descriptor,
) -> Result<PolicySession, Error> {
    let policy =
        PolicySession::try_from(session).map_err(|error| tss_error("apply_policy", error))?;
    context
        .policy_pcr(
            policy,
            Digest::try_from(descriptor.tpm_pcr_digest.as_slice())
                .map_err(|error| tss_error("apply_policy", error))?,
            selection(descriptor.tpm_pcr_mask)?,
        )
        .map_err(|error| tss_error("apply_policy", error))?;
    context
        .policy_command_code(policy, CommandCode::Unseal)
        .map_err(|error| tss_error("apply_policy", error))?;
    Ok(policy)
}

fn expected_policy(context: &mut Context, descriptor: &Descriptor) -> Result<Digest, Error> {
    let session = start_session(context, None, SessionType::Trial)?;
    let policy = apply_policy(context, session, descriptor)?;
    let digest = context
        .policy_get_digest(policy)
        .map_err(|error| tss_error("expected_policy", error))?;
    context
        .flush_context(SessionHandle::from(session).into())
        .map_err(|error| tss_error("expected_policy", error))?;
    Ok(digest)
}

fn validate_public(public: &Public, expected: &Digest) -> Result<(), Error> {
    match public {
        Public::KeyedHash {
            object_attributes,
            name_hashing_algorithm,
            auth_policy,
            parameters,
            unique,
        } if *object_attributes == sealed_attributes()?
            && *name_hashing_algorithm == HashingAlgorithm::Sha256
            && auth_policy == expected
            && *parameters == PublicKeyedHashParameters::new(KeyedHashScheme::Null)
            && unique.value().len() == 32 =>
        {
            Ok(())
        }
        _ => Err(Error::Provider(
            "sealed object has unexpected policy or attributes",
        )),
    }
}

fn require_network_bound(descriptor: &Descriptor) -> Result<(), Error> {
    if descriptor.policy.mode() != Mode::NetworkBound {
        return Err(Error::UnsupportedMode);
    }
    // Validate the complete descriptor before the first platform operation.
    leelo_envelope::descriptor_bytes(descriptor)?;
    Ok(())
}

impl TpmProvider for Tpm2Provider {
    fn supports_mode(&self, mode: Mode) -> bool {
        mode == Mode::NetworkBound
    }
    fn seal(&mut self, descriptor: &Descriptor, seed: &[u8; 32]) -> Result<TpmBlob, Error> {
        require_network_bound(descriptor)?;
        let mut context = self.context()?;
        let auth_policy = expected_policy(&mut context, descriptor)?;
        let (parent, parent_name) = create_parent(&mut context)?;
        let session = start_session(&mut context, Some(parent), SessionType::Hmac)?;
        set_protection(&mut context, session, true, true)?;
        let public = sealed_public(auth_policy.clone())?;
        let sensitive =
            SensitiveData::try_from(seed.as_slice()).map_err(|error| tss_error("seal", error))?;
        let result = context
            .execute_with_session(Some(session), |ctx| {
                ctx.create(parent, public, None, Some(sensitive), None, None)
            })
            .map_err(|error| tss_error("seal", error))?;
        validate_public(&result.out_public, &auth_policy)?;
        let name = sha256_name(&result.out_public)?;
        Ok(TpmBlob {
            public: result
                .out_public
                .marshall()
                .map_err(|error| tss_error("seal", error))?,
            private: result.out_private.value().to_vec(),
            name,
            parent_name,
        })
        // Context drop flushes only the objects and sessions that this context owns.
    }

    fn unseal(&mut self, envelope: &AuthenticatedEnvelope) -> Result<UnsealedSeed, Error> {
        let body = envelope.body();
        let descriptor = &body.descriptor;
        require_network_bound(descriptor)?;
        let public =
            Public::unmarshall(&body.tpm.public).map_err(|error| tss_error("unseal", error))?;
        if public
            .marshall()
            .map_err(|error| tss_error("unseal", error))?
            != body.tpm.public
            || sha256_name(&public)? != body.tpm.name
            || body.tpm.parent_name.len() != 34
        {
            return Err(Error::Provider(
                "noncanonical TPM public or mismatched object Name",
            ));
        }
        let private = Private::try_from(body.tpm.private.as_slice())
            .map_err(|error| tss_error("unseal", error))?;
        let mut context = self.context()?;
        let auth_policy = expected_policy(&mut context, descriptor)?;
        validate_public(&public, &auth_policy)?;
        let (parent, parent_name) = create_parent(&mut context)?;
        if parent_name != body.tpm.parent_name {
            return Err(Error::Provider("TPM storage parent identity changed"));
        }
        let object = context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.load(parent, private, public)
            })
            .map_err(|error| tss_error("unseal", error))?;
        if context
            .tr_get_name(object.into())
            .map_err(|error| tss_error("unseal", error))?
            .value()
            != body.tpm.name
        {
            return Err(Error::Provider("loaded TPM object Name mismatch"));
        }
        let session = start_session(&mut context, Some(parent), SessionType::Policy)?;
        apply_policy(&mut context, session, descriptor)?;
        // Encrypt the Unseal response. Unseal has no encryptable request parameter.
        // Keep the decrypt attribute clear.
        set_protection(&mut context, session, false, true)?;
        let sensitive = context
            .execute_with_session(Some(session), |ctx| ctx.unseal(object.into()))
            .map_err(|error| tss_error("unseal", error))?;
        if sensitive.value().len() != 32 {
            return Err(Error::Provider("unsealed seed has unexpected length"));
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        seed.copy_from_slice(sensitive.value());
        Ok(UnsealedSeed {
            seed,
            authorization: TpmAuthorization::LocalMeasuredBoot,
        })
    }
}

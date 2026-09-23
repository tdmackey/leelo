//! These deterministic-CBOR envelopes have size limits. Trust keys are external to the token.
#![forbid(unsafe_code)]

use leelo_crypto::{SecretSigningKey, WrappedKey};
use leelo_policy::{Mode, NetworkNode, ProductionPolicy};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha384};

pub const VERSION: u8 = 1;
pub const SUITE: u8 = 1;
pub const MAX_ENVELOPE: usize = 64 * 1024;
pub const MAX_TPM_BLOB: usize = 4096;
const SIGN_DOMAIN: &[u8] = b"leelo/v1/envelope\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Malformed,
    NonCanonical,
    Unsupported,
    InvalidPolicy,
    InvalidProvider,
    InvalidSignature,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "envelope: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkBinding {
    pub node_id: u8,
    pub provider_id: [u8; 32],
    pub key_id: [u8; 32],
    pub public_key: [u8; 49],
    pub input_seed: [u8; 32],
}

/// This public configuration contains no paths, URLs, private keys, or algorithm names.
#[derive(Clone, Debug)]
pub struct Descriptor {
    pub binding_id: [u8; 32],
    pub volume_uuid: [u8; 16],
    pub slot: u8,
    pub generation: u64,
    pub policy: ProductionPolicy,
    pub networks: Vec<NetworkBinding>,
    pub tpm_pcr_mask: u32,
    pub tpm_pcr_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmBlob {
    pub public: Vec<u8>,
    pub private: Vec<u8>,
    pub name: Vec<u8>,
    pub parent_name: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct WrappedLeaf {
    pub node_id: u8,
    pub value: WrappedKey,
}

/// Use this material to construct an envelope. It does not authorize a recovery operation.
#[derive(Clone, Debug)]
pub struct EnvelopeBody {
    pub descriptor: Descriptor,
    pub tpm: TpmBlob,
    pub leaves: Vec<WrappedLeaf>,
    pub payload: WrappedKey,
}

/// Only signature verification against an external key can construct this value.
pub struct AuthenticatedEnvelope {
    body: EnvelopeBody,
    context: [u8; 48],
}
impl AuthenticatedEnvelope {
    pub fn body(&self) -> &EnvelopeBody {
        &self.body
    }
    pub fn context(&self) -> &[u8; 48] {
        &self.context
    }
}

type Enc = Encoder<Vec<u8>>;
fn malformed<T>(_: T) -> Error {
    Error::Malformed
}
fn arr(d: &mut Decoder<'_>, size: u64) -> Result<(), Error> {
    if d.array().map_err(malformed)? != Some(size) {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn bytes<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], Error> {
    d.bytes().map_err(malformed)?.try_into().map_err(malformed)
}
fn bounded_bytes(d: &mut Decoder<'_>, max: usize) -> Result<Vec<u8>, Error> {
    let b = d.bytes().map_err(malformed)?;
    if b.is_empty() || b.len() > max {
        return Err(Error::TooLarge);
    }
    Ok(b.to_vec())
}
fn bounded_array(d: &mut Decoder<'_>, max: u64) -> Result<usize, Error> {
    let n = d.array().map_err(malformed)?.ok_or(Error::Malformed)?;
    if n > max {
        return Err(Error::TooLarge);
    }
    Ok(n as usize)
}

fn put_node(e: &mut Enc, n: &NetworkNode) {
    match n {
        NetworkNode::Leaf { id, provider_id } => {
            e.array(3)
                .unwrap()
                .u8(0)
                .unwrap()
                .u8(*id)
                .unwrap()
                .bytes(provider_id)
                .unwrap();
        }
        NetworkNode::Threshold {
            id,
            required,
            children,
        } => {
            e.array(4)
                .unwrap()
                .u8(1)
                .unwrap()
                .u8(*id)
                .unwrap()
                .u8(*required)
                .unwrap()
                .array(children.len() as u64)
                .unwrap();
            for child in children {
                put_node(e, child);
            }
        }
    }
}

fn get_node(d: &mut Decoder<'_>, depth: usize, nodes: &mut usize) -> Result<NetworkNode, Error> {
    if depth > 4 || *nodes >= 30 {
        return Err(Error::TooLarge);
    }
    *nodes += 1;
    let n = d.array().map_err(malformed)?.ok_or(Error::Malformed)?;
    let tag = d.u8().map_err(malformed)?;
    let id = d.u8().map_err(malformed)?;
    match (n, tag) {
        (3, 0) => Ok(NetworkNode::Leaf {
            id,
            provider_id: bytes(d)?,
        }),
        (4, 1) => {
            let required = d.u8().map_err(malformed)?;
            let count = bounded_array(d, 30)?;
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(get_node(d, depth + 1, nodes)?);
            }
            Ok(NetworkNode::Threshold {
                id,
                required,
                children,
            })
        }
        _ => Err(Error::Malformed),
    }
}

pub fn descriptor_bytes(d: &Descriptor) -> Result<Vec<u8>, Error> {
    validate_descriptor(d)?;
    let mut e = Encoder::new(Vec::new());
    e.array(13)
        .unwrap()
        .u8(VERSION)
        .unwrap()
        .u8(SUITE)
        .unwrap()
        .bytes(&d.binding_id)
        .unwrap()
        .bytes(&d.volume_uuid)
        .unwrap()
        .u8(d.slot)
        .unwrap()
        .u64(d.generation)
        .unwrap()
        .u8(match d.policy.mode() {
            Mode::NetworkBound => 0,
            Mode::Attested => 1,
        })
        .unwrap()
        .u8(d.policy.tpm_node_id())
        .unwrap();
    put_node(&mut e, d.policy.network());
    e.array(d.networks.len() as u64).unwrap();
    for n in &d.networks {
        e.array(5)
            .unwrap()
            .u8(n.node_id)
            .unwrap()
            .bytes(&n.provider_id)
            .unwrap()
            .bytes(&n.key_id)
            .unwrap()
            .bytes(&n.public_key)
            .unwrap()
            .bytes(&n.input_seed)
            .unwrap();
    }
    e.u32(d.tpm_pcr_mask)
        .unwrap()
        .bytes(&d.tpm_pcr_digest)
        .unwrap()
        .str("luks2-slot")
        .unwrap();
    Ok(e.into_writer())
}

fn read_descriptor(raw: &[u8]) -> Result<Descriptor, Error> {
    let mut d = Decoder::new(raw);
    arr(&mut d, 13)?;
    if d.u8().map_err(malformed)? != VERSION || d.u8().map_err(malformed)? != SUITE {
        return Err(Error::Unsupported);
    }
    let binding_id = bytes(&mut d)?;
    let volume_uuid = bytes(&mut d)?;
    let slot = d.u8().map_err(malformed)?;
    let generation = d.u64().map_err(malformed)?;
    let mode = match d.u8().map_err(malformed)? {
        0 => Mode::NetworkBound,
        1 => Mode::Attested,
        _ => return Err(Error::Unsupported),
    };
    let tpm_id = d.u8().map_err(malformed)?;
    let network = get_node(&mut d, 1, &mut 0)?;
    let policy = ProductionPolicy::new(mode, tpm_id, network).map_err(|_| Error::InvalidPolicy)?;
    let count = bounded_array(&mut d, 30)?;
    let mut networks = Vec::with_capacity(count);
    for _ in 0..count {
        arr(&mut d, 5)?;
        networks.push(NetworkBinding {
            node_id: d.u8().map_err(malformed)?,
            provider_id: bytes(&mut d)?,
            key_id: bytes(&mut d)?,
            public_key: bytes(&mut d)?,
            input_seed: bytes(&mut d)?,
        });
    }
    let tpm_pcr_mask = d.u32().map_err(malformed)?;
    let tpm_pcr_digest = bytes(&mut d)?;
    if d.str().map_err(malformed)? != "luks2-slot" || d.position() != raw.len() {
        return Err(Error::Malformed);
    }
    let desc = Descriptor {
        binding_id,
        volume_uuid,
        slot,
        generation,
        policy,
        networks,
        tpm_pcr_mask,
        tpm_pcr_digest,
    };
    if descriptor_bytes(&desc)? != raw {
        return Err(Error::NonCanonical);
    }
    Ok(desc)
}

fn collect_leaves(n: &NetworkNode, leaves: &mut Vec<(u8, [u8; 32])>) {
    match n {
        NetworkNode::Leaf { id, provider_id } => leaves.push((*id, *provider_id)),
        NetworkNode::Threshold { children, .. } => {
            for n in children {
                collect_leaves(n, leaves);
            }
        }
    }
}

fn validate_descriptor(d: &Descriptor) -> Result<(), Error> {
    if d.slot >= 32
        || d.generation == 0
        || d.binding_id == [0; 32]
        || d.volume_uuid == [0; 16]
        || d.tpm_pcr_mask == 0
        || d.tpm_pcr_mask & 0xff00_0000 != 0
    {
        return Err(Error::InvalidPolicy);
    }
    let mut leaves = Vec::new();
    collect_leaves(d.policy.network(), &mut leaves);
    if leaves.len() != d.networks.len() {
        return Err(Error::InvalidProvider);
    }
    for ((id, provider_id), binding) in leaves.iter().zip(&d.networks) {
        if *id != binding.node_id || *provider_id != binding.provider_id {
            return Err(Error::InvalidProvider);
        }
        leelo_crypto::ServerPublicKey::from_bytes(binding.public_key)
            .map_err(|_| Error::InvalidProvider)?;
    }
    for (i, binding) in d.networks.iter().enumerate() {
        if d.networks[..i]
            .iter()
            .any(|other| other.key_id == binding.key_id || other.public_key == binding.public_key)
        {
            return Err(Error::InvalidProvider);
        }
    }
    Ok(())
}

pub fn context_hash(d: &Descriptor) -> Result<[u8; 48], Error> {
    let mut hash = Sha384::new();
    hash.update(b"leelo/v1/context\0");
    hash.update(descriptor_bytes(d)?);
    Ok(hash.finalize().into())
}

pub fn leaf_context(context: &[u8; 48], node_id: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(80);
    v.extend_from_slice(b"leelo/v1/leaf\0");
    v.extend_from_slice(context);
    v.push(node_id);
    v
}

pub fn network_input(d: &Descriptor, n: &NetworkBinding) -> Vec<u8> {
    let mut v = Vec::with_capacity(100);
    v.extend_from_slice(b"leelo/v1/network-input\0");
    v.extend_from_slice(&d.binding_id);
    v.push(n.node_id);
    v.extend_from_slice(&n.input_seed);
    v
}

fn put_wrapped(e: &mut Enc, w: &WrappedKey) {
    e.array(2)
        .unwrap()
        .bytes(&w.nonce)
        .unwrap()
        .bytes(&w.ciphertext)
        .unwrap();
}
fn get_wrapped(d: &mut Decoder<'_>) -> Result<WrappedKey, Error> {
    arr(d, 2)?;
    Ok(WrappedKey {
        nonce: bytes(d)?,
        ciphertext: bytes(d)?,
    })
}

fn body_bytes(b: &EnvelopeBody) -> Result<Vec<u8>, Error> {
    let desc = descriptor_bytes(&b.descriptor)?;
    if b.tpm.public.is_empty()
        || b.tpm.public.len() > MAX_TPM_BLOB
        || b.tpm.private.is_empty()
        || b.tpm.private.len() > MAX_TPM_BLOB
        || b.tpm.name.is_empty()
        || b.tpm.name.len() > 68
        || b.tpm.parent_name.is_empty()
        || b.tpm.parent_name.len() > 68
    {
        return Err(Error::TooLarge);
    }
    let mut expected = vec![b.descriptor.policy.tpm_node_id()];
    expected.extend(b.descriptor.networks.iter().map(|x| x.node_id));
    if b.leaves.iter().map(|x| x.node_id).collect::<Vec<_>>() != expected {
        return Err(Error::Malformed);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .bytes(&desc)
        .unwrap()
        .array(4)
        .unwrap()
        .bytes(&b.tpm.public)
        .unwrap()
        .bytes(&b.tpm.private)
        .unwrap()
        .bytes(&b.tpm.name)
        .unwrap()
        .bytes(&b.tpm.parent_name)
        .unwrap()
        .array(b.leaves.len() as u64)
        .unwrap();
    for leaf in &b.leaves {
        e.array(2).unwrap().u8(leaf.node_id).unwrap();
        put_wrapped(&mut e, &leaf.value);
    }
    put_wrapped(&mut e, &b.payload);
    let result = e.into_writer();
    if result.len() > MAX_ENVELOPE - 128 {
        return Err(Error::TooLarge);
    }
    Ok(result)
}

fn read_body(raw: &[u8]) -> Result<EnvelopeBody, Error> {
    let mut d = Decoder::new(raw);
    arr(&mut d, 4)?;
    let descriptor = read_descriptor(d.bytes().map_err(malformed)?)?;
    arr(&mut d, 4)?;
    let tpm = TpmBlob {
        public: bounded_bytes(&mut d, MAX_TPM_BLOB)?,
        private: bounded_bytes(&mut d, MAX_TPM_BLOB)?,
        name: bounded_bytes(&mut d, 68)?,
        parent_name: bounded_bytes(&mut d, 68)?,
    };
    let count = bounded_array(&mut d, 31)?;
    let mut leaves = Vec::with_capacity(count);
    for _ in 0..count {
        arr(&mut d, 2)?;
        leaves.push(WrappedLeaf {
            node_id: d.u8().map_err(malformed)?,
            value: get_wrapped(&mut d)?,
        });
    }
    let payload = get_wrapped(&mut d)?;
    if d.position() != raw.len() {
        return Err(Error::Malformed);
    }
    let body = EnvelopeBody {
        descriptor,
        tpm,
        leaves,
        payload,
    };
    if body_bytes(&body)? != raw {
        return Err(Error::NonCanonical);
    }
    Ok(body)
}

fn sign_input(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGN_DOMAIN.len() + body.len());
    message.extend_from_slice(SIGN_DOMAIN);
    message.extend_from_slice(body);
    message
}

pub fn sign(body: &EnvelopeBody, key: &SecretSigningKey) -> Result<Vec<u8>, Error> {
    let bytes = body_bytes(body)?;
    let sig = key
        .sign(&sign_input(&bytes))
        .map_err(|_| Error::InvalidSignature)?;
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .bytes(&bytes)
        .unwrap()
        .bytes(&sig)
        .unwrap();
    Ok(e.into_writer())
}

pub fn authenticate(raw: &[u8], trusted_key: &[u8; 32]) -> Result<AuthenticatedEnvelope, Error> {
    if raw.len() > MAX_ENVELOPE {
        return Err(Error::TooLarge);
    }
    let mut d = Decoder::new(raw);
    arr(&mut d, 2)?;
    let raw_body = d.bytes().map_err(malformed)?;
    let signature = bytes::<64>(&mut d)?;
    if d.position() != raw.len() {
        return Err(Error::Malformed);
    }
    leelo_crypto::verify(trusted_key, &sign_input(raw_body), &signature)
        .map_err(|_| Error::InvalidSignature)?;
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .bytes(raw_body)
        .unwrap()
        .bytes(&signature)
        .unwrap();
    if e.into_writer() != raw {
        return Err(Error::NonCanonical);
    }
    let body = read_body(raw_body)?;
    let context = context_hash(&body.descriptor)?;
    Ok(AuthenticatedEnvelope { body, context })
}

//! Production policies own validation, leaf order, and secret-sharing coordinates.
//! TPM and network factors are mandatory.
//!
//! The caller must authenticate provider, TPM, and AEAD observations before it records them.
//! The executable decisions and source-to-plan certificate checker have Verus proofs.
//! Sharing and recovery use the same private plan. They do not authenticate observations.
#![forbid(unsafe_code)]

mod verified;
mod verified_compile;
pub use verified_compile::NetworkNode;

use leelo_sss::Share;
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

pub const MAX_NODES: usize = 31;
pub const MAX_DEPTH: usize = 4;

/// A network leaf ID and its secret payload. This type does not establish authentication.
pub type NetworkShare = (u8, Zeroizing<[u8; 32]>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    NetworkBound,
    Attested,
}

impl NetworkNode {
    pub fn id(&self) -> u8 {
        match self {
            Self::Leaf { id, .. } | Self::Threshold { id, .. } => *id,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    TooManyNodes,
    TooDeep,
    DuplicateNodeId(u8),
    DuplicateProvider,
    InvalidThreshold,
    InvalidCompilation,
    EnvelopeNotAuthenticated,
    UnknownNetworkLeaf(u8),
    DuplicateResponse(u8),
    FactorsNotSatisfied,
    RootNotAuthenticated,
    AlreadyReleased,
    Sharing(leelo_sss::Error),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sharing(error) => Some(error),
            _ => None,
        }
    }
}

impl From<leelo_sss::Error> for PolicyError {
    fn from(error: leelo_sss::Error) -> Self {
        Self::Sharing(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NetworkPlan {
    gates: Vec<verified::Gate>,
    leaves: Vec<(u8, [u8; 32])>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPolicy {
    mode: Mode,
    tpm_node_id: u8,
    network: NetworkNode,
    plan: NetworkPlan,
}

impl ProductionPolicy {
    /// Create the implicit root `all(TPM, network)`.
    /// The network subtree cannot contain an alternative TPM path or an executable plugin.
    pub fn new(mode: Mode, tpm_node_id: u8, network: NetworkNode) -> Result<Self, PolicyError> {
        let mut ids = BTreeSet::from([tpm_node_id]);
        let mut providers = BTreeSet::new();
        // Count the implicit all() root and mandatory TPM node.
        let mut count = 2;
        let mut plan = NetworkPlan {
            gates: Vec::new(),
            leaves: Vec::new(),
        };
        compile_node(&network, 2, &mut count, &mut ids, &mut providers, &mut plan)?;
        // Certify the unverified compiler's output before any decision or sharing uses it.
        if !verified_compile::check_compilation(&network, &plan.gates, &plan.leaves) {
            return Err(PolicyError::InvalidCompilation);
        }
        Ok(Self {
            mode,
            tpm_node_id,
            network,
            plan,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn tpm_node_id(&self) -> u8 {
        self.tpm_node_id
    }
    pub fn network(&self) -> &NetworkNode {
        &self.network
    }
    pub fn node_count(&self) -> usize {
        self.plan.gates.len() + 2
    }

    pub fn network_leaf_ids(&self) -> Vec<u8> {
        self.plan.leaves.iter().map(|(id, _)| *id).collect()
    }

    /// Return leaf identities in the order used by sharing and envelope encoding.
    pub fn network_leaves(&self) -> &[(u8, [u8; 32])] {
        &self.plan.leaves
    }

    /// Check the network threshold without requiring a TPM observation.
    /// Reject unknown and repeated leaf IDs before evaluation.
    pub fn network_satisfied(&self, available: &[u8]) -> Result<bool, PolicyError> {
        let responses = self.plan.responses(available.iter().copied())?;
        Ok(verified::evaluate_network(&self.plan.gates, &responses))
    }

    /// Split a network secret according to the validated policy.
    /// The caller must authenticate each leaf wrapper before later recovery.
    pub fn split_network<R: CryptoRng + RngCore + ?Sized>(
        &self,
        secret: &[u8; 32],
        rng: &mut R,
    ) -> Result<Vec<NetworkShare>, PolicyError> {
        let mut leaves = Vec::with_capacity(self.plan.leaves.len());
        self.plan
            .split_gate(self.plan.gates.len() - 1, secret, rng, &mut leaves)?;
        Ok(leaves)
    }

    /// Recover a candidate from authenticated leaves. The caller must authenticate the root payload.
    /// Check every supplied leaf, including surplus leaves and branches that the root does not need.
    pub fn recover_network(
        &self,
        recovered: &[NetworkShare],
    ) -> Result<Zeroizing<[u8; 32]>, PolicyError> {
        self.plan.responses(recovered.iter().map(|(id, _)| *id))?;
        let mut values: Vec<Option<Zeroizing<[u8; 32]>>> =
            Vec::with_capacity(self.plan.gates.len());
        for gate in &self.plan.gates {
            let value = match gate {
                verified::Gate::Leaf { response_index } => {
                    let id = self.plan.leaves[*response_index].0;
                    recovered
                        .iter()
                        .find(|(node, _)| *node == id)
                        .map(|(_, secret)| Zeroizing::new(**secret))
                }
                verified::Gate::Threshold { required, children } => {
                    let mut shares = Vec::new();
                    for (position, child) in children.iter().enumerate() {
                        if let Some(secret) = values[*child].take() {
                            // The plan bounds child positions below MAX_NODES.
                            let coordinate = (position + 1) as u8;
                            shares.push(Share::from_parts(coordinate, secret)?);
                        }
                    }
                    if shares.len() < *required {
                        None
                    } else {
                        Some(leelo_sss::reconstruct(*required as u8, &shares)?)
                    }
                }
            };
            values.push(value);
        }
        values
            .pop()
            .flatten()
            .ok_or(PolicyError::FactorsNotSatisfied)
    }
}

impl NetworkPlan {
    fn responses(&self, available: impl Iterator<Item = u8>) -> Result<Vec<bool>, PolicyError> {
        let mut responses = vec![false; self.leaves.len()];
        for id in available {
            let index = self
                .leaves
                .iter()
                .position(|(leaf, _)| *leaf == id)
                .ok_or(PolicyError::UnknownNetworkLeaf(id))?;
            if !verified::record_response(&mut responses, index) {
                return Err(PolicyError::DuplicateResponse(id));
            }
        }
        Ok(responses)
    }

    fn split_gate<R: CryptoRng + RngCore + ?Sized>(
        &self,
        index: usize,
        secret: &[u8; 32],
        rng: &mut R,
        leaves: &mut Vec<NetworkShare>,
    ) -> Result<(), PolicyError> {
        match &self.gates[index] {
            verified::Gate::Leaf { response_index } => {
                leaves.push((self.leaves[*response_index].0, Zeroizing::new(*secret)));
            }
            verified::Gate::Threshold { required, children } => {
                // Shamir assigns coordinates 1..n in this child order.
                let shares = leelo_sss::split(secret, *required as u8, children.len() as u8, rng)?;
                for (child, share) in children.iter().zip(&shares) {
                    self.split_gate(*child, share.value(), rng, leaves)?;
                }
            }
        }
        Ok(())
    }
}

fn compile_node(
    node: &NetworkNode,
    depth: usize,
    count: &mut usize,
    ids: &mut BTreeSet<u8>,
    providers: &mut BTreeSet<[u8; 32]>,
    plan: &mut NetworkPlan,
) -> Result<usize, PolicyError> {
    if depth > MAX_DEPTH {
        return Err(PolicyError::TooDeep);
    }
    if *count >= MAX_NODES {
        return Err(PolicyError::TooManyNodes);
    }
    *count += 1;
    if !ids.insert(node.id()) {
        return Err(PolicyError::DuplicateNodeId(node.id()));
    }
    let gate = match node {
        NetworkNode::Leaf { id, provider_id } => {
            if !providers.insert(*provider_id) {
                return Err(PolicyError::DuplicateProvider);
            }
            let response_index = plan.leaves.len();
            plan.leaves.push((*id, *provider_id));
            verified::Gate::Leaf { response_index }
        }
        NetworkNode::Threshold {
            required, children, ..
        } => {
            if *required == 0 || usize::from(*required) > children.len() {
                return Err(PolicyError::InvalidThreshold);
            }
            let mut indices = Vec::new();
            for child in children {
                indices.push(compile_node(child, depth + 1, count, ids, providers, plan)?);
            }
            verified::Gate::Threshold {
                required: usize::from(*required),
                children: indices,
            }
        }
    };
    let index = plan.gates.len();
    plan.gates.push(gate);
    Ok(index)
}

/// This decision session permits one release.
/// Its methods record authenticated observations from trusted adapters.
/// A call to these methods does not authenticate a provider.
pub struct PolicySession {
    require_live: bool,
    plan: NetworkPlan,
    responses: Vec<bool>,
    state: verified::ReleaseState,
}

impl PolicySession {
    pub fn new(policy: &ProductionPolicy) -> Self {
        let responses = vec![false; policy.plan.leaves.len()];
        Self {
            require_live: policy.mode == Mode::Attested,
            plan: policy.plan.clone(),
            responses,
            state: verified::ReleaseState {
                envelope_authenticated: false,
                tpm_authenticated: false,
                network_satisfied: false,
                live_authorized: false,
                root_authenticated: false,
                released: false,
            },
        }
    }

    pub fn authenticate_envelope(&mut self) -> Result<(), PolicyError> {
        if self.state.released {
            return Err(PolicyError::AlreadyReleased);
        }
        self.state.envelope_authenticated = true;
        Ok(())
    }

    fn require_authenticated(&self) -> Result<(), PolicyError> {
        if self.state.released {
            Err(PolicyError::AlreadyReleased)
        } else if !self.state.envelope_authenticated {
            Err(PolicyError::EnvelopeNotAuthenticated)
        } else {
            Ok(())
        }
    }

    pub fn accept_network(&mut self, node_id: u8) -> Result<(), PolicyError> {
        self.require_authenticated()?;
        let index = self
            .plan
            .leaves
            .iter()
            .position(|(id, _)| *id == node_id)
            .ok_or(PolicyError::UnknownNetworkLeaf(node_id))?;
        if !verified::record_response(&mut self.responses, index) {
            return Err(PolicyError::DuplicateResponse(node_id));
        }
        self.state.network_satisfied =
            verified::evaluate_network(&self.plan.gates, &self.responses);
        Ok(())
    }

    pub fn confirm_tpm(&mut self) -> Result<(), PolicyError> {
        self.require_authenticated()?;
        self.state.tpm_authenticated = true;
        Ok(())
    }

    pub fn confirm_live_authorization(&mut self) -> Result<(), PolicyError> {
        self.require_authenticated()?;
        self.state.live_authorized = true;
        Ok(())
    }

    pub fn can_reconstruct(&self) -> bool {
        self.state.envelope_authenticated
            && self.state.tpm_authenticated
            && self.state.network_satisfied
            && (!self.require_live || self.state.live_authorized)
            && !self.state.released
    }

    pub fn authenticate_root(&mut self) -> Result<(), PolicyError> {
        self.require_authenticated()?;
        if !self.can_reconstruct() {
            return Err(PolicyError::FactorsNotSatisfied);
        }
        self.state.root_authenticated = true;
        Ok(())
    }

    pub fn can_release(&self) -> bool {
        verified::can_release(&self.state, self.require_live)
    }

    pub fn release(&mut self) -> Result<(), PolicyError> {
        self.require_authenticated()?;
        if !self.can_reconstruct() {
            return Err(PolicyError::FactorsNotSatisfied);
        }
        if !self.state.root_authenticated {
            return Err(PolicyError::RootNotAuthenticated);
        }
        if verified::try_release(&mut self.state, self.require_live) {
            Ok(())
        } else {
            Err(PolicyError::AlreadyReleased)
        }
    }
}

#[cfg(test)]
mod tests;

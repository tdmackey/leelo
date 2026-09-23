//! Production policies have a closed format and size limits. TPM and network factors are mandatory.
//!
//! The caller must authenticate provider, TPM, and AEAD observations before it records them.
//! This crate makes the decision. It does not authenticate observations.
#![forbid(unsafe_code)]

mod verified;

use std::collections::BTreeSet;

pub const MAX_NODES: usize = 31;
pub const MAX_DEPTH: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    NetworkBound,
    Attested,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkNode {
    Leaf {
        id: u8,
        provider_id: [u8; 32],
    },
    Threshold {
        id: u8,
        required: u8,
        children: Vec<NetworkNode>,
    },
}

impl NetworkNode {
    pub fn id(&self) -> u8 {
        match self {
            Self::Leaf { id, .. } | Self::Threshold { id, .. } => *id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    TooManyNodes,
    TooDeep,
    DuplicateNodeId(u8),
    DuplicateProvider,
    InvalidThreshold,
    EnvelopeNotAuthenticated,
    UnknownNetworkLeaf(u8),
    DuplicateResponse(u8),
    FactorsNotSatisfied,
    RootNotAuthenticated,
    AlreadyReleased,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PolicyError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPolicy {
    mode: Mode,
    tpm_node_id: u8,
    network: NetworkNode,
    node_count: usize,
}

impl ProductionPolicy {
    /// Create the implicit root `all(TPM, network)`.
    /// The network subtree cannot contain an alternative TPM path or an executable plugin.
    pub fn new(mode: Mode, tpm_node_id: u8, network: NetworkNode) -> Result<Self, PolicyError> {
        let mut ids = BTreeSet::from([tpm_node_id]);
        let mut providers = BTreeSet::new();
        // Count the implicit all() root and mandatory TPM node.
        let mut count = 2;
        validate_node(&network, 2, &mut count, &mut ids, &mut providers)?;
        Ok(Self {
            mode,
            tpm_node_id,
            network,
            node_count: count,
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
        self.node_count
    }

    pub fn network_leaf_ids(&self) -> Vec<u8> {
        let mut result = Vec::new();
        collect_leaf_ids(&self.network, &mut result);
        result
    }
}

fn validate_node(
    node: &NetworkNode,
    depth: usize,
    count: &mut usize,
    ids: &mut BTreeSet<u8>,
    providers: &mut BTreeSet<[u8; 32]>,
) -> Result<(), PolicyError> {
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
    match node {
        NetworkNode::Leaf { provider_id, .. } => {
            if !providers.insert(*provider_id) {
                return Err(PolicyError::DuplicateProvider);
            }
        }
        NetworkNode::Threshold {
            required, children, ..
        } => {
            if *required == 0 || usize::from(*required) > children.len() {
                return Err(PolicyError::InvalidThreshold);
            }
            for child in children {
                validate_node(child, depth + 1, count, ids, providers)?;
            }
        }
    }
    Ok(())
}

fn collect_leaf_ids(node: &NetworkNode, result: &mut Vec<u8>) {
    match node {
        NetworkNode::Leaf { id, .. } => result.push(*id),
        NetworkNode::Threshold { children, .. } => {
            for child in children {
                collect_leaf_ids(child, result);
            }
        }
    }
}

fn compile_node(
    node: &NetworkNode,
    gates: &mut Vec<verified::Gate>,
    leaves: &mut Vec<u8>,
) -> usize {
    let gate = match node {
        NetworkNode::Leaf { id, .. } => {
            let response_index = leaves.len();
            leaves.push(*id);
            verified::Gate::Leaf { response_index }
        }
        NetworkNode::Threshold {
            required, children, ..
        } => {
            let mut indices = Vec::new();
            for child in children {
                indices.push(compile_node(child, gates, leaves));
            }
            verified::Gate::Threshold {
                required: usize::from(*required),
                children: indices,
            }
        }
    };
    let index = gates.len();
    gates.push(gate);
    index
}

/// This decision session permits one release.
/// Its methods record authenticated observations from trusted adapters.
/// A call to these methods does not authenticate a provider.
pub struct PolicySession {
    require_live: bool,
    gates: Vec<verified::Gate>,
    leaves: Vec<u8>,
    responses: Vec<bool>,
    state: verified::ReleaseState,
}

impl PolicySession {
    pub fn new(policy: &ProductionPolicy) -> Self {
        let mut gates = Vec::new();
        let mut leaves = Vec::new();
        compile_node(&policy.network, &mut gates, &mut leaves);
        let responses = vec![false; leaves.len()];
        Self {
            require_live: policy.mode == Mode::Attested,
            gates,
            leaves,
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
            .leaves
            .iter()
            .position(|id| *id == node_id)
            .ok_or(PolicyError::UnknownNetworkLeaf(node_id))?;
        if !verified::record_response(&mut self.responses, index) {
            return Err(PolicyError::DuplicateResponse(node_id));
        }
        self.state.network_satisfied = verified::evaluate_network(&self.gates, &self.responses);
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

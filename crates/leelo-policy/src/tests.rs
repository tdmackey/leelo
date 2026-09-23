use super::*;

fn leaf(id: u8) -> NetworkNode {
    NetworkNode::Leaf {
        id,
        provider_id: [id; 32],
    }
}

fn threshold(id: u8, required: u8, children: Vec<NetworkNode>) -> NetworkNode {
    NetworkNode::Threshold {
        id,
        required,
        children,
    }
}

fn sample(mode: Mode) -> ProductionPolicy {
    ProductionPolicy::new(mode, 1, threshold(2, 1, vec![leaf(3), leaf(4)])).unwrap()
}

#[test]
fn policy_rejects_duplicate_and_unbounded_inputs() {
    assert_eq!(
        ProductionPolicy::new(Mode::NetworkBound, 1, leaf(1)),
        Err(PolicyError::DuplicateNodeId(1))
    );
    assert_eq!(
        ProductionPolicy::new(Mode::NetworkBound, 1, threshold(2, 0, vec![leaf(3)])),
        Err(PolicyError::InvalidThreshold)
    );
    assert_eq!(
        ProductionPolicy::new(Mode::NetworkBound, 1, threshold(2, 2, vec![leaf(3)])),
        Err(PolicyError::InvalidThreshold)
    );
    assert_eq!(
        ProductionPolicy::new(Mode::NetworkBound, 1, threshold(2, 1, vec![])),
        Err(PolicyError::InvalidThreshold)
    );
    let repeated_provider = NetworkNode::Leaf {
        id: 4,
        provider_id: [3; 32],
    };
    assert_eq!(
        ProductionPolicy::new(
            Mode::NetworkBound,
            1,
            threshold(2, 1, vec![leaf(3), repeated_provider])
        ),
        Err(PolicyError::DuplicateProvider)
    );
    let too_deep = threshold(
        2,
        1,
        vec![threshold(3, 1, vec![threshold(4, 1, vec![leaf(5)])])],
    );
    assert_eq!(
        ProductionPolicy::new(Mode::NetworkBound, 1, too_deep),
        Err(PolicyError::TooDeep)
    );
    let too_many = threshold(2, 1, (3..32).map(leaf).collect());
    assert_eq!(
        ProductionPolicy::new(Mode::NetworkBound, 1, too_many),
        Err(PolicyError::TooManyNodes)
    );
    let maximum = threshold(2, 1, (3..31).map(leaf).collect());
    assert_eq!(
        ProductionPolicy::new(Mode::NetworkBound, 1, maximum)
            .unwrap()
            .node_count(),
        MAX_NODES
    );
}

#[test]
fn two_network_responses_never_replace_tpm() {
    let mut state = PolicySession::new(&sample(Mode::NetworkBound));
    assert_eq!(
        state.accept_network(3),
        Err(PolicyError::EnvelopeNotAuthenticated)
    );
    state.authenticate_envelope().unwrap();
    state.accept_network(3).unwrap();
    state.accept_network(4).unwrap();
    assert!(!state.can_reconstruct());
    assert_eq!(
        state.authenticate_root(),
        Err(PolicyError::FactorsNotSatisfied)
    );
    assert_eq!(state.release(), Err(PolicyError::FactorsNotSatisfied));
    state.confirm_tpm().unwrap();
    assert!(state.can_reconstruct());
    assert_eq!(state.release(), Err(PolicyError::RootNotAuthenticated));
    state.authenticate_root().unwrap();
    state.release().unwrap();
    assert_eq!(state.release(), Err(PolicyError::AlreadyReleased));
    assert_eq!(state.accept_network(3), Err(PolicyError::AlreadyReleased));
}

#[test]
fn duplicate_retries_never_satisfy_another_share() {
    let policy = ProductionPolicy::new(
        Mode::NetworkBound,
        1,
        threshold(2, 2, vec![leaf(3), leaf(4)]),
    )
    .unwrap();
    let mut state = PolicySession::new(&policy);
    state.authenticate_envelope().unwrap();
    state.confirm_tpm().unwrap();
    state.accept_network(3).unwrap();
    assert_eq!(
        state.accept_network(3),
        Err(PolicyError::DuplicateResponse(3))
    );
    assert_eq!(
        state.accept_network(2),
        Err(PolicyError::UnknownNetworkLeaf(2))
    );
    assert_eq!(
        state.accept_network(1),
        Err(PolicyError::UnknownNetworkLeaf(1))
    );
    assert!(!state.can_reconstruct());
    state.accept_network(4).unwrap();
    assert!(state.can_reconstruct());
}

#[test]
fn attested_requires_explicit_live_observation() {
    let mut state = PolicySession::new(&sample(Mode::Attested));
    state.authenticate_envelope().unwrap();
    state.confirm_tpm().unwrap();
    state.accept_network(3).unwrap();
    assert!(!state.can_reconstruct());
    assert_eq!(
        state.authenticate_root(),
        Err(PolicyError::FactorsNotSatisfied)
    );
    state.confirm_live_authorization().unwrap();
    assert!(state.can_reconstruct());
    state.authenticate_root().unwrap();
    assert!(state.can_release());
    state.release().unwrap();
    assert!(!state.can_release());
}

fn reference_value(node: &NetworkNode, available: &BTreeSet<u8>) -> bool {
    match node {
        NetworkNode::Leaf { id, .. } => available.contains(id),
        NetworkNode::Threshold {
            required, children, ..
        } => {
            children
                .iter()
                .filter(|child| reference_value(child, available))
                .count()
                >= usize::from(*required)
        }
    }
}

#[test]
fn every_subset_of_nested_policy_matches_reference_semantics() {
    let policy = ProductionPolicy::new(
        Mode::NetworkBound,
        1,
        threshold(
            2,
            2,
            vec![
                threshold(3, 1, vec![leaf(4), leaf(5)]),
                threshold(6, 2, vec![leaf(7), leaf(8)]),
                leaf(9),
            ],
        ),
    )
    .unwrap();
    let leaves = policy.network_leaf_ids();
    for bits in 0..(1 << leaves.len()) {
        let available: BTreeSet<_> = leaves
            .iter()
            .enumerate()
            .filter(|(i, _)| bits & (1 << i) != 0)
            .map(|(_, id)| *id)
            .collect();
        let mut session = PolicySession::new(&policy);
        session.authenticate_envelope().unwrap();
        session.confirm_tpm().unwrap();
        for id in &available {
            session.accept_network(*id).unwrap();
        }
        assert_eq!(
            session.can_reconstruct(),
            reference_value(policy.network(), &available),
            "subset {bits}"
        );
    }
}

#[test]
fn all_release_gate_combinations_match_mandatory_requirements() {
    for bits in 0u8..128 {
        for require_live in [false, true] {
            let mut state = verified::ReleaseState {
                envelope_authenticated: bits & 1 != 0,
                tpm_authenticated: bits & 2 != 0,
                network_satisfied: bits & 4 != 0,
                live_authorized: bits & 8 != 0,
                root_authenticated: bits & 16 != 0,
                released: bits & 32 != 0,
            };
            let expected = (bits & 0b110111 == 0b010111) && (!require_live || bits & 8 != 0);
            assert_eq!(verified::try_release(&mut state, require_live), expected);
            assert!(!verified::try_release(&mut state, require_live));
        }
    }
}

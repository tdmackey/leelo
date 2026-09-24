use super::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

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
                leaf(9),
                threshold(6, 2, vec![leaf(8), leaf(7)]),
                threshold(3, 1, vec![leaf(5), leaf(4)]),
            ],
        ),
    )
    .unwrap();
    let leaves = policy.network_leaf_ids();
    let secret = [0xa7; 32];
    let mut rng = ChaCha20Rng::from_seed([11; 32]);
    let shares = policy.split_network(&secret, &mut rng).unwrap();
    assert_eq!(shares.iter().map(|(id, _)| *id).collect::<Vec<_>>(), leaves);
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
        let ids: Vec<_> = available.iter().copied().collect();
        let expected = reference_value(policy.network(), &available);
        assert_eq!(policy.network_satisfied(&ids).unwrap(), expected);
        let mut recovered: Vec<_> = shares
            .iter()
            .filter(|(id, _)| available.contains(id))
            .map(|(id, value)| (*id, Zeroizing::new(**value)))
            .collect();
        for _ in 0..2 {
            match policy.recover_network(&recovered) {
                Ok(candidate) => {
                    assert!(expected, "unexpected recovery for subset {bits}");
                    assert_eq!(*candidate, secret);
                }
                Err(error) => {
                    assert!(!expected, "failed recovery for subset {bits}");
                    assert_eq!(error, PolicyError::FactorsNotSatisfied);
                }
            }
            recovered.reverse();
        }
    }
}

#[test]
fn all_small_threshold_subsets_use_the_same_plan_for_sharing_and_decisions() {
    let secret = [0x69; 32];
    let mut rng = ChaCha20Rng::from_seed([23; 32]);
    for count in 1..=6_u8 {
        for required in 1..=count {
            let policy = ProductionPolicy::new(
                Mode::NetworkBound,
                1,
                threshold(2, required, (3..count + 3).map(leaf).collect()),
            )
            .unwrap();
            let shares = policy.split_network(&secret, &mut rng).unwrap();
            for mask in 0..(1_u32 << count) {
                let recovered: Vec<_> = shares
                    .iter()
                    .enumerate()
                    .filter(|(position, _)| mask & (1 << position) != 0)
                    .map(|(_, (id, value))| (*id, Zeroizing::new(**value)))
                    .collect();
                let ids: Vec<_> = recovered.iter().map(|(id, _)| *id).collect();
                let expected = ids.len() >= usize::from(required);
                assert_eq!(policy.network_satisfied(&ids).unwrap(), expected);
                match policy.recover_network(&recovered) {
                    Ok(candidate) => {
                        assert!(expected);
                        assert_eq!(*candidate, secret);
                    }
                    Err(error) => {
                        assert!(!expected);
                        assert_eq!(error, PolicyError::FactorsNotSatisfied);
                    }
                }
            }
        }
    }
}

#[test]
fn recovery_checks_surplus_shares_in_nested_and_unneeded_branches() {
    let policy = ProductionPolicy::new(
        Mode::NetworkBound,
        1,
        threshold(
            2,
            1,
            vec![threshold(3, 2, vec![leaf(4), leaf(5), leaf(6)]), leaf(7)],
        ),
    )
    .unwrap();
    let mut rng = ChaCha20Rng::from_seed([37; 32]);
    let shares = policy.split_network(&[0x91; 32], &mut rng).unwrap();
    for changed_id in [6, 7] {
        let mut changed: Vec<_> = shares
            .iter()
            .map(|(id, secret)| (*id, Zeroizing::new(**secret)))
            .collect();
        changed
            .iter_mut()
            .find(|(id, _)| *id == changed_id)
            .unwrap()
            .1[0] ^= 1;
        assert_eq!(
            policy.recover_network(&changed).err(),
            Some(PolicyError::Sharing(leelo_sss::Error::InconsistentShares)),
            "changed leaf {changed_id}",
        );
    }
}

#[test]
fn collected_leaves_reject_unknown_and_duplicate_ids_before_recovery() {
    let policy = sample(Mode::NetworkBound);
    for (ids, expected) in [
        (vec![3, 3], PolicyError::DuplicateResponse(3)),
        (vec![3, 99], PolicyError::UnknownNetworkLeaf(99)),
    ] {
        assert_eq!(
            policy.network_satisfied(&ids).err().as_ref(),
            Some(&expected)
        );
        let recovered: Vec<_> = ids
            .iter()
            .map(|id| (*id, Zeroizing::new([1; 32])))
            .collect();
        assert_eq!(policy.recover_network(&recovered).err(), Some(expected));
    }
    assert_eq!(policy.network_leaves(), &[(3, [3; 32]), (4, [4; 32])]);
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

#[test]
fn certificate_rejects_compiler_output_corruption() {
    let policy = ProductionPolicy::new(
        Mode::NetworkBound,
        1,
        threshold(2, 2, vec![threshold(3, 1, vec![leaf(4), leaf(5)]), leaf(6)]),
    )
    .unwrap();
    let accepts = |plan: &NetworkPlan| {
        verified_compile::check_compilation(&policy.network, &plan.gates, &plan.leaves)
    };
    assert!(accepts(&policy.plan));
    for index in 0..policy.plan.gates.len() {
        let mut changed = policy.plan.clone();
        match &mut changed.gates[index] {
            verified::Gate::Leaf { response_index } => *response_index = usize::MAX,
            verified::Gate::Threshold { required, .. } => *required += 1,
        }
        assert!(!accepts(&changed), "changed gate {index}");

        if let verified::Gate::Threshold { children, .. } = &policy.plan.gates[index] {
            for child in 0..children.len() {
                let mut changed = policy.plan.clone();
                if let verified::Gate::Threshold { children, .. } = &mut changed.gates[index] {
                    children[child] = index;
                }
                assert!(!accepts(&changed), "forward/self edge {index}/{child}");
            }
            let mut changed = policy.plan.clone();
            if let verified::Gate::Threshold { children, .. } = &mut changed.gates[index] {
                children.reverse();
            }
            assert!(!accepts(&changed), "reordered child coordinates {index}");
        }
    }
    for index in 0..policy.plan.leaves.len() {
        let mut changed = policy.plan.clone();
        changed.leaves[index].0 ^= 1;
        assert!(!accepts(&changed), "changed leaf identity {index}");
        let mut changed = policy.plan.clone();
        changed.leaves[index].1[31] ^= 1;
        assert!(!accepts(&changed), "changed provider identity {index}");
    }
    let mut changed = policy.plan.clone();
    changed.leaves.swap(0, 1);
    assert!(!accepts(&changed));
    let mut changed = policy.plan.clone();
    changed
        .gates
        .push(verified::Gate::Leaf { response_index: 0 });
    assert!(!accepts(&changed));
    let mut changed = policy.plan.clone();
    changed.leaves.push((99, [99; 32]));
    assert!(!accepts(&changed));
    let mut changed = policy.plan.clone();
    changed.gates.pop();
    assert!(!accepts(&changed));
    let mut changed = policy.plan.clone();
    changed.leaves.pop();
    assert!(!accepts(&changed));
    assert!(!verified_compile::check_compilation(
        &policy.network,
        &[],
        &[]
    ));
}

#[test]
fn generated_source_trees_match_compiled_decisions_for_every_subset() {
    fn generate(rng: &mut ChaCha20Rng, depth: usize, budget: usize, next: &mut u8) -> NetworkNode {
        let id = *next;
        *next += 1;
        if depth == 1 || rng.next_u32() & 3 == 0 {
            return leaf(id);
        }
        let count = 1 + rng.next_u32() as usize % budget.min(3);
        let required = 1 + rng.next_u32() as u8 % count as u8;
        let mut remaining = budget;
        let children = (0..count)
            .map(|position| {
                let child_budget = if position + 1 == count {
                    remaining
                } else {
                    1 + rng.next_u32() as usize % (remaining - (count - position - 1))
                };
                remaining -= child_budget;
                generate(rng, depth - 1, child_budget, next)
            })
            .collect();
        threshold(id, required, children)
    }
    fn source_leaves(node: &NetworkNode, result: &mut Vec<(u8, [u8; 32])>) {
        match node {
            NetworkNode::Leaf { id, provider_id } => result.push((*id, *provider_id)),
            NetworkNode::Threshold { children, .. } => {
                for child in children {
                    source_leaves(child, result);
                }
            }
        }
    }
    let mut rng = ChaCha20Rng::from_seed([0x83; 32]);
    for example in 0..256 {
        let source = generate(&mut rng, 3, 8, &mut 2);
        let mut expected_leaves = Vec::new();
        source_leaves(&source, &mut expected_leaves);
        let policy = ProductionPolicy::new(Mode::NetworkBound, 1, source).unwrap();
        assert_eq!(policy.network_leaves(), expected_leaves);
        for mask in 0..(1_u32 << expected_leaves.len()) {
            let available: BTreeSet<_> = expected_leaves
                .iter()
                .enumerate()
                .filter(|(position, _)| mask & (1 << position) != 0)
                .map(|(_, (id, _))| *id)
                .collect();
            let ids: Vec<_> = available.iter().copied().collect();
            assert_eq!(
                policy.network_satisfied(&ids).unwrap(),
                reference_value(policy.network(), &available),
                "generated tree {example}, subset {mask}",
            );
        }
    }
}

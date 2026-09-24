//! Source-to-plan certificate checker, executed before a policy is admitted.
//! The public source tree below is the same type parsed by the envelope codec.
//! Acceptance proves the plan's result equals direct tree evaluation for every
//! response assignment, with the same leaf identities, providers, and child order.
//! The compiler need not be trusted to preserve those properties: a mismatch fails
//! admission. This does not prove compiler completeness, identifier uniqueness,
//! cryptographic authentication, or the split/recovery implementation.
use crate::verified::Gate;
#[cfg(verus_keep_ghost)]
use crate::verified::{children_valid, count_selected, evaluated_prefix, gate_value};
use vstd::prelude::*;

verus! {

// Only derived traits are omitted from verification; the tree and checker are shared.
#[cfg_attr(not(verus_keep_ghost), derive(Clone, Debug, PartialEq, Eq))]
pub enum NetworkNode {
    Leaf { id: u8, provider_id: [u8; 32] },
    Threshold { id: u8, required: u8, children: Vec<NetworkNode> },
}

pub open spec fn node_count(node: &NetworkNode, depth: nat) -> nat
    decreases depth, 1nat, 0nat,
{
    if depth == 0 { 0 } else {
        match node {
            NetworkNode::Leaf { .. } => 1,
            NetworkNode::Threshold { children, .. } => 1 + forest_nodes(children@, children.len() as nat, depth),
        }
    }
}

pub open spec fn forest_nodes(nodes: Seq<NetworkNode>, n: nat, depth: nat) -> nat
    decreases depth, 0nat, n,
{
    if n == 0 || depth == 0 { 0 } else {
        forest_nodes(nodes, (n - 1) as nat, depth) + node_count(&nodes[n - 1], (depth - 1) as nat)
    }
}

pub open spec fn leaf_count(node: &NetworkNode, depth: nat) -> nat
    decreases depth, 1nat, 0nat,
{
    if depth == 0 { 0 } else {
        match node {
            NetworkNode::Leaf { .. } => 1,
            NetworkNode::Threshold { children, .. } => forest_leaves(children@, children.len() as nat, depth),
        }
    }
}

pub open spec fn forest_leaves(nodes: Seq<NetworkNode>, n: nat, depth: nat) -> nat
    decreases depth, 0nat, n,
{
    if n == 0 || depth == 0 { 0 } else {
        forest_leaves(nodes, (n - 1) as nat, depth) + leaf_count(&nodes[n - 1], (depth - 1) as nat)
    }
}

/// Direct source-tree semantics: response positions follow source leaf order.
pub open spec fn source_value(node: &NetworkNode, responses: Seq<bool>, leaf_start: nat, depth: nat) -> bool
    decreases depth, 1nat, 0nat,
{
    if depth == 0 { false } else {
        match node {
            NetworkNode::Leaf { .. } => leaf_start < responses.len() && responses[leaf_start as int],
            NetworkNode::Threshold { required, children, .. } =>
                0 < *required <= children.len()
                && source_successes(children@, children.len() as nat, responses, leaf_start, depth) >= *required,
        }
    }
}

pub open spec fn source_successes(nodes: Seq<NetworkNode>, n: nat, responses: Seq<bool>, leaf_start: nat, depth: nat) -> nat
    decreases depth, 0nat, n,
{
    if n == 0 || depth == 0 { 0 } else {
        source_successes(nodes, (n - 1) as nat, responses, leaf_start, depth)
        + if source_value(&nodes[n - 1], responses,
            leaf_start + forest_leaves(nodes, (n - 1) as nat, depth), (depth - 1) as nat) { 1nat } else { 0nat }
    }
}

pub open spec fn compiled_at(
    node: &NetworkNode, gates: Seq<Gate>, leaves: Seq<(u8, [u8; 32])>,
    gate_start: nat, leaf_start: nat, depth: nat,
) -> bool
    decreases depth,
{
    let nc = node_count(node, depth);
    let lc = leaf_count(node, depth);
    depth > 0 && nc > 0 && lc > 0
    && gate_start + nc <= gates.len() && leaf_start + lc <= leaves.len()
    && match node {
        NetworkNode::Leaf { id, provider_id } =>
            leaves[leaf_start as int].0 == *id && leaves[leaf_start as int].1@ == provider_id@
            && match &gates[gate_start as int] {
                Gate::Leaf { response_index } => *response_index == leaf_start,
                _ => false,
            },
        NetworkNode::Threshold { required, children, .. } =>
            0 < *required <= children.len()
            && match &gates[(gate_start + nc - 1) as int] {
                Gate::Threshold { required: actual, children: edges } =>
                    *actual == *required && edges.len() == children.len()
                    && forall |i: int| 0 <= i < children.len() ==> {
                        let begin = gate_start + forest_nodes(children@, i as nat, depth);
                        let size = node_count(&children@[i], (depth - 1) as nat);
                        &&& #[trigger] edges@[i] == begin + size - 1
                        &&& edges@[i] < gate_start + nc - 1
                        &&& compiled_at(&children@[i], gates, leaves, begin,
                            leaf_start + forest_leaves(children@, i as nat, depth), (depth - 1) as nat)
                    },
                _ => false,
            },
    }
}

fn same_provider(a: &[u8; 32], b: &[u8; 32]) -> (same: bool)
    ensures same ==> a@ == b@,
{
    let mut i = 0usize;
    while i < 32
        invariant i <= 32, forall |j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases 32 - i,
    {
        if a[i] != b[i] { return false; }
        i += 1;
    }
    assert(a@ =~= b@);
    true
}

/// Return success and the consumed gate/leaf endpoints. A failure is never admitted.
fn check_subtree(
    node: &NetworkNode, gates: &[Gate], leaves: &[(u8, [u8; 32])],
    gate_start: usize, leaf_start: usize, depth: usize,
) -> (result: (bool, usize, usize))
    ensures result.0 ==> (
        compiled_at(node, gates@, leaves@, gate_start as nat, leaf_start as nat, depth as nat)
        && result.1 == gate_start + node_count(node, depth as nat)
        && result.2 == leaf_start + leaf_count(node, depth as nat)
        && gate_start < result.1 <= gates.len()
        && leaf_start < result.2 <= leaves.len()
    ),
    decreases depth,
{
    if depth == 0 || gate_start >= gates.len() || leaf_start >= leaves.len() {
        return (false, gate_start, leaf_start);
    }
    match node {
        NetworkNode::Leaf { id, provider_id } => {
            if leaves[leaf_start].0 != *id || !same_provider(&leaves[leaf_start].1, provider_id) {
                return (false, gate_start, leaf_start);
            }
            match &gates[gate_start] {
                Gate::Leaf { response_index } => {
                    if *response_index != leaf_start { return (false, gate_start, leaf_start); }
                }
                _ => { return (false, gate_start, leaf_start); }
            }
            (true, gate_start + 1, leaf_start + 1)
        }
        NetworkNode::Threshold { required, children, .. } => {
            if *required == 0 || *required as usize > children.len() {
                return (false, gate_start, leaf_start);
            }
            let mut gc = gate_start;
            let mut lc = leaf_start;
            let mut expected: Vec<usize> = Vec::new();
            let mut i = 0usize;
            while i < children.len()
                invariant
                    depth > 0,
                    i <= children.len(), expected.len() == i,
                    gate_start <= gc <= gates.len(), leaf_start <= lc <= leaves.len(),
                    gc == gate_start + forest_nodes(children@, i as nat, depth as nat),
                    lc == leaf_start + forest_leaves(children@, i as nat, depth as nat),
                    i > 0 ==> lc > leaf_start,
                    forall |j: int| 0 <= j < i ==> {
                        let begin = (gate_start as nat) + forest_nodes(children@, j as nat, depth as nat);
                        let size = node_count(&children@[j], (depth - 1) as nat);
                        &&& #[trigger] expected@[j] == begin + size - 1
                        &&& expected@[j] < gc
                        &&& compiled_at(&children@[j], gates@, leaves@, begin,
                            (leaf_start as nat) + forest_leaves(children@, j as nat, depth as nat), (depth - 1) as nat)
                    },
                decreases children.len() - i,
            {
                let child = check_subtree(&children[i], gates, leaves, gc, lc, depth - 1);
                if !child.0 { return (false, gate_start, leaf_start); }
                expected.push(child.1 - 1);
                gc = child.1;
                lc = child.2;
                i += 1;
            }
            if gc >= gates.len() { return (false, gate_start, leaf_start); }
            match &gates[gc] {
                Gate::Threshold { required: actual, children: edges } => {
                    if *actual != *required as usize || edges.len() != expected.len() {
                        return (false, gate_start, leaf_start);
                    }
                    let mut j = 0usize;
                    while j < edges.len()
                        invariant j <= edges.len(), edges.len() == expected.len(),
                            forall |k: int| 0 <= k < j ==> edges@[k] == expected@[k],
                        decreases edges.len() - j,
                    {
                        if edges[j] != expected[j] { return (false, gate_start, leaf_start); }
                        j += 1;
                    }
                    assert(edges@ =~= expected@);
                }
                _ => { return (false, gate_start, leaf_start); }
            }
            (true, gc + 1, lc)
        }
    }
}

proof fn prefix_length(gates: Seq<Gate>, responses: Seq<bool>, n: nat)
    ensures evaluated_prefix(gates, responses, n).len() == n,
    decreases n,
{
    if n > 0 { prefix_length(gates, responses, (n - 1) as nat); }
}

proof fn prefix_index(gates: Seq<Gate>, responses: Seq<bool>, n: nat, i: nat)
    requires i < n,
    ensures evaluated_prefix(gates, responses, n)[i as int]
        == gate_value(&gates[i as int], evaluated_prefix(gates, responses, i), responses),
    decreases n,
{
    prefix_length(gates, responses, (n - 1) as nat);
    if i < n - 1 { prefix_index(gates, responses, (n - 1) as nat, i); }
}

/// A checked child forest has exactly the source forest's success count.
proof fn forest_semantics(
    nodes: Seq<NetworkNode>, edges: Seq<usize>, gates: Seq<Gate>, leaves: Seq<(u8, [u8; 32])>,
    gate_start: nat, leaf_start: nat, depth: nat, parent_root: nat,
    responses: Seq<bool>, n: nat,
)
    requires
        depth > 0, n <= nodes.len(), edges.len() == nodes.len(),
        forall |i: int| 0 <= i < n ==> {
            let begin = gate_start + forest_nodes(nodes, i as nat, depth);
            let size = node_count(&nodes[i], (depth - 1) as nat);
            &&& #[trigger] edges[i] == begin + size - 1
            &&& edges[i] < parent_root
            &&& compiled_at(&nodes[i], gates, leaves, begin,
                leaf_start + forest_leaves(nodes, i as nat, depth), (depth - 1) as nat)
        },
    ensures
        children_valid(edges, evaluated_prefix(gates, responses, parent_root), n),
        count_selected(edges, evaluated_prefix(gates, responses, parent_root), n)
            == source_successes(nodes, n, responses, leaf_start, depth),
    decreases depth, 0nat, n,
{
    prefix_length(gates, responses, parent_root);
    if n > 0 {
        forest_semantics(nodes, edges, gates, leaves, gate_start, leaf_start, depth,
            parent_root, responses, (n - 1) as nat);
        let i = (n - 1) as nat;
        let begin = gate_start + forest_nodes(nodes, i, depth);
        let child_leaf = leaf_start + forest_leaves(nodes, i, depth);
        assert(edges[i as int] < parent_root);
        compiled_semantics(&nodes[i as int], gates, leaves, begin, child_leaf,
            (depth - 1) as nat, responses);
        prefix_index(gates, responses, parent_root, edges[i as int] as nat);
    }
}

/// Structural acceptance implies equivalence to direct source-tree semantics.
pub proof fn compiled_semantics(
    node: &NetworkNode, gates: Seq<Gate>, leaves: Seq<(u8, [u8; 32])>,
    gate_start: nat, leaf_start: nat, depth: nat, responses: Seq<bool>,
)
    requires compiled_at(node, gates, leaves, gate_start, leaf_start, depth),
    ensures {
        let root = (gate_start + node_count(node, depth) - 1) as nat;
        gate_value(&gates[root as int], evaluated_prefix(gates, responses, root), responses)
            == source_value(node, responses, leaf_start, depth)
    },
    decreases depth, 1nat, 0nat,
{
    match node {
        NetworkNode::Leaf { .. } => {},
        NetworkNode::Threshold { children, .. } => {
            let root = (gate_start + node_count(node, depth) - 1) as nat;
            match &gates[root as int] {
                Gate::Threshold { children: edges, .. } => {
                    forest_semantics(children@, edges@, gates, leaves, gate_start, leaf_start,
                        depth, root, responses, children.len() as nat);
                },
                _ => {},
            }
        },
    }
}

pub fn check_compilation(node: &NetworkNode, gates: &[Gate], leaves: &[(u8, [u8; 32])]) -> (accepted: bool)
    ensures accepted ==> (
        compiled_at(node, gates@, leaves@, 0, 0, 3)
        && gates.len() == node_count(node, 3) && leaves.len() == leaf_count(node, 3)
        && forall |responses: Seq<bool>|
            #[trigger] evaluated_prefix(gates@, responses, gates.len() as nat).last()
                == source_value(node, responses, 0, 3)
    ),
{
    // Source network depth is at most three: the implicit all(TPM, network)
    // root occupies depth one in the public MAX_DEPTH == 4 limit.
    let checked = check_subtree(node, gates, leaves, 0, 0, 3);
    let accepted = checked.0 && checked.1 == gates.len() && checked.2 == leaves.len();
    proof {
        if accepted {
            assert forall |responses: Seq<bool>|
                #[trigger] evaluated_prefix(gates@, responses, gates.len() as nat).last()
                    == source_value(node, responses, 0, 3) by {
                compiled_semantics(node, gates@, leaves@, 0, 0, 3, responses);
                prefix_length(gates@, responses, gates.len() as nat);
                prefix_index(gates@, responses, gates.len() as nat, (gates.len() - 1) as nat);
            }
        }
    }
    accepted
}

}

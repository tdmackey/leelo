//! This file contains executable decision functions. Verus also checks this exact file.
//! The specifications describe authenticated observations. They do not describe the cryptography that authenticates those observations.
use vstd::prelude::*;

verus! {

#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    Leaf { response_index: usize },
    Threshold { required: usize, children: Vec<usize> },
}

impl Clone for Gate {
    fn clone(&self) -> (result: Self)
        ensures
            match (self, &result) {
                (Gate::Leaf { response_index: original }, Gate::Leaf { response_index: copied }) =>
                    original == copied,
                (Gate::Threshold { required: original, children: original_children },
                 Gate::Threshold { required: copied, children: copied_children }) =>
                    original == copied && original_children@ == copied_children@,
                _ => false,
            },
    {
        match self {
            Self::Leaf { response_index } => Self::Leaf { response_index: *response_index },
            Self::Threshold { required, children } => Self::Threshold {
                required: *required,
                children: children.clone(),
            },
        }
    }
}

pub open spec fn count_selected(children: Seq<usize>, values: Seq<bool>, n: nat) -> nat
    decreases n,
{
    if n == 0 { 0 } else {
        count_selected(children, values, (n - 1) as nat)
        + if children[n - 1] < values.len() && values[children[n - 1] as int] { 1nat } else { 0nat }
    }
}

pub open spec fn children_valid(children: Seq<usize>, values: Seq<bool>, n: nat) -> bool
    decreases n,
{
    if n == 0 { true } else {
        children_valid(children, values, (n - 1) as nat)
        && children[n - 1] < values.len()
    }
}

pub open spec fn gate_value(gate: &Gate, values: Seq<bool>, responses: Seq<bool>) -> bool {
    match gate {
        Gate::Leaf { response_index } =>
            *response_index < responses.len() && responses[*response_index as int],
        Gate::Threshold { required, children } =>
            0 < *required <= children.len()
            && children_valid(children@, values, children.len() as nat)
            && count_selected(children@, values, children.len() as nat) >= *required,
    }
}

/// Evaluate one threshold from previous gate results. Reject edges with no preceding gate.
pub fn evaluate_gate(gate: &Gate, values: &[bool], responses: &[bool]) -> (result: bool)
    ensures result == gate_value(gate, values@, responses@),
{
    match gate {
        Gate::Leaf { response_index } => {
            *response_index < responses.len() && responses[*response_index]
        }
        Gate::Threshold { required, children } => {
            if *required == 0 || *required > children.len() {
                return false;
            }
            let mut i: usize = 0;
            let mut successes: usize = 0;
            let mut valid = true;
            while i < children.len()
                invariant
                    i <= children.len(),
                    successes <= i,
                    successes == count_selected(children@, values@, i as nat),
                    valid == children_valid(children@, values@, i as nat),
                decreases children.len() - i,
            {
                let child = children[i];
                if child < values.len() {
                    if values[child] {
                        successes += 1;
                    }
                } else {
                    valid = false;
                }
                i += 1;
            }
            valid && successes >= *required
        }
    }
}

pub open spec fn evaluated_prefix(gates: Seq<Gate>, responses: Seq<bool>, n: nat) -> Seq<bool>
    decreases n,
{
    if n == 0 { Seq::empty() } else {
        let previous = evaluated_prefix(gates, responses, (n - 1) as nat);
        previous.push(gate_value(&gates[n - 1], previous, responses))
    }
}

/// The production PolicySession uses this postorder network evaluator.
pub fn evaluate_network(gates: &[Gate], responses: &[bool]) -> (result: bool)
    ensures result == (gates.len() > 0
        && evaluated_prefix(gates@, responses@, gates.len() as nat).last()),
{
    let mut values: Vec<bool> = Vec::new();
    let mut i: usize = 0;
    while i < gates.len()
        invariant
            i <= gates.len(),
            values.len() == i,
            values@ == evaluated_prefix(gates@, responses@, i as nat),
        decreases gates.len() - i,
    {
        let result = evaluate_gate(&gates[i], &values, responses);
        values.push(result);
        i += 1;
    }
    if values.is_empty() { false } else { values[values.len() - 1] }
}

/// Count each successful observation once. Keep all state unchanged after rejection.
pub fn record_response(responses: &mut Vec<bool>, index: usize) -> (accepted: bool)
    ensures
        final(responses).len() == old(responses).len(),
        accepted == (index < old(responses).len() && !old(responses)@[index as int]),
        final(responses)@ == if accepted { old(responses)@.update(index as int, true) } else { old(responses)@ },
{
    if index >= responses.len() || responses[index] {
        false
    } else {
        responses.set(index, true);
        true
    }
}

pub struct ReleaseState {
    pub envelope_authenticated: bool,
    pub tpm_authenticated: bool,
    pub network_satisfied: bool,
    pub live_authorized: bool,
    pub root_authenticated: bool,
    pub released: bool,
}

pub open spec fn release_permitted(state: &ReleaseState, require_live: bool) -> bool {
    state.envelope_authenticated && state.tpm_authenticated && state.network_satisfied
    && (!require_live || state.live_authorized) && state.root_authenticated && !state.released
}

pub fn can_release(state: &ReleaseState, require_live: bool) -> (allowed: bool)
    ensures allowed == release_permitted(state, require_live),
{
    state.envelope_authenticated && state.tpm_authenticated && state.network_satisfied
    && (!require_live || state.live_authorized) && state.root_authenticated && !state.released
}

/// A release is possible only when every mandatory observation is present.
/// The state transition makes a second release impossible.
pub fn try_release(state: &mut ReleaseState, require_live: bool) -> (allowed: bool)
    ensures
        allowed == release_permitted(old(state), require_live),
        final(state).released == (old(state).released || allowed),
        final(state).envelope_authenticated == old(state).envelope_authenticated,
        final(state).tpm_authenticated == old(state).tpm_authenticated,
        final(state).network_satisfied == old(state).network_satisfied,
        final(state).live_authorized == old(state).live_authorized,
        final(state).root_authenticated == old(state).root_authenticated,
        !release_permitted(final(state), require_live),
        allowed ==> (old(state).envelope_authenticated && old(state).tpm_authenticated
            && old(state).network_satisfied && old(state).root_authenticated
            && (!require_live || old(state).live_authorized)),
{
    if can_release(state, require_live) {
        state.released = true;
        true
    } else {
        false
    }
}

}

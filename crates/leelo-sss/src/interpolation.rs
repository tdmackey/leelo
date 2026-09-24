//! Executable bytewise polynomial evaluation and interpolation, checked by Verus.
//! The specifications establish functional arithmetic, not secrecy or erasure.
#[cfg(verus_keep_ghost)]
use crate::gf256::{inverse_identity, inverse_spec, product_spec};
use crate::gf256::{inverse_nonzero, mul};
use vstd::prelude::*;

verus! {

pub open spec fn polynomial_tail(coefficients: Seq<u8>, x: u8, start: nat) -> u8
    decreases coefficients.len() - start,
{
    if start >= coefficients.len() { 0u8 } else {
        product_spec(polynomial_tail(coefficients, x, start + 1), x) ^ coefficients[start as int]
    }
}

pub open spec fn polynomial(secret: u8, coefficients: Seq<u8>, x: u8) -> u8 {
    product_spec(polynomial_tail(coefficients, x, 0), x) ^ secret
}

/// Horner evaluation with a fixed public loop bound and no coefficient-dependent branches.
pub(crate) fn evaluate(secret: u8, coefficients: &[u8], x: u8) -> (result: u8)
    ensures result == polynomial(secret, coefficients@, x),
{
    let mut remaining = coefficients.len();
    let mut value = 0u8;
    while remaining > 0
        invariant
            remaining <= coefficients.len(),
            value == polynomial_tail(coefficients@, x, remaining as nat),
        decreases remaining,
    {
        remaining -= 1;
        value = mul(value, x) ^ coefficients[remaining];
    }
    mul(value, x) ^ secret
}

pub open spec fn numerator(indices: Seq<u8>, target: u8, selected: nat, n: nat) -> u8
    decreases n,
{
    if n == 0 { 1u8 } else if n - 1 == selected {
        numerator(indices, target, selected, (n - 1) as nat)
    } else {
        product_spec(numerator(indices, target, selected, (n - 1) as nat),
            target ^ indices[n - 1])
    }
}

pub open spec fn denominator(indices: Seq<u8>, selected: nat, n: nat) -> u8
    decreases n,
{
    if n == 0 { 1u8 } else if n - 1 == selected {
        denominator(indices, selected, (n - 1) as nat)
    } else {
        product_spec(denominator(indices, selected, (n - 1) as nat),
            indices[selected as int] ^ indices[n - 1])
    }
}

pub open spec fn weight(indices: Seq<u8>, target: u8, selected: nat) -> u8 {
    product_spec(numerator(indices, target, selected, indices.len()),
        inverse_spec(denominator(indices, selected, indices.len())))
}

/// Compute exactly the Lagrange weights in the specification.
/// The public caller validates distinct nonzero coordinates before interpolation.
pub(crate) fn weights(indices: &[u8], target: u8) -> (result: Vec<u8>)
    ensures
        result.len() == indices.len(),
        forall |i: int| 0 <= i < indices.len() ==> result@[i] == weight(indices@, target, i as nat),
{
    let mut result = Vec::new();
    let mut i = 0usize;
    while i < indices.len()
        invariant
            i <= indices.len(), result.len() == i,
            forall |k: int| 0 <= k < i ==> result@[k] == weight(indices@, target, k as nat),
        decreases indices.len() - i,
    {
        let mut top = 1u8;
        let mut bottom = 1u8;
        let mut j = 0usize;
        while j < indices.len()
            invariant
                i < indices.len(), j <= indices.len(),
                top == numerator(indices@, target, i as nat, j as nat),
                bottom == denominator(indices@, i as nat, j as nat),
            decreases indices.len() - j,
        {
            if i != j {
                top = mul(top, target ^ indices[j]);
                bottom = mul(bottom, indices[i] ^ indices[j]);
            }
            j += 1;
        }
        result.push(mul(top, inverse_nonzero(bottom)));
        i += 1;
    }
    result
}

pub open spec fn weighted_prefix(values: Seq<u8>, weights: Seq<u8>, n: nat) -> u8
    decreases n,
{
    if n == 0 { 0u8 } else {
        weighted_prefix(values, weights, (n - 1) as nat)
            ^ product_spec(values[n - 1], weights[n - 1])
    }
}

/// Interpolate one byte using the public weights previously computed by `weights`.
pub(crate) fn weighted_sum(values: &[u8], weights: &[u8]) -> (result: u8)
    requires values.len() == weights.len(),
    ensures result == weighted_prefix(values@, weights@, values.len() as nat),
{
    let mut result = 0u8;
    let mut i = 0usize;
    while i < values.len()
        invariant
            i <= values.len(), values.len() == weights.len(),
            result == weighted_prefix(values@, weights@, i as nat),
        decreases values.len() - i,
    {
        result ^= mul(values[i], weights[i]);
        i += 1;
    }
    result
}

proof fn mandatory_root_weights()
    ensures
        weight(seq![1u8, 2u8], 0, 0) == 0xf7u8,
        weight(seq![1u8, 2u8], 0, 1) == 0xf6u8,
{
    inverse_identity(3u8);
    let inverse_three = inverse_spec(3u8);
    assert(inverse_three == 0xf6u8) by (bit_vector)
        requires product_spec(3u8, inverse_three) == 1u8;
    reveal_with_fuel(numerator, 3);
    reveal_with_fuel(denominator, 3);
    assert(product_spec(1u8, 1u8) == 1u8) by (bit_vector);
    assert(product_spec(1u8, 2u8) == 2u8) by (bit_vector);
    assert(product_spec(1u8, 3u8) == 3u8) by (bit_vector);
    assert(product_spec(1u8, 0xf6u8) == 0xf6u8) by (bit_vector);
    assert(product_spec(2u8, 0xf6u8) == 0xf7u8) by (bit_vector);
    assert((0u8 ^ 1u8) == 1u8 && (0u8 ^ 2u8) == 2u8
        && (1u8 ^ 2u8) == 3u8 && (2u8 ^ 1u8) == 3u8) by (bit_vector);
    assert(numerator(seq![1u8, 2u8], 0, 0, 2) == 2u8);
    assert(numerator(seq![1u8, 2u8], 0, 1, 2) == 1u8);
    assert(denominator(seq![1u8, 2u8], 0, 2) == 3u8);
    assert(denominator(seq![1u8, 2u8], 1, 2) == 3u8);
    assert(weight(seq![1u8, 2u8], 0, 0) == 0xf7u8);
    assert(weight(seq![1u8, 2u8], 0, 1) == 0xf6u8);
}

/// For every secret byte and slope, the mandatory root's coordinates 1 and 2
/// reconstruct the secret. This statement uses the same specifications as the
/// production evaluation, weight, and interpolation functions above.
pub proof fn mandatory_root_roundtrip(secret: u8, slope: u8)
    ensures
        weighted_prefix(
            seq![polynomial(secret, seq![slope], 1), polynomial(secret, seq![slope], 2)],
            seq![weight(seq![1u8, 2u8], 0, 0), weight(seq![1u8, 2u8], 0, 1)], 2) == secret,
{
    mandatory_root_weights();
    reveal_with_fuel(weighted_prefix, 3);
    reveal_with_fuel(polynomial_tail, 3);
    assert(product_spec(0u8, 1u8) == 0u8) by (bit_vector);
    assert(product_spec(0u8, 2u8) == 0u8) by (bit_vector);
    let first = product_spec(slope, 1u8) ^ secret;
    let second = product_spec(slope, 2u8) ^ secret;
    assert((0u8 ^ slope) == slope) by (bit_vector);
    assert(polynomial(secret, seq![slope], 1) == first);
    assert(polynomial(secret, seq![slope], 2) == second);
    let first_term = product_spec(first, 0xf7u8);
    assert((0u8 ^ first_term) == first_term) by (bit_vector);
    assert((product_spec(first, 0xf7u8) ^ product_spec(second, 0xf6u8)) == secret)
        by (bit_vector)
        requires first == (product_spec(slope, 1u8) ^ secret),
            second == (product_spec(slope, 2u8) ^ secret),
    ;
}

}

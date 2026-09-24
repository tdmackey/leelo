//! This module supplies arithmetic in GF(2^8), with a polynomial basis modulo 0x11b.
//!
//! The masked multiplication rounds are fixed. They do not index tables with secret data.
//! This property applies to source code. It makes no claim about compiler output or a completed constant-time audit.

use vstd::prelude::*;

verus! {

#[verifier::inline]
pub open spec fn polynomial_term(a: u8, b: u8, bit: u16) -> u16 {
    if ((b as u16) & (1u16 << bit)) != 0 { (a as u16) << bit } else { 0u16 }
}

#[verifier::inline]
pub open spec fn carryless_product(a: u8, b: u8) -> u16 {
    polynomial_term(a, b, 0) ^ polynomial_term(a, b, 1)
    ^ polynomial_term(a, b, 2) ^ polynomial_term(a, b, 3)
    ^ polynomial_term(a, b, 4) ^ polynomial_term(a, b, 5)
    ^ polynomial_term(a, b, 6) ^ polynomial_term(a, b, 7)
}

#[verifier::inline]
pub open spec fn reduced_term(value: u16, mask: u16, basis: u8) -> u8 {
    if (value & mask) != 0 { basis } else { 0u8 }
}

/// This independent mathematical specification uses carryless multiplication.
/// Polynomial long division by x^8+x^4+x^3+x+1 (0x11b) follows the multiplication.
#[verifier::inline]
pub open spec fn polynomial_reduce(value: u16) -> u8 {
    (value as u8)
    ^ reduced_term(value, 0x0100, 0x1b)
    ^ reduced_term(value, 0x0200, 0x36)
    ^ reduced_term(value, 0x0400, 0x6c)
    ^ reduced_term(value, 0x0800, 0xd8)
    ^ reduced_term(value, 0x1000, 0xab)
    ^ reduced_term(value, 0x2000, 0x4d)
    ^ reduced_term(value, 0x4000, 0x9a)
    ^ reduced_term(value, 0x8000, 0x2f)
}

/// The compact basis-reduction specification equals polynomial long division for each 16-bit polynomial.
/// This equivalence includes values outside the production multiplier outputs.
proof fn reduction_matches_long_division(value: u16) {
    let r15 = if (value & 0x8000u16) != 0 { value ^ (0x11bu16 << 7) } else { value };
    let r14 = if (r15 & 0x4000u16) != 0 { r15 ^ (0x11bu16 << 6) } else { r15 };
    let r13 = if (r14 & 0x2000u16) != 0 { r14 ^ (0x11bu16 << 5) } else { r14 };
    let r12 = if (r13 & 0x1000u16) != 0 { r13 ^ (0x11bu16 << 4) } else { r13 };
    let r11 = if (r12 & 0x0800u16) != 0 { r12 ^ (0x11bu16 << 3) } else { r12 };
    let r10 = if (r11 & 0x0400u16) != 0 { r11 ^ (0x11bu16 << 2) } else { r11 };
    let r9 = if (r10 & 0x0200u16) != 0 { r10 ^ (0x11bu16 << 1) } else { r10 };
    let r8 = if (r9 & 0x0100u16) != 0 { r9 ^ 0x11bu16 } else { r9 };
    assert(polynomial_reduce(value) == r8 as u8 && r8 < 256) by (bit_vector)
        requires
            r15 == if (value & 0x8000u16) != 0 { value ^ (0x11bu16 << 7) } else { value },
            r14 == if (r15 & 0x4000u16) != 0 { r15 ^ (0x11bu16 << 6) } else { r15 },
            r13 == if (r14 & 0x2000u16) != 0 { r14 ^ (0x11bu16 << 5) } else { r14 },
            r12 == if (r13 & 0x1000u16) != 0 { r13 ^ (0x11bu16 << 4) } else { r13 },
            r11 == if (r12 & 0x0800u16) != 0 { r12 ^ (0x11bu16 << 3) } else { r12 },
            r10 == if (r11 & 0x0400u16) != 0 { r11 ^ (0x11bu16 << 2) } else { r11 },
            r9 == if (r10 & 0x0200u16) != 0 { r10 ^ (0x11bu16 << 1) } else { r10 },
            r8 == if (r9 & 0x0100u16) != 0 { r9 ^ 0x11bu16 } else { r9 },
    ;
}

pub open spec fn product_spec(a: u8, b: u8) -> u8 {
    polynomial_reduce(carryless_product(a, b))
}

#[verifier::inline]
pub open spec fn xtime_spec(a: u8) -> u8 {
    (a << 1) ^ if (a >> 7) == 1 { 0x1bu8 } else { 0u8 }
}

#[verifier::inline]
pub open spec fn low_term(a: u8, b: u8) -> u8 {
    if (b & 1) == 1 { a } else { 0u8 }
}

#[inline(always)]
fn xtime(a: u8) -> (result: u8)
    ensures result == xtime_spec(a),
{
    let reduce = 0_u8.wrapping_sub(a >> 7);
    let result = (a << 1) ^ (0x1b & reduce);
    proof {
        assert((a >> 7) <= 1) by (bit_vector);
        assert(reduce == if (a >> 7) == 1 { 255u8 } else { 0u8 });
        assert(result == xtime_spec(a)) by (bit_vector)
            requires result == ((a << 1) ^ (0x1b & reduce)),
                reduce == if (a >> 7) == 1 { 255u8 } else { 0u8 },
        ;
    }
    result
}

#[inline(always)]
fn masked(a: u8, b: u8) -> (result: u8)
    ensures result == low_term(a, b),
{
    let mask = 0_u8.wrapping_sub(b & 1);
    let result = a & mask;
    proof {
        assert((b & 1) <= 1) by (bit_vector);
        assert(mask == if (b & 1) == 1 { 255u8 } else { 0u8 });
        assert(result == low_term(a, b)) by (bit_vector)
            requires result == (a & mask), mask == if (b & 1) == 1 { 255u8 } else { 0u8 },
        ;
    }
    result
}

/// Multiply two polynomial-basis field elements with eight fixed, unrolled masked rounds.
/// Unrolled rounds keep the polynomial-refinement proof small.
pub(crate) fn mul(a: u8, b: u8) -> (result: u8)
    ensures result == product_spec(a, b),
{
    let a1 = xtime(a);
    let a2 = xtime(a1);
    let a3 = xtime(a2);
    let a4 = xtime(a3);
    let a5 = xtime(a4);
    let a6 = xtime(a5);
    let a7 = xtime(a6);
    let p0 = masked(a, b);
    let p1 = masked(a1, b >> 1);
    let p2 = masked(a2, b >> 2);
    let p3 = masked(a3, b >> 3);
    let p4 = masked(a4, b >> 4);
    let p5 = masked(a5, b >> 5);
    let p6 = masked(a6, b >> 6);
    let p7 = masked(a7, b >> 7);
    let product = p0 ^ p1 ^ p2 ^ p3 ^ p4 ^ p5 ^ p6 ^ p7;
    proof {
        assert(product == product_spec(a, b)) by (bit_vector)
            requires
                a1 == xtime_spec(a), a2 == xtime_spec(a1), a3 == xtime_spec(a2),
                a4 == xtime_spec(a3), a5 == xtime_spec(a4), a6 == xtime_spec(a5), a7 == xtime_spec(a6),
                p0 == low_term(a, b), p1 == low_term(a1, b >> 1), p2 == low_term(a2, b >> 2),
                p3 == low_term(a3, b >> 3), p4 == low_term(a4, b >> 4), p5 == low_term(a5, b >> 5),
                p6 == low_term(a6, b >> 6), p7 == low_term(a7, b >> 7),
                product == (p0 ^ p1 ^ p2 ^ p3 ^ p4 ^ p5 ^ p6 ^ p7),
        ;
    }
    product
}

pub closed spec fn inverse_spec(a: u8) -> u8 {
    let a2 = product_spec(a, a);
    let a4 = product_spec(a2, a2);
    let a8 = product_spec(a4, a4);
    let a16 = product_spec(a8, a8);
    let a32 = product_spec(a16, a16);
    let a64 = product_spec(a32, a32);
    let a128 = product_spec(a64, a64);
    product_spec(product_spec(product_spec(a2, a4), product_spec(a8, a16)),
        product_spec(a32, product_spec(a64, a128)))
}

pub proof fn inverse_identity(a: u8)
    requires a != 0,
    ensures product_spec(a, inverse_spec(a)) == 1,
{
    let a2 = product_spec(a, a);
    let a4 = product_spec(a2, a2);
    let a8 = product_spec(a4, a4);
    let a16 = product_spec(a8, a8);
    let a32 = product_spec(a16, a16);
    let a64 = product_spec(a32, a32);
    let a128 = product_spec(a64, a64);
    let a6 = product_spec(a2, a4);
    let a24 = product_spec(a8, a16);
    let a192 = product_spec(a64, a128);
    let a224 = product_spec(a32, a192);
    let a30 = product_spec(a6, a24);
    let result = product_spec(a30, a224);
    assert(product_spec(a, result) == 1) by (bit_vector)
        requires
            a != 0,
            a2 == product_spec(a, a), a4 == product_spec(a2, a2),
            a8 == product_spec(a4, a4), a16 == product_spec(a8, a8),
            a32 == product_spec(a16, a16), a64 == product_spec(a32, a32),
            a128 == product_spec(a64, a64), a6 == product_spec(a2, a4),
            a24 == product_spec(a8, a16), a192 == product_spec(a64, a128),
            a224 == product_spec(a32, a192), a30 == product_spec(a6, a24),
            result == product_spec(a30, a224),
    ;
}

/// Compute a^-1 = a^254. The verifier proves the nonzero inverse identity.
///
/// This function returns zero for a=0. That value is not a field inverse.
/// Public coordinate validation establishes the nonzero precondition in the interpolation caller.
pub(crate) fn inverse_nonzero(a: u8) -> (result: u8)
    ensures result == inverse_spec(a), a != 0 ==> product_spec(a, result) == 1,
{
    let a2 = mul(a, a);
    let a4 = mul(a2, a2);
    let a8 = mul(a4, a4);
    let a16 = mul(a8, a8);
    let a32 = mul(a16, a16);
    let a64 = mul(a32, a32);
    let a128 = mul(a64, a64);
    let result = mul(mul(mul(a2, a4), mul(a8, a16)), mul(a32, mul(a64, a128)));
    proof { if a != 0 { inverse_identity(a); } }
    result
}

}

#[cfg(test)]
mod tests {
    use super::{inverse_nonzero, mul};

    // Form a 16-bit carryless polynomial product for an independent reference.
    // Then use polynomial long division.
    // The production code reduces each shift of an 8-bit multiplicand.
    fn polynomial_reference(a: u8, b: u8) -> u8 {
        let mut polynomial = 0_u16;
        for bit in 0..8 {
            if b & (1 << bit) != 0 {
                polynomial ^= u16::from(a) << bit;
            }
        }
        for degree in (8..=14).rev() {
            if polynomial & (1 << degree) != 0 {
                polynomial ^= 0x11b << (degree - 8);
            }
        }
        u8::try_from(polynomial).expect("reduced field element")
    }

    #[test]
    fn every_product_matches_independent_polynomial_reduction() {
        for a in 0..=255_u8 {
            for b in 0..=255_u8 {
                assert_eq!(mul(a, b), polynomial_reference(a, b), "a={a}, b={b}");
                assert_eq!(mul(a, b), mul(b, a));
            }
            assert_eq!(mul(a, 0), 0);
            assert_eq!(mul(a, 1), a);
        }
    }

    #[test]
    fn every_nonzero_element_has_the_computed_inverse() {
        for value in 1..=255_u8 {
            assert_eq!(mul(value, inverse_nonzero(value)), 1, "value={value}");
        }
    }

    #[test]
    fn published_aes_field_example() {
        assert_eq!(mul(0x57, 0x83), 0xc1);
    }
}

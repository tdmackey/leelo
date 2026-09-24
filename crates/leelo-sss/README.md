# leelo-sss

This crate uses bytewise Shamir sharing for 32-byte policy secrets over GF(256).
The field polynomial is `0x11b`. The public threshold and share count cannot
exceed 31. Imported coordinates can be any unique nonzero field elements.

`split` uses uniform independent coefficient bytes, including zero.
`Share` owns storage that zeroizes on drop. It has no `Copy`, `Clone`, `Debug`,
or generic serialization implementation. Callers must authenticate wrapped
shares before they call `reconstruct`. Callers must then authenticate the
recovered root payload. Polynomial consistency checks do not authenticate data.

Finite tests compare all 65,536 field products with independent polynomial
long division. Tests also check all 255 nonzero inverses.
Tests cover each sufficient subset for all thresholds with up to six shares.
They also cover permutations, maximum-size sharing, invalid coordinates,
inconsistent surplus shares, zero coefficients, and RNG failure.
These tests validate the implementation. They are not a complete secrecy
proof or constant-time proof.

`verification/sss.rs` imports the actual production arithmetic and interpolation
modules. With pinned Verus and `--no-cheating`, their contracts prove:

- The field multiplier agrees with polynomial multiplication modulo `0x11b`.
- For every nonzero byte `a`, the production exponentiation returns an inverse:
  `a * inverse(a) = 1`.
- Horner evaluation, public Lagrange weights, and the byte interpolation loop
  agree with their recursive specifications and satisfy index and arithmetic safety.
- For all secret bytes and coefficient bytes, the two shares at coordinates 1
  and 2 interpolate to the secret at coordinate 0. These are the mandatory
  root's coordinates. The theorem uses the production functions' specifications.

The public validation, randomness, 32-byte column assembly, and surplus-share
adapter remain ordinary Rust. Integration tests compare reconstruction against
independently evaluated polynomials at nonconsecutive coordinates and several
thresholds, including rotated bases and surplus shares. There is no general
mechanized t-of-n reconstruction theorem or probabilistic secrecy theorem.
These functional proofs do not establish authentication, erasure, or timing.

Secret arrays and polynomial coefficients zeroize on drop.
This claim does not cover compiler temporaries, register spills, or copies
that the caller makes.

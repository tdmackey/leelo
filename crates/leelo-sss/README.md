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

Secret arrays and polynomial coefficients zeroize on drop.
This claim does not cover compiler temporaries, register spills, or copies
that the caller makes.

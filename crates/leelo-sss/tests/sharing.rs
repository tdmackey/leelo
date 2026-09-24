use leelo_sss::{Error, MAX_SHARES, Share, reconstruct, split};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use zeroize::Zeroizing;

// This code intentionally copies secret bytes to construct test fixtures.
// Production callers use an authenticated wrapper codec.
fn fixture_copy(share: &Share) -> Share {
    Share::from_parts(share.index(), Zeroizing::new(*share.value())).unwrap()
}

#[test]
fn every_sufficient_small_subset_recovers_in_either_order() {
    for seed in [0_u8, 17, 255] {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let secret = core::array::from_fn(|i| seed.wrapping_add((i as u8).wrapping_mul(37)));
        for count in 1..=6_u8 {
            for threshold in 1..=count {
                let all = split(&secret, threshold, count, &mut rng).unwrap();
                for mask in 1..(1_u32 << count) {
                    let mut subset: Vec<Share> = all
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| mask & (1 << i) != 0)
                        .map(|(_, share)| fixture_copy(share))
                        .collect();
                    if subset.len() < usize::from(threshold) {
                        assert!(matches!(
                            reconstruct(threshold, &subset),
                            Err(Error::InsufficientShares { .. })
                        ));
                        continue;
                    }
                    let restored = reconstruct(threshold, &subset).unwrap();
                    assert_eq!(*restored, secret, "n={count}, t={threshold}, mask={mask}");
                    subset.reverse();
                    assert_eq!(*reconstruct(threshold, &subset).unwrap(), secret);
                }
            }
        }
    }
}

#[test]
fn maximum_count_and_threshold_round_trip() {
    let mut rng = ChaCha20Rng::from_seed([42; 32]);
    let secret = [0xa5; 32];
    for threshold in [1, 2, 16, MAX_SHARES] {
        let shares = split(&secret, threshold, MAX_SHARES, &mut rng).unwrap();
        assert_eq!(*reconstruct(threshold, &shares).unwrap(), secret);
    }
}

#[test]
fn zero_coefficients_are_accepted_without_rejection_sampling() {
    struct ZeroRng;
    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }
        fn next_u64(&mut self) -> u64 {
            0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    // This test fixture intentionally uses nonrandom data to test the all-zero coefficient outcome.
    // Never use this fixture as an actual RNG.
    impl CryptoRng for ZeroRng {}
    let secret = [0xa5; 32];
    let shares = split(&secret, 3, 5, &mut ZeroRng).unwrap();
    assert!(shares.iter().all(|share| share.value() == &secret));
    assert_eq!(*reconstruct(3, &shares).unwrap(), secret);
}

#[test]
fn entropy_failure_does_not_return_partial_shares() {
    struct FailRng;
    impl RngCore for FailRng {
        fn next_u32(&mut self) -> u32 {
            panic!("fallible API required")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("fallible API required")
        }
        fn fill_bytes(&mut self, _: &mut [u8]) {
            panic!("fallible API required")
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), rand_core::Error> {
            Err(rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            ))
        }
    }
    impl CryptoRng for FailRng {}
    assert_eq!(
        split(&[1; 32], 2, 3, &mut FailRng).err(),
        Some(Error::EntropyUnavailable)
    );
}

#[test]
fn validates_threshold_count_and_imported_indices() {
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    for threshold in [0, 32, 255] {
        assert_eq!(
            split(&[1; 32], threshold, 3, &mut rng).err(),
            Some(Error::InvalidThreshold { threshold })
        );
        assert_eq!(
            reconstruct(threshold, &[]).err(),
            Some(Error::InvalidThreshold { threshold })
        );
    }
    for count in [0, 32, 255] {
        assert_eq!(
            split(&[1; 32], 1, count, &mut rng).err(),
            Some(Error::InvalidShareCount {
                count: count.into()
            })
        );
    }
    assert_eq!(
        split(&[1; 32], 3, 2, &mut rng).err(),
        Some(Error::InsufficientShares {
            required: 3,
            provided: 2
        })
    );
    assert_eq!(
        reconstruct(1, &[]).err(),
        Some(Error::InsufficientShares {
            required: 1,
            provided: 0
        })
    );
    assert_eq!(
        Share::from_parts(0, Zeroizing::new([0; 32])).err(),
        Some(Error::ZeroIndex)
    );
    let too_many: Vec<Share> = (1..=32)
        .map(|index| Share::from_parts(index, Zeroizing::new([1; 32])).unwrap())
        .collect();
    assert_eq!(
        reconstruct(1, &too_many).err(),
        Some(Error::InvalidShareCount { count: 32 })
    );
    let arbitrary_indices = [
        Share::from_parts(127, Zeroizing::new([9; 32])).unwrap(),
        Share::from_parts(255, Zeroizing::new([9; 32])).unwrap(),
    ];
    assert_eq!(*reconstruct(1, &arbitrary_indices).unwrap(), [9; 32]);
}

#[test]
fn duplicate_surplus_coordinate_is_rejected() {
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let mut shares = split(&[0x13; 32], 2, 3, &mut rng).unwrap();
    shares.push(fixture_copy(&shares[0]));
    assert_eq!(
        reconstruct(2, &shares).err(),
        Some(Error::DuplicateIndex { index: 1 })
    );
}

#[test]
fn inconsistent_surplus_share_is_rejected() {
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let mut shares = split(&[0x13; 32], 2, 3, &mut rng).unwrap();
    let mut changed = Zeroizing::new(*shares[2].value());
    changed[31] ^= 1;
    shares[2] = Share::from_parts(3, changed).unwrap();
    assert_eq!(
        reconstruct(2, &shares).err(),
        Some(Error::InconsistentShares)
    );
}

#[test]
fn exactly_threshold_shares_are_not_an_authenticity_check() {
    let secret = [0x13; 32];
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let mut shares = split(&secret, 2, 2, &mut rng).unwrap();
    let mut changed = Zeroizing::new(*shares[1].value());
    changed[0] ^= 1;
    shares[1] = Share::from_parts(2, changed).unwrap();
    assert_ne!(*reconstruct(2, &shares).unwrap(), secret);
}

// Independent polynomial long division, used only by the integration oracle.
fn reference_product(a: u8, b: u8) -> u8 {
    let mut product = 0u16;
    for bit in 0..8 {
        if (b >> bit) & 1 != 0 {
            product ^= u16::from(a) << bit;
        }
    }
    for bit in (8..=14).rev() {
        if (product >> bit) & 1 != 0 {
            product ^= 0x11b << (bit - 8);
        }
    }
    product as u8
}

#[test]
fn independently_evaluated_polynomials_recover_at_nonconsecutive_coordinates() {
    // This exercises validation, share-to-column wiring, surplus checks, and
    // general thresholds outside the bytewise root theorem's coordinates 1, 2.
    let coordinates = [255u8, 17, 1, 127, 64, 3];
    let secret = core::array::from_fn(|byte| (byte as u8).wrapping_mul(29));
    for threshold in 1..=5u8 {
        let shares: Vec<Share> = coordinates
            .iter()
            .map(|&index| {
                let value = core::array::from_fn(|byte| {
                    let mut value = secret[byte];
                    let mut power = 1u8;
                    for degree in 1..threshold {
                        power = reference_product(power, index);
                        let coefficient = (byte as u8).wrapping_mul(71).wrapping_add(degree);
                        value ^= reference_product(coefficient, power);
                    }
                    value
                });
                Share::from_parts(index, Zeroizing::new(value)).unwrap()
            })
            .collect();
        for rotation in 0..shares.len() {
            let mut reordered: Vec<Share> = shares.iter().map(fixture_copy).collect();
            reordered.rotate_left(rotation);
            assert_eq!(*reconstruct(threshold, &reordered).unwrap(), secret);
            assert_eq!(
                *reconstruct(threshold, &reordered[..usize::from(threshold)]).unwrap(),
                secret
            );
        }
    }
}

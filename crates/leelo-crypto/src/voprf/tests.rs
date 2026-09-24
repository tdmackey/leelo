use super::*;

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

const RFC_SECRET: &str = concat!(
    "051646b9e6e7a71ae27c1e1d0b87b4381db6d3595eeeb1adb41579adbf992",
    "f4278f9016eafc944edaa2b43183581779d"
);
const RFC_PUBLIC: &str = concat!(
    "031d689686c611991b55f1a1d8f4305ccd6cb719446f660a30db61b7aa87b",
    "46acf59b7c0d4a9077b3da21c25dd482229a0"
);
const RFC_BLIND: &str = concat!(
    "504650f53df8f16f6861633388936ea23338fa65ec36e0290022b48eb562",
    "889d89dbfa691d1cde91517fa222ed7ad364"
);

// These single-element VOPRF vectors come from RFC 9497 Appendix A.4.2.1 and A.4.2.2.
#[test]
fn rfc9497_p384_single_element_vectors() {
    let server = SecretServer::from_secret_bytes(&bytes(RFC_SECRET)).unwrap();
    assert_eq!(server.public_key().as_bytes(), &bytes::<49>(RFC_PUBLIC));
    let vectors = [
        (
            "00",
            concat!(
                "02d338c05cbecb82de13d6700f09cb61190543a7b7e2c6cd4fc",
                "a56887e564ea82653b27fdad383995ea6d02cf26d0e24d9"
            ),
            concat!(
                "02a7bba589b3e8672aa19e8fd258de2e6aae20101c8d7612",
                "46de97a6b5ee9cf105febce4327a326255a3c604f63f600ef6"
            ),
            concat!(
                "bfc6cf3859127f5fe25548859856d6b7fa1c7459f0ba5712a806fc091a30",
                "00c42d8ba34ff45f32a52e40533efd2a03bc87f3bf4f9f58028297ccb9ccb18ae718",
                "2bcd1ef239df77e3be65ef147f3acf8bc9cbfc5524b702263414f043e3b7ca2e"
            ),
            concat!(
                "3333230886b562ffb8329a8be08fea8025755372817ec969d114d1203d0",
                "26b4a622beab60220bf19078bca35a529b35c"
            ),
        ),
        (
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            concat!(
                "02f27469e059886f221be5f2cca03d2bdc61e55221721c3b3e5",
                "6fc012e36d31ae5f8dc058109591556a6dbd3a8c69c433b"
            ),
            concat!(
                "03f16f903947035400e96b7f531a38d4a07ac89a80f89d86",
                "a1bf089c525a92c7f4733729ca30c56ce78b1ab4f7d92db8b4"
            ),
            concat!(
                "d005d6daaad7571414c1e0c75f7e57f2113ca9f4604e84bc90f9be52da89",
                "6fff3bee496dcde2a578ae9df315032585f801fb21c6080ac05672b291e575a40295",
                "b306d967717b28e08fcc8ad1cab47845d16af73b3e643ddcc191208e71c64630"
            ),
            concat!(
                "b91c70ea3d4d62ba922eb8a7d03809a441e1c3c7af915cbc2226f485213",
                "e895942cd0f8580e6d99f82221e66c40d274f"
            ),
        ),
    ];
    for (input, blinded, evaluated, proof, expected) in vectors {
        let mut state_bytes = hex::decode(RFC_BLIND).unwrap();
        state_bytes.extend_from_slice(&bytes::<49>(blinded));
        // Only tests can import deterministic state. Production code has no such API.
        let state = BlindState {
            inner: VoprfClient::deserialize(&state_bytes).unwrap(),
            input: Zeroizing::new(hex::decode(input).unwrap()),
        };
        let evaluation = Evaluation {
            element: bytes(evaluated),
            proof: bytes(proof),
        };
        assert_eq!(
            hex::encode(
                state
                    .finalize(&evaluation, &server.public_key())
                    .unwrap()
                    .as_ref()
            ),
            expected
        );
        // The evaluated point does not depend on proof randomness.
        assert_eq!(
            server.evaluate(&bytes(blinded)).unwrap().element,
            bytes::<49>(evaluated)
        );
    }
}

#[test]
fn same_input_fresh_blinds_same_output() {
    let server = SecretServer::generate().unwrap();
    let (state_a, a) = blind(b"leelo/v1/test-input").unwrap();
    let (state_b, b) = blind(b"leelo/v1/test-input").unwrap();
    assert_ne!(a, b);
    let output_a = state_a
        .finalize(&server.evaluate(&a).unwrap(), &server.public_key())
        .unwrap();
    let output_b = state_b
        .finalize(&server.evaluate(&b).unwrap(), &server.public_key())
        .unwrap();
    assert_eq!(*output_a, *output_b);
    let restored = SecretServer::from_secret_bytes(&server.export_secret_bytes()).unwrap();
    assert_eq!(restored.public_key(), server.public_key());
}

#[test]
fn wrong_public_pin_and_tampering_fail() {
    let server = SecretServer::generate().unwrap();
    let other = SecretServer::generate().unwrap();
    let (state, request) = blind(b"input").unwrap();
    assert!(
        state
            .finalize(&server.evaluate(&request).unwrap(), &other.public_key())
            .is_err()
    );
    for tamper_proof in [true, false] {
        let (state, request) = blind(b"input").unwrap();
        let mut response = server.evaluate(&request).unwrap();
        if tamper_proof {
            response.proof[0] ^= 1;
        } else {
            response.element[1] ^= 1;
        }
        assert!(state.finalize(&response, &server.public_key()).is_err());
    }
    // A valid response for a different blind cannot be replayed into this state.
    let (state, _) = blind(b"input").unwrap();
    let (_, different_request) = blind(b"input").unwrap();
    assert!(
        state
            .finalize(
                &server.evaluate(&different_request).unwrap(),
                &server.public_key()
            )
            .is_err()
    );
}

#[test]
fn reject_invalid_points_scalars_and_input_bounds() {
    let server = SecretServer::generate().unwrap();
    for encoding in [[0; 49], [0xff; 49]] {
        assert!(ServerPublicKey::from_bytes(encoding).is_err());
        assert!(server.evaluate(&encoding).is_err());
    }
    assert!(SecretServer::from_secret_bytes(&[0; 48]).is_err());
    assert!(SecretServer::from_secret_bytes(&[0xff; 48]).is_err());
    assert!(blind(b"").is_err());
    assert!(blind(&vec![1; MAX_INPUT_BYTES + 1]).is_err());
}

struct FailingEntropy {
    calls: usize,
}

impl RngCore for FailingEntropy {
    fn next_u32(&mut self) -> u32 {
        panic!("infallible entropy method used")
    }
    fn next_u64(&mut self) -> u64 {
        panic!("infallible entropy method used")
    }
    fn fill_bytes(&mut self, _: &mut [u8]) {
        panic!("infallible entropy method used")
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.calls += 1;
        // Also model an entropy provider that modifies the seed before failing.
        bytes.fill(0x5a);
        Err(rand_core::Error::from(
            core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
        ))
    }
}
impl CryptoRng for FailingEntropy {}

#[test]
fn entropy_failure_returns_an_error_before_blinding_or_evaluation() {
    let mut entropy = FailingEntropy { calls: 0 };
    assert_eq!(
        blind_with_entropy(b"input", &mut entropy).err(),
        Some(Error::Randomness)
    );
    assert_eq!(entropy.calls, 1);
    let server = SecretServer::from_secret_bytes(&bytes(RFC_SECRET)).unwrap();
    // A public key encoding is also a valid input point for testing this boundary.
    assert_eq!(
        server
            .evaluate_with_entropy(&bytes(RFC_PUBLIC), &mut entropy)
            .err(),
        Some(Error::Randomness)
    );
    assert_eq!(entropy.calls, 2);
    // Reject public malformed input before requesting entropy.
    assert_eq!(
        blind_with_entropy(b"", &mut entropy).err(),
        Some(Error::InvalidInput)
    );
    assert_eq!(
        server
            .evaluate_with_entropy(&[0; POINT_BYTES], &mut entropy)
            .err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(entropy.calls, 2);
}

#[test]
fn fresh_proof_randomness_changes_proof_without_changing_evaluated_point() {
    let server = SecretServer::from_secret_bytes(&bytes(RFC_SECRET)).unwrap();
    let a = server.evaluate(&bytes(RFC_PUBLIC)).unwrap();
    let b = server.evaluate(&bytes(RFC_PUBLIC)).unwrap();
    assert_eq!(a.element, b.element);
    assert_ne!(a.proof, b.proof);
}

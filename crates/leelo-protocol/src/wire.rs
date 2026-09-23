//! This protocol uses exact message lengths. It rejects unsupported modes and versions.
use leelo_crypto::Evaluation;

pub const CONTENT_TYPE: &str = "application/vnd.leelo.network-bound-v1";
pub const REQUEST_BYTES: usize = 89;
pub const RESPONSE_BYTES: usize = 153;
const HEADER: [u8; 8] = [b'L', b'E', b'E', b'L', 1, 1, 1, 0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidMessage;

pub struct Request {
    pub key_id: [u8; 32],
    pub point: [u8; 49],
}

pub fn encode_request(key_id: &[u8; 32], point: &[u8; 49]) -> [u8; REQUEST_BYTES] {
    let mut message = [0; REQUEST_BYTES];
    message[..8].copy_from_slice(&HEADER);
    message[8..40].copy_from_slice(key_id);
    message[40..].copy_from_slice(point);
    message
}
pub fn decode_request(bytes: &[u8]) -> Result<Request, InvalidMessage> {
    if bytes.len() != REQUEST_BYTES || bytes[..8] != HEADER {
        return Err(InvalidMessage);
    }
    let mut key_id = [0; 32];
    let mut point = [0; 49];
    key_id.copy_from_slice(&bytes[8..40]);
    point.copy_from_slice(&bytes[40..]);
    Ok(Request { key_id, point })
}
pub fn encode_response(evaluation: &Evaluation) -> [u8; RESPONSE_BYTES] {
    let mut message = [0; RESPONSE_BYTES];
    message[..8].copy_from_slice(&HEADER);
    message[8..57].copy_from_slice(&evaluation.element);
    message[57..].copy_from_slice(&evaluation.proof);
    message
}
pub fn decode_response(bytes: &[u8]) -> Result<Evaluation, InvalidMessage> {
    if bytes.len() != RESPONSE_BYTES || bytes[..8] != HEADER {
        return Err(InvalidMessage);
    }
    let mut element = [0; 49];
    let mut proof = [0; 96];
    element.copy_from_slice(&bytes[8..57]);
    proof.copy_from_slice(&bytes[57..]);
    Ok(Evaluation { element, proof })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_length_and_all_header_fields_are_mandatory() {
        let request = encode_request(&[4; 32], &[2; 49]);
        let decoded = decode_request(&request).unwrap();
        assert_eq!(decoded.key_id, [4; 32]);
        assert_eq!(decoded.point, [2; 49]);
        for size in 0..REQUEST_BYTES {
            assert!(decode_request(&request[..size]).is_err());
        }
        let mut too_long = request.to_vec();
        too_long.push(0);
        assert!(decode_request(&too_long).is_err());
        for index in 0..8 {
            let mut changed = request;
            changed[index] ^= 1;
            assert!(decode_request(&changed).is_err());
        }
        let response = encode_response(&Evaluation {
            element: [2; 49],
            proof: [3; 96],
        });
        for size in 0..RESPONSE_BYTES {
            assert!(decode_response(&response[..size]).is_err());
        }
        let mut too_long = response.to_vec();
        too_long.push(0);
        assert!(decode_response(&too_long).is_err());
        for index in 0..8 {
            let mut changed = response;
            changed[index] ^= 1;
            assert!(decode_response(&changed).is_err());
        }
        assert_eq!(decode_response(&response).unwrap().proof, [3; 96]);
    }
}

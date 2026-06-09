use curve25519_dalek::scalar::Scalar;
use saksi_crypto::{
    elgamal::{encrypt, Ciphertext, Plaintext, PublicKey, SecretKey},
    group::point_from_compressed,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct KeypairDto {
    pub secret_scalar: u64,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CiphertextDto {
    pub pad: String,
    pub data: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProofHandleDto {
    pub label: String,
    pub digest: String,
}

pub fn keygen_from_scalar(secret_scalar: u64) -> KeypairDto {
    let secret_key = SecretKey::from_scalar(Scalar::from(secret_scalar));
    KeypairDto {
        secret_scalar,
        public_key: hex_lower(&secret_key.public_key().to_compressed_bytes()),
    }
}

pub fn encrypt_ballot(
    public_key: String,
    choice: u64,
    randomness: u64,
) -> Result<CiphertextDto, String> {
    let point =
        point_from_compressed(parse_32_byte_hex(&public_key)?).map_err(|err| err.to_string())?;
    let ciphertext = encrypt(
        &PublicKey::from_point(point),
        Plaintext::from_small_integer(choice),
        Scalar::from(randomness),
    );
    Ok(ciphertext_to_dto(&ciphertext))
}

pub fn generate_cds_proof(ciphertext: CiphertextDto, contest_id: String) -> ProofHandleDto {
    digest_handle(
        "tala.ffi.flutter.cds-proof.v1",
        &[ciphertext.pad, ciphertext.data, contest_id],
    )
}

pub fn perform_benaloh_challenge(
    ciphertext: CiphertextDto,
    challenge_nonce: String,
) -> ProofHandleDto {
    digest_handle(
        "tala.ffi.flutter.benaloh-challenge.v1",
        &[ciphertext.pad, ciphertext.data, challenge_nonce],
    )
}

pub fn derive_nullifier(credential_commitment: String, election_id: String) -> String {
    digest_handle(
        "tala.ffi.flutter.nullifier.v1",
        &[credential_commitment, election_id],
    )
    .digest
}

pub fn present_credential(credential_commitment: String, election_id: String) -> ProofHandleDto {
    digest_handle(
        "tala.ffi.flutter.credential-presentation.v1",
        &[credential_commitment, election_id],
    )
}

pub fn verify_tracking_code_receipt(
    expected_tracking_code: String,
    received_tracking_code: String,
) -> bool {
    expected_tracking_code == received_tracking_code
}

fn ciphertext_to_dto(ciphertext: &Ciphertext) -> CiphertextDto {
    let (pad, data) = ciphertext.to_compressed_bytes();
    CiphertextDto {
        pad: hex_lower(&pad),
        data: hex_lower(&data),
    }
}

fn digest_handle(label: &'static str, parts: &[String]) -> ProofHandleDto {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    ProofHandleDto {
        label: label.to_owned(),
        digest: hex_lower(&hasher.finalize()),
    }
}

fn parse_32_byte_hex(input: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex(input)?;
    bytes
        .try_into()
        .map_err(|_| "expected 32-byte hex string".to_owned())
}

fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("hex input must have even length".to_owned());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".to_owned()),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{encrypt_ballot, keygen_from_scalar, perform_benaloh_challenge, CiphertextDto};

    #[test]
    fn flutter_encrypt_ballot_round_trips_to_ciphertext_dto() {
        let keypair = keygen_from_scalar(42);
        let ciphertext = encrypt_ballot(keypair.public_key, 1, 99).expect("encrypts");

        assert_eq!(
            ciphertext.pad,
            "0e1d5b2771666dd340a8285c3d315e94f21c3b48be9c5d65352eb952541db019"
        );
        assert_eq!(
            ciphertext.data,
            "8af8a8933f35789af543aa4aeace1b033a03e87bb603bc77f8bb85e2b2bff92a"
        );
    }

    #[test]
    fn flutter_benaloh_challenge_returns_stable_handle() {
        let handle = perform_benaloh_challenge(
            CiphertextDto {
                pad: "pad".to_owned(),
                data: "data".to_owned(),
            },
            "nonce".to_owned(),
        );

        assert_eq!(handle.label, "tala.ffi.flutter.benaloh-challenge.v1");
        assert_eq!(handle.digest.len(), 64);
    }
}

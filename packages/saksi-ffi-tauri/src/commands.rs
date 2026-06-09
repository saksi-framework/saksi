use curve25519_dalek::scalar::Scalar;
use saksi_crypto::group::point_from_compressed;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CiphertextDto {
    pub pad: String,
    pub data: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialDecryptionDto {
    pub trustee_id: String,
    pub share: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct TranscriptPublicationDto {
    pub label: String,
    pub digest: String,
}

pub fn partial_decrypt(
    trustee_id: String,
    secret_share: u64,
    ciphertext: CiphertextDto,
) -> Result<PartialDecryptionDto, String> {
    let pad = point_from_compressed(parse_32_byte_hex(&ciphertext.pad)?)
        .map_err(|err| err.to_string())?;
    let share = Scalar::from(secret_share) * pad;
    Ok(PartialDecryptionDto {
        trustee_id,
        share: hex_lower(&share.compress().to_bytes()),
    })
}

pub fn publish_dkg_transcript(
    trustee_id: String,
    transcript_bytes: String,
) -> TranscriptPublicationDto {
    digest_handle(
        "tala.ffi.tauri.dkg-transcript.v1",
        &[trustee_id, transcript_bytes],
    )
}

pub fn publish_partial_decryption(partial: PartialDecryptionDto) -> TranscriptPublicationDto {
    digest_handle(
        "tala.ffi.tauri.partial-decryption.v1",
        &[partial.trustee_id, partial.share],
    )
}

fn digest_handle(label: &'static str, parts: &[String]) -> TranscriptPublicationDto {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    TranscriptPublicationDto {
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
    use super::{partial_decrypt, publish_dkg_transcript, CiphertextDto};

    #[test]
    fn tauri_partial_decrypt_returns_share() {
        let partial = partial_decrypt(
            "trustee-1".to_owned(),
            42,
            CiphertextDto {
                pad: "0e1d5b2771666dd340a8285c3d315e94f21c3b48be9c5d65352eb952541db019".to_owned(),
                data: "8af8a8933f35789af543aa4aeace1b033a03e87bb603bc77f8bb85e2b2bff92a".to_owned(),
            },
        )
        .expect("partial decrypts");

        assert_eq!(partial.trustee_id, "trustee-1");
        assert_eq!(partial.share.len(), 64);
    }

    #[test]
    fn tauri_transcript_publication_returns_digest() {
        let publication = publish_dkg_transcript("trustee-1".to_owned(), "transcript".to_owned());
        assert_eq!(publication.label, "tala.ffi.tauri.dkg-transcript.v1");
        assert_eq!(publication.digest.len(), 64);
    }
}

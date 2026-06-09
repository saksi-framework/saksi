use merlin::Transcript;

pub const TRANSCRIPT_LABEL_ELGAMAL_ENCRYPTION: &[u8] = b"tala.elgamal.encryption.v1";
pub const TRANSCRIPT_LABEL_CHAUM_PEDERSEN: &[u8] = b"tala.nizk.chaum-pedersen.v1";
pub const TRANSCRIPT_LABEL_CDS: &[u8] = b"tala.nizk.cds.v1";
pub const TRANSCRIPT_LABEL_SCHNORR: &[u8] = b"tala.nizk.schnorr.v1";
pub const TRANSCRIPT_LABEL_PEDERSEN_COMMITMENT: &[u8] = b"tala.commitment.pedersen.v1";
pub const TRANSCRIPT_LABEL_BENALOH_CHALLENGE: &[u8] = b"tala.benaloh.challenge.v1";
pub const TRANSCRIPT_LABEL_DKG: &[u8] = b"tala.dkg.pedersen.v1";

pub fn new_transcript(label: &'static [u8]) -> Transcript {
    Transcript::new(label)
}

pub trait TranscriptExt {
    fn append_domain_separator(&mut self, label: &'static [u8]);
}

impl TranscriptExt for Transcript {
    fn append_domain_separator(&mut self, label: &'static [u8]) {
        self.append_message(b"domain-separator", label);
    }
}

#[cfg(test)]
mod tests {
    use super::{new_transcript, TranscriptExt, TRANSCRIPT_LABEL_DKG};

    #[test]
    fn transcript_accepts_domain_separator() {
        let mut transcript = new_transcript(TRANSCRIPT_LABEL_DKG);
        transcript.append_domain_separator(b"round-1");
    }
}

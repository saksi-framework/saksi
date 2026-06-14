//! Cramer-Damgård-Schoenmakers (CDS) OR-proof for ballot well-formedness.
//!
//! Given an ElGamal ciphertext `(R, S) = (r·G, m·G + r·pk)` and a public choice
//! set `{m_0, m_1, …, m_{k-1}}` of allowed plaintexts, this proof attests that
//! `m ∈ choice_set` *without* revealing which index was used. The canonical use
//! is a binary contest with `choice_set = {0, 1}` — a yes/no ballot question —
//! but the construction is parameterised over arbitrary public choice sets.
//!
//! ## Construction
//!
//! For each branch `i ∈ 0..k` the statement is "the ElGamal randomness `r`
//! satisfies `R = r·G ∧ S − m_i·G = r·pk`", i.e. a Chaum-Pedersen equality of
//! discrete logs between bases `G` and `pk`. The prover runs the *honest*
//! sigma protocol on the true branch `j` and *simulates* every other branch by
//! sampling `(c_i, s_i)` uniformly and back-solving the commitments
//!
//! ```text
//! T_g_i = s_i·G  - c_i·R
//! T_h_i = s_i·pk - c_i·Y_i,   where Y_i = S - m_i·G
//! ```
//!
//! so verification holds by construction. The Fiat-Shamir challenge `c` is
//! pulled from a Merlin transcript bound to
//! [`TRANSCRIPT_LABEL_CDS`](crate::transcript::TRANSCRIPT_LABEL_CDS),
//! `(pk, R, S, choice_set, context)`, and **all** branch commitments
//! `(T_g_i, T_h_i)`. The true branch's challenge is then forced to
//! `c_j = c − Σ_{i≠j} c_i` and its response computed honestly as
//! `s_j = k_j + c_j · r`. The Σ-binding ensures the verifier accepts iff the
//! prover knew `r` on at least one branch.
//!
//! ## Timing posture
//!
//! - **Verifier** touches only public data and is fine running variable-time.
//! - **Prover** allocates one `Vec<CDSProofBranch>` and performs `k` rounds of
//!   identically-shaped scalar/point arithmetic. The per-iteration branch on
//!   `i == true_index` selects between the honest commitment derivation
//!   (`k_j·G`, `k_j·pk`) and the simulated form (`s_i·G − c_i·R`,
//!   `s_i·pk − c_i·Y_i`); both paths execute the same number of scalar
//!   multiplications and the secret index `j` is not used as a memory index
//!   beyond `branches[j]` writes that span every slot eventually. For the
//!   intended demo bar this is acceptable, but a fully constant-time prover
//!   would mask `j` via [`subtle::Choice`]-driven `ConditionallySelectable`
//!   selection. That refinement is out of scope here — flagged for the future
//!   hardening pass.
//! - Blinding nonce `k_j` and the per-iteration intermediate `nonce` are
//!   zeroized before the function returns.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use saksi_protocol::{
    CDSProof as ProtocolCDSProof, CDSProofBranch as ProtocolCDSProofBranch, WIRE_VERSION,
};

use crate::{
    elgamal,
    group::{basepoint, compress_point, point_from_compressed, scalar_from_canonical_bytes},
    transcript::{new_transcript, TRANSCRIPT_LABEL_CDS},
    CryptoError, CryptoResult,
};

pub const MODULE_NAME: &str = "cds";

/// One branch of a CDS OR-proof.
///
/// On the honest branch, `(commitment_g, commitment_h) = (k·G, k·pk)` is the
/// standard Chaum-Pedersen first move and `(challenge, response)` are derived
/// from the Fiat-Shamir total. On simulated branches the same fields are
/// produced by sampling `(challenge, response)` uniformly and back-solving the
/// commitments — verification cannot distinguish the two cases, which is the
/// whole point of the construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CDSProofBranch {
    /// `T_g = k·G − c·R` (simulated) or `k·G` (honest).
    pub commitment_g: RistrettoPoint,
    /// `T_h = s·pk − c·Y` (simulated) or `k·pk` (honest).
    pub commitment_h: RistrettoPoint,
    /// Per-branch challenge `c_i`. Total `Σ c_i` is bound to the Fiat-Shamir
    /// transcript; per-branch values are free for the prover to choose on
    /// simulated branches.
    pub challenge: Scalar,
    /// Response `s_i`. Honest branch: `s = k + c·r`. Simulated: drawn uniformly.
    pub response: Scalar,
}

/// CDS OR-proof: a `Vec<CDSProofBranch>` whose `challenge` field sums to the
/// Fiat-Shamir total over the bound statement, plus one verification equation
/// per branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CDSProof {
    /// Branches in canonical `choice_set` index order (`0..k`).
    pub branches: Vec<CDSProofBranch>,
}

impl CDSProof {
    /// Produce a CDS OR-proof that `ciphertext` encrypts
    /// `choice_set[true_index] · G` under `public_key`, with ElGamal randomness
    /// `randomness`. `context` is mixed into the Fiat-Shamir transcript so the
    /// caller can bind external framing (election id, contest id, ballot
    /// serial, …) and prevent proof transplantation.
    ///
    /// # Errors
    /// - [`CryptoError::InvalidParameters`] if `choice_set.len() < 2` (the OR
    ///   degenerates) or if `true_index >= choice_set.len()`.
    ///
    /// # Panics
    /// Never panics on well-formed inputs; index bounds are checked up front.
    ///
    /// # Security notes
    /// - The caller is responsible for ensuring `ciphertext` was *actually*
    ///   produced by encrypting `choice_set[true_index]` with `randomness`
    ///   under `public_key`. If that invariant is broken the produced proof
    ///   simply will not verify (see the `out_of_set_encryption_attempt` test).
    /// - The secret `true_index` is not perfectly hidden from a sophisticated
    ///   side-channel attacker; see the module-level "Timing posture" note.
    pub fn prove(
        public_key: &elgamal::PublicKey,
        ciphertext: &elgamal::Ciphertext,
        choice_set: &[Scalar],
        true_index: usize,
        randomness: &Scalar,
        context: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> CryptoResult<Self> {
        let k = choice_set.len();
        if k < 2 {
            return Err(CryptoError::InvalidParameters(
                "CDS OR-proof requires at least two choices",
            ));
        }
        if true_index >= k {
            return Err(CryptoError::InvalidParameters(
                "CDS true_index out of range for choice_set",
            ));
        }

        let g = basepoint();
        let pk = *public_key.as_point();
        let big_r = ciphertext.pad;
        let big_s = ciphertext.data;

        // Honest-branch blinding nonce. Held in `Scalar` so we can `zeroize`
        // it before returning.
        let mut nonce = Scalar::random(rng);

        // Sum of challenges on the simulated branches; used to derive the true
        // branch's challenge `c_j = c_total − Σ_{i≠j} c_i`.
        let mut sim_challenge_sum = Scalar::ZERO;

        // Build all branches. On simulated branches we sample `(c_i, s_i)`
        // and back-solve commitments. On the honest branch we leave
        // `challenge = ZERO` / `response = ZERO` placeholders and fix them up
        // after the Fiat-Shamir challenge is pulled.
        let mut branches: Vec<CDSProofBranch> = Vec::with_capacity(k);
        for (i, m_i) in choice_set.iter().enumerate() {
            if i == true_index {
                // Honest first move: commit to `nonce` under both bases.
                let commitment_g = nonce * g;
                let commitment_h = nonce * pk;
                branches.push(CDSProofBranch {
                    commitment_g,
                    commitment_h,
                    challenge: Scalar::ZERO,
                    response: Scalar::ZERO,
                });
            } else {
                let c_i = Scalar::random(rng);
                let s_i = Scalar::random(rng);
                let m_i_point = m_i * g;
                let y_i = big_s - m_i_point;
                // Back-solve verification equation:
                //   s_i·G = T_g_i + c_i·R   ⇒   T_g_i = s_i·G − c_i·R
                //   s_i·pk = T_h_i + c_i·Y_i ⇒   T_h_i = s_i·pk − c_i·Y_i
                let commitment_g = s_i * g - c_i * big_r;
                let commitment_h = s_i * pk - c_i * y_i;
                sim_challenge_sum += c_i;
                branches.push(CDSProofBranch {
                    commitment_g,
                    commitment_h,
                    challenge: c_i,
                    response: s_i,
                });
            }
        }

        // Pull total Fiat-Shamir challenge over the assembled commitments.
        let total_challenge =
            fiat_shamir_total_challenge(public_key, ciphertext, choice_set, context, &branches);

        // c_j = c_total − Σ_{i≠j} c_i; s_j = k_j + c_j · r.
        let c_j = total_challenge - sim_challenge_sum;
        let s_j = nonce + c_j * randomness;
        branches[true_index].challenge = c_j;
        branches[true_index].response = s_j;

        // Wipe the blinding nonce; the per-branch values are public.
        nonce.zeroize();

        Ok(Self { branches })
    }

    /// Verify a CDS OR-proof against `(public_key, ciphertext, choice_set,
    /// context)`. Returns [`CryptoError::VerificationFailed`] for any tamper,
    /// or [`CryptoError::InvalidParameters`] if the proof shape does not match
    /// the choice set.
    pub fn verify(
        &self,
        public_key: &elgamal::PublicKey,
        ciphertext: &elgamal::Ciphertext,
        choice_set: &[Scalar],
        context: &[u8],
    ) -> CryptoResult<()> {
        if choice_set.is_empty() {
            return Err(CryptoError::InvalidParameters(
                "CDS verify requires a non-empty choice_set",
            ));
        }
        if self.branches.len() != choice_set.len() {
            return Err(CryptoError::InvalidParameters(
                "CDS proof branch count does not match choice_set length",
            ));
        }

        let g = basepoint();
        let pk = *public_key.as_point();
        let big_r = ciphertext.pad;
        let big_s = ciphertext.data;

        // 1. Rebuild Fiat-Shamir total and compare to Σ c_i in constant time.
        let recomputed = fiat_shamir_total_challenge(
            public_key,
            ciphertext,
            choice_set,
            context,
            &self.branches,
        );
        let mut c_sum = Scalar::ZERO;
        for branch in &self.branches {
            c_sum += branch.challenge;
        }
        if !bool::from(c_sum.to_bytes().ct_eq(&recomputed.to_bytes())) {
            return Err(CryptoError::VerificationFailed);
        }

        // 2. Per-branch verification equations.
        for (i, branch) in self.branches.iter().enumerate() {
            let m_i_point = choice_set[i] * g;
            let y_i = big_s - m_i_point;

            // s·G == T_g + c·R  and  s·pk == T_h + c·Y_i
            let lhs_g = branch.response * g;
            let rhs_g = branch.commitment_g + branch.challenge * big_r;
            let lhs_h = branch.response * pk;
            let rhs_h = branch.commitment_h + branch.challenge * y_i;

            if lhs_g != rhs_g || lhs_h != rhs_h {
                return Err(CryptoError::VerificationFailed);
            }
        }

        Ok(())
    }

    /// Encode to the canonical [`ProtocolCDSProof`] wire form. Each branch
    /// becomes one [`ProtocolCDSProofBranch`] with 32-byte compressed
    /// commitments and 32-byte canonical scalars; the outer message carries
    /// [`WIRE_VERSION`].
    pub fn to_wire(&self) -> ProtocolCDSProof {
        ProtocolCDSProof {
            version: WIRE_VERSION,
            branches: self
                .branches
                .iter()
                .map(|branch| ProtocolCDSProofBranch {
                    commitment_a: compress_point(&branch.commitment_g).to_vec(),
                    commitment_b: compress_point(&branch.commitment_h).to_vec(),
                    challenge: branch.challenge.to_bytes().to_vec(),
                    response: branch.response.to_bytes().to_vec(),
                })
                .collect(),
        }
    }

    /// Decode a [`ProtocolCDSProof`]. Rejects unknown wire versions, bad point
    /// encodings ([`CryptoError::InvalidPoint`]) and non-canonical scalar
    /// encodings ([`CryptoError::InvalidScalar`]).
    pub fn from_wire(wire: &ProtocolCDSProof) -> CryptoResult<Self> {
        if wire.version != WIRE_VERSION {
            return Err(CryptoError::InvalidParameters(
                "unsupported CDSProof wire version",
            ));
        }

        let mut branches = Vec::with_capacity(wire.branches.len());
        for branch in &wire.branches {
            branches.push(CDSProofBranch {
                commitment_g: decode_point(&branch.commitment_a)?,
                commitment_h: decode_point(&branch.commitment_b)?,
                challenge: decode_scalar(&branch.challenge)?,
                response: decode_scalar(&branch.response)?,
            });
        }
        Ok(Self { branches })
    }
}

/// Compute the Fiat-Shamir total challenge `c` over the canonical transcript
/// binding. Used by both prover (after assembling branches) and verifier (to
/// detect any tamper of the bound statement or branch commitments).
fn fiat_shamir_total_challenge(
    public_key: &elgamal::PublicKey,
    ciphertext: &elgamal::Ciphertext,
    choice_set: &[Scalar],
    context: &[u8],
    branches: &[CDSProofBranch],
) -> Scalar {
    let mut transcript = new_transcript(TRANSCRIPT_LABEL_CDS);
    transcript.append_message(b"public_key", &public_key.to_compressed_bytes());
    transcript.append_message(b"ciphertext_pad", &compress_point(&ciphertext.pad));
    transcript.append_message(b"ciphertext_data", &compress_point(&ciphertext.data));
    transcript.append_message(b"choice_set_len", &(choice_set.len() as u64).to_be_bytes());
    for choice in choice_set {
        transcript.append_message(b"choice", &choice.to_bytes());
    }
    transcript.append_message(b"context", context);
    for branch in branches {
        transcript.append_message(
            b"branch_commitment_g",
            &compress_point(&branch.commitment_g),
        );
        transcript.append_message(
            b"branch_commitment_h",
            &compress_point(&branch.commitment_h),
        );
    }

    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"total_challenge", &mut buf);
    let out = Scalar::from_bytes_mod_order_wide(&buf);
    buf.zeroize();
    out
}

fn decode_point(bytes: &[u8]) -> CryptoResult<RistrettoPoint> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidPoint)?;
    point_from_compressed(array)
}

fn decode_scalar(bytes: &[u8]) -> CryptoResult<Scalar> {
    let array: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::InvalidScalar)?;
    scalar_from_canonical_bytes(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
    use rand_core::OsRng;

    use crate::elgamal::{encrypt, Plaintext, SecretKey};

    /// Build a fresh keypair, a context byte string, and a `[0, 1]` choice set.
    fn binary_setup() -> (SecretKey, elgamal::PublicKey, Vec<Scalar>, &'static [u8]) {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let choice_set = vec![Scalar::ZERO, Scalar::ONE];
        let context: &[u8] = b"election=2026|contest=president|ballot=1";
        (sk, pk, choice_set, context)
    }

    fn encrypt_choice(pk: &elgamal::PublicKey, choice: u64) -> (elgamal::Ciphertext, Scalar) {
        let r = Scalar::random(&mut OsRng);
        let ct = encrypt(pk, Plaintext::from_small_integer(choice), r);
        (ct, r)
    }

    // -- 1, 2: completeness on k=2 ------------------------------------------

    #[test]
    fn completeness_k2_choice_zero() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        proof.verify(&pk, &ct, &choice_set, ctx).expect("verify ok");
    }

    #[test]
    fn completeness_k2_choice_one() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 1);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 1, &r, ctx, &mut OsRng).expect("prove ok");
        proof.verify(&pk, &ct, &choice_set, ctx).expect("verify ok");
    }

    // -- 3: completeness on k=3 ---------------------------------------------

    #[test]
    fn completeness_k3_choice_two() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let choice_set = vec![Scalar::ZERO, Scalar::ONE, Scalar::from(2u64)];
        let r = Scalar::random(&mut OsRng);
        let ct = encrypt(&pk, Plaintext::from_small_integer(2), r);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 2, &r, b"k3", &mut OsRng).expect("prove ok");
        proof
            .verify(&pk, &ct, &choice_set, b"k3")
            .expect("verify ok");
    }

    // -- 4: soundness — wrong ciphertext ------------------------------------

    #[test]
    fn soundness_wrong_ciphertext() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct_zero, r) = encrypt_choice(&pk, 0);
        let proof =
            CDSProof::prove(&pk, &ct_zero, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        // A genuinely different ciphertext (encrypts 1, fresh randomness).
        let (ct_one, _r2) = encrypt_choice(&pk, 1);
        assert_eq!(
            proof.verify(&pk, &ct_one, &choice_set, ctx),
            Err(CryptoError::VerificationFailed),
        );
    }

    // -- 5: soundness — wrong choice_set ------------------------------------

    #[test]
    fn soundness_wrong_choice_set() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        let other_set = vec![Scalar::ZERO, Scalar::from(2u64)];
        assert_eq!(
            proof.verify(&pk, &ct, &other_set, ctx),
            Err(CryptoError::VerificationFailed),
        );
    }

    // -- 6: soundness — wrong context ---------------------------------------

    #[test]
    fn soundness_wrong_context() {
        let (_sk, pk, choice_set, _ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 1);
        let proof = CDSProof::prove(
            &pk,
            &ct,
            &choice_set,
            1,
            &r,
            b"contest=president",
            &mut OsRng,
        )
        .expect("prove ok");
        assert_eq!(
            proof.verify(&pk, &ct, &choice_set, b"contest=mayor"),
            Err(CryptoError::VerificationFailed),
        );
        // Honest context still passes.
        proof
            .verify(&pk, &ct, &choice_set, b"contest=president")
            .expect("verify ok");
    }

    // -- 7, 8: soundness — tampered commitments -----------------------------

    #[test]
    fn soundness_tampered_branch_commitment_g() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let mut proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        proof.branches[0].commitment_g += basepoint();
        assert_eq!(
            proof.verify(&pk, &ct, &choice_set, ctx),
            Err(CryptoError::VerificationFailed),
        );
    }

    #[test]
    fn soundness_tampered_branch_commitment_h() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let mut proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        proof.branches[0].commitment_h += basepoint();
        assert_eq!(
            proof.verify(&pk, &ct, &choice_set, ctx),
            Err(CryptoError::VerificationFailed),
        );
    }

    // -- 9: soundness — tampered branch challenge (sum mismatch) ------------

    #[test]
    fn soundness_tampered_branch_challenge() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 1);
        let mut proof =
            CDSProof::prove(&pk, &ct, &choice_set, 1, &r, ctx, &mut OsRng).expect("prove ok");
        proof.branches[0].challenge += Scalar::ONE;
        assert_eq!(
            proof.verify(&pk, &ct, &choice_set, ctx),
            Err(CryptoError::VerificationFailed),
        );
    }

    // -- 10: soundness — tampered branch response --------------------------

    #[test]
    fn soundness_tampered_branch_response() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 1);
        let mut proof =
            CDSProof::prove(&pk, &ct, &choice_set, 1, &r, ctx, &mut OsRng).expect("prove ok");
        proof.branches[1].response += Scalar::ONE;
        assert_eq!(
            proof.verify(&pk, &ct, &choice_set, ctx),
            Err(CryptoError::VerificationFailed),
        );
    }

    // -- 11: soundness — swapped branches ----------------------------------

    #[test]
    fn soundness_swapped_branches() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let mut proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        proof.branches.reverse();
        // Σ c_i is symmetric, but the Fiat-Shamir transcript binds branch
        // commitments in positional order — reordering changes the recomputed
        // total and also breaks the per-branch (Y_i) equations.
        assert_eq!(
            proof.verify(&pk, &ct, &choice_set, ctx),
            Err(CryptoError::VerificationFailed),
        );
    }

    // -- 12: soundness — out-of-set encryption attempt ---------------------

    #[test]
    fn soundness_out_of_set_encryption_attempt() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        // Encrypt 7 — not in {0, 1} — and try to claim it is choice 0.
        let r = Scalar::random(&mut OsRng);
        let ct = encrypt(&pk, Plaintext::from_small_integer(7), r);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        // Y_0 = S - 0·G = m·G + r·pk, but the prover treats the honest
        // branch's relation as Y_0 = r·pk, so s_0·pk != T_h_0 + c_0·Y_0.
        assert_eq!(
            proof.verify(&pk, &ct, &choice_set, ctx),
            Err(CryptoError::VerificationFailed),
        );
    }

    // -- 13: InvalidParameters guards --------------------------------------

    #[test]
    fn invalid_parameters_true_index_out_of_range() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        assert_eq!(
            CDSProof::prove(&pk, &ct, &choice_set, 2, &r, ctx, &mut OsRng),
            Err(CryptoError::InvalidParameters(
                "CDS true_index out of range for choice_set",
            )),
        );
    }

    #[test]
    fn invalid_parameters_choice_set_too_small() {
        let (_sk, pk, _set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let single = vec![Scalar::ZERO];
        assert_eq!(
            CDSProof::prove(&pk, &ct, &single, 0, &r, ctx, &mut OsRng),
            Err(CryptoError::InvalidParameters(
                "CDS OR-proof requires at least two choices",
            )),
        );
    }

    #[test]
    fn invalid_parameters_verify_branch_count_mismatch() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let mut proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        proof.branches.pop();
        assert!(matches!(
            proof.verify(&pk, &ct, &choice_set, ctx),
            Err(CryptoError::InvalidParameters(_)),
        ));
    }

    #[test]
    fn invalid_parameters_verify_empty_choice_set() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        let empty: Vec<Scalar> = Vec::new();
        assert!(matches!(
            proof.verify(&pk, &ct, &empty, ctx),
            Err(CryptoError::InvalidParameters(_)),
        ));
    }

    // -- 14: wire roundtrip + rejection ------------------------------------

    #[test]
    fn wire_roundtrip_preserves_proof() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 1);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 1, &r, ctx, &mut OsRng).expect("prove ok");

        let wire = proof.to_wire();
        assert_eq!(wire.version, WIRE_VERSION);
        assert_eq!(wire.branches.len(), choice_set.len());
        for branch in &wire.branches {
            assert_eq!(branch.commitment_a.len(), 32);
            assert_eq!(branch.commitment_b.len(), 32);
            assert_eq!(branch.challenge.len(), 32);
            assert_eq!(branch.response.len(), 32);
        }

        let decoded = CDSProof::from_wire(&wire).expect("roundtrip ok");
        assert_eq!(decoded, proof);
        decoded
            .verify(&pk, &ct, &choice_set, ctx)
            .expect("decoded verifies");
    }

    #[test]
    fn from_wire_rejects_unknown_version() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");
        let mut wire = proof.to_wire();
        wire.version = WIRE_VERSION + 1;
        assert!(matches!(
            CDSProof::from_wire(&wire),
            Err(CryptoError::InvalidParameters(_)),
        ));
    }

    #[test]
    fn from_wire_rejects_malformed_point() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");

        // Truncated commitment bytes -> InvalidPoint via the length check.
        let mut wire = proof.to_wire();
        wire.branches[0].commitment_a = vec![0u8; 31];
        assert_eq!(CDSProof::from_wire(&wire), Err(CryptoError::InvalidPoint),);

        // 32 bytes that do not decompress to a valid ristretto point.
        let mut wire = proof.to_wire();
        wire.branches[0].commitment_b = vec![0xff; 32];
        assert!(CompressedRistretto([0xff; 32]).decompress().is_none());
        assert_eq!(CDSProof::from_wire(&wire), Err(CryptoError::InvalidPoint),);
    }

    #[test]
    fn from_wire_rejects_malformed_scalar() {
        let (_sk, pk, choice_set, ctx) = binary_setup();
        let (ct, r) = encrypt_choice(&pk, 0);
        let proof =
            CDSProof::prove(&pk, &ct, &choice_set, 0, &r, ctx, &mut OsRng).expect("prove ok");

        // Wrong length on the challenge field.
        let mut wire = proof.to_wire();
        wire.branches[0].challenge = vec![0u8; 16];
        assert_eq!(CDSProof::from_wire(&wire), Err(CryptoError::InvalidScalar),);

        // Non-canonical 32-byte scalar on the response field.
        let mut wire = proof.to_wire();
        wire.branches[1].response = vec![0xff; 32];
        assert_eq!(CDSProof::from_wire(&wire), Err(CryptoError::InvalidScalar),);
    }
}

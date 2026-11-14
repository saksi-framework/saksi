//! Blind issuance across process boundaries.
//!
//! Thin wrappers over `saksi_credentials::issuance`: every step is the library
//! function, and the only thing added here is the hex form of each step's
//! input, output and in-between state, so the voter's steps can run in the
//! phone's WebAssembly and the issuer's in two separate CLI calls.
//!
//! Flow (who runs what):
//!
//! ```text
//! voter  voter_begin()                 -> blinded_commitment, state1
//! issuer issuer_presign(sk, C')        -> r, session (secret nonce, use once)
//! voter  voter_blind(state1, r, Pk)    -> e_prime, state2
//! issuer issuer_sign(sk, session, e')  -> s_iss
//! voter  voter_finalize(state2, s, Pk) -> credential
//! ```

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use saksi_credentials::{
    issuer_pre_sign, issuer_sign as lib_issuer_sign, voter_begin_issuance, voter_blind_challenge,
    voter_finalize_issuance, BlindRequest, BlindedChallenge, Credential, IssuerPreSignature,
    IssuerPublicKey, IssuerResponse, IssuerSecretKey, IssuerSession, VoterBlindState,
    VoterFinalizeState,
};

use crate::codec::{self, LiveResult};

/// The voter's secret state between `voter-begin` and `voter-blind`.
/// Its strings are wiped when it is dropped.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct BlindState {
    /// Credential secret `s_cred` (scalar hex). Secret.
    pub s_cred: String,
    /// Commitment blinding factor `b` (scalar hex). Secret.
    pub b: String,
}

/// The voter's secret state between `voter-blind` and `voter-finalize`.
/// Its strings are wiped when it is dropped.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct FinalizeState {
    /// Credential secret `s_cred` (scalar hex). Secret.
    pub s_cred: String,
    /// Re-randomised nonce `R'` (point hex).
    pub r_prime: String,
    /// Response blinding `α` (scalar hex). Secret.
    pub alpha: String,
    /// Challenge blinding `β` (scalar hex). Secret.
    pub beta: String,
}

/// A finished credential, as the phone stores it.
/// Its strings are wiped when it is dropped.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct CredentialParts {
    /// Credential secret `s_cred` (scalar hex). Secret: it votes.
    pub s_cred: String,
    /// Issuer signature nonce `R'` (point hex).
    pub signature_r: String,
    /// Issuer signature response `s_sig` (scalar hex).
    pub signature_s: String,
}

/// `voter-begin` output.
#[derive(Clone, Serialize, Deserialize)]
pub struct BeginResponse {
    /// `C' = C + b·G` (point hex), sent to the issuer.
    pub blinded_commitment: String,
    /// Kept by the voter for `voter-blind`.
    pub state: BlindState,
}

/// `voter-blind` input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlindRequestJson {
    /// From `voter-begin`.
    pub state: BlindState,
    /// The issuer's `R` from `issue-presign` (point hex).
    pub r: String,
    /// The election's issuer public key (point hex).
    pub issuer_public_key: String,
}

/// `voter-blind` output.
#[derive(Clone, Serialize, Deserialize)]
pub struct BlindResponse {
    /// `e' = e + β` (scalar hex), sent to the issuer.
    pub e_prime: String,
    /// Kept by the voter for `voter-finalize`.
    pub state: FinalizeState,
}

/// `voter-finalize` input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeRequest {
    /// From `voter-blind`.
    pub state: FinalizeState,
    /// The issuer's `s_iss` from `issue-sign` (scalar hex).
    pub s_iss: String,
    /// The election's issuer public key (point hex).
    pub issuer_public_key: String,
}

/// `voter-finalize` output.
#[derive(Clone, Serialize, Deserialize)]
pub struct FinalizeResponse {
    /// The credential. Secret.
    pub credential: CredentialParts,
    /// Public commitment `C = s_cred·G` (point hex).
    pub commitment: String,
}

/// Parses an issuer public key.
pub fn issuer_public_key(value: &str) -> LiveResult<IssuerPublicKey> {
    Ok(IssuerPublicKey(codec::nonzero_point(
        value,
        "issuer_public_key",
    )?))
}

/// A fresh issuer key: `(secret, public)`.
pub fn issuer_keygen(rng: &mut (impl RngCore + CryptoRng)) -> (Scalar, IssuerPublicKey) {
    let secret = Scalar::random(rng);
    let public = IssuerSecretKey::from_scalar(secret).public_key();
    (secret, public)
}

/// **Voter step 1** (`voter_begin_issuance`).
pub fn voter_begin(rng: &mut (impl RngCore + CryptoRng)) -> BeginResponse {
    let (request, state) = voter_begin_issuance(rng);
    let (s_cred, b) = state.to_parts();
    BeginResponse {
        blinded_commitment: codec::point_hex(&request.blinded_commitment),
        state: BlindState {
            s_cred: codec::scalar_hex(&s_cred),
            b: codec::scalar_hex(&b),
        },
    }
}

/// **Issuer step 1** (`issuer_pre_sign`): returns `(R, k)`. The nonce `k`
/// must be used by exactly one [`issuer_sign`] call and then destroyed.
pub fn issuer_presign(
    issuer_secret: &Scalar,
    blinded_commitment: &str,
    rng: &mut (impl RngCore + CryptoRng),
) -> LiveResult<(String, Scalar)> {
    let request = BlindRequest {
        blinded_commitment: codec::nonzero_point(blinded_commitment, "blinded_commitment")?,
    };
    let sk = IssuerSecretKey::from_scalar(*issuer_secret);
    let (pre, session) = issuer_pre_sign(&sk, &request, rng);
    Ok((codec::point_hex(&pre.r), session.to_scalar()))
}

/// **Voter step 2** (`voter_blind_challenge`).
pub fn voter_blind(
    req: &BlindRequestJson,
    rng: &mut (impl RngCore + CryptoRng),
) -> LiveResult<BlindResponse> {
    let state = VoterBlindState::from_parts(
        codec::scalar(&req.state.s_cred, "state.s_cred")?,
        codec::scalar(&req.state.b, "state.b")?,
    );
    let pre = IssuerPreSignature {
        r: codec::nonzero_point(&req.r, "r")?,
    };
    let pk = issuer_public_key(&req.issuer_public_key)?;
    let (blinded, next) = voter_blind_challenge(state, &pre, &pk, rng);
    let (s_cred, r_prime, alpha, beta) = next.to_parts();
    Ok(BlindResponse {
        e_prime: codec::scalar_hex(&blinded.e_prime),
        state: FinalizeState {
            s_cred: codec::scalar_hex(&s_cred),
            r_prime: codec::point_hex(&r_prime),
            alpha: codec::scalar_hex(&alpha),
            beta: codec::scalar_hex(&beta),
        },
    })
}

/// **Issuer step 2** (`issuer_sign`): `s_iss = k + e'·x`.
pub fn issuer_sign(issuer_secret: &Scalar, session_k: Scalar, e_prime: &str) -> LiveResult<String> {
    let blinded = BlindedChallenge {
        e_prime: codec::scalar(e_prime, "e_prime")?,
    };
    let sk = IssuerSecretKey::from_scalar(*issuer_secret);
    let response = lib_issuer_sign(&sk, IssuerSession::from_scalar(session_k), &blinded);
    Ok(codec::scalar_hex(&response.s_iss))
}

/// **Voter step 3** (`voter_finalize_issuance`), which refuses a response
/// that does not unblind into a valid issuer signature.
pub fn voter_finalize(req: &FinalizeRequest) -> LiveResult<FinalizeResponse> {
    let state = VoterFinalizeState::from_parts(
        codec::scalar(&req.state.s_cred, "state.s_cred")?,
        codec::point(&req.state.r_prime, "state.r_prime")?,
        codec::scalar(&req.state.alpha, "state.alpha")?,
        codec::scalar(&req.state.beta, "state.beta")?,
    );
    let response = IssuerResponse {
        s_iss: codec::scalar(&req.s_iss, "s_iss")?,
    };
    let pk = issuer_public_key(&req.issuer_public_key)?;
    let credential = voter_finalize_issuance(state, &response, &pk)
        .map_err(|_| "the issuer's response does not unblind into a valid signature".to_string())?;
    let (s_cred, signature_r, signature_s) = credential.to_parts();
    Ok(FinalizeResponse {
        credential: CredentialParts {
            s_cred: codec::scalar_hex(&s_cred),
            signature_r: codec::point_hex(&signature_r),
            signature_s: codec::scalar_hex(&signature_s),
        },
        commitment: codec::point_hex(&credential.public_commitment()),
    })
}

/// Rebuilds a stored credential and checks it is signed by `issuer`.
pub fn credential(parts: &CredentialParts, issuer: &IssuerPublicKey) -> LiveResult<Credential> {
    let credential = Credential::from_parts(
        codec::scalar(&parts.s_cred, "credential.s_cred")?,
        codec::point(&parts.signature_r, "credential.signature_r")?,
        codec::scalar(&parts.signature_s, "credential.signature_s")?,
    );
    credential
        .verify_against_issuer(issuer)
        .map_err(|_| "the credential is not signed by this election's issuer".to_string())?;
    Ok(credential)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    /// Runs the five steps through their hex forms only.
    pub(crate) fn issue(sk: &Scalar, pk: &IssuerPublicKey) -> CredentialParts {
        let mut rng = OsRng;
        let pk_hex = codec::point_hex(pk.as_point());
        let begin = voter_begin(&mut rng);
        let (r, k) = issuer_presign(sk, &begin.blinded_commitment, &mut rng).unwrap();
        let blind = voter_blind(
            &BlindRequestJson {
                state: begin.state,
                r,
                issuer_public_key: pk_hex.clone(),
            },
            &mut rng,
        )
        .unwrap();
        let s_iss = issuer_sign(sk, k, &blind.e_prime).unwrap();
        voter_finalize(&FinalizeRequest {
            state: blind.state,
            s_iss,
            issuer_public_key: pk_hex,
        })
        .unwrap()
        .credential
    }

    #[test]
    fn hex_round_trip_issuance_yields_a_signed_credential() {
        let (sk, pk) = issuer_keygen(&mut OsRng);
        let parts = issue(&sk, &pk);
        assert!(credential(&parts, &pk).is_ok());
        let (_, other) = issuer_keygen(&mut OsRng);
        assert!(credential(&parts, &other).is_err());
    }

    #[test]
    fn a_wrong_issuer_response_is_refused() {
        let mut rng = OsRng;
        let (sk, pk) = issuer_keygen(&mut rng);
        let pk_hex = codec::point_hex(pk.as_point());
        let begin = voter_begin(&mut rng);
        let (r, _k) = issuer_presign(&sk, &begin.blinded_commitment, &mut rng).unwrap();
        let blind = voter_blind(
            &BlindRequestJson {
                state: begin.state,
                r,
                issuer_public_key: pk_hex.clone(),
            },
            &mut rng,
        )
        .unwrap();
        let err = voter_finalize(&FinalizeRequest {
            state: blind.state,
            s_iss: codec::scalar_hex(&Scalar::from(1u64)),
            issuer_public_key: pk_hex,
        })
        .err()
        .unwrap();
        assert!(err.contains("valid signature"));
    }
}

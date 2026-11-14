//! The DKG run across separate trustee processes, with the console as a relay
//! that cannot read the shares.
//!
//! Every polynomial step is `saksi_crypto::dkg`: [`Dealer::random`],
//! [`Dealer::commitments`], [`Dealer::share_for`] and [`verify_share`]. The one
//! new construction is how a share `f_i(j)` travels from dealer `i` to trustee
//! `j` through the relay: a **hashed Diffie-Hellman mask with a tag**.
//!
//! Each trustee holds a receive key `(x, X = x·G)` used for nothing else.
//! Dealer `i` sending to recipient `j`:
//!
//! ```text
//! nonce      32 fresh random bytes
//! dh         compress(x_i · X_j)            (= compress(x_j · X_i))
//! okm        SHA-512( "saksi.live.dkg-share.v1"
//!                     || u64be(len election_id) || election_id
//!                     || u64be(i) || u64be(j)
//!                     || compress(X_i) || compress(X_j)
//!                     || nonce || dh )
//! pad, mk    okm[0..32], okm[32..64]
//! ciphertext share_bytes XOR pad            (32 bytes)
//! tag        SHA-512( "saksi.live.dkg-share-tag.v1" || mk || ciphertext )[0..32]
//! ```
//!
//! Only `i` and `j` can compute `dh`, so the relay learns nothing about the
//! share and cannot change one without failing the tag (encrypt-then-MAC; the
//! MAC'd message is a fixed 32 bytes, so the prefix MAC has no length-extension
//! surface). The derivation binds the election, both ids and both keys: a share
//! cannot be replayed into another election or redirected to another trustee.
//! The fresh nonce keeps two deals in the same election from reusing a pad.
//! After unmasking, the recipient still checks the share against the dealer's
//! public commitments with [`verify_share`], so a dealer who masks a wrong
//! value is caught and named.

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use saksi_crypto::{
    dkg::{verify_share, Dealer, DealerCommitments, DealerShare},
    group::{basepoint, compress_point},
};

use crate::codec::{self, LiveResult};

/// Key-derivation domain of the share mask.
pub const MASK_DOMAIN: &[u8] = b"saksi.live.dkg-share.v1";
/// Domain of the share tag.
pub const TAG_DOMAIN: &[u8] = b"saksi.live.dkg-share-tag.v1";
/// Domain of a verification key's fingerprint.
pub const FINGERPRINT_DOMAIN: &[u8] = b"saksi.live.share-fingerprint.v1";

/// A masked share as it travels through the relay.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MaskedShare {
    /// Dealer `i`.
    pub dealer_id: usize,
    /// Recipient `j`.
    pub recipient_id: usize,
    /// 32 random bytes (hex).
    pub nonce: String,
    /// `share XOR pad` (32 bytes hex).
    pub ciphertext: String,
    /// Tag (32 bytes hex).
    pub tag: String,
}

/// A trustee's receive public key, as the ceremony lists it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// Trustee id `1..=n`.
    pub trustee_id: usize,
    /// Receive public key `X` (point hex).
    pub receive_public_key: String,
}

/// `dkg-deal` input (without the dealer's receive secret, which the caller
/// reads from its key file).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DealRequest {
    /// Election id the shares are bound to.
    pub election_id: String,
    /// This dealer's trustee id.
    pub dealer_id: usize,
    /// Threshold `t`.
    pub threshold: usize,
    /// Trustee count `n`.
    pub trustees: usize,
    /// Every trustee's receive key, ids `1..=n`, **including this dealer's**.
    pub peers: Vec<Peer>,
}

/// `dkg-deal` output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DealResponse {
    /// Election id.
    pub election_id: String,
    /// This dealer's trustee id.
    pub dealer_id: usize,
    /// `A_{i,k} = a_{i,k}·G`, `k = 0..t` (point hex).
    pub commitments: Vec<String>,
    /// One masked share per trustee `1..=n`, including this dealer's own.
    pub masked_shares: Vec<MaskedShare>,
}

/// One dealer's public contribution, as a recipient receives it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DealerInput {
    /// Dealer id.
    pub dealer_id: usize,
    /// The dealer's receive public key (point hex).
    pub receive_public_key: String,
    /// The dealer's coefficient commitments (point hex).
    pub commitments: Vec<String>,
    /// The share the dealer masked for this recipient.
    pub masked_share: MaskedShare,
}

/// `dkg-receive` input (without the receive secret and the output path).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveRequest {
    /// Election id.
    pub election_id: String,
    /// This trustee's id.
    pub trustee_id: usize,
    /// Threshold `t`.
    pub threshold: usize,
    /// Trustee count `n`.
    pub trustees: usize,
    /// One entry per dealer `1..=n`, including this trustee's own deal.
    pub dealers: Vec<DealerInput>,
}

/// What `dkg-receive` computes.
pub struct Received {
    /// This trustee's key share `s_j = Σ_i f_i(j)`. Secret.
    pub share: Scalar,
    /// `s_j·G`.
    pub verification_key: RistrettoPoint,
    /// `Y = Σ_i A_{i,0}`.
    pub joint_public_key: RistrettoPoint,
}

impl Drop for Received {
    fn drop(&mut self) {
        self.share.zeroize();
    }
}

/// A fresh receive key pair `(x, x·G)`.
pub fn receive_keygen(rng: &mut (impl RngCore + CryptoRng)) -> (Scalar, RistrettoPoint) {
    let x = Scalar::random(rng);
    (x, x * basepoint())
}

/// The short fingerprint of a verification key that trustee pages show:
/// `SHA-256(FINGERPRINT_DOMAIN || compress(vk))[0..8]`, upper-case hex in four
/// groups, e.g. `1A2B-3C4D-5E6F-7081`.
pub fn fingerprint(vk: &RistrettoPoint) -> String {
    let mut h = Sha256::new();
    h.update(FINGERPRINT_DOMAIN);
    h.update(compress_point(vk));
    let d = hex::encode_upper(&h.finalize()[..8]);
    format!("{}-{}-{}-{}", &d[0..4], &d[4..8], &d[8..12], &d[12..16])
}

#[allow(clippy::too_many_arguments)]
fn derive(
    election_id: &str,
    dealer_id: usize,
    recipient_id: usize,
    dealer_pk: &RistrettoPoint,
    recipient_pk: &RistrettoPoint,
    nonce: &[u8; 32],
    dh: &RistrettoPoint,
) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha512::new();
    h.update(MASK_DOMAIN);
    h.update((election_id.len() as u64).to_be_bytes());
    h.update(election_id.as_bytes());
    h.update((dealer_id as u64).to_be_bytes());
    h.update((recipient_id as u64).to_be_bytes());
    h.update(compress_point(dealer_pk));
    h.update(compress_point(recipient_pk));
    h.update(nonce);
    h.update(compress_point(dh));
    let mut okm: [u8; 64] = h.finalize().into();
    let mut pad = [0u8; 32];
    let mut mk = [0u8; 32];
    pad.copy_from_slice(&okm[..32]);
    mk.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (pad, mk)
}

fn tag(mk: &[u8; 32], ciphertext: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(TAG_DOMAIN);
    h.update(mk);
    h.update(ciphertext);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize()[..32]);
    out
}

/// Masks `share` from dealer `i` (receive secret `dealer_secret`) to recipient
/// `j` (receive key `recipient_pk`).
#[allow(clippy::too_many_arguments)]
pub fn mask_share(
    election_id: &str,
    dealer_id: usize,
    recipient_id: usize,
    dealer_secret: &Scalar,
    recipient_pk: &RistrettoPoint,
    share: &Scalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> MaskedShare {
    let dealer_pk = dealer_secret * basepoint();
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let dh = dealer_secret * recipient_pk;
    let (mut pad, mut mk) = derive(
        election_id,
        dealer_id,
        recipient_id,
        &dealer_pk,
        recipient_pk,
        &nonce,
        &dh,
    );
    let mut ct = share.to_bytes();
    for (c, p) in ct.iter_mut().zip(pad.iter()) {
        *c ^= p;
    }
    let t = tag(&mk, &ct);
    pad.zeroize();
    mk.zeroize();
    MaskedShare {
        dealer_id,
        recipient_id,
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ct),
        tag: hex::encode(t),
    }
}

/// Unmasks a share addressed to `recipient_id`. Fails on a wrong tag (a
/// tampered share, a wrong key, or a share meant for someone else) and on a
/// non-canonical result.
pub fn unmask_share(
    election_id: &str,
    recipient_id: usize,
    recipient_secret: &Scalar,
    dealer_pk: &RistrettoPoint,
    masked: &MaskedShare,
) -> LiveResult<Scalar> {
    if masked.recipient_id != recipient_id {
        return Err(format!(
            "dealer {}: the share is addressed to trustee {}, not {recipient_id}",
            masked.dealer_id, masked.recipient_id
        ));
    }
    let nonce = codec::bytes32(&masked.nonce, "masked_share.nonce")?;
    let ct = codec::bytes32(&masked.ciphertext, "masked_share.ciphertext")?;
    let got = codec::bytes32(&masked.tag, "masked_share.tag")?;
    let recipient_pk = recipient_secret * basepoint();
    let dh = recipient_secret * dealer_pk;
    let (mut pad, mut mk) = derive(
        election_id,
        masked.dealer_id,
        recipient_id,
        dealer_pk,
        &recipient_pk,
        &nonce,
        &dh,
    );
    let want = tag(&mk, &ct);
    mk.zeroize();
    if !bool::from(want.ct_eq(&got)) {
        pad.zeroize();
        return Err(format!(
            "dealer {}: masked share failed authentication (tampered, or not masked for this trustee's key)",
            masked.dealer_id
        ));
    }
    let mut plain = ct;
    for (c, p) in plain.iter_mut().zip(pad.iter()) {
        *c ^= p;
    }
    pad.zeroize();
    let share = saksi_crypto::group::scalar_from_canonical_bytes(plain).map_err(|_| {
        format!(
            "dealer {}: unmasked share is not a canonical scalar",
            masked.dealer_id
        )
    });
    plain.zeroize();
    share
}

fn check_ids(ids: impl Iterator<Item = usize>, n: usize, what: &str) -> LiveResult<()> {
    let mut ids: Vec<usize> = ids.collect();
    ids.sort_unstable();
    if ids != (1..=n).collect::<Vec<_>>() {
        return Err(format!(
            "{what} must name every trustee 1..={n} exactly once"
        ));
    }
    Ok(())
}

fn check_config(threshold: usize, trustees: usize, own: usize) -> LiveResult<()> {
    saksi_crypto::dkg::DkgConfig::new(threshold, trustees)
        .map_err(|e| format!("bad threshold/trustees: {e}"))?;
    if own == 0 || own > trustees {
        return Err(format!("trustee id {own} is outside 1..={trustees}"));
    }
    Ok(())
}

/// Deals this trustee's polynomial: fresh `Dealer::random`, its commitments,
/// and every trustee's share masked to that trustee's receive key. The
/// coefficients are wiped before returning; only the commitments and the
/// masked shares leave.
pub fn deal(
    req: &DealRequest,
    dealer_secret: &Scalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> LiveResult<DealResponse> {
    check_config(req.threshold, req.trustees, req.dealer_id)?;
    check_ids(
        req.peers.iter().map(|p| p.trustee_id),
        req.trustees,
        "peers",
    )?;
    let mut peers = Vec::with_capacity(req.peers.len());
    for peer in &req.peers {
        let pk = codec::nonzero_point(
            &peer.receive_public_key,
            &format!("peer {} receive_public_key", peer.trustee_id),
        )?;
        if peer.trustee_id == req.dealer_id && pk != dealer_secret * basepoint() {
            return Err("this dealer's own receive_public_key does not match its key file".into());
        }
        peers.push((peer.trustee_id, pk));
    }
    peers.sort_by_key(|(id, _)| *id);

    let mut dealer = Dealer::random(req.dealer_id, req.threshold, rng);
    let commitments = dealer
        .commitments()
        .coefficient_commitments
        .iter()
        .map(codec::point_hex)
        .collect();
    let mut masked_shares = Vec::with_capacity(peers.len());
    for (recipient_id, pk) in &peers {
        let mut share = dealer.share_for(*recipient_id);
        masked_shares.push(mask_share(
            &req.election_id,
            req.dealer_id,
            *recipient_id,
            dealer_secret,
            pk,
            &share.value,
            rng,
        ));
        share.value.zeroize();
    }
    dealer.coefficients.iter_mut().for_each(Zeroize::zeroize);
    Ok(DealResponse {
        election_id: req.election_id.clone(),
        dealer_id: req.dealer_id,
        commitments,
        masked_shares,
    })
}

/// Unmasks and checks every dealer's share for this trustee, then sums them.
/// Refuses, naming the dealer, on a missing dealer, a commitment of the wrong
/// size, a share that fails its tag, or a share that fails [`verify_share`].
pub fn receive(req: &ReceiveRequest, receive_secret: &Scalar) -> LiveResult<Received> {
    check_config(req.threshold, req.trustees, req.trustee_id)?;
    check_ids(
        req.dealers.iter().map(|d| d.dealer_id),
        req.trustees,
        "dealers",
    )?;
    let own_pk = receive_secret * basepoint();
    let mut share_sum = Scalar::ZERO;
    let mut joint = RistrettoPoint::identity();
    for d in &req.dealers {
        let name = |what: &str| format!("dealer {} {what}", d.dealer_id);
        if d.masked_share.dealer_id != d.dealer_id {
            return Err(format!(
                "dealer {}: the masked share claims dealer {}",
                d.dealer_id, d.masked_share.dealer_id
            ));
        }
        let dealer_pk = codec::nonzero_point(&d.receive_public_key, &name("receive_public_key"))?;
        if d.dealer_id == req.trustee_id && dealer_pk != own_pk {
            return Err("this trustee's own receive_public_key does not match its key file".into());
        }
        if d.commitments.len() != req.threshold {
            return Err(format!(
                "dealer {}: {} commitments, want threshold {}",
                d.dealer_id,
                d.commitments.len(),
                req.threshold
            ));
        }
        let points = d
            .commitments
            .iter()
            .map(|c| codec::point(c, &name("commitment")))
            .collect::<LiveResult<Vec<_>>>()?;
        let mut value = unmask_share(
            &req.election_id,
            req.trustee_id,
            receive_secret,
            &dealer_pk,
            &d.masked_share,
        )?;
        let share = DealerShare {
            dealer_id: d.dealer_id,
            recipient_id: req.trustee_id,
            value,
        };
        let commitments = DealerCommitments {
            trustee_id: d.dealer_id,
            coefficient_commitments: points,
        };
        if !verify_share(&share, &commitments) {
            value.zeroize();
            share_sum.zeroize();
            return Err(format!(
                "dealer {}: share does not verify against the dealer's commitments",
                d.dealer_id
            ));
        }
        share_sum += value;
        value.zeroize();
        joint += commitments.coefficient_commitments[0];
    }
    Ok(Received {
        verification_key: share_sum * basepoint(),
        share: share_sum,
        joint_public_key: joint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    struct Party {
        secret: Scalar,
        public: RistrettoPoint,
    }

    fn parties(n: usize) -> Vec<Party> {
        (0..n)
            .map(|_| {
                let (secret, public) = receive_keygen(&mut OsRng);
                Party { secret, public }
            })
            .collect()
    }

    fn peers(ps: &[Party]) -> Vec<Peer> {
        ps.iter()
            .enumerate()
            .map(|(i, p)| Peer {
                trustee_id: i + 1,
                receive_public_key: codec::point_hex(&p.public),
            })
            .collect()
    }

    fn deals(ps: &[Party], t: usize) -> Vec<DealResponse> {
        (1..=ps.len())
            .map(|i| {
                deal(
                    &DealRequest {
                        election_id: "e".into(),
                        dealer_id: i,
                        threshold: t,
                        trustees: ps.len(),
                        peers: peers(ps),
                    },
                    &ps[i - 1].secret,
                    &mut OsRng,
                )
                .unwrap()
            })
            .collect()
    }

    fn request_for(ps: &[Party], deals: &[DealResponse], j: usize, t: usize) -> ReceiveRequest {
        ReceiveRequest {
            election_id: "e".into(),
            trustee_id: j,
            threshold: t,
            trustees: ps.len(),
            dealers: deals
                .iter()
                .map(|d| DealerInput {
                    dealer_id: d.dealer_id,
                    receive_public_key: codec::point_hex(&ps[d.dealer_id - 1].public),
                    commitments: d.commitments.clone(),
                    masked_share: d.masked_shares[j - 1].clone(),
                })
                .collect(),
        }
    }

    #[test]
    fn mask_round_trips_only_for_the_addressed_recipient() {
        let ps = parties(3);
        let s = Scalar::from(42u64);
        let m = mask_share("e", 1, 2, &ps[0].secret, &ps[1].public, &s, &mut OsRng);
        assert_eq!(
            unmask_share("e", 2, &ps[1].secret, &ps[0].public, &m).unwrap(),
            s
        );
        // Trustee 3's key cannot open a share masked for trustee 2, whether it
        // claims its own id or trustee 2's.
        assert!(unmask_share("e", 3, &ps[2].secret, &ps[0].public, &m).is_err());
        assert!(unmask_share("e", 2, &ps[2].secret, &ps[0].public, &m)
            .unwrap_err()
            .contains("authentication"));
        // Bound to the election id.
        assert!(unmask_share("other", 2, &ps[1].secret, &ps[0].public, &m).is_err());
        // Bound to the dealer id.
        let mut moved = m.clone();
        moved.dealer_id = 3;
        assert!(unmask_share("e", 2, &ps[1].secret, &ps[0].public, &moved).is_err());
    }

    #[test]
    fn five_trustees_agree_on_the_joint_key_and_verification_keys() {
        let ps = parties(5);
        let ds = deals(&ps, 3);
        let got: Vec<Received> = (1..=5)
            .map(|j| receive(&request_for(&ps, &ds, j, 3), &ps[j - 1].secret).unwrap())
            .collect();
        for r in &got {
            assert_eq!(r.joint_public_key, got[0].joint_public_key);
            assert_eq!(r.verification_key, r.share * basepoint());
        }
    }

    #[test]
    fn a_tampered_or_dishonest_share_names_the_dealer() {
        let ps = parties(5);
        let mut ds = deals(&ps, 3);
        // Relay flips one ciphertext bit of dealer 4's share to trustee 1.
        let ct = &mut ds[3].masked_shares[0].ciphertext;
        let mut raw = hex::decode(&*ct).unwrap();
        raw[0] ^= 1;
        *ct = hex::encode(raw);
        let err = receive(&request_for(&ps, &ds, 1, 3), &ps[0].secret)
            .err()
            .unwrap();
        assert!(err.starts_with("dealer 4:"), "{err}");

        // Dealer 2 masks a value that is not its polynomial's: the tag passes,
        // the commitment check names it.
        let mut ds = deals(&ps, 3);
        ds[1].masked_shares[0] = mask_share(
            "e",
            2,
            1,
            &ps[1].secret,
            &ps[0].public,
            &Scalar::from(9u64),
            &mut OsRng,
        );
        let err = receive(&request_for(&ps, &ds, 1, 3), &ps[0].secret)
            .err()
            .unwrap();
        assert!(
            err.starts_with("dealer 2:") && err.contains("commitments"),
            "{err}"
        );
    }
}

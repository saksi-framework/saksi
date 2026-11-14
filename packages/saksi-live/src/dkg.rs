//! The DKG run across separate trustee processes, with the console as a relay.
//!
//! Every polynomial step is `saksi_crypto::dkg`: [`Dealer::random`],
//! [`Dealer::commitments`], [`Dealer::share_for`] and [`verify_share`]. The one
//! new construction is how a share `f_i(j)` travels from dealer `i` to trustee
//! `j` through the relay: a **hashed Diffie-Hellman mask with a tag**, bound to
//! a digest of the whole receive-key roster.
//!
//! Each trustee holds a receive key `(x, X = x·G)` used for nothing else. The
//! **roster** is the ordered list `(1, X_1) .. (n, X_n)`; its digest is
//!
//! ```text
//! roster_digest = SHA-256( "saksi.live.dkg-roster.v1"
//!                          || u64be(len election_id) || election_id
//!                          || u64be(n) || u64be(t)
//!                          || u64be(1) || compress(X_1) || ... || u64be(n) || compress(X_n) )
//! ```
//!
//! Dealer `i` sending to recipient `j`:
//!
//! ```text
//! nonce      32 fresh random bytes
//! dh         compress(x_i · X_j)            (= compress(x_j · X_i))
//! okm        SHA-512( "saksi.live.dkg-share.v2"
//!                     || roster_digest
//!                     || u64be(len election_id) || election_id
//!                     || u64be(i) || u64be(j)
//!                     || compress(X_i) || compress(X_j)
//!                     || nonce || dh )
//! pad, mk    okm[0..32], okm[32..64]
//! ciphertext share_bytes XOR pad            (32 bytes)
//! tag        SHA-512( "saksi.live.dkg-share-tag.v1" || mk || ciphertext )[0..32]
//! ```
//!
//! **What this protects, and on what condition.** Every key comes through the
//! relay, so the relay can hand a dealer its own key in place of `X_j` and read
//! the share. The relay cannot read or forge a share **provided every trustee
//! confirms the same roster digest** (each trustee page shows its fingerprint,
//! and the trustee processes compare it). A dealer masks under the roster it
//! was given and a recipient unmasks under the roster it was given; the digest
//! is in the key derivation, so a share masked under a substituted roster
//! fails the recipient's tag and is refused naming the dealer, and two
//! trustees shown different rosters show different fingerprints. Without that
//! comparison the relay can substitute keys.
//!
//! Given an authentic roster: only `i` and `j` can compute `dh`; the tag
//! (encrypt-then-MAC over a fixed 32 bytes, checked in constant time) stops the
//! relay changing a share; the derivation binds the election, both ids and
//! both keys; the fresh nonce keeps two deals in the same election from
//! reusing a pad. After unmasking, the recipient still checks the share against
//! the dealer's commitments with [`verify_share`], so a dealer who masks a
//! wrong value is caught and named.

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

/// Key-derivation domain of the share mask (v2: binds the roster digest).
pub const MASK_DOMAIN: &[u8] = b"saksi.live.dkg-share.v2";
/// Domain of the share tag.
pub const TAG_DOMAIN: &[u8] = b"saksi.live.dkg-share-tag.v1";
/// Domain of the receive-key roster digest.
pub const ROSTER_DOMAIN: &[u8] = b"saksi.live.dkg-roster.v1";
/// Domain of a verification key's fingerprint.
pub const FINGERPRINT_DOMAIN: &[u8] = b"saksi.live.share-fingerprint.v1";
/// Domain of a receive key's fingerprint.
pub const RECEIVE_KEY_FINGERPRINT_DOMAIN: &[u8] = b"saksi.live.receive-key-fingerprint.v1";

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

/// The checked receive-key roster of one election and its digest.
#[derive(Clone, Debug)]
pub struct Roster {
    election_id: String,
    keys: Vec<RistrettoPoint>,
    digest: [u8; 32],
}

impl Roster {
    /// Checks `peers` (exactly ids `1..=trustees`, each a canonical,
    /// non-identity point, no key twice) and computes the digest.
    pub fn new(
        election_id: &str,
        threshold: usize,
        trustees: usize,
        peers: &[Peer],
    ) -> LiveResult<Self> {
        saksi_crypto::dkg::DkgConfig::new(threshold, trustees)
            .map_err(|e| format!("bad threshold/trustees: {e}"))?;
        check_ids(peers.iter().map(|p| p.trustee_id), trustees, "peers")?;
        let mut sorted: Vec<&Peer> = peers.iter().collect();
        sorted.sort_by_key(|p| p.trustee_id);
        let mut keys = Vec::with_capacity(trustees);
        for p in sorted {
            let key = codec::nonzero_point(
                &p.receive_public_key,
                &format!("peer {} receive_public_key", p.trustee_id),
            )?;
            if keys.contains(&key) {
                return Err(format!(
                    "peer {} receive_public_key repeats another trustee's key",
                    p.trustee_id
                ));
            }
            keys.push(key);
        }
        let mut h = Sha256::new();
        h.update(ROSTER_DOMAIN);
        h.update((election_id.len() as u64).to_be_bytes());
        h.update(election_id.as_bytes());
        h.update((trustees as u64).to_be_bytes());
        h.update((threshold as u64).to_be_bytes());
        for (k, key) in keys.iter().enumerate() {
            h.update(((k + 1) as u64).to_be_bytes());
            h.update(compress_point(key));
        }
        Ok(Self {
            election_id: election_id.to_string(),
            keys,
            digest: h.finalize().into(),
        })
    }

    /// Trustee count `n`.
    pub fn trustees(&self) -> usize {
        self.keys.len()
    }

    /// The receive key of trustee `id` (`1..=n`).
    pub fn key(&self, id: usize) -> LiveResult<&RistrettoPoint> {
        id.checked_sub(1)
            .and_then(|k| self.keys.get(k))
            .ok_or_else(|| format!("trustee id {id} is outside 1..={}", self.keys.len()))
    }

    /// Hex of the roster digest.
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest)
    }

    /// The digest's short form for trustee pages: its first 16 bytes (128
    /// bits) as eight groups of four upper-case hex digits.
    pub fn fingerprint(&self) -> String {
        crate::election::short_fingerprint(&self.digest)
    }

    /// Refuses unless `secret` is the key at `id`.
    fn check_own(&self, id: usize, secret: &Scalar, who: &str) -> LiveResult<()> {
        if *self.key(id)? != secret * basepoint() {
            return Err(format!(
                "the roster's key at id {id} is not this {who}'s key file"
            ));
        }
        Ok(())
    }
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
    /// The full roster, ids `1..=n`, **including this dealer's**.
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
    /// Digest of the roster the shares were masked under (hex).
    pub roster_digest: String,
    /// Its short form.
    pub roster_fingerprint: String,
}

/// One dealer's public contribution, as a recipient receives it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DealerInput {
    /// Dealer id.
    pub dealer_id: usize,
    /// The dealer's receive public key (point hex); must equal the roster's.
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
    /// The full roster, ids `1..=n`, including this trustee's.
    pub peers: Vec<Peer>,
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
    /// The roster every share was unmasked under.
    pub roster: Roster,
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

fn fingerprint_with(domain: &[u8], point: &RistrettoPoint) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(compress_point(point));
    crate::election::short_fingerprint(&h.finalize())
}

/// The short fingerprint of a verification key that trustee pages show:
/// `SHA-256(FINGERPRINT_DOMAIN || compress(vk))[0..16]`, upper-case hex in
/// eight groups of four, e.g. `1A2B-3C4D-5E6F-7081-90A1-B2C3-D4E5-F607`.
pub fn fingerprint(vk: &RistrettoPoint) -> String {
    fingerprint_with(FINGERPRINT_DOMAIN, vk)
}

/// The short fingerprint of a receive key, the same form under
/// [`RECEIVE_KEY_FINGERPRINT_DOMAIN`].
pub fn receive_key_fingerprint(key: &RistrettoPoint) -> String {
    fingerprint_with(RECEIVE_KEY_FINGERPRINT_DOMAIN, key)
}

fn derive(
    roster: &Roster,
    dealer_id: usize,
    recipient_id: usize,
    nonce: &[u8; 32],
    dh: &RistrettoPoint,
) -> LiveResult<([u8; 32], [u8; 32])> {
    let mut h = Sha512::new();
    h.update(MASK_DOMAIN);
    h.update(roster.digest);
    h.update((roster.election_id.len() as u64).to_be_bytes());
    h.update(roster.election_id.as_bytes());
    h.update((dealer_id as u64).to_be_bytes());
    h.update((recipient_id as u64).to_be_bytes());
    h.update(compress_point(roster.key(dealer_id)?));
    h.update(compress_point(roster.key(recipient_id)?));
    h.update(nonce);
    h.update(compress_point(dh));
    let mut okm: [u8; 64] = h.finalize().into();
    let mut pad = [0u8; 32];
    let mut mk = [0u8; 32];
    pad.copy_from_slice(&okm[..32]);
    mk.copy_from_slice(&okm[32..]);
    okm.zeroize();
    Ok((pad, mk))
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

/// Masks `share` from dealer `dealer_id` (receive secret `dealer_secret`, which
/// must be the roster's key at `dealer_id`) to `recipient_id` under `roster`.
pub fn mask_share(
    roster: &Roster,
    dealer_id: usize,
    recipient_id: usize,
    dealer_secret: &Scalar,
    share: &Scalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> LiveResult<MaskedShare> {
    roster.check_own(dealer_id, dealer_secret, "dealer")?;
    let mut nonce = [0u8; 32];
    rng.fill_bytes(&mut nonce);
    let dh = dealer_secret * roster.key(recipient_id)?;
    let (mut pad, mut mk) = derive(roster, dealer_id, recipient_id, &nonce, &dh)?;
    let mut ct = share.to_bytes();
    for (c, p) in ct.iter_mut().zip(pad.iter()) {
        *c ^= p;
    }
    let t = tag(&mk, &ct);
    pad.zeroize();
    mk.zeroize();
    Ok(MaskedShare {
        dealer_id,
        recipient_id,
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ct),
        tag: hex::encode(t),
    })
}

/// Unmasks a share addressed to `recipient_id` under `roster`. Fails on a
/// wrong tag (a tampered share, a wrong key, a share meant for someone else,
/// or one masked under another roster) and on a non-canonical result.
pub fn unmask_share(
    roster: &Roster,
    recipient_id: usize,
    recipient_secret: &Scalar,
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
    let dh = recipient_secret * roster.key(masked.dealer_id)?;
    let (mut pad, mut mk) = derive(roster, masked.dealer_id, recipient_id, &nonce, &dh)?;
    let want = tag(&mk, &ct);
    mk.zeroize();
    if !bool::from(want.ct_eq(&got)) {
        pad.zeroize();
        return Err(format!(
            "dealer {}: masked share failed authentication (tampered, masked under another roster, or not for this trustee's key)",
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

/// Deals this trustee's polynomial: fresh `Dealer::random`, its commitments,
/// and every trustee's share masked under the roster. The coefficients are
/// wiped before returning; only the commitments and the masked shares leave.
pub fn deal(
    req: &DealRequest,
    dealer_secret: &Scalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> LiveResult<DealResponse> {
    let roster = Roster::new(&req.election_id, req.threshold, req.trustees, &req.peers)?;
    roster.key(req.dealer_id)?;
    roster.check_own(req.dealer_id, dealer_secret, "dealer")?;

    let mut dealer = Dealer::random(req.dealer_id, req.threshold, rng);
    let commitments = dealer
        .commitments()
        .coefficient_commitments
        .iter()
        .map(codec::point_hex)
        .collect();
    let mut masked_shares = Vec::with_capacity(roster.trustees());
    let mut result = Ok(());
    for recipient_id in 1..=roster.trustees() {
        let mut share = dealer.share_for(recipient_id);
        match mask_share(
            &roster,
            req.dealer_id,
            recipient_id,
            dealer_secret,
            &share.value,
            rng,
        ) {
            Ok(m) => masked_shares.push(m),
            Err(e) => result = Err(e),
        }
        share.value.zeroize();
    }
    dealer.coefficients.iter_mut().for_each(Zeroize::zeroize);
    result?;
    Ok(DealResponse {
        election_id: req.election_id.clone(),
        dealer_id: req.dealer_id,
        commitments,
        masked_shares,
        roster_digest: roster.digest_hex(),
        roster_fingerprint: roster.fingerprint(),
    })
}

/// Unmasks and checks every dealer's share for this trustee, then sums them.
/// Refuses, naming the dealer, on a missing dealer, a dealer key that is not
/// the roster's, a commitment of the wrong size, a share that fails its tag
/// (including one masked under another roster), or a share that fails
/// [`verify_share`]. Refuses an identity joint key or verification key.
pub fn receive(req: &ReceiveRequest, receive_secret: &Scalar) -> LiveResult<Received> {
    let roster = Roster::new(&req.election_id, req.threshold, req.trustees, &req.peers)?;
    roster.key(req.trustee_id)?;
    roster.check_own(req.trustee_id, receive_secret, "trustee")?;
    check_ids(
        req.dealers.iter().map(|d| d.dealer_id),
        req.trustees,
        "dealers",
    )?;
    let mut share_sum = Scalar::ZERO;
    let mut joint = RistrettoPoint::identity();
    fn fail(share_sum: &mut Scalar, e: String) -> LiveResult<Received> {
        share_sum.zeroize();
        Err(e)
    }
    for d in &req.dealers {
        let name = |what: &str| format!("dealer {} {what}", d.dealer_id);
        if d.masked_share.dealer_id != d.dealer_id {
            return fail(
                &mut share_sum,
                format!(
                    "dealer {}: the masked share claims dealer {}",
                    d.dealer_id, d.masked_share.dealer_id
                ),
            );
        }
        let dealer_pk = match codec::point(&d.receive_public_key, &name("receive_public_key")) {
            Ok(p) => p,
            Err(e) => return fail(&mut share_sum, e),
        };
        if dealer_pk != *roster.key(d.dealer_id)? {
            return fail(
                &mut share_sum,
                format!(
                    "dealer {}: receive_public_key is not the roster's key for that id",
                    d.dealer_id
                ),
            );
        }
        if d.commitments.len() != req.threshold {
            return fail(
                &mut share_sum,
                format!(
                    "dealer {}: {} commitments, want threshold {}",
                    d.dealer_id,
                    d.commitments.len(),
                    req.threshold
                ),
            );
        }
        let points = match d
            .commitments
            .iter()
            .map(|c| codec::point(c, &name("commitment")))
            .collect::<LiveResult<Vec<_>>>()
        {
            Ok(p) => p,
            Err(e) => return fail(&mut share_sum, e),
        };
        let mut value = match unmask_share(&roster, req.trustee_id, receive_secret, &d.masked_share)
        {
            Ok(v) => v,
            Err(e) => return fail(&mut share_sum, e),
        };
        let share = DealerShare {
            dealer_id: d.dealer_id,
            recipient_id: req.trustee_id,
            value,
        };
        let commitments = DealerCommitments {
            trustee_id: d.dealer_id,
            coefficient_commitments: points,
        };
        let ok = verify_share(&share, &commitments);
        if ok {
            share_sum += value;
        }
        value.zeroize();
        if !ok {
            return fail(
                &mut share_sum,
                format!(
                    "dealer {}: share does not verify against the dealer's commitments",
                    d.dealer_id
                ),
            );
        }
        joint += commitments.coefficient_commitments[0];
    }
    let verification_key = share_sum * basepoint();
    if joint == RistrettoPoint::identity() {
        return fail(
            &mut share_sum,
            "the joint public key is the identity: every vote would be in the clear".into(),
        );
    }
    if verification_key == RistrettoPoint::identity() {
        return fail(
            &mut share_sum,
            "this trustee's verification key is the identity".into(),
        );
    }
    Ok(Received {
        verification_key,
        share: share_sum,
        joint_public_key: joint,
        roster,
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

    fn roster(ps: &[Party], t: usize) -> Roster {
        Roster::new("e", t, ps.len(), &peers(ps)).unwrap()
    }

    /// Deals by the first `ps.len()` trustees under `roster_peers`.
    fn deals_with(ps: &[Party], t: usize, roster_peers: &[Peer]) -> Vec<DealResponse> {
        (1..=ps.len())
            .map(|i| {
                deal(
                    &DealRequest {
                        election_id: "e".into(),
                        dealer_id: i,
                        threshold: t,
                        trustees: roster_peers.len(),
                        peers: roster_peers.to_vec(),
                    },
                    &ps[i - 1].secret,
                    &mut OsRng,
                )
                .unwrap()
            })
            .collect()
    }

    fn deals(ps: &[Party], t: usize) -> Vec<DealResponse> {
        deals_with(ps, t, &peers(ps))
    }

    fn request_for(ps: &[Party], deals: &[DealResponse], j: usize, t: usize) -> ReceiveRequest {
        ReceiveRequest {
            election_id: "e".into(),
            trustee_id: j,
            threshold: t,
            trustees: ps.len(),
            peers: peers(ps),
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
        let r = roster(&ps, 2);
        let s = Scalar::from(42u64);
        let m = mask_share(&r, 1, 2, &ps[0].secret, &s, &mut OsRng).unwrap();
        assert_eq!(unmask_share(&r, 2, &ps[1].secret, &m).unwrap(), s);
        // Trustee 3's key cannot open a share masked for trustee 2, whether it
        // claims its own id or trustee 2's.
        assert!(unmask_share(&r, 3, &ps[2].secret, &m).is_err());
        assert!(unmask_share(&r, 2, &ps[2].secret, &m)
            .unwrap_err()
            .contains("authentication"));
        // Bound to the election id (through the roster).
        let other = Roster::new("other", 2, 3, &peers(&ps)).unwrap();
        assert!(unmask_share(&other, 2, &ps[1].secret, &m).is_err());
        // Bound to the dealer id.
        let mut moved = m.clone();
        moved.dealer_id = 3;
        assert!(unmask_share(&r, 2, &ps[1].secret, &moved).is_err());
        // A dealer cannot mask under a roster that does not hold its key.
        assert!(mask_share(&r, 2, 1, &ps[0].secret, &s, &mut OsRng).is_err());
    }

    #[test]
    fn roster_refuses_duplicates_gaps_and_identity() {
        let ps = parties(3);
        let mut dup = peers(&ps);
        dup[2].receive_public_key = dup[0].receive_public_key.clone();
        assert!(Roster::new("e", 2, 3, &dup)
            .unwrap_err()
            .contains("repeats"));
        let mut gap = peers(&ps);
        gap[2].trustee_id = 4;
        assert!(Roster::new("e", 2, 3, &gap).is_err());
        let mut zero = peers(&ps);
        zero[1].receive_public_key = "00".repeat(32);
        assert!(Roster::new("e", 2, 3, &zero)
            .unwrap_err()
            .contains("identity"));
        let mut bad = peers(&ps);
        bad[1].receive_public_key = "ff".repeat(32);
        assert!(Roster::new("e", 2, 3, &bad).is_err());
        // The digest binds t, n, the order and every key.
        let base = roster(&ps, 2).digest_hex();
        assert_ne!(base, roster(&ps, 3).digest_hex());
        let mut swapped = peers(&ps);
        swapped.swap(0, 1);
        swapped[0].trustee_id = 1;
        swapped[1].trustee_id = 2;
        assert_ne!(base, Roster::new("e", 2, 3, &swapped).unwrap().digest_hex());
    }

    #[test]
    fn five_trustees_agree_on_the_joint_key_and_roster() {
        let ps = parties(5);
        let ds = deals(&ps, 3);
        let got: Vec<Received> = (1..=5)
            .map(|j| receive(&request_for(&ps, &ds, j, 3), &ps[j - 1].secret).unwrap())
            .collect();
        for r in &got {
            assert_eq!(r.joint_public_key, got[0].joint_public_key);
            assert_eq!(r.verification_key, r.share * basepoint());
            assert_eq!(r.roster.digest_hex(), ds[0].roster_digest);
        }
    }

    #[test]
    fn a_relay_that_swaps_one_receive_key_is_caught() {
        let ps = parties(5);
        // The relay shows every dealer a roster with its own key at trustee 5.
        let (_relay_secret, relay_key) = receive_keygen(&mut OsRng);
        let mut forged = peers(&ps);
        forged[4].receive_public_key = codec::point_hex(&relay_key);
        // Trustee 5 itself refuses to deal under a roster without its key.
        let err = deal(
            &DealRequest {
                election_id: "e".into(),
                dealer_id: 5,
                threshold: 3,
                trustees: 5,
                peers: forged.clone(),
            },
            &ps[4].secret,
            &mut OsRng,
        )
        .unwrap_err();
        assert!(err.contains("not this dealer's key file"), "{err}");
        let mut ds = deals_with(&ps[..4], 3, &forged);
        ds.push(deals(&ps, 3).pop().unwrap());
        // The dealers' digest differs from the one the genuine roster gives.
        assert_ne!(ds[0].roster_digest, roster(&ps, 3).digest_hex());
        // Trustee 1, holding the genuine roster, refuses every share: they
        // were masked under another roster. The first dealer is named.
        let err = receive(&request_for(&ps, &ds, 1, 3), &ps[0].secret)
            .err()
            .unwrap();
        assert!(
            err.starts_with("dealer 1:") && err.contains("authentication"),
            "{err}"
        );
        // A dealer key that is not the roster's is refused before unmasking.
        let ds = deals(&ps, 3);
        let mut req = request_for(&ps, &ds, 1, 3);
        req.dealers[2].receive_public_key = codec::point_hex(&relay_key);
        let err = receive(&req, &ps[0].secret).err().unwrap();
        assert!(err.starts_with("dealer 3:"), "{err}");
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
            &roster(&ps, 3),
            2,
            1,
            &ps[1].secret,
            &Scalar::from(9u64),
            &mut OsRng,
        )
        .unwrap();
        let err = receive(&request_for(&ps, &ds, 1, 3), &ps[0].secret)
            .err()
            .unwrap();
        assert!(
            err.starts_with("dealer 2:") && err.contains("commitments"),
            "{err}"
        );
    }

    #[test]
    fn an_identity_joint_key_is_refused() {
        // Two dealers whose constant terms cancel: Y = 0 and every share is 0.
        let ps = parties(2);
        let r = roster(&ps, 1);
        let polys = [Scalar::from(5u64), -Scalar::from(5u64)];
        let ds: Vec<DealResponse> = (1..=2)
            .map(|i| {
                let dealer = Dealer::new(i, vec![polys[i - 1]]);
                DealResponse {
                    election_id: "e".into(),
                    dealer_id: i,
                    commitments: dealer
                        .commitments()
                        .coefficient_commitments
                        .iter()
                        .map(codec::point_hex)
                        .collect(),
                    masked_shares: (1..=2)
                        .map(|j| {
                            mask_share(
                                &r,
                                i,
                                j,
                                &ps[i - 1].secret,
                                &dealer.share_for(j).value,
                                &mut OsRng,
                            )
                            .unwrap()
                        })
                        .collect(),
                    roster_digest: r.digest_hex(),
                    roster_fingerprint: r.fingerprint(),
                }
            })
            .collect();
        let err = receive(&request_for(&ps, &ds, 1, 1), &ps[0].secret)
            .err()
            .unwrap();
        assert!(err.contains("identity"), "{err}");
    }
}

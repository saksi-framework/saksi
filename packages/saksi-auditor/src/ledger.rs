//! Order-dependent digest over a recorded ballot sequence.
//!
//! **No verifier uses this.** [`crate::audit`] never calls [`ledger_digest`],
//! the chaincode has no ordering check, and the console's `reordered-ballots`
//! scenario has no gate. Ballot reordering (paper adversary class 5, a
//! malicious bulletin-board node) is therefore **not detected**: the
//! homomorphic tally is order-independent, so reordering cannot change the
//! result, and ordering integrity is not claimed.
//!
//! A dropped ballot, by contrast, is detected: the recorded set no longer sums
//! to the published tally (`tally.homomorphic_sum`).
//!
//! The function is kept as public API, but nothing compares its output against
//! a committed order (on Fabric, the block/transaction order).

use saksi_protocol::{domain_hash, Ballot};

/// Order-dependent hash chain over `ballots`. Folds each ballot's identifying
/// content (position id, nullifier, credential commitment, and every ciphertext)
/// into a running SHA-256 digest, so the result depends on both the set **and**
/// its order. Reordering or dropping any ballot changes the output.
///
/// Not called by [`crate::audit`] or any other verifier (see the module docs).
pub fn ledger_digest(ballots: &[Ballot]) -> [u8; 32] {
    let mut acc = domain_hash(b"saksi.auditor.ledger.v1", &[]);
    for ballot in ballots {
        let nullifier: &[u8] = ballot
            .credential_presentation
            .as_ref()
            .and_then(|p| p.nullifier.as_ref())
            .map(|n| n.value.as_slice())
            .unwrap_or(&[]);

        let mut parts: Vec<&[u8]> = Vec::with_capacity(4 + ballot.ciphertexts.len() * 2);
        parts.push(&acc); // chain in the running digest → order-dependent
        parts.push(ballot.position_id.as_bytes());
        parts.push(nullifier);
        parts.push(&ballot.voter_credential_commitment);
        for ct in &ballot.ciphertexts {
            parts.push(&ct.pad);
            parts.push(&ct.data);
        }
        acc = domain_hash(b"saksi.auditor.ledger.chain.v1", &parts);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::ledger_digest;
    use crate::fixtures::{multi_position_fixture, GenParams, SelectionProfile};

    /// Unit test of the digest function alone. No verifier runs the digest, so
    /// this proves nothing about whether an audit detects a reorder (it does not).
    #[test]
    fn ledger_digest_is_order_dependent() {
        let f = multi_position_fixture(&GenParams::simple(4, 2, 2, SelectionProfile::Uniform));
        let recorded = ledger_digest(&f.ballots);
        assert_eq!(recorded, ledger_digest(&f.ballots), "deterministic");

        let mut reversed = f.ballots.clone();
        reversed.reverse();
        assert_ne!(ledger_digest(&reversed), recorded, "order-dependent");
    }
}

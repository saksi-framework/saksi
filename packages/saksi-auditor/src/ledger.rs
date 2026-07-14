//! Ledger-ordering digest for bulletin-board integrity (paper §Security,
//! adversary class 5: a malicious bulletin-board node that drops **or reorders**
//! ballots — "detected by proof and hash verification").
//!
//! A dropped ballot is caught by the homomorphic-sum check (the recorded set no
//! longer matches the published tally). **Reordering** does not change the
//! order-independent homomorphic tally, so it cannot be caught that way — it is
//! caught by **hash verification**: this order-dependent digest over the recorded
//! ballot sequence. A verifier recomputes it from the bulletin board's committed
//! order (on Fabric, the block/transaction order) and compares; any reordering or
//! omission yields a different digest.

use saksi_protocol::{domain_hash, Ballot};

/// Order-dependent hash chain over `ballots`. Folds each ballot's identifying
/// content (position id, nullifier, credential commitment, and every ciphertext)
/// into a running SHA-256 digest, so the result depends on both the set **and**
/// its order. Reordering or dropping any ballot changes the output.
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

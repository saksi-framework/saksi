# Security Policy

## Project Maturity

Saksi is **research-grade software** under active development. It has **not
undergone any third-party security audit** and is not yet suitable for
production use. Cryptographic constructions, protocols, and implementations in
this repository are still being designed, reviewed, and revised, and may contain
undiscovered vulnerabilities. Treat the codebase accordingly.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in Saksi, please report it
privately. Do **not** open a public GitHub issue, discussion, or pull request
describing the vulnerability.

Send disclosures to:

**security@saksi-framework.org**

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a proof-of-concept where applicable.
- The affected component, commit, or version.
- Any suggested mitigation, if you have one.

> Note: The address above is a placeholder reserved for this purpose and will be
> activated as the project matures. Until then, disclosures may not receive an
> immediate response. The address is reserved exclusively for security reports;
> please do not use it for general inquiries.

## Disclosure Window

We follow a **90-day coordinated disclosure** policy. After a report is received,
the project will work to investigate and remediate the issue, and the reporter is
asked to refrain from public disclosure for 90 days from the date of the report,
or until a fix has been published, whichever comes first. Extensions may be
agreed upon for complex issues.

## Scope

In scope:

- Cryptographic flaws in Saksi constructions, protocols, and implementations
  (threshold encryption, distributed key generation, zero-knowledge proofs,
  anonymous credentials, commitments, the bulletin-board chaincode, and the wire
  format).
- Vulnerabilities in the framework code, chaincode, client SDK, FFI surfaces, or
  supporting tooling within this repository.
- Issues that compromise the confidentiality, integrity, or verifiability
  guarantees the framework is intended to provide.

Out of scope:

- Issues in third-party dependencies — please report those upstream, though we
  welcome notification.
- Theoretical issues without a practical attack path against this codebase.
- Social engineering, physical attacks, or attacks requiring privileged access
  already granted by a deployment operator.

## Acknowledgment

Researchers who report vulnerabilities in good faith and follow this policy will
be credited in release notes once a fix has been published, unless they request
anonymity.

//! Structured audit-report types.
//!
//! Every check the auditor performs pushes one [`AuditFinding`] into the
//! report regardless of outcome — the report doubles as both an audit trail
//! ("we ran these checks") and an indictment ("here is what failed and why").
//! Callers should rely on [`AuditReport::passed`] (or the equivalent
//! `overall == AuditStatus::Pass`) for the bottom-line verdict instead of
//! scanning findings by hand.

use serde::Serialize;

/// Severity of an audit finding.
///
/// - [`Severity::Fatal`] — a soundness failure. Any Fatal finding whose
///   `status == AuditStatus::Fail` flips the overall report to `Fail`.
/// - [`Severity::Warning`] — shape / version drift that we explicitly tolerate
///   in v1 (e.g. unknown extra fields). Reserved for forward-compat; not
///   currently produced.
/// - [`Severity::Info`] — informational; never affects `overall`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Severity {
    /// Informational entry. Never affects the overall verdict.
    Info,
    /// Non-fatal anomaly (e.g. forward-compat shape drift).
    Warning,
    /// Soundness failure — flips overall to Fail when status is Fail.
    Fatal,
}

/// Per-finding pass/fail flag, separate from severity so an "Info" check can
/// still record a Pass result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum AuditStatus {
    /// Check passed.
    Pass,
    /// Check failed.
    Fail,
}

/// One row in the audit report.
#[derive(Clone, Debug, Serialize)]
pub struct AuditFinding {
    /// Short stable identifier, e.g. `"ballot.cds_proof"`. Stable across
    /// releases so downstream tooling can match on it.
    pub check: &'static str,
    /// Severity of the check (see [`Severity`]).
    pub severity: Severity,
    /// Pass/fail flag for this individual check.
    pub status: AuditStatus,
    /// Human-readable detail. Free-form; suitable for logging and UIs.
    pub detail: String,
}

impl AuditFinding {
    /// Convenience constructor for a passing fatal-severity check (the common
    /// case — "this soundness check passed").
    pub fn fatal_pass(check: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check,
            severity: Severity::Fatal,
            status: AuditStatus::Pass,
            detail: detail.into(),
        }
    }

    /// Convenience constructor for a failing fatal-severity check.
    pub fn fatal_fail(check: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check,
            severity: Severity::Fatal,
            status: AuditStatus::Fail,
            detail: detail.into(),
        }
    }
}

/// The full report emitted by [`crate::audit`].
#[derive(Clone, Debug, Serialize)]
pub struct AuditReport {
    /// Bottom-line verdict. Equal to `Fail` iff any finding has
    /// `severity == Fatal && status == Fail`.
    pub overall: AuditStatus,
    /// Every check the auditor ran, in evaluation order.
    pub findings: Vec<AuditFinding>,
}

impl AuditReport {
    /// Returns `true` iff `overall == AuditStatus::Pass`.
    pub fn passed(&self) -> bool {
        matches!(self.overall, AuditStatus::Pass)
    }

    /// Returns the first finding whose `check` matches, if any. Test-only
    /// helper but useful enough at the API surface that we expose it.
    pub fn finding(&self, check: &str) -> Option<&AuditFinding> {
        self.findings.iter().find(|f| f.check == check)
    }
}

/// Internal report builder used by the auditor pipeline. Collects findings
/// and computes the final `overall` verdict on consumption.
pub(crate) struct ReportBuilder {
    findings: Vec<AuditFinding>,
}

impl ReportBuilder {
    pub(crate) fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, finding: AuditFinding) {
        self.findings.push(finding);
    }

    pub(crate) fn pass(&mut self, check: &'static str, detail: impl Into<String>) {
        self.push(AuditFinding::fatal_pass(check, detail));
    }

    pub(crate) fn fail(&mut self, check: &'static str, detail: impl Into<String>) {
        self.push(AuditFinding::fatal_fail(check, detail));
    }

    pub(crate) fn finish(self) -> AuditReport {
        let any_fatal = self
            .findings
            .iter()
            .any(|f| f.severity == Severity::Fatal && f.status == AuditStatus::Fail);
        AuditReport {
            overall: if any_fatal {
                AuditStatus::Fail
            } else {
                AuditStatus::Pass
            },
            findings: self.findings,
        }
    }
}

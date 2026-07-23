from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class VerificationResult:
    report: dict[str, Any]
    rejected_claim_ids: tuple[str, ...]
    missing_evidence_ids: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.rejected_claim_ids and not self.missing_evidence_ids


def verify_report_claims(
    report: dict[str, Any],
    evidence_packet: dict[str, Any],
    *,
    verifier_revision: str,
) -> VerificationResult:
    verified = deepcopy(report)
    evidence_index = {
        str(item["evidence_id"]): item for item in evidence_packet.get("evidence", [])
    }
    rejected: list[str] = []
    missing: set[str] = set()
    for finding in verified.get("findings", []):
        verified_texts: set[str] = set()
        for claim in finding.get("claims", []):
            claim_id = str(claim["claim_id"])
            claim_text = str(claim["text"])
            supported = False
            for evidence_id in claim.get("evidence_ids", []):
                evidence = evidence_index.get(str(evidence_id))
                if evidence is None:
                    missing.add(str(evidence_id))
                    continue
                claims_supported = evidence.get("claims_supported", [])
                if claim_text in claims_supported:
                    supported = True
            claim["verification_status"] = "verified" if supported else "rejected"
            if supported:
                verified_texts.add(claim_text)
            if not supported:
                rejected.append(claim_id)
        for known_item in finding.get("known", []):
            if str(known_item) not in verified_texts:
                rejected.append(f"known:{finding.get('finding_id')}:{len(rejected)}")
    passed = not rejected and not missing
    verified["verification"] = {
        "all_claims_cited": not missing and _all_claims_have_citations(verified),
        "all_claims_verified": passed,
        "verifier_revision": verifier_revision,
    }
    return VerificationResult(
        report=verified,
        rejected_claim_ids=tuple(sorted(rejected)),
        missing_evidence_ids=tuple(sorted(missing)),
    )


def require_verified_report(report: dict[str, Any]) -> None:
    verification = report.get("verification")
    if not isinstance(verification, dict):
        raise ValueError("report is missing verification")
    if verification.get("all_claims_cited") is not True:
        raise ValueError("report contains uncited claims")
    if verification.get("all_claims_verified") is not True:
        raise ValueError("report contains unverified claims")
    for finding in report.get("findings", []):
        for claim in finding.get("claims", []):
            if claim.get("verification_status") != "verified":
                raise ValueError(f"claim {claim.get('claim_id')} is not verified")


def _all_claims_have_citations(report: dict[str, Any]) -> bool:
    return all(
        bool(claim.get("evidence_ids"))
        for finding in report.get("findings", [])
        for claim in finding.get("claims", [])
    )

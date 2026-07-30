from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from packages.common.canonical import canonical_json_bytes


def _is_primary_report(path: Path, reports_root: Path) -> bool:
    relative_parts = set(path.relative_to(reports_root).parts[:-1])
    generated_derivatives = {
        "baseline",
        "candidates",
        "original",
        "replay",
        "restored",
        "reviews",
    }
    return relative_parts.isdisjoint(generated_derivatives)


def evaluate_source_coverage(
    *,
    reports_root: Path,
    output_root: Path,
    minimum_surface_count: int = 4,
    maximum_single_surface_share: float = 0.6,
    maximum_x_share: float = 0.5,
) -> dict[str, Any]:
    if not 1 <= minimum_surface_count <= 20:
        raise ValueError("minimum surface count must be between 1 and 20")
    if not 0 < maximum_single_surface_share <= 1:
        raise ValueError("maximum surface share must be between zero and one")
    if not 0 <= maximum_x_share <= 1:
        raise ValueError("maximum X share must be between zero and one")
    source_counts: Counter[str] = Counter()
    source_type_counts: Counter[str] = Counter()
    discovered_signal_counts: Counter[str] = Counter()
    telemetry_report_count = 0
    report_count = 0
    finding_count = 0
    evidence_count = 0
    unattributed_evidence = 0
    findings_without_non_x = 0
    report_paths: list[str] = []

    for path in sorted(reports_root.rglob("rp_*.json")):
        if not _is_primary_report(path, reports_root):
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            continue
        report_count += 1
        report_paths.append(str(path))
        telemetry = report.get("discovery_telemetry")
        if isinstance(telemetry, dict) and isinstance(telemetry.get("surfaces"), list):
            telemetry_report_count += 1
            for surface in telemetry["surfaces"]:
                if not isinstance(surface, dict):
                    continue
                source_id = surface.get("source_id")
                signal_count = surface.get("discovered_signal_count")
                if (
                    isinstance(source_id, str)
                    and isinstance(signal_count, int)
                    and not isinstance(signal_count, bool)
                    and signal_count >= 0
                ):
                    discovered_signal_counts[source_id] += signal_count
        for finding in report["findings"]:
            if not isinstance(finding, dict):
                continue
            evidence = finding.get("source_evidence")
            if not isinstance(evidence, list) or not evidence:
                continue
            finding_count += 1
            finding_non_x = False
            for item in evidence:
                if not isinstance(item, dict):
                    unattributed_evidence += 1
                    continue
                source_id = item.get("source_id")
                source_type = item.get("source_type")
                if not isinstance(source_id, str) or not isinstance(source_type, str):
                    unattributed_evidence += 1
                    continue
                evidence_count += 1
                source_counts[source_id] += 1
                source_type_counts[source_type] += 1
                if source_type != "x_post":
                    finding_non_x = True
            if not finding_non_x:
                findings_without_non_x += 1

    x_count = source_type_counts["x_post"]
    x_share = x_count / evidence_count if evidence_count else 0.0
    largest_surface_count = max(source_counts.values(), default=0)
    largest_surface_share = largest_surface_count / evidence_count if evidence_count else 0.0
    non_x_count = evidence_count - x_count
    discovered_signal_count = sum(discovered_signal_counts.values())
    signal_surface_count = sum(count > 0 for count in discovered_signal_counts.values())
    x_discovered_signal_count = discovered_signal_counts["x-researchers"]
    x_discovered_signal_share = (
        x_discovered_signal_count / discovered_signal_count if discovered_signal_count else 0.0
    )
    largest_signal_surface_count = max(discovered_signal_counts.values(), default=0)
    largest_signal_surface_share = (
        largest_signal_surface_count / discovered_signal_count if discovered_signal_count else 0.0
    )
    metrics = {
        "report_count": report_count,
        "telemetry_report_count": telemetry_report_count,
        "finding_count": finding_count,
        "evidence_count": evidence_count,
        "surface_count": len(source_counts),
        "source_type_count": len(source_type_counts),
        "x_evidence_count": x_count,
        "non_x_evidence_count": non_x_count,
        "x_share": round(x_share, 4),
        "largest_surface_share": round(largest_surface_share, 4),
        "findings_without_non_x_evidence": findings_without_non_x,
        "unattributed_evidence_count": unattributed_evidence,
        "discovered_signal_count": discovered_signal_count,
        "signal_surface_count": signal_surface_count,
        "x_discovered_signal_count": x_discovered_signal_count,
        "non_x_discovered_signal_count": (discovered_signal_count - x_discovered_signal_count),
        "x_discovered_signal_share": round(x_discovered_signal_share, 4),
        "largest_signal_surface_share": round(largest_signal_surface_share, 4),
        "discovered_signals_by_source": dict(sorted(discovered_signal_counts.items())),
        "sources": dict(sorted(source_counts.items())),
        "source_types": dict(sorted(source_type_counts.items())),
    }
    gates = {
        "evidence_observed": evidence_count > 0,
        "minimum_surface_count": len(source_counts) >= minimum_surface_count,
        "single_surface_concentration_bounded": (
            largest_surface_share <= maximum_single_surface_share
        ),
        "x_share_bounded": x_share <= maximum_x_share,
        "non_x_evidence_present": non_x_count > 0,
        "all_evidence_attributed": unattributed_evidence == 0,
        "every_finding_has_non_x_evidence": findings_without_non_x == 0,
        "discovery_telemetry_present": telemetry_report_count > 0,
        "minimum_signal_surface_count": (signal_surface_count >= minimum_surface_count),
        "single_signal_surface_concentration_bounded": (
            largest_signal_surface_share <= maximum_single_surface_share
        ),
        "x_discovered_signal_share_bounded": (x_discovered_signal_share <= maximum_x_share),
        "non_x_discovered_signals_present": (discovered_signal_count > x_discovered_signal_count),
    }
    result = {
        "schema_version": "1.0",
        "suite": "source-coverage-evaluation",
        "thresholds": {
            "minimum_surface_count": minimum_surface_count,
            "maximum_single_surface_share": maximum_single_surface_share,
            "maximum_x_share": maximum_x_share,
        },
        "metrics": metrics,
        "gates": gates,
        "passed": all(gates.values()),
        "reports": report_paths,
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "source-coverage-results.json").write_bytes(canonical_json_bytes(result) + b"\n")
    return result

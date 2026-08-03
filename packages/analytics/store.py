from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from packages.common.canonical import canonical_json_bytes, sha256_hex, stable_id
from packages.contracts.validation import validate_payload
from packages.discovery.clients import BRAVE_COST_PER_REQUEST
from packages.discovery.emerging import classify_taxonomy
from packages.verification.claims import require_verified_report


@dataclass(frozen=True, slots=True)
class IndexResult:
    report_id: str
    inserted: bool
    finding_count: int
    telemetry_scope: Literal["operational", "fixture"]


class AnalyticsStore:
    """Read-optimized SQLite index for trends, reporting, and portable telemetry."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def index_report(
        self,
        report: dict[str, Any],
        *,
        report_path: Path,
        html_path: Path | None = None,
        telemetry_scope: Literal["operational", "fixture"] | None = None,
    ) -> IndexResult:
        validate_payload("report.schema.json", report)
        require_verified_report(report)
        encoded = canonical_json_bytes(report)
        report_hash = sha256_hex(encoded)
        report_id = str(report["report_id"])
        scope = telemetry_scope or _report_telemetry_scope(report)
        findings = [item for item in report["findings"] if isinstance(item, dict)]
        scores = [float(item["priority_score"]) for item in findings]
        usage = [item for item in report["usage"] if isinstance(item, dict)]
        source_health = [item for item in report["source_health"] if isinstance(item, dict)]
        classes = {
            name: sum(1 for item in findings if item["publication_class"] == name)
            for name in ("flash", "watch", "daily", "archive")
        }
        row = (
            report_id,
            str(report["generated_at"]),
            str(report["edition"]),
            len(findings),
            max(scores, default=0.0),
            sum(scores) / len(scores) if scores else 0.0,
            classes["flash"],
            classes["watch"],
            classes["daily"],
            classes["archive"],
            len(report.get("degraded_sources", [])),
            sum(int(item.get("requests", 0)) for item in usage),
            sum(
                int(item.get("input_tokens", 0)) + int(item.get("output_tokens", 0))
                for item in usage
            ),
            sum(_usage_cost(item) for item in usage),
            str(report_path.resolve()),
            str(html_path.resolve()) if html_path is not None else None,
            report_hash,
            encoded.decode("utf-8"),
            scope,
        )
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT report_hash, telemetry_scope FROM analytics_reports WHERE report_id = ?",
                (report_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["report_hash"]) != report_hash:
                    raise ValueError(f"immutable analytics conflict for {report_id}")
                if str(existing["telemetry_scope"]) != scope:
                    connection.execute(
                        "UPDATE analytics_reports SET telemetry_scope = ? WHERE report_id = ?",
                        (scope, report_id),
                    )
                    connection.execute(
                        "UPDATE analytics_events SET telemetry_scope = ? "
                        "WHERE metric = 'report.indexed' "
                        "AND json_extract(dimensions_json, '$.report_id') = ?",
                        (scope, report_id),
                    )
                _index_finding_dimensions(
                    connection,
                    report_id=report_id,
                    findings=findings,
                )
                _index_usage_dimensions(
                    connection,
                    report_id=report_id,
                    usage=usage,
                )
                connection.execute(
                    """
                    UPDATE analytics_reports
                    SET request_count = ?, token_count = ?, estimated_cost = ?
                    WHERE report_id = ?
                    """,
                    (
                        sum(int(item.get("requests", 0)) for item in usage),
                        sum(
                            int(item.get("input_tokens", 0))
                            + int(item.get("output_tokens", 0))
                            for item in usage
                        ),
                        sum(_usage_cost(item) for item in usage),
                        report_id,
                    ),
                )
                connection.commit()
                return IndexResult(report_id, False, len(findings), scope)
            connection.execute(
                """
                INSERT INTO analytics_reports (
                  report_id, generated_at, edition, finding_count, max_score,
                  mean_score, flash_count, watch_count, daily_count, archive_count,
                  degraded_source_count, request_count, token_count, estimated_cost,
                  report_path, html_path, report_hash, report_json, telemetry_scope
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            _index_finding_dimensions(
                connection,
                report_id=report_id,
                findings=findings,
            )
            _index_usage_dimensions(
                connection,
                report_id=report_id,
                usage=usage,
            )
            for source in source_health:
                connection.execute(
                    """
                    INSERT INTO analytics_source_health (
                      report_id, source_id, status, last_success_at,
                      freshness_seconds, error_rate
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report_id,
                        str(source["source_id"]),
                        str(source["status"]),
                        source.get("last_success_at"),
                        source.get("freshness_seconds"),
                        float(source.get("error_rate", 0)),
                    ),
                )
            connection.commit()
        self.record_event(
            metric="report.indexed",
            value=1,
            unit="report",
            occurred_at=str(report["generated_at"]),
            run_id=_run_id_from_path(report_path),
            dimensions={
                "report_id": report_id,
                "edition": str(report["edition"]),
                "finding_count": str(len(findings)),
            },
            telemetry_scope=scope,
        )
        return IndexResult(report_id, True, len(findings), scope)

    def index_path(
        self,
        report_path: Path,
        *,
        telemetry_scope: Literal["operational", "fixture"] | None = None,
    ) -> IndexResult:
        value = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("report JSON must contain one object")
        html_path = report_path.with_suffix(".html")
        return self.index_report(
            value,
            report_path=report_path,
            html_path=html_path if html_path.is_file() else None,
            telemetry_scope=telemetry_scope,
        )

    def sync_reports(self, reports_root: Path) -> dict[str, int]:
        inserted = 0
        unchanged = 0
        skipped = 0
        excluded = 0
        if not reports_root.exists():
            return {"inserted": 0, "unchanged": 0, "skipped": 0, "excluded": 0}
        for path in sorted(reports_root.rglob("rp_*.json")):
            relative_parts = path.relative_to(reports_root).parts
            if (
                path.name.endswith(".delivery.json")
                or not relative_parts[0].startswith("run_")
                or "candidates" in relative_parts
                or "improvement" in relative_parts
            ):
                skipped += 1
                continue
            result = self.index_path(path)
            if result.telemetry_scope != "operational":
                excluded += 1
            if result.inserted:
                inserted += 1
            else:
                unchanged += 1
        return {
            "inserted": inserted,
            "unchanged": unchanged,
            "skipped": skipped,
            "excluded": excluded,
        }

    def record_event(
        self,
        *,
        metric: str,
        value: float,
        unit: str,
        dimensions: dict[str, str],
        occurred_at: str | None = None,
        run_id: str | None = None,
        telemetry_scope: Literal["operational", "fixture"] = "operational",
    ) -> str:
        if not metric or len(metric) > 100:
            raise ValueError("metric must contain 1 to 100 characters")
        if len(dimensions) > 20 or any(
            len(key) > 100 or len(item) > 300 for key, item in dimensions.items()
        ):
            raise ValueError("telemetry dimensions exceed bounded limits")
        timestamp = occurred_at or datetime.now(UTC).isoformat()
        dimensions_text = json.dumps(dimensions, sort_keys=True, separators=(",", ":"))
        event_id = stable_id(
            "evt",
            timestamp,
            run_id or "",
            metric,
            str(value),
            unit,
            dimensions_text,
        )
        with self._connection() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO analytics_events (
                  event_id, occurred_at, run_id, metric, value, unit, dimensions_json,
                  telemetry_scope
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    timestamp,
                    run_id,
                    metric,
                    value,
                    unit,
                    dimensions_text,
                    telemetry_scope,
                ),
            )
        return event_id

    def overview(self, *, days: int = 30) -> dict[str, Any]:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._connection() as connection:
            totals = connection.execute(
                """
                SELECT COUNT(*) AS reports,
                       COALESCE(MAX(max_score), 0) AS max_score,
                       COALESCE(SUM(degraded_source_count), 0) AS degraded,
                       COALESCE(SUM(request_count), 0) AS requests,
                       COALESCE(SUM(token_count), 0) AS tokens,
                       COALESCE(SUM(estimated_cost), 0) AS estimated_cost
                FROM analytics_reports
                WHERE telemetry_scope = 'operational' AND generated_at >= ?
                """,
                (since,),
            ).fetchone()
            finding_count = connection.execute(
                """
                SELECT COUNT(DISTINCT f.finding_id) AS findings
                FROM analytics_findings f
                JOIN analytics_reports r ON r.report_id = f.report_id
                WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                """,
                (since,),
            ).fetchone()
            latest = connection.execute(
                """
                SELECT report_id, generated_at, edition, finding_count, max_score
                FROM analytics_reports
                WHERE telemetry_scope = 'operational'
                ORDER BY generated_at DESC
                LIMIT 1
                """
            ).fetchone()
            event_count = connection.execute(
                """
                SELECT COUNT(*) AS events
                FROM analytics_events
                WHERE telemetry_scope = 'operational' AND occurred_at >= ?
                """,
                (since,),
            ).fetchone()
        assert totals is not None
        assert finding_count is not None
        assert event_count is not None
        return {
            "days": days,
            "reports": int(totals["reports"]),
            "findings": int(finding_count["findings"]),
            "max_score": float(totals["max_score"]),
            "degraded": int(totals["degraded"]),
            "requests": int(totals["requests"]),
            "tokens": int(totals["tokens"]),
            "estimated_cost": float(totals["estimated_cost"]),
            "events": int(event_count["events"]),
            "latest": dict(latest) if latest is not None else None,
        }

    def intelligence_summary(self, *, days: int = 30) -> dict[str, Any]:
        """Build deduplicated posture metrics from operational report telemetry only."""
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._connection() as connection:
            findings = connection.execute(
                """
                WITH operational_findings AS (
                  SELECT f.*, r.generated_at,
                         ROW_NUMBER() OVER (
                           PARTITION BY f.finding_id
                           ORDER BY r.generated_at DESC, r.report_id DESC
                         ) AS recency_rank
                  FROM analytics_findings f
                  JOIN analytics_reports r ON r.report_id = f.report_id
                  WHERE r.telemetry_scope = 'operational'
                ),
                first_seen AS (
                  SELECT finding_id, MIN(generated_at) AS first_report_at
                  FROM operational_findings
                  GROUP BY finding_id
                ),
                latest_in_window AS (
                  SELECT *
                  FROM (
                    SELECT f.*, r.generated_at,
                           ROW_NUMBER() OVER (
                             PARTITION BY f.finding_id
                             ORDER BY r.generated_at DESC, r.report_id DESC
                           ) AS window_rank
                    FROM analytics_findings f
                    JOIN analytics_reports r ON r.report_id = f.report_id
                    WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                  )
                  WHERE window_rank = 1
                )
                SELECT COUNT(*) AS findings,
                       COALESCE(AVG(f.priority_score), 0) AS mean_score,
                       COALESCE(AVG(f.confidence_probability), 0) AS mean_confidence,
                       SUM(CASE WHEN s.first_report_at >= ? THEN 1 ELSE 0 END) AS new_findings,
                       SUM(CASE WHEN f.priority_score >= 75 THEN 1 ELSE 0 END) AS high_priority,
                       SUM(CASE WHEN f.publication_class = 'flash' THEN 1 ELSE 0 END) AS flash,
                       SUM(CASE WHEN f.publication_class = 'watch' THEN 1 ELSE 0 END) AS watch,
                       SUM(CASE WHEN f.publication_class = 'daily' THEN 1 ELSE 0 END) AS daily,
                       SUM(CASE WHEN f.publication_class = 'archive' THEN 1 ELSE 0 END) AS archive,
                       SUM(CASE WHEN f.emergence_stage != 'confirmed' THEN 1 ELSE 0 END)
                         AS emerging
                FROM latest_in_window f
                JOIN first_seen s ON s.finding_id = f.finding_id
                """,
                (since, since),
            ).fetchone()
            source_rows = connection.execute(
                """
                WITH latest_findings AS (
                  SELECT *
                  FROM (
                    SELECT f.finding_id, f.report_id,
                           ROW_NUMBER() OVER (
                             PARTITION BY f.finding_id
                             ORDER BY r.generated_at DESC, r.report_id DESC
                           ) AS recency_rank
                    FROM analytics_findings f
                    JOIN analytics_reports r ON r.report_id = f.report_id
                    WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                  )
                  WHERE recency_rank = 1
                )
                SELECT s.source_type,
                       COUNT(DISTINCT s.evidence_id) AS evidence,
                       COUNT(DISTINCT s.source_id) AS source_count
                FROM latest_findings f
                JOIN analytics_finding_sources s
                  ON s.report_id = f.report_id AND s.finding_id = f.finding_id
                GROUP BY s.source_type
                ORDER BY evidence DESC, s.source_type
                """,
                (since,),
            ).fetchall()
            source_total = connection.execute(
                """
                WITH latest_findings AS (
                  SELECT *
                  FROM (
                    SELECT f.finding_id, f.report_id,
                           ROW_NUMBER() OVER (
                             PARTITION BY f.finding_id
                             ORDER BY r.generated_at DESC, r.report_id DESC
                           ) AS recency_rank
                    FROM analytics_findings f
                    JOIN analytics_reports r ON r.report_id = f.report_id
                    WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                  )
                  WHERE recency_rank = 1
                )
                SELECT COUNT(DISTINCT s.source_id) AS source_count
                FROM latest_findings f
                JOIN analytics_finding_sources s
                  ON s.report_id = f.report_id AND s.finding_id = f.finding_id
                """,
                (since,),
            ).fetchone()
            usage = connection.execute(
                """
                SELECT COALESCE(SUM(
                         CASE
                           WHEN u.stage LIKE '%review%' OR u.stage LIKE '%agent%'
                           THEN u.requests ELSE 0
                         END
                       ), 0) AS agent_requests,
                       COALESCE(SUM(
                         CASE
                           WHEN u.stage LIKE '%review%' OR u.stage LIKE '%agent%'
                           THEN u.input_tokens + u.output_tokens ELSE 0
                         END
                       ), 0) AS agent_tokens,
                       COUNT(DISTINCT CASE
                         WHEN u.stage LIKE '%review%' OR u.stage LIKE '%agent%'
                         THEN u.model
                       END) AS agent_models
                FROM analytics_usage u
                JOIN analytics_reports r ON r.report_id = u.report_id
                WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                """,
                (since,),
            ).fetchone()
            report_rows = connection.execute(
                """
                SELECT report_id, report_json
                FROM analytics_reports
                WHERE telemetry_scope = 'operational' AND generated_at >= ?
                ORDER BY generated_at DESC
                """,
                (since,),
            ).fetchall()
            latest_finding_rows = connection.execute(
                """
                SELECT finding_id, report_id
                FROM (
                  SELECT f.finding_id, f.report_id,
                         ROW_NUMBER() OVER (
                           PARTITION BY f.finding_id
                           ORDER BY r.generated_at DESC, r.report_id DESC
                         ) AS recency_rank
                  FROM analytics_findings f
                  JOIN analytics_reports r ON r.report_id = f.report_id
                  WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                )
                WHERE recency_rank = 1
                """,
                (since,),
            ).fetchall()
        assert findings is not None
        assert source_total is not None
        assert usage is not None
        total_evidence = sum(int(row["evidence"]) for row in source_rows)
        sources: list[dict[str, Any]] = [
            {
                "source_type": str(row["source_type"]),
                "evidence": int(row["evidence"]),
                "source_count": int(row["source_count"]),
                "share": (
                    round(int(row["evidence"]) / total_evidence * 100, 1)
                    if total_evidence
                    else 0.0
                ),
                "width": (
                    max(1, min(10, round(int(row["evidence"]) / total_evidence * 10)))
                    if total_evidence
                    else 0
                ),
            }
            for row in source_rows
        ]
        x_evidence = sum(
            item["evidence"] for item in sources if item["source_type"] == "x_post"
        )
        claim_count = 0
        verified_claim_count = 0
        plan_count = 0
        review_count = 0
        assessment_count = 0
        failed_role_count = 0
        review_duration_ms = 0
        report_index: dict[str, dict[str, Any]] = {}
        for row in report_rows:
            report = json.loads(str(row["report_json"]))
            if not isinstance(report, dict):
                continue
            report_index[str(row["report_id"])] = report
            plans = report.get("agent_shadow_plans")
            if isinstance(plans, list):
                plan_count += len(plans)
            reviews = report.get("agent_reviews")
            if isinstance(reviews, list):
                review_count += len(reviews)
                for review in reviews:
                    if not isinstance(review, dict):
                        continue
                    assessments = review.get("assessments")
                    failures = review.get("failures")
                    assessment_count += len(assessments) if isinstance(assessments, list) else 0
                    failed_role_count += len(failures) if isinstance(failures, list) else 0
                    review_duration_ms += int(review.get("duration_ms", 0))
        latest_references = {
            (str(row["report_id"]), str(row["finding_id"])) for row in latest_finding_rows
        }
        for report_id, finding_id in latest_references:
            report = report_index.get(report_id, {})
            current = next(
                (
                    item
                    for item in report.get("findings", [])
                    if isinstance(item, dict) and str(item.get("finding_id")) == finding_id
                ),
                None,
            )
            if current is None:
                continue
            for claim in current.get("claims", []):
                if not isinstance(claim, dict):
                    continue
                claim_count += 1
                if (
                    claim.get("verification_status") == "verified"
                    and isinstance(claim.get("evidence_ids"), list)
                    and claim["evidence_ids"]
                ):
                    verified_claim_count += 1
        unique_findings = int(findings["findings"])
        new_findings = int(findings["new_findings"] or 0)
        expected_role_count = review_count * 5
        return {
            "days": days,
            "telemetry_scope": "operational",
            "findings": unique_findings,
            "mean_score": float(findings["mean_score"]),
            "mean_confidence": float(findings["mean_confidence"]),
            "new_findings": new_findings,
            "recurring_findings": max(0, unique_findings - new_findings),
            "high_priority": int(findings["high_priority"] or 0),
            "publication": {
                "flash": int(findings["flash"] or 0),
                "watch": int(findings["watch"] or 0),
                "daily": int(findings["daily"] or 0),
                "archive": int(findings["archive"] or 0),
            },
            "emerging": int(findings["emerging"] or 0),
            "evidence_count": total_evidence,
            "source_count": int(source_total["source_count"] or 0),
            "evidence_type_count": len(sources),
            "sources": sources,
            "x_share": round(x_evidence / total_evidence * 100, 1) if total_evidence else 0.0,
            "non_x_evidence": total_evidence - x_evidence,
            "claim_count": claim_count,
            "verified_claim_count": verified_claim_count,
            "claim_verification_rate": (
                round(verified_claim_count / claim_count * 100, 1) if claim_count else 0.0
            ),
            "agent_plan_count": plan_count,
            "agent_review_count": review_count,
            "agent_assessment_count": assessment_count,
            "agent_failed_role_count": failed_role_count,
            "agent_expected_role_count": expected_role_count,
            "agent_blocked_role_count": max(
                0,
                expected_role_count - assessment_count - failed_role_count,
            ),
            "agent_role_completion_rate": (
                round(assessment_count / expected_role_count * 100, 1)
                if expected_role_count
                else None
            ),
            "agent_review_duration_ms": review_duration_ms,
            "agent_requests": int(usage["agent_requests"]),
            "agent_tokens": int(usage["agent_tokens"]),
            "agent_models": int(usage["agent_models"]),
        }

    def cost_breakdown(self, *, days: int = 30) -> dict[str, Any]:
        """Analyze API-equivalent usage estimates without claiming cash spend."""
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._connection() as connection:
            totals = connection.execute(
                """
                SELECT COUNT(DISTINCT r.report_id) AS reports,
                       COALESCE(SUM(u.requests), 0) AS requests,
                       COALESCE(SUM(u.input_tokens + u.output_tokens), 0) AS tokens,
                       COALESCE(SUM(u.estimated_cost), 0) AS estimated_cost
                FROM analytics_reports r
                LEFT JOIN analytics_usage u ON u.report_id = r.report_id
                WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                """,
                (since,),
            ).fetchone()
            providers = connection.execute(
                """
                SELECT u.provider,
                       u.model,
                       COALESCE(SUM(u.requests), 0) AS requests,
                       COALESCE(SUM(u.input_tokens + u.output_tokens), 0) AS tokens,
                       COALESCE(SUM(u.estimated_cost), 0) AS estimated_cost
                FROM analytics_usage u
                JOIN analytics_reports r ON r.report_id = u.report_id
                WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                GROUP BY u.provider, u.model
                ORDER BY estimated_cost DESC, requests DESC, u.provider, u.model
                """,
                (since,),
            ).fetchall()
            stages = connection.execute(
                """
                SELECT u.stage,
                       COALESCE(SUM(u.requests), 0) AS requests,
                       COALESCE(SUM(u.input_tokens + u.output_tokens), 0) AS tokens,
                       COALESCE(SUM(u.estimated_cost), 0) AS estimated_cost
                FROM analytics_usage u
                JOIN analytics_reports r ON r.report_id = u.report_id
                WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                GROUP BY u.stage
                ORDER BY estimated_cost DESC, requests DESC, u.stage
                """,
                (since,),
            ).fetchall()
        assert totals is not None
        report_count = int(totals["reports"])
        estimated_cost = float(totals["estimated_cost"])
        request_count = int(totals["requests"])
        provider_rows = _cost_rows(providers, estimated_cost=estimated_cost)
        stage_rows = _cost_rows(stages, estimated_cost=estimated_cost)
        return {
            "days": days,
            "reports": report_count,
            "requests": request_count,
            "tokens": int(totals["tokens"]),
            "estimated_cost": estimated_cost,
            "average_per_report": estimated_cost / report_count if report_count else 0.0,
            "average_per_request": (estimated_cost / request_count if request_count else 0.0),
            "providers": provider_rows,
            "stages": stage_rows,
        }

    def local_inference_status(self) -> dict[str, Any] | None:
        """Return the newest persisted semantic shadow observation, if any."""
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT report_id, generated_at, report_json
                FROM analytics_reports
                WHERE telemetry_scope = 'operational'
                ORDER BY generated_at DESC
                LIMIT 100
                """
            ).fetchall()
        for row in rows:
            report = json.loads(str(row["report_json"]))
            if not isinstance(report, dict):
                continue
            shadow = report.get("semantic_shadow")
            if not isinstance(shadow, dict):
                continue
            return {
                **shadow,
                "report_id": str(row["report_id"]),
                "generated_at": str(row["generated_at"]),
            }
        return None

    def list_reports(
        self,
        *,
        limit: int = 100,
        edition: str | None = None,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = ["r.telemetry_scope = 'operational'"]
        parameters: list[Any] = []
        if edition:
            clauses.append("r.edition = ?")
            parameters.append(edition)
        if query:
            clauses.append(
                "(r.report_id LIKE ? OR EXISTS ("
                "SELECT 1 FROM analytics_findings f "
                "WHERE f.report_id = r.report_id AND f.title LIKE ?))"
            )
            pattern = f"%{query}%"
            parameters.extend((pattern, pattern))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(max(1, min(limit, 500)))
        with self._connection() as connection:
            rows = connection.execute(
                f"""
                SELECT r.report_id, r.generated_at, r.edition, r.finding_count,
                       r.max_score, r.degraded_source_count, r.estimated_cost,
                       r.report_path, r.html_path
                FROM analytics_reports r
                {where}
                ORDER BY r.generated_at DESC
                LIMIT ?
                """,  # noqa: S608 -- clauses are fixed application strings
                parameters,
            ).fetchall()
        return [dict(row) for row in rows]

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT report_json
                FROM analytics_reports
                WHERE report_id = ? AND telemetry_scope = 'operational'
                """,
                (report_id,),
            ).fetchone()
        if row is None:
            return None
        value = json.loads(str(row["report_json"]))
        return value if isinstance(value, dict) else None

    def list_findings(
        self,
        *,
        limit: int = 200,
        query: str | None = None,
        category: str | None = None,
        tag: str | None = None,
        source_type: str | None = None,
        days: int | None = None,
        priority_first: bool = False,
    ) -> list[dict[str, Any]]:
        base_clauses = ["r.telemetry_scope = 'operational'"]
        base_parameters: list[Any] = []
        clauses = ["f.recency_rank = 1"]
        filter_parameters: list[Any] = []
        if query:
            clauses.append("(f.finding_id LIKE ? OR f.title LIKE ?)")
            pattern = f"%{query}%"
            filter_parameters.extend((pattern, pattern))
        if category:
            clauses.append("f.category = ?")
            filter_parameters.append(category)
        if tag:
            clauses.append(
                "EXISTS (SELECT 1 FROM analytics_finding_tags ft "
                "WHERE ft.report_id = f.report_id AND ft.finding_id = f.finding_id "
                "AND ft.tag = ?)"
            )
            filter_parameters.append(tag)
        if source_type:
            clauses.append(
                "EXISTS (SELECT 1 FROM analytics_finding_sources fs "
                "WHERE fs.report_id = f.report_id AND fs.finding_id = f.finding_id "
                "AND fs.source_type = ?)"
            )
            filter_parameters.append(source_type)
        if days is not None:
            base_clauses.append("r.generated_at >= ?")
            base_parameters.append(
                (datetime.now(UTC) - timedelta(days=max(1, min(days, 3650)))).isoformat()
            )
        base_where = " AND ".join(base_clauses)
        where = " AND ".join(clauses)
        order = (
            "f.priority_score DESC, f.generated_at DESC, f.finding_id"
            if priority_first
            else "f.generated_at DESC, f.priority_score DESC, f.finding_id"
        )
        parameters = [
            *base_parameters,
            *filter_parameters,
            max(1, min(limit, 1000)),
        ]
        with self._connection() as connection:
            rows = connection.execute(
                f"""
                WITH ranked_findings AS (
                  SELECT f.*, r.generated_at, r.edition,
                         ROW_NUMBER() OVER (
                           PARTITION BY f.finding_id
                           ORDER BY r.generated_at DESC, r.report_id DESC
                         ) AS recency_rank
                  FROM analytics_findings f
                  JOIN analytics_reports r ON r.report_id = f.report_id
                  WHERE {base_where}
                )
                SELECT f.finding_id, f.report_id, f.title, f.category,
                       f.emergence_stage, f.publication_class, f.priority_score,
                       f.confidence_level, f.confidence_probability,
                       f.first_observed_at, f.lead_time_hours,
                       f.generated_at, f.edition,
                       COALESCE((
                         SELECT GROUP_CONCAT(tag, '|')
                         FROM (
                           SELECT ft.tag AS tag
                           FROM analytics_finding_tags ft
                           WHERE ft.report_id = f.report_id
                             AND ft.finding_id = f.finding_id
                           ORDER BY ft.tag
                         )
                       ), '') AS tags,
                       COALESCE((
                         SELECT GROUP_CONCAT(source_type, '|')
                         FROM (
                           SELECT DISTINCT fs.source_type AS source_type
                           FROM analytics_finding_sources fs
                           WHERE fs.report_id = f.report_id
                             AND fs.finding_id = f.finding_id
                           ORDER BY fs.source_type
                         )
                       ), '') AS source_types
                FROM ranked_findings f
                WHERE {where}
                ORDER BY {order}
                LIMIT ?
                """,  # noqa: S608 -- clauses are fixed application strings
                parameters,
            ).fetchall()
        return [_finding_row(row) for row in rows]

    def taxonomy_options(self) -> dict[str, list[str]]:
        with self._connection() as connection:
            categories = connection.execute(
                """
                SELECT DISTINCT f.category
                FROM analytics_findings f
                JOIN analytics_reports r ON r.report_id = f.report_id
                WHERE r.telemetry_scope = 'operational'
                ORDER BY f.category
                """
            ).fetchall()
            tags = connection.execute(
                """
                SELECT DISTINCT t.tag
                FROM analytics_finding_tags t
                JOIN analytics_reports r ON r.report_id = t.report_id
                WHERE r.telemetry_scope = 'operational'
                ORDER BY t.tag
                """
            ).fetchall()
            source_types = connection.execute(
                """
                SELECT DISTINCT s.source_type
                FROM analytics_finding_sources s
                JOIN analytics_reports r ON r.report_id = s.report_id
                WHERE r.telemetry_scope = 'operational'
                ORDER BY s.source_type
                """
            ).fetchall()
        return {
            "categories": [str(row["category"]) for row in categories],
            "tags": [str(row["tag"]) for row in tags],
            "source_types": [str(row["source_type"]) for row in source_types],
        }

    def taxonomy_counts(self, *, days: int = 30) -> dict[str, list[dict[str, Any]]]:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._connection() as connection:
            categories = connection.execute(
                """
                WITH latest_findings AS (
                  SELECT *
                  FROM (
                    SELECT f.category, f.finding_id, f.report_id,
                           ROW_NUMBER() OVER (
                             PARTITION BY f.finding_id
                             ORDER BY r.generated_at DESC, r.report_id DESC
                           ) AS recency_rank
                    FROM analytics_findings f
                    JOIN analytics_reports r ON r.report_id = f.report_id
                    WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                  )
                  WHERE recency_rank = 1
                )
                SELECT f.category AS name, COUNT(*) AS findings
                FROM latest_findings f
                GROUP BY f.category
                ORDER BY findings DESC, name
                """,
                (since,),
            ).fetchall()
            tags = connection.execute(
                """
                WITH latest_findings AS (
                  SELECT *
                  FROM (
                    SELECT f.finding_id, f.report_id,
                           ROW_NUMBER() OVER (
                             PARTITION BY f.finding_id
                             ORDER BY r.generated_at DESC, r.report_id DESC
                           ) AS recency_rank
                    FROM analytics_findings f
                    JOIN analytics_reports r ON r.report_id = f.report_id
                    WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                  )
                  WHERE recency_rank = 1
                )
                SELECT t.tag AS name, COUNT(*) AS findings
                FROM analytics_finding_tags t
                JOIN latest_findings f
                  ON f.report_id = t.report_id AND f.finding_id = t.finding_id
                GROUP BY t.tag
                ORDER BY findings DESC, name
                """,
                (since,),
            ).fetchall()
        return {
            "categories": [dict(row) for row in categories],
            "tags": [dict(row) for row in tags],
        }

    def daily_trend(self, *, days: int = 30) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._connection() as connection:
            rows = connection.execute(
                """
                WITH report_days AS (
                  SELECT substr(generated_at, 1, 10) AS day,
                         COUNT(*) AS reports,
                         SUM(degraded_source_count) AS degraded
                  FROM analytics_reports
                  WHERE telemetry_scope = 'operational' AND generated_at >= ?
                  GROUP BY substr(generated_at, 1, 10)
                ),
                ranked_findings AS (
                  SELECT substr(r.generated_at, 1, 10) AS day,
                         f.finding_id, f.priority_score, f.publication_class,
                         ROW_NUMBER() OVER (
                           PARTITION BY substr(r.generated_at, 1, 10), f.finding_id
                           ORDER BY r.generated_at DESC, r.report_id DESC
                         ) AS recency_rank
                  FROM analytics_findings f
                  JOIN analytics_reports r ON r.report_id = f.report_id
                  WHERE r.telemetry_scope = 'operational' AND r.generated_at >= ?
                ),
                finding_days AS (
                  SELECT day,
                         COUNT(*) AS findings,
                         MAX(priority_score) AS max_score,
                         SUM(CASE WHEN publication_class = 'flash' THEN 1 ELSE 0 END) AS flash,
                         SUM(CASE WHEN publication_class = 'watch' THEN 1 ELSE 0 END) AS watch,
                         SUM(CASE WHEN publication_class = 'daily' THEN 1 ELSE 0 END) AS daily
                  FROM ranked_findings
                  WHERE recency_rank = 1
                  GROUP BY day
                )
                SELECT r.day, r.reports,
                       COALESCE(f.findings, 0) AS findings,
                       COALESCE(f.max_score, 0) AS max_score,
                       COALESCE(f.flash, 0) AS flash,
                       COALESCE(f.watch, 0) AS watch,
                       COALESCE(f.daily, 0) AS daily,
                       r.degraded
                FROM report_days r
                LEFT JOIN finding_days f ON f.day = r.day
                ORDER BY r.day
                """,
                (since, since),
            ).fetchall()
        return [dict(row) for row in rows]

    def source_health(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT source_id, status, last_success_at,
                       freshness_seconds, error_rate, generated_at
                FROM (
                  SELECT h.source_id, h.status, h.last_success_at,
                         h.freshness_seconds, h.error_rate, r.generated_at,
                         ROW_NUMBER() OVER (
                           PARTITION BY h.source_id
                           ORDER BY r.generated_at DESC, r.report_id DESC
                         ) AS recency_rank
                  FROM analytics_source_health h
                  JOIN analytics_reports r ON r.report_id = h.report_id
                  WHERE r.telemetry_scope = 'operational'
                )
                WHERE recency_rank = 1
                ORDER BY source_id
                LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def event_summary(self, *, days: int = 30) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT metric, unit, COUNT(*) AS events, SUM(value) AS total_value,
                       MAX(occurred_at) AS latest_at
                FROM analytics_events
                WHERE telemetry_scope = 'operational' AND occurred_at >= ?
                GROUP BY metric, unit
                ORDER BY latest_at DESC, metric, unit
                """,
                (since,),
            ).fetchall()
        return [dict(row) for row in rows]

    def export_rows(self) -> list[dict[str, Any]]:
        return self.list_reports(limit=500)

    def export_finding_rows(self) -> list[dict[str, Any]]:
        return self.list_findings(limit=1000)

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS analytics_meta (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO analytics_meta (key, value)
                  VALUES ('schema_version', '4');
                CREATE TABLE IF NOT EXISTS analytics_reports (
                  report_id TEXT PRIMARY KEY,
                  generated_at TEXT NOT NULL,
                  edition TEXT NOT NULL,
                  finding_count INTEGER NOT NULL,
                  max_score REAL NOT NULL,
                  mean_score REAL NOT NULL,
                  flash_count INTEGER NOT NULL,
                  watch_count INTEGER NOT NULL,
                  daily_count INTEGER NOT NULL,
                  archive_count INTEGER NOT NULL,
                  degraded_source_count INTEGER NOT NULL,
                  request_count INTEGER NOT NULL,
                  token_count INTEGER NOT NULL,
                  estimated_cost REAL NOT NULL,
                  report_path TEXT NOT NULL,
                  html_path TEXT,
                  report_hash TEXT NOT NULL,
                  report_json TEXT NOT NULL,
                  telemetry_scope TEXT NOT NULL DEFAULT 'fixture'
                    CHECK (telemetry_scope IN ('operational', 'fixture')),
                  indexed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS analytics_reports_generated_idx
                  ON analytics_reports (generated_at DESC);
                CREATE TABLE IF NOT EXISTS analytics_findings (
                  finding_id TEXT NOT NULL,
                  report_id TEXT NOT NULL REFERENCES analytics_reports(report_id),
                  title TEXT NOT NULL,
                  category TEXT NOT NULL,
                  emergence_stage TEXT NOT NULL,
                  publication_class TEXT NOT NULL,
                  priority_score REAL NOT NULL,
                  confidence_level TEXT NOT NULL,
                  confidence_probability REAL NOT NULL,
                  first_observed_at TEXT NOT NULL,
                  lead_time_hours REAL,
                  PRIMARY KEY (report_id, finding_id)
                );
                CREATE INDEX IF NOT EXISTS analytics_findings_score_idx
                  ON analytics_findings (priority_score DESC);
                CREATE INDEX IF NOT EXISTS analytics_findings_category_idx
                  ON analytics_findings (category, priority_score DESC);
                CREATE TABLE IF NOT EXISTS analytics_finding_tags (
                  report_id TEXT NOT NULL,
                  finding_id TEXT NOT NULL,
                  tag TEXT NOT NULL,
                  PRIMARY KEY (report_id, finding_id, tag),
                  FOREIGN KEY (report_id, finding_id)
                    REFERENCES analytics_findings (report_id, finding_id)
                );
                CREATE INDEX IF NOT EXISTS analytics_finding_tags_tag_idx
                  ON analytics_finding_tags (tag, report_id);
                CREATE TABLE IF NOT EXISTS analytics_finding_sources (
                  report_id TEXT NOT NULL,
                  finding_id TEXT NOT NULL,
                  evidence_id TEXT NOT NULL,
                  source_id TEXT NOT NULL,
                  source_type TEXT NOT NULL,
                  source_url TEXT NOT NULL,
                  PRIMARY KEY (report_id, finding_id, evidence_id),
                  FOREIGN KEY (report_id, finding_id)
                    REFERENCES analytics_findings (report_id, finding_id)
                );
                CREATE INDEX IF NOT EXISTS analytics_finding_sources_type_idx
                  ON analytics_finding_sources (source_type, report_id);
                CREATE TABLE IF NOT EXISTS analytics_source_health (
                  report_id TEXT NOT NULL REFERENCES analytics_reports(report_id),
                  source_id TEXT NOT NULL,
                  status TEXT NOT NULL,
                  last_success_at TEXT,
                  freshness_seconds INTEGER,
                  error_rate REAL NOT NULL,
                  PRIMARY KEY (report_id, source_id)
                );
                CREATE TABLE IF NOT EXISTS analytics_usage (
                  report_id TEXT NOT NULL REFERENCES analytics_reports(report_id),
                  usage_index INTEGER NOT NULL,
                  stage TEXT NOT NULL,
                  provider TEXT NOT NULL,
                  model TEXT NOT NULL,
                  requests INTEGER NOT NULL,
                  input_tokens INTEGER NOT NULL,
                  output_tokens INTEGER NOT NULL,
                  estimated_cost REAL NOT NULL,
                  PRIMARY KEY (report_id, usage_index)
                );
                CREATE INDEX IF NOT EXISTS analytics_usage_provider_idx
                  ON analytics_usage (provider, model, report_id);
                CREATE INDEX IF NOT EXISTS analytics_usage_stage_idx
                  ON analytics_usage (stage, report_id);
                CREATE TABLE IF NOT EXISTS analytics_events (
                  event_id TEXT PRIMARY KEY,
                  occurred_at TEXT NOT NULL,
                  run_id TEXT,
                  metric TEXT NOT NULL,
                  value REAL NOT NULL,
                  unit TEXT NOT NULL,
                  dimensions_json TEXT NOT NULL,
                  telemetry_scope TEXT NOT NULL DEFAULT 'operational'
                    CHECK (telemetry_scope IN ('operational', 'fixture'))
                );
                CREATE INDEX IF NOT EXISTS analytics_events_metric_idx
                  ON analytics_events (metric, occurred_at DESC);
                """
            )
            report_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(analytics_reports)").fetchall()
            }
            if "telemetry_scope" not in report_columns:
                connection.execute(
                    "ALTER TABLE analytics_reports "
                    "ADD COLUMN telemetry_scope TEXT NOT NULL DEFAULT 'fixture'"
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS analytics_reports_scope_generated_idx "
                "ON analytics_reports (telemetry_scope, generated_at DESC)"
            )
            event_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(analytics_events)").fetchall()
            }
            if "telemetry_scope" not in event_columns:
                connection.execute(
                    "ALTER TABLE analytics_events "
                    "ADD COLUMN telemetry_scope TEXT NOT NULL DEFAULT 'operational'"
                )
            version = connection.execute(
                "SELECT value FROM analytics_meta WHERE key = 'schema_version'"
            ).fetchone()
            if version is not None and str(version["value"]) in {"1", "2", "3"}:
                for row in connection.execute(
                    "SELECT report_id, report_json FROM analytics_reports"
                ).fetchall():
                    try:
                        report = json.loads(str(row["report_json"]))
                    except json.JSONDecodeError:
                        report = None
                    scope = (
                        _report_telemetry_scope(report)
                        if isinstance(report, dict)
                        else "fixture"
                    )
                    connection.execute(
                        "UPDATE analytics_reports SET telemetry_scope = ? WHERE report_id = ?",
                        (scope, str(row["report_id"])),
                    )
                connection.execute(
                    """
                    UPDATE analytics_events
                    SET telemetry_scope = 'fixture'
                    WHERE metric = 'report.indexed'
                      AND json_extract(dimensions_json, '$.report_id') IN (
                        SELECT report_id
                        FROM analytics_reports
                        WHERE telemetry_scope = 'fixture'
                      )
                    """
                )
                connection.execute(
                    "UPDATE analytics_meta SET value = '4' WHERE key = 'schema_version'"
                )
                version = connection.execute(
                    "SELECT value FROM analytics_meta WHERE key = 'schema_version'"
                ).fetchone()
            if version is None or str(version["value"]) != "4":
                raise RuntimeError("unsupported analytics schema")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()


def _run_id_from_path(path: Path) -> str | None:
    for part in path.parts:
        if part.startswith("run_"):
            return part
    return None


def _report_telemetry_scope(
    report: dict[str, Any],
) -> Literal["operational", "fixture"]:
    discovery = report.get("discovery_telemetry")
    if not isinstance(discovery, dict):
        return "fixture"
    surfaces = discovery.get("surfaces")
    if not isinstance(surfaces, list):
        return "fixture"
    return "operational"


def _index_finding_dimensions(
    connection: sqlite3.Connection,
    *,
    report_id: str,
    findings: list[dict[str, Any]],
) -> None:
    for finding in findings:
        confidence = finding.get("confidence", {})
        connection.execute(
            """
            INSERT OR IGNORE INTO analytics_findings (
              finding_id, report_id, title, category, emergence_stage,
              publication_class, priority_score, confidence_level,
              confidence_probability, first_observed_at, lead_time_hours
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(finding["finding_id"]),
                report_id,
                str(finding["title"]),
                str(finding["category"]),
                str(finding["emergence_stage"]),
                str(finding["publication_class"]),
                float(finding["priority_score"]),
                str(confidence.get("level", "low")),
                float(confidence.get("probability", 0)),
                str(finding["first_observed_at"]),
                finding.get("lead_time_hours"),
            ),
        )
        raw_tags = finding.get("tags")
        if isinstance(raw_tags, list):
            tags = [item for item in raw_tags if isinstance(item, str)]
        else:
            identifiers = tuple(
                str(mapping["identifier"])
                for mapping in finding.get("mappings", [])
                if isinstance(mapping, dict) and isinstance(mapping.get("identifier"), str)
            )
            taxonomy = classify_taxonomy(
                str(finding.get("title", "")),
                "\n".join(
                    [
                        str(finding.get("why_now", "")),
                        *(str(item) for item in finding.get("known", [])),
                    ]
                ),
                identifiers=identifiers,
            )
            tags = list(taxonomy.tags)
        for tag in tags:
            if isinstance(tag, str):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO analytics_finding_tags (
                      report_id, finding_id, tag
                    ) VALUES (?, ?, ?)
                    """,
                    (report_id, str(finding["finding_id"]), tag),
                )
        for source in finding.get("source_evidence", []):
            if not isinstance(source, dict):
                continue
            connection.execute(
                """
                INSERT OR IGNORE INTO analytics_finding_sources (
                  report_id, finding_id, evidence_id, source_id,
                  source_type, source_url
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    str(finding["finding_id"]),
                    str(source["evidence_id"]),
                    str(source["source_id"]),
                    str(source["source_type"]),
                    str(source["url"]),
                ),
            )


def _index_usage_dimensions(
    connection: sqlite3.Connection,
    *,
    report_id: str,
    usage: list[dict[str, Any]],
) -> None:
    for index, item in enumerate(usage):
        connection.execute(
            """
            INSERT INTO analytics_usage (
              report_id, usage_index, stage, provider, model, requests,
              input_tokens, output_tokens, estimated_cost
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (report_id, usage_index) DO UPDATE SET
              stage = excluded.stage,
              provider = excluded.provider,
              model = excluded.model,
              requests = excluded.requests,
              input_tokens = excluded.input_tokens,
              output_tokens = excluded.output_tokens,
              estimated_cost = excluded.estimated_cost
            """,
            (
                report_id,
                index,
                str(item["stage"]),
                str(item["provider"]),
                str(item["model"]),
                int(item.get("requests", 0)),
                int(item.get("input_tokens", 0)),
                int(item.get("output_tokens", 0)),
                _usage_cost(item),
            ),
        )


def _usage_cost(item: dict[str, Any]) -> float:
    reported = float(item.get("estimated_currency", 0))
    if reported > 0:
        return reported
    if str(item.get("provider", "")).lower() == "brave":
        return round(int(item.get("requests", 0)) * BRAVE_COST_PER_REQUEST, 6)
    return 0.0


def _cost_rows(
    rows: list[sqlite3.Row],
    *,
    estimated_cost: float,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item_cost = float(item["estimated_cost"])
        item["estimated_cost"] = item_cost
        item["cost_share"] = round(item_cost / estimated_cost * 100, 1) if estimated_cost else 0.0
        result.append(item)
    return result


def _finding_row(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    value["tags"] = [item for item in str(value["tags"]).split("|") if item]
    value["source_types"] = [item for item in str(value["source_types"]).split("|") if item]
    return value

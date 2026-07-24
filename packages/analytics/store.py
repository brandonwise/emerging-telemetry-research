from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from packages.common.canonical import canonical_json_bytes, sha256_hex, stable_id
from packages.contracts.validation import validate_payload
from packages.discovery.emerging import classify_taxonomy
from packages.verification.claims import require_verified_report


@dataclass(frozen=True, slots=True)
class IndexResult:
    report_id: str
    inserted: bool
    finding_count: int


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
    ) -> IndexResult:
        validate_payload("report.schema.json", report)
        require_verified_report(report)
        encoded = canonical_json_bytes(report)
        report_hash = sha256_hex(encoded)
        report_id = str(report["report_id"])
        findings = [item for item in report["findings"] if isinstance(item, dict)]
        scores = [float(item["priority_score"]) for item in findings]
        usage = [item for item in report["usage"] if isinstance(item, dict)]
        source_health = [
            item for item in report["source_health"] if isinstance(item, dict)
        ]
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
            sum(float(item.get("estimated_currency", 0)) for item in usage),
            str(report_path.resolve()),
            str(html_path.resolve()) if html_path is not None else None,
            report_hash,
            encoded.decode("utf-8"),
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT report_hash FROM analytics_reports WHERE report_id = ?",
                (report_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["report_hash"]) != report_hash:
                    raise ValueError(f"immutable analytics conflict for {report_id}")
                _index_finding_dimensions(
                    connection,
                    report_id=report_id,
                    findings=findings,
                )
                connection.commit()
                return IndexResult(report_id, False, len(findings))
            connection.execute(
                """
                INSERT INTO analytics_reports (
                  report_id, generated_at, edition, finding_count, max_score,
                  mean_score, flash_count, watch_count, daily_count, archive_count,
                  degraded_source_count, request_count, token_count, estimated_cost,
                  report_path, html_path, report_hash, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            _index_finding_dimensions(
                connection,
                report_id=report_id,
                findings=findings,
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
        )
        return IndexResult(report_id, True, len(findings))

    def index_path(self, report_path: Path) -> IndexResult:
        value = json.loads(report_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("report JSON must contain one object")
        html_path = report_path.with_suffix(".html")
        return self.index_report(
            value,
            report_path=report_path,
            html_path=html_path if html_path.is_file() else None,
        )

    def sync_reports(self, reports_root: Path) -> dict[str, int]:
        inserted = 0
        unchanged = 0
        skipped = 0
        if not reports_root.exists():
            return {"inserted": 0, "unchanged": 0, "skipped": 0}
        for path in sorted(reports_root.rglob("rp_*.json")):
            relative_parts = path.relative_to(reports_root).parts
            if (
                path.name.endswith(".delivery.json")
                or "candidates" in relative_parts
                or "improvement" in relative_parts
            ):
                skipped += 1
                continue
            result = self.index_path(path)
            if result.inserted:
                inserted += 1
            else:
                unchanged += 1
        return {"inserted": inserted, "unchanged": unchanged, "skipped": skipped}

    def record_event(
        self,
        *,
        metric: str,
        value: float,
        unit: str,
        dimensions: dict[str, str],
        occurred_at: str | None = None,
        run_id: str | None = None,
    ) -> str:
        if not metric or len(metric) > 100:
            raise ValueError("metric must contain 1 to 100 characters")
        if len(dimensions) > 20 or any(
            len(key) > 100 or len(item) > 300
            for key, item in dimensions.items()
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
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO analytics_events (
                  event_id, occurred_at, run_id, metric, value, unit, dimensions_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, timestamp, run_id, metric, value, unit, dimensions_text),
            )
        return event_id

    def overview(self, *, days: int = 30) -> dict[str, Any]:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._connect() as connection:
            totals = connection.execute(
                """
                SELECT COUNT(*) AS reports,
                       COALESCE(SUM(finding_count), 0) AS findings,
                       COALESCE(MAX(max_score), 0) AS max_score,
                       COALESCE(SUM(degraded_source_count), 0) AS degraded,
                       COALESCE(SUM(request_count), 0) AS requests,
                       COALESCE(SUM(token_count), 0) AS tokens,
                       COALESCE(SUM(estimated_cost), 0) AS estimated_cost
                FROM analytics_reports
                WHERE generated_at >= ?
                """,
                (since,),
            ).fetchone()
            latest = connection.execute(
                """
                SELECT report_id, generated_at, edition, finding_count, max_score
                FROM analytics_reports
                ORDER BY generated_at DESC
                LIMIT 1
                """
            ).fetchone()
            event_count = connection.execute(
                """
                SELECT COUNT(*) AS events
                FROM analytics_events
                WHERE occurred_at >= ?
                """,
                (since,),
            ).fetchone()
        assert totals is not None
        assert event_count is not None
        return {
            "days": days,
            "reports": int(totals["reports"]),
            "findings": int(totals["findings"]),
            "max_score": float(totals["max_score"]),
            "degraded": int(totals["degraded"]),
            "requests": int(totals["requests"]),
            "tokens": int(totals["tokens"]),
            "estimated_cost": float(totals["estimated_cost"]),
            "events": int(event_count["events"]),
            "latest": dict(latest) if latest is not None else None,
        }

    def list_reports(
        self,
        *,
        limit: int = 100,
        edition: str | None = None,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
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
        with self._connect() as connection:
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
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT report_json
                FROM analytics_reports
                WHERE report_id = ?
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
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[Any] = []
        if query:
            clauses.append("(f.finding_id LIKE ? OR f.title LIKE ?)")
            pattern = f"%{query}%"
            parameters.extend((pattern, pattern))
        if category:
            clauses.append("f.category = ?")
            parameters.append(category)
        if tag:
            clauses.append(
                "EXISTS (SELECT 1 FROM analytics_finding_tags ft "
                "WHERE ft.report_id = f.report_id AND ft.finding_id = f.finding_id "
                "AND ft.tag = ?)"
            )
            parameters.append(tag)
        if source_type:
            clauses.append(
                "EXISTS (SELECT 1 FROM analytics_finding_sources fs "
                "WHERE fs.report_id = f.report_id AND fs.finding_id = f.finding_id "
                "AND fs.source_type = ?)"
            )
            parameters.append(source_type)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        parameters.append(max(1, min(limit, 1000)))
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                SELECT f.finding_id, f.report_id, f.title, f.category,
                       f.emergence_stage, f.publication_class, f.priority_score,
                       f.confidence_level, f.confidence_probability,
                       f.first_observed_at, f.lead_time_hours,
                       r.generated_at, r.edition,
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
                FROM analytics_findings f
                JOIN analytics_reports r ON r.report_id = f.report_id
                {where}
                ORDER BY r.generated_at DESC, f.priority_score DESC, f.finding_id
                LIMIT ?
                """,  # noqa: S608 -- clauses are fixed application strings
                parameters,
            ).fetchall()
        return [_finding_row(row) for row in rows]

    def taxonomy_options(self) -> dict[str, list[str]]:
        with self._connect() as connection:
            categories = connection.execute(
                "SELECT DISTINCT category FROM analytics_findings ORDER BY category"
            ).fetchall()
            tags = connection.execute(
                "SELECT DISTINCT tag FROM analytics_finding_tags ORDER BY tag"
            ).fetchall()
            source_types = connection.execute(
                "SELECT DISTINCT source_type FROM analytics_finding_sources "
                "ORDER BY source_type"
            ).fetchall()
        return {
            "categories": [str(row["category"]) for row in categories],
            "tags": [str(row["tag"]) for row in tags],
            "source_types": [str(row["source_type"]) for row in source_types],
        }

    def taxonomy_counts(self, *, days: int = 30) -> dict[str, list[dict[str, Any]]]:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._connect() as connection:
            categories = connection.execute(
                """
                SELECT f.category AS name, COUNT(*) AS findings
                FROM analytics_findings f
                JOIN analytics_reports r ON r.report_id = f.report_id
                WHERE r.generated_at >= ?
                GROUP BY f.category
                ORDER BY findings DESC, name
                """,
                (since,),
            ).fetchall()
            tags = connection.execute(
                """
                SELECT t.tag AS name, COUNT(*) AS findings
                FROM analytics_finding_tags t
                JOIN analytics_reports r ON r.report_id = t.report_id
                WHERE r.generated_at >= ?
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
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT substr(generated_at, 1, 10) AS day,
                       COUNT(*) AS reports,
                       SUM(finding_count) AS findings,
                       MAX(max_score) AS max_score,
                       SUM(flash_count) AS flash,
                       SUM(watch_count) AS watch,
                       SUM(daily_count) AS daily,
                       SUM(degraded_source_count) AS degraded
                FROM analytics_reports
                WHERE generated_at >= ?
                GROUP BY substr(generated_at, 1, 10)
                ORDER BY day
                """,
                (since,),
            ).fetchall()
        return [dict(row) for row in rows]

    def source_health(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT h.source_id, h.status, h.last_success_at,
                       h.freshness_seconds, h.error_rate, r.generated_at
                FROM analytics_source_health h
                JOIN analytics_reports r ON r.report_id = h.report_id
                ORDER BY r.generated_at DESC, h.source_id
                LIMIT ?
                """,
                (max(1, min(limit, 1000)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def event_summary(self, *, days: int = 30) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT metric, COUNT(*) AS events, SUM(value) AS total_value,
                       MAX(occurred_at) AS latest_at
                FROM analytics_events
                WHERE occurred_at >= ?
                GROUP BY metric
                ORDER BY latest_at DESC, metric
                """,
                (since,),
            ).fetchall()
        return [dict(row) for row in rows]

    def export_rows(self) -> list[dict[str, Any]]:
        return self.list_reports(limit=500)

    def export_finding_rows(self) -> list[dict[str, Any]]:
        return self.list_findings(limit=1000)

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS analytics_meta (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                INSERT OR IGNORE INTO analytics_meta (key, value)
                  VALUES ('schema_version', '2');
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
                CREATE TABLE IF NOT EXISTS analytics_events (
                  event_id TEXT PRIMARY KEY,
                  occurred_at TEXT NOT NULL,
                  run_id TEXT,
                  metric TEXT NOT NULL,
                  value REAL NOT NULL,
                  unit TEXT NOT NULL,
                  dimensions_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS analytics_events_metric_idx
                  ON analytics_events (metric, occurred_at DESC);
                """
            )
            version = connection.execute(
                "SELECT value FROM analytics_meta WHERE key = 'schema_version'"
            ).fetchone()
            if version is not None and str(version["value"]) == "1":
                connection.execute(
                    "UPDATE analytics_meta SET value = '2' WHERE key = 'schema_version'"
                )
                version = connection.execute(
                    "SELECT value FROM analytics_meta WHERE key = 'schema_version'"
                ).fetchone()
            if version is None or str(version["value"]) != "2":
                raise RuntimeError("unsupported analytics schema")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection


def _run_id_from_path(path: Path) -> str | None:
    for part in path.parts:
        if part.startswith("run_"):
            return part
    return None


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
                if isinstance(mapping, dict)
                and isinstance(mapping.get("identifier"), str)
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


def _finding_row(row: sqlite3.Row) -> dict[str, Any]:
    value = dict(row)
    value["tags"] = [item for item in str(value["tags"]).split("|") if item]
    value["source_types"] = [
        item for item in str(value["source_types"]).split("|") if item
    ]
    return value

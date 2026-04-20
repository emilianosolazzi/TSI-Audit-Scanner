#!/usr/bin/env python3
"""
Scanner Scheduler — Autonomous crawl loop for continuous bug hunting.

Modes:
  - one-shot: scan a single repo/address and exit
  - watch: periodically re-scan configured targets
  - crawl: discover new targets from Immunefi/Code4rena scope lists

Stores scan history in SQLite to avoid redundant re-scans.
"""

import os
import sys
import json
import time
import logging
import sqlite3
import hashlib
import threading
import requests
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

# Windows consoles default to cp1252 which can't encode the unicode box-drawing
# characters used in the summary printer.  Reconfigure to UTF-8 if possible.
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

logger = logging.getLogger("ScanScheduler")


@dataclass
class ScanTarget:
    """A target to be scanned."""
    id: str                     # Unique identifier
    target_type: str            # "repo", "address", "immunefi", "code4rena"
    url: str                    # GitHub URL or contract address
    chain: Optional[str] = None # For address targets
    branch: str = "main"
    scope_paths: Optional[List[str]] = None
    priority: int = 0           # Higher = scanned sooner
    interval_hours: int = 24    # Re-scan interval (0 = one-shot)
    added_at: Optional[str] = None
    last_scanned: Optional[str] = None
    last_findings: int = 0
    enabled: bool = True


@dataclass
class ScanRecord:
    """Record of a completed scan."""
    target_id: str
    scan_id: str
    started_at: str
    completed_at: str
    status: str             # "success", "failed"
    findings_count: int
    critical_count: int
    high_count: int
    commit_hash: Optional[str] = None
    result_path: Optional[str] = None


class ScanScheduler:
    """Manages scan targets and scheduling."""

    def __init__(self, db_path: str = "scan_history.db",
                 results_dir: str = "scan_results"):
        self.db_path = db_path
        self.results_dir = results_dir
        self._running = False
        self._lock = threading.Lock()
        self.alert_webhook_url = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
        self.alert_webhook_timeout = float(os.environ.get("ALERT_WEBHOOK_TIMEOUT", "5"))
        self.alert_webhook_retries = int(os.environ.get("ALERT_WEBHOOK_RETRIES", "2"))
        self.alert_high_delta_threshold = int(os.environ.get("ALERT_HIGH_DELTA_THRESHOLD", "1"))

        os.makedirs(results_dir, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()

    # ------------------------------------------------------------------
    # DATABASE
    # ------------------------------------------------------------------

    def _init_db(self):
        """Initialize SQLite schema."""
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                target_type TEXT NOT NULL,
                url TEXT NOT NULL,
                chain TEXT,
                branch TEXT DEFAULT 'main',
                scope_paths TEXT,
                priority INTEGER DEFAULT 0,
                interval_hours INTEGER DEFAULT 24,
                added_at TEXT,
                last_scanned TEXT,
                last_findings INTEGER DEFAULT 0,
                enabled INTEGER DEFAULT 1
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                scan_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                status TEXT,
                findings_count INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                commit_hash TEXT,
                result_path TEXT,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_history_target
            ON scan_history(target_id, completed_at)
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_events (
                alert_key TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                scan_id TEXT,
                created_at TEXT,
                severity TEXT,
                title TEXT,
                payload TEXT,
                status TEXT,
                attempts INTEGER DEFAULT 0,
                last_error TEXT,
                delivered_at TEXT
            )
        """)
        self._conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_target
            ON alert_events(target_id, created_at)
        """)
        self._conn.commit()

    def _load_risk_level(self, record: ScanRecord) -> Optional[str]:
        """Load risk level from persisted result file when available."""
        if not record.result_path:
            return None
        try:
            data = json.loads(Path(record.result_path).read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None
        scores = data.get("scores")
        if isinstance(scores, dict):
            return scores.get("risk_level")
        return None

    def _risk_rank(self, level: Optional[str]) -> int:
        return {
            "SAFE": 0,
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }.get((level or "").upper(), -1)

    def _make_alert_key(self, target_id: str, alert: Dict[str, Any]) -> str:
        delta = alert.get("delta", {})
        basis = (
            f"{target_id}|{delta.get('critical', 0)}|{delta.get('high', 0)}|"
            f"{delta.get('findings', 0)}|{alert.get('risk_transition', '')}"
        )
        return hashlib.sha256(basis.encode()).hexdigest()[:32]

    def _get_alert_event(self, alert_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                """SELECT alert_key, status, attempts, last_error, delivered_at
                   FROM alert_events WHERE alert_key = ?""",
                (alert_key,)
            ).fetchone()
        if not row:
            return None
        return {
            "alert_key": row[0],
            "delivery_status": row[1],
            "delivery_attempts": row[2],
            "delivery_error": row[3],
            "delivered_at": row[4],
        }

    def _record_alert_event(
        self,
        alert_key: str,
        target_id: str,
        scan_id: Optional[str],
        severity: str,
        title: str,
        payload: Dict[str, Any],
        status: str,
        attempts: int,
        last_error: Optional[str] = None,
        delivered_at: Optional[str] = None,
    ):
        created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO alert_events
                   (alert_key, target_id, scan_id, created_at, severity, title,
                    payload, status, attempts, last_error, delivered_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    alert_key,
                    target_id,
                    scan_id,
                    created_at,
                    severity,
                    title,
                    json.dumps(payload),
                    status,
                    attempts,
                    last_error,
                    delivered_at,
                ),
            )
            self._conn.commit()

    def list_alert_events(
        self,
        target_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List persisted alert delivery events."""
        query = (
            "SELECT alert_key, target_id, scan_id, created_at, severity, title, "
            "status, attempts, last_error, delivered_at "
            "FROM alert_events"
        )
        conditions: List[str] = []
        params: List[Any] = []

        if target_id:
            conditions.append("target_id = ?")
            params.append(target_id)
        if status:
            conditions.append("status = ?")
            params.append(status)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()

        return [
            {
                "alert_key": row[0],
                "target_id": row[1],
                "scan_id": row[2],
                "created_at": row[3],
                "severity": row[4],
                "title": row[5],
                "delivery_status": row[6],
                "delivery_attempts": row[7],
                "delivery_error": row[8],
                "delivered_at": row[9],
            }
            for row in rows
        ]

    def retry_alert_event(self, alert_key: str) -> Dict[str, Any]:
        """Retry delivery for one alert event by key."""
        with self._lock:
            row = self._conn.execute(
                """SELECT target_id, scan_id, severity, title, payload
                   FROM alert_events WHERE alert_key = ?""",
                (alert_key,)
            ).fetchone()

        if not row:
            return {
                "alert_key": alert_key,
                "status": "not_found",
                "message": "Alert event not found",
            }

        target_id, scan_id, severity, title, payload_raw = row
        try:
            payload = json.loads(payload_raw) if payload_raw else {}
        except Exception:
            payload = {}

        delivery = self._deliver_webhook(payload)
        self._record_alert_event(
            alert_key=alert_key,
            target_id=target_id,
            scan_id=scan_id,
            severity=severity,
            title=title,
            payload=payload,
            status=delivery["status"],
            attempts=delivery["attempts"],
            last_error=delivery.get("error"),
            delivered_at=delivery.get("delivered_at"),
        )

        return {
            "alert_key": alert_key,
            "target_id": target_id,
            "scan_id": scan_id,
            "delivery_status": delivery["status"],
            "delivery_attempts": delivery["attempts"],
            "delivery_error": delivery.get("error"),
            "delivered_at": delivery.get("delivered_at"),
        }

    def retry_failed_alerts(self, limit: int = 20) -> Dict[str, Any]:
        """Retry delivery for failed alert events."""
        failed = self.list_alert_events(status="failed", limit=limit)
        retried = [self.retry_alert_event(event["alert_key"]) for event in failed]
        return {
            "requested": limit,
            "failed_found": len(failed),
            "retried": len(retried),
            "results": retried,
        }

    def _deliver_webhook(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Deliver one alert payload to webhook with retries."""
        if not self.alert_webhook_url:
            return {
                "status": "disabled",
                "attempts": 0,
                "error": "ALERT_WEBHOOK_URL not configured",
                "delivered_at": None,
            }

        last_error = None
        attempts = 0
        for attempt in range(1, self.alert_webhook_retries + 2):
            attempts = attempt
            try:
                response = requests.post(
                    self.alert_webhook_url,
                    json=alert_payload,
                    timeout=self.alert_webhook_timeout,
                )
                if 200 <= response.status_code < 300:
                    return {
                        "status": "sent",
                        "attempts": attempts,
                        "error": None,
                        "delivered_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    }
                last_error = f"HTTP {response.status_code}: {response.text[:200]}"
            except Exception as exc:
                last_error = str(exc)

        return {
            "status": "failed",
            "attempts": attempts,
            "error": last_error,
            "delivered_at": None,
        }

    def dispatch_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Dispatch new alerts and persist delivery status; dedupe by alert key."""
        delivered: List[Dict[str, Any]] = []
        for alert in alerts:
            alert_key = alert.get("alert_key")
            if not alert_key:
                continue

            existing = self._get_alert_event(alert_key)
            if existing:
                merged = dict(alert)
                merged.update(existing)
                delivered.append(merged)
                continue

            payload = {
                "event": "scan_risk_worsened",
                "alert": alert,
            }
            delivery = self._deliver_webhook(payload)
            self._record_alert_event(
                alert_key=alert_key,
                target_id=alert.get("target_id", ""),
                scan_id=alert.get("scan_id"),
                severity=alert.get("severity", "medium"),
                title=alert.get("title", "Risk worsened"),
                payload=payload,
                status=delivery["status"],
                attempts=delivery["attempts"],
                last_error=delivery.get("error"),
                delivered_at=delivery.get("delivered_at"),
            )
            merged = dict(alert)
            merged.update({
                "delivery_status": delivery["status"],
                "delivery_attempts": delivery["attempts"],
                "delivery_error": delivery.get("error"),
                "delivered_at": delivery.get("delivered_at"),
            })
            delivered.append(merged)
        return delivered

    def _target_to_row(self, t: ScanTarget) -> tuple:
        return (
            t.id, t.target_type, t.url, t.chain, t.branch,
            json.dumps(t.scope_paths) if t.scope_paths else None,
            t.priority, t.interval_hours,
            t.added_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            t.last_scanned, t.last_findings, 1 if t.enabled else 0
        )

    def _row_to_target(self, row: tuple) -> ScanTarget:
        return ScanTarget(
            id=row[0], target_type=row[1], url=row[2],
            chain=row[3], branch=row[4],
            scope_paths=json.loads(row[5]) if row[5] else None,
            priority=row[6], interval_hours=row[7],
            added_at=row[8], last_scanned=row[9],
            last_findings=row[10], enabled=bool(row[11])
        )

    # ------------------------------------------------------------------
    # TARGET MANAGEMENT
    # ------------------------------------------------------------------

    def add_target(self, target: ScanTarget) -> str:
        """Add a new scan target. Returns target ID."""
        if not target.id:
            target.id = hashlib.sha256(
                f"{target.target_type}:{target.url}:{target.chain}".encode()
            ).hexdigest()[:16]

        target.added_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO targets
                   (id, target_type, url, chain, branch, scope_paths,
                    priority, interval_hours, added_at, last_scanned,
                    last_findings, enabled)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                self._target_to_row(target)
            )
            self._conn.commit()
        logger.info(f"Added target: {target.id} ({target.url})")
        return target.id

    def remove_target(self, target_id: str):
        """Remove a target."""
        with self._lock:
            self._conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            self._conn.commit()

    def list_targets(self, enabled_only: bool = True) -> List[ScanTarget]:
        """List all scan targets."""
        with self._lock:
            query = "SELECT * FROM targets"
            if enabled_only:
                query += " WHERE enabled = 1"
            query += " ORDER BY priority DESC, added_at ASC"
            rows = self._conn.execute(query).fetchall()
        return [self._row_to_target(r) for r in rows]

    def get_target(self, target_id: str) -> Optional[ScanTarget]:
        """Get a specific target."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
        return self._row_to_target(row) if row else None

    # ------------------------------------------------------------------
    # SCAN EXECUTION
    # ------------------------------------------------------------------

    def get_due_targets(self) -> List[ScanTarget]:
        """Get targets that are due for scanning."""
        targets = self.list_targets(enabled_only=True)
        now = datetime.now(timezone.utc)
        due = []

        for t in targets:
            if not t.last_scanned:
                due.append(t)
                continue
            if t.interval_hours == 0:
                continue  # one-shot, already done

            last = datetime.fromisoformat(t.last_scanned.rstrip("Z"))
            if now - last >= timedelta(hours=t.interval_hours):
                due.append(t)

        return sorted(due, key=lambda t: -t.priority)

    def record_scan(self, target_id: str, scan_id: str,
                    started_at: str, completed_at: str,
                    status: str, findings_count: int,
                    critical_count: int, high_count: int,
                    commit_hash: Optional[str] = None,
                    result_path: Optional[str] = None):
        """Record a completed scan."""
        with self._lock:
            self._conn.execute(
                """INSERT INTO scan_history
                   (scan_id, target_id, started_at, completed_at, status,
                    findings_count, critical_count, high_count,
                    commit_hash, result_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, target_id, started_at, completed_at, status,
                 findings_count, critical_count, high_count,
                 commit_hash, result_path)
            )
            self._conn.execute(
                """UPDATE targets SET last_scanned = ?, last_findings = ?
                   WHERE id = ?""",
                (completed_at, findings_count, target_id)
            )
            self._conn.commit()

    def get_scan_history(self, target_id: str, limit: int = 10) -> List[ScanRecord]:
        """Get scan history for a target."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT target_id, scan_id, started_at, completed_at,
                          status, findings_count, critical_count, high_count,
                          commit_hash, result_path
                   FROM scan_history
                   WHERE target_id = ?
                   ORDER BY completed_at DESC
                   LIMIT ?""",
                (target_id, limit)
            ).fetchall()
        return [
            ScanRecord(
                target_id=r[0], scan_id=r[1], started_at=r[2],
                completed_at=r[3], status=r[4], findings_count=r[5],
                critical_count=r[6], high_count=r[7],
                commit_hash=r[8], result_path=r[9]
            )
            for r in rows
        ]

    def get_scan_alerts(self, target_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Compute change alerts by comparing consecutive successful scans."""
        history = self.get_scan_history(target_id, limit=max(limit + 1, 2))
        successful = [h for h in history if h.status == "complete"]
        alerts: List[Dict[str, Any]] = []

        for idx in range(len(successful) - 1):
            current = successful[idx]
            previous = successful[idx + 1]

            critical_delta = current.critical_count - previous.critical_count
            high_delta = current.high_count - previous.high_count
            findings_delta = current.findings_count - previous.findings_count
            current_risk = self._load_risk_level(current)
            previous_risk = self._load_risk_level(previous)
            risk_worsened = self._risk_rank(current_risk) > self._risk_rank(previous_risk)

            meaningful_change = (
                critical_delta > 0
                or high_delta >= self.alert_high_delta_threshold
                or risk_worsened
            )

            if not meaningful_change:
                continue

            if critical_delta > 0:
                severity = "critical"
                title = "Critical findings increased"
            elif risk_worsened:
                severity = "high"
                title = f"Risk level worsened ({previous_risk or 'UNKNOWN'} -> {current_risk or 'UNKNOWN'})"
            elif high_delta > 0:
                severity = "high"
                title = "High-severity findings increased"
            else:
                severity = "medium"
                title = "Total findings increased"

            alert = {
                "target_id": target_id,
                "scan_id": current.scan_id,
                "previous_scan_id": previous.scan_id,
                "completed_at": current.completed_at,
                "severity": severity,
                "title": title,
                "delta": {
                    "critical": critical_delta,
                    "high": high_delta,
                    "findings": findings_delta,
                },
                "current": {
                    "critical": current.critical_count,
                    "high": current.high_count,
                    "findings": current.findings_count,
                },
                "previous": {
                    "critical": previous.critical_count,
                    "high": previous.high_count,
                    "findings": previous.findings_count,
                },
                "risk_transition": f"{previous_risk or 'UNKNOWN'}->{current_risk or 'UNKNOWN'}",
            }
            alert["alert_key"] = self._make_alert_key(target_id, alert)
            existing = self._get_alert_event(alert["alert_key"])
            if existing:
                alert.update(existing)
            else:
                alert.update({
                    "delivery_status": "pending",
                    "delivery_attempts": 0,
                    "delivery_error": None,
                    "delivered_at": None,
                })
            alerts.append(alert)

            if len(alerts) >= limit:
                break

        return alerts

    # ------------------------------------------------------------------
    # SCAN LOOP
    # ------------------------------------------------------------------

    def run_scan(self, target: ScanTarget) -> Dict[str, Any]:
        """Execute a single scan for a target."""
        from repo_scanner import RepoScanner
        from advanced_auditor import AdvancedAuditor

        scan_id = hashlib.sha256(
            f"{target.id}:{time.time()}".encode()
        ).hexdigest()[:16]
        started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        try:
            if target.target_type == "repo":
                scanner = RepoScanner(
                    github_token=os.environ.get("GITHUB_TOKEN")
                )
                result = scanner.scan_repo(
                    target.url, branch=target.branch,
                    scope_paths=target.scope_paths
                )
                result_dict = result.to_dict()

                # Count severities
                critical = sum(
                    1 for f in result.findings
                    if f.get("severity") == "CRITICAL"
                )
                high = sum(
                    1 for f in result.findings
                    if f.get("severity") == "HIGH"
                )

                # Save result
                result_file = os.path.join(
                    self.results_dir, f"{scan_id}.json"
                )
                Path(result_file).write_text(json.dumps(result_dict, indent=2))

                self.record_scan(
                    target_id=target.id, scan_id=scan_id,
                    started_at=started,
                    completed_at=result.completed_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    status=result.status.value,
                    findings_count=len(result.findings),
                    critical_count=critical, high_count=high,
                    commit_hash=result.repo.commit_hash,
                    result_path=result_file
                )
                alerts = self.dispatch_alerts(self.get_scan_alerts(target.id, limit=1))
                result_dict["scan_id"] = scan_id
                result_dict["results_dir"] = self.results_dir
                result_dict["alerts"] = alerts
                return result_dict

            elif target.target_type == "address":
                etherscan_key = os.environ.get("ETHERSCAN_API_KEY", "")
                auditor = AdvancedAuditor(etherscan_key, target.chain or "ethereum")
                report = auditor.audit(target.url)
                result_dict = report.to_dict()

                critical = sum(
                    1 for f in report.findings
                    if f.severity.name == "CRITICAL"
                )
                high = sum(
                    1 for f in report.findings
                    if f.severity.name == "HIGH"
                )

                result_file = os.path.join(
                    self.results_dir, f"{scan_id}.json"
                )
                Path(result_file).write_text(json.dumps(result_dict, indent=2))

                completed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                self.record_scan(
                    target_id=target.id, scan_id=scan_id,
                    started_at=started, completed_at=completed,
                    status="complete",
                    findings_count=len(report.findings),
                    critical_count=critical, high_count=high,
                    result_path=result_file
                )
                alerts = self.dispatch_alerts(self.get_scan_alerts(target.id, limit=1))
                result_dict["scan_id"] = scan_id
                result_dict["results_dir"] = self.results_dir
                result_dict["alerts"] = alerts
                return result_dict

            else:
                raise ValueError(f"Unsupported target type: {target.target_type}")

        except Exception as e:
            logger.exception(f"Scan failed for {target.url}")
            completed = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            self.record_scan(
                target_id=target.id, scan_id=scan_id,
                started_at=started, completed_at=completed,
                status="failed",
                findings_count=0, critical_count=0, high_count=0
            )
            return {"error": str(e), "status": "failed"}

    def run_loop(self, poll_interval: int = 60):
        """Run continuous scan loop. Call stop() to break."""
        self._running = True
        logger.info("Scanner loop started")

        while self._running:
            due = self.get_due_targets()
            if due:
                logger.info(f"{len(due)} target(s) due for scanning")

            for target in due:
                if not self._running:
                    break
                logger.info(f"Scanning: {target.url}")
                try:
                    self.run_scan(target)
                except Exception as e:
                    logger.exception(f"Scan error for {target.id}: {e}")

            # Sleep in small increments so stop() is responsive
            for _ in range(poll_interval):
                if not self._running:
                    break
                time.sleep(1)

        logger.info("Scanner loop stopped")

    def stop(self):
        """Signal the loop to stop."""
        self._running = False

    # ------------------------------------------------------------------
    # CONVENIENCE
    # ------------------------------------------------------------------

    def add_repo(self, url: str, branch: str = "main",
                 scope_paths: Optional[List[str]] = None,
                 interval_hours: int = 0, priority: int = 0) -> str:
        """Shortcut: add a GitHub repo target."""
        return self.add_target(ScanTarget(
            id="", target_type="repo", url=url,
            branch=branch, scope_paths=scope_paths,
            interval_hours=interval_hours, priority=priority
        ))

    def add_address(self, address: str, chain: str = "ethereum",
                    interval_hours: int = 0, priority: int = 0) -> str:
        """Shortcut: add a contract address target."""
        return self.add_target(ScanTarget(
            id="", target_type="address", url=address,
            chain=chain, interval_hours=interval_hours,
            priority=priority
        ))

    def scan_now(self, url: str, **kwargs) -> Dict[str, Any]:
        """One-shot: scan immediately and return result."""
        if url.startswith("0x") and len(url) == 42:
            target_id = self.add_address(url, **kwargs)
        else:
            target_id = self.add_repo(url, **kwargs)

        target = self.get_target(target_id)
        return self.run_scan(target)


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

def _print_scan_summary(result: dict) -> None:
    """Print a structured, human-readable scan summary to stdout."""
    if result.get("status") == "failed":
        print(f"SCAN FAILED: {result.get('error', 'unknown error')}")
        return

    findings = result.get("findings", [])
    triage = result.get("triage", {})
    verifs = result.get("exploit_verifications", [])

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "GAS", "INFO"]
    sevs: dict = {s: 0 for s in sev_order}
    for f in findings:
        sev = f.get("severity", "INFO")
        sevs[sev] = sevs.get(sev, 0) + 1

    repo = result.get("repo", {})
    target_label = (
        repo.get("url")
        or result.get("contract", {}).get("address")
        or "?"
    )

    print("\n" + "=" * 62)
    print("  TSI-Audit-Scanner — Scan Complete")
    print("=" * 62)
    print(f"  Target  : {target_label}")
    print(f"  Status  : {result.get('status', '?').upper()}")
    duration = result.get("duration_seconds", 0) or 0
    print(f"  Duration: {duration:.1f}s")
    print(f"  Files   : {result.get('files_scanned', 0)}")
    print()

    print("  FINDINGS SUMMARY")
    print("  " + "-" * 32)
    any_finding = False
    for sev in sev_order:
        count = sevs.get(sev, 0)
        if count:
            any_finding = True
            bar = "\u2588" * min(count, 38)
            print(f"  {sev:<8} {count:>4}  {bar}")
    if not any_finding:
        print("  No findings.")
    print()

    if triage:
        c1 = triage.get("confirm_first", 0)
        c2 = triage.get("needs_context", 0)
        c3 = triage.get("likely_noise", 0)
        print(f"  TRIAGE  confirm_first={c1}  needs_context={c2}  likely_noise={c3}")
        print()

    confirmed = [v for v in verifs if v.get("exploitable")]
    if confirmed:
        print(f"  EXPLOIT VERIFIER \u2014 {len(confirmed)} confirmed exploitable:")
        for v in confirmed[:5]:
            fid = v.get("finding_id", "?")
            atk = v.get("attack_vector", "?")
            print(f"    \u25cf {fid}  [{atk}]")
        print()

    top = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")][:5]
    if top:
        print("  TOP CRITICAL/HIGH FINDINGS")
        print("  " + "-" * 32)
        for f in top:
            sev = f.get("severity", "?")
            fid = f.get("id", "?")
            title = f.get("title", "")[:50]
            line = f.get("line_number", "")
            fp = f.get("file", "")
            fp_short = fp.split("/")[-1] if fp else ""
            loc = f"{fp_short}:{line}" if fp_short else f"line {line}"
            print(f"  [{sev}] {fid:<20} {title}")
            print(f"         {loc}")
        print()

    scan_id = result.get("scan_id", "")
    results_dir = result.get("results_dir", "scan_results")
    print("=" * 62)
    if scan_id:
        print(f"  Full JSON: {results_dir}/{scan_id}.json")
    print("=" * 62 + "\n")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Audit Scanner Scheduler")
    sub = parser.add_subparsers(dest="command")

    # scan <url>
    sp = sub.add_parser("scan", help="One-shot scan")
    sp.add_argument("url", help="GitHub URL or contract address")
    sp.add_argument("--branch", default="main")
    sp.add_argument("--chain", default="ethereum")
    sp.add_argument("--scope", nargs="*", help="Paths within repo to scan")

    # add <url>
    sp = sub.add_parser("add", help="Add recurring target")
    sp.add_argument("url")
    sp.add_argument("--branch", default="main")
    sp.add_argument("--chain", default="ethereum")
    sp.add_argument("--interval", type=int, default=24, help="Hours between scans")
    sp.add_argument("--priority", type=int, default=0)

    # list
    sub.add_parser("list", help="List targets")

    # run
    rp = sub.add_parser("run", help="Start continuous scan loop")
    rp.add_argument("--poll", type=int, default=60, help="Poll interval (seconds)")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    scheduler = ScanScheduler()

    if args.command == "scan":
        url = args.url
        # Auto-detect block-explorer URLs
        if url.startswith("http") and "scan" in url.lower():
            try:
                from config import parse_explorer_url
                chain, address = parse_explorer_url(url)
                print(f"Detected {chain} contract: {address}")
                result = scheduler.scan_now(address, chain=chain)
            except ValueError as e:
                print(f"Error parsing explorer URL: {e}")
                sys.exit(1)
        elif url.startswith("0x"):
            result = scheduler.scan_now(url, chain=args.chain)
        else:
            result = scheduler.scan_now(
                url, branch=args.branch, scope_paths=args.scope
            )
        _print_scan_summary(result)

    elif args.command == "add":
        url = args.url
        if url.startswith("http") and "scan" in url.lower():
            try:
                from config import parse_explorer_url
                chain, address = parse_explorer_url(url)
                print(f"Detected {chain} contract: {address}")
                tid = scheduler.add_address(
                    address, chain=chain,
                    interval_hours=args.interval, priority=args.priority
                )
            except ValueError as e:
                print(f"Error parsing explorer URL: {e}")
                sys.exit(1)
        elif url.startswith("0x"):
            tid = scheduler.add_address(
                url, chain=args.chain,
                interval_hours=args.interval, priority=args.priority
            )
        else:
            tid = scheduler.add_repo(
                url, branch=args.branch,
                interval_hours=args.interval, priority=args.priority
            )
        print(f"Added target: {tid}")

    elif args.command == "list":
        targets = scheduler.list_targets(enabled_only=False)
        for t in targets:
            status = "enabled" if t.enabled else "disabled"
            print(f"  {t.id}  {t.target_type:8s}  {status:8s}  {t.url}")

    elif args.command == "run":
        scheduler.run_loop(poll_interval=args.poll)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

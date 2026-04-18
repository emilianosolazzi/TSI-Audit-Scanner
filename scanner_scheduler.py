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
import json
import time
import logging
import sqlite3
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

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
        self._conn.commit()

    def _target_to_row(self, t: ScanTarget) -> tuple:
        return (
            t.id, t.target_type, t.url, t.chain, t.branch,
            json.dumps(t.scope_paths) if t.scope_paths else None,
            t.priority, t.interval_hours,
            t.added_at or datetime.utcnow().isoformat() + "Z",
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

        target.added_at = datetime.utcnow().isoformat() + "Z"

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
        now = datetime.utcnow()
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
        started = datetime.utcnow().isoformat() + "Z"

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
                    completed_at=result.completed_at or datetime.utcnow().isoformat() + "Z",
                    status=result.status.value,
                    findings_count=len(result.findings),
                    critical_count=critical, high_count=high,
                    commit_hash=result.repo.commit_hash,
                    result_path=result_file
                )
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

                completed = datetime.utcnow().isoformat() + "Z"
                self.record_scan(
                    target_id=target.id, scan_id=scan_id,
                    started_at=started, completed_at=completed,
                    status="complete",
                    findings_count=len(report.findings),
                    critical_count=critical, high_count=high,
                    result_path=result_file
                )
                return result_dict

            else:
                raise ValueError(f"Unsupported target type: {target.target_type}")

        except Exception as e:
            logger.exception(f"Scan failed for {target.url}")
            completed = datetime.utcnow().isoformat() + "Z"
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
        if args.url.startswith("0x"):
            result = scheduler.scan_now(args.url, chain=args.chain)
        else:
            result = scheduler.scan_now(
                args.url, branch=args.branch, scope_paths=args.scope
            )
        print(json.dumps(result, indent=2))

    elif args.command == "add":
        if args.url.startswith("0x"):
            tid = scheduler.add_address(
                args.url, chain=args.chain,
                interval_hours=args.interval, priority=args.priority
            )
        else:
            tid = scheduler.add_repo(
                args.url, branch=args.branch,
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

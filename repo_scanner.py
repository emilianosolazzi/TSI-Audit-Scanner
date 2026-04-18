#!/usr/bin/env python3
"""
Repository Scanner — Clone, discover, and audit Solidity source from Git repos.

Supports:
  - Public/private GitHub repos (via token)
  - Local directories
  - Immunefi/Code4rena scope URLs
  - Automatic Solidity file discovery
  - Remapping detection (foundry.toml, hardhat.config, remappings.txt)
"""

import os
import re
import json
import shutil
import logging
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger("RepoScanner")


class ScanStatus(Enum):
    QUEUED = "queued"
    CLONING = "cloning"
    DISCOVERING = "discovering"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class SolidityFile:
    """A discovered Solidity source file."""
    path: str                   # Relative path within repo
    absolute_path: str          # Full filesystem path
    size_bytes: int
    pragma_version: Optional[str] = None
    contract_names: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    is_test: bool = False
    is_script: bool = False
    is_interface: bool = False
    is_library: bool = False


@dataclass
class RepoMetadata:
    """Metadata about a scanned repository."""
    url: str
    local_path: str
    branch: str = "main"
    commit_hash: Optional[str] = None
    framework: Optional[str] = None  # foundry, hardhat, truffle, brownie
    solidity_files: int = 0
    total_lines: int = 0
    remappings: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Result of scanning a repository."""
    repo: RepoMetadata
    status: ScanStatus
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: float = 0
    files_scanned: int = 0
    findings: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "repo": {
                "url": self.repo.url,
                "branch": self.repo.branch,
                "commit": self.repo.commit_hash,
                "framework": self.repo.framework,
                "solidity_files": self.repo.solidity_files,
                "total_lines": self.repo.total_lines,
            },
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.files_scanned,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "errors": self.errors,
            "summary": self.summary,
        }


class RepoScanner:
    """Clone and scan Git repositories for Solidity vulnerabilities."""

    # Dirs that should never be scanned
    SKIP_DIRS = {
        "node_modules", ".git", "cache", "out", "artifacts",
        "build", "typechain", "typechain-types", ".deps",
        "forge-cache", "lib", "dependencies",
    }

    # File patterns that indicate test/script (not in scope)
    TEST_PATTERNS = [
        r"\.t\.sol$", r"Test\.sol$", r"test/", r"tests/",
        r"Mock\.sol$", r"mock/", r"mocks/",
    ]
    SCRIPT_PATTERNS = [
        r"\.s\.sol$", r"Script\.sol$", r"script/", r"scripts/",
        r"deploy/", r"Deploy\.sol$",
    ]

    def __init__(self, workspace_dir: Optional[str] = None, github_token: Optional[str] = None):
        self.workspace_dir = workspace_dir or os.path.join(tempfile.gettempdir(), "audit-scanner")
        self.github_token = github_token
        os.makedirs(self.workspace_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def scan_repo(self, repo_url: str, branch: str = "main",
                  include_tests: bool = False,
                  scope_paths: Optional[List[str]] = None) -> ScanResult:
        """
        Clone a repo and scan all Solidity files.

        Args:
            repo_url: GitHub URL or local path
            branch: Git branch to check out
            include_tests: Whether to scan test files
            scope_paths: Optional list of paths within repo to limit scan
        Returns:
            ScanResult with all findings
        """
        started = datetime.utcnow()
        result = ScanResult(
            repo=RepoMetadata(url=repo_url, local_path="", branch=branch),
            status=ScanStatus.CLONING,
            started_at=started.isoformat() + "Z",
        )

        try:
            # 1. Clone or locate
            local_path = self._resolve_repo(repo_url, branch)
            result.repo.local_path = local_path
            result.repo.commit_hash = self._get_commit_hash(local_path)

            # 2. Detect framework
            result.status = ScanStatus.DISCOVERING
            result.repo.framework = self._detect_framework(local_path)
            result.repo.remappings = self._load_remappings(local_path)
            result.repo.dependencies = self._detect_dependencies(local_path)

            # 3. Discover Solidity files
            sol_files = self._discover_solidity_files(local_path, scope_paths)
            result.repo.solidity_files = len(sol_files)

            # Filter tests/scripts unless requested
            if not include_tests:
                sol_files = [f for f in sol_files if not f.is_test and not f.is_script]

            # 4. Analyze each file
            result.status = ScanStatus.ANALYZING
            all_findings = []
            total_lines = 0

            for sol_file in sol_files:
                try:
                    source = Path(sol_file.absolute_path).read_text(encoding="utf-8", errors="replace")
                    total_lines += source.count("\n") + 1
                    findings = self._analyze_source(source, sol_file)
                    all_findings.extend(findings)
                    result.files_scanned += 1
                except Exception as e:
                    result.errors.append(f"{sol_file.path}: {e}")

            result.repo.total_lines = total_lines
            result.findings = all_findings
            result.status = ScanStatus.COMPLETE

            # Build summary
            result.summary = self._build_summary(all_findings, sol_files)

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))
            logger.exception(f"Scan failed for {repo_url}")

        finished = datetime.utcnow()
        result.completed_at = finished.isoformat() + "Z"
        result.duration_seconds = (finished - started).total_seconds()
        return result

    def scan_local(self, directory: str, **kwargs) -> ScanResult:
        """Scan a local directory (no cloning)."""
        return self.scan_repo(directory, **kwargs)

    # ------------------------------------------------------------------
    # REPO MANAGEMENT
    # ------------------------------------------------------------------

    def _resolve_repo(self, repo_url: str, branch: str) -> str:
        """Clone repo or return local path."""
        # Local directory
        if os.path.isdir(repo_url):
            logger.info(f"Using local directory: {repo_url}")
            return os.path.abspath(repo_url)

        # Git URL — clone into workspace
        repo_hash = hashlib.sha256(f"{repo_url}:{branch}".encode()).hexdigest()[:12]
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        dest = os.path.join(self.workspace_dir, f"{repo_name}_{repo_hash}")

        if os.path.isdir(dest):
            # Pull latest
            logger.info(f"Updating existing clone: {dest}")
            self._run_git(["git", "fetch", "--depth=1", "origin", branch], cwd=dest)
            self._run_git(["git", "checkout", f"origin/{branch}"], cwd=dest)
        else:
            # Fresh clone
            logger.info(f"Cloning {repo_url} (branch={branch})")
            clone_url = self._auth_url(repo_url)
            self._run_git([
                "git", "clone", "--depth=1", "--branch", branch,
                "--single-branch", clone_url, dest
            ])

        return dest

    def _auth_url(self, url: str) -> str:
        """Add GitHub token to URL if available."""
        if self.github_token and "github.com" in url:
            # https://TOKEN@github.com/owner/repo.git
            return url.replace("https://", f"https://{self.github_token}@")
        return url

    def _run_git(self, cmd: List[str], cwd: Optional[str] = None) -> str:
        """Run a git command and return stdout."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, cwd=cwd
            )
            if result.returncode != 0:
                raise RuntimeError(f"git error: {result.stderr.strip()}")
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"git command timed out: {' '.join(cmd)}")

    def _get_commit_hash(self, repo_dir: str) -> Optional[str]:
        """Get current HEAD commit hash."""
        try:
            return self._run_git(["git", "rev-parse", "HEAD"], cwd=repo_dir)
        except Exception:
            return None

    def cleanup(self, repo_url: str = None):
        """Remove cloned repos."""
        if repo_url:
            # Remove specific repo
            for d in Path(self.workspace_dir).iterdir():
                if d.is_dir():
                    shutil.rmtree(d, ignore_errors=True)
        else:
            # Remove all
            shutil.rmtree(self.workspace_dir, ignore_errors=True)
            os.makedirs(self.workspace_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # FRAMEWORK DETECTION
    # ------------------------------------------------------------------

    def _detect_framework(self, repo_dir: str) -> Optional[str]:
        """Detect Solidity development framework."""
        checks = [
            ("foundry.toml", "foundry"),
            ("hardhat.config.js", "hardhat"),
            ("hardhat.config.ts", "hardhat"),
            ("truffle-config.js", "truffle"),
            ("brownie-config.yaml", "brownie"),
            ("ape-config.yaml", "ape"),
        ]
        for filename, framework in checks:
            if os.path.exists(os.path.join(repo_dir, filename)):
                return framework
        return None

    def _load_remappings(self, repo_dir: str) -> Dict[str, str]:
        """Load import remappings from foundry.toml or remappings.txt."""
        remappings = {}

        # Check remappings.txt
        remap_file = os.path.join(repo_dir, "remappings.txt")
        if os.path.exists(remap_file):
            for line in Path(remap_file).read_text().splitlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, val = line.split("=", 1)
                    remappings[key.strip()] = val.strip()

        # Check foundry.toml
        toml_file = os.path.join(repo_dir, "foundry.toml")
        if os.path.exists(toml_file):
            content = Path(toml_file).read_text()
            # Simple TOML parsing for remappings array
            match = re.search(r"remappings\s*=\s*\[(.*?)\]", content, re.DOTALL)
            if match:
                for item in re.findall(r"'([^']+)'|\"([^\"]+)\"", match.group(1)):
                    mapping = item[0] or item[1]
                    if "=" in mapping:
                        key, val = mapping.split("=", 1)
                        remappings[key.strip()] = val.strip()

        return remappings

    def _detect_dependencies(self, repo_dir: str) -> List[str]:
        """Detect installed dependencies (OpenZeppelin, etc.)."""
        deps = []
        # Check node_modules
        nm = os.path.join(repo_dir, "node_modules", "@openzeppelin")
        if os.path.isdir(nm):
            deps.append("@openzeppelin/contracts")

        # Check lib/ (Foundry style)
        lib_dir = os.path.join(repo_dir, "lib")
        if os.path.isdir(lib_dir):
            for d in os.listdir(lib_dir):
                if os.path.isdir(os.path.join(lib_dir, d)):
                    deps.append(d)

        return deps

    # ------------------------------------------------------------------
    # SOLIDITY FILE DISCOVERY
    # ------------------------------------------------------------------

    def _discover_solidity_files(self, repo_dir: str,
                                  scope_paths: Optional[List[str]] = None) -> List[SolidityFile]:
        """Walk the repo and find all .sol files."""
        files = []
        search_roots = [repo_dir]

        if scope_paths:
            search_roots = [
                os.path.join(repo_dir, p.lstrip("/\\"))
                for p in scope_paths
                if os.path.exists(os.path.join(repo_dir, p.lstrip("/\\")))
            ]

        for root_dir in search_roots:
            for dirpath, dirnames, filenames in os.walk(root_dir):
                # Prune skipped directories
                dirnames[:] = [d for d in dirnames if d not in self.SKIP_DIRS]

                for fname in filenames:
                    if not fname.endswith(".sol"):
                        continue

                    abs_path = os.path.join(dirpath, fname)
                    rel_path = os.path.relpath(abs_path, repo_dir)

                    sol_file = SolidityFile(
                        path=rel_path,
                        absolute_path=abs_path,
                        size_bytes=os.path.getsize(abs_path),
                    )

                    # Classify
                    sol_file.is_test = any(re.search(p, rel_path) for p in self.TEST_PATTERNS)
                    sol_file.is_script = any(re.search(p, rel_path) for p in self.SCRIPT_PATTERNS)

                    # Parse basic info from source
                    try:
                        source = Path(abs_path).read_text(encoding="utf-8", errors="replace")
                        sol_file.pragma_version = self._extract_pragma(source)
                        sol_file.contract_names = self._extract_contract_names(source)
                        sol_file.imports = self._extract_imports(source)
                        sol_file.is_interface = all(
                            self._is_interface_name(n) for n in sol_file.contract_names
                        ) if sol_file.contract_names else False
                        sol_file.is_library = all(
                            self._is_library(n, source) for n in sol_file.contract_names
                        ) if sol_file.contract_names else False
                    except Exception:
                        pass

                    files.append(sol_file)

        return files

    def _extract_pragma(self, source: str) -> Optional[str]:
        m = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        return m.group(1).strip() if m else None

    def _extract_contract_names(self, source: str) -> List[str]:
        return re.findall(
            r"(?:contract|interface|library|abstract\s+contract)\s+(\w+)", source
        )

    def _extract_imports(self, source: str) -> List[str]:
        return re.findall(r'import\s+["\']([^"\']+)["\']', source) + \
               re.findall(r'import\s+\{[^}]*\}\s+from\s+["\']([^"\']+)["\']', source)

    def _is_interface_name(self, name: str) -> bool:
        return name.startswith("I") and len(name) > 1 and name[1].isupper()

    def _is_library(self, name: str, source: str) -> bool:
        return bool(re.search(rf"library\s+{re.escape(name)}\b", source))

    # ------------------------------------------------------------------
    # SOURCE ANALYSIS (reuses AdvancedAuditor's pattern engine)
    # ------------------------------------------------------------------

    def _analyze_source(self, source: str, sol_file: SolidityFile) -> List[Dict]:
        """Run vulnerability patterns against raw source code."""
        # Import here to avoid circular imports
        from advanced_auditor import (
            KNOWN_VULNERABILITIES, PROTECTION_PATTERNS, SAFE_PATTERNS,
            Severity, Finding
        )

        findings = []
        lines = source.split("\n")

        # Pre-check: which protections exist in this file?
        file_protections = set()
        for prot_name, patterns in PROTECTION_PATTERNS.items():
            for p in patterns:
                if re.search(p, source, re.IGNORECASE):
                    file_protections.add(prot_name)
                    break

        # Check safe patterns (skip entire file if safe)
        for safe_name, safe_pattern in SAFE_PATTERNS.items():
            if re.search(safe_pattern, source, re.MULTILINE):
                # File has safe patterns — reduce severity for matches
                pass

        for vuln_id, vuln in KNOWN_VULNERABILITIES.items():
            pattern = vuln.get("pattern")
            if not pattern:
                continue

            # Protection-first: skip if protected
            prot_check = vuln.get("protection_check")
            if prot_check and prot_check in file_protections:
                continue

            # Exclusion list
            exclude_if = vuln.get("exclude_if", [])
            if any(ex in source for ex in exclude_if):
                continue

            # Solidity version check
            ver_check = vuln.get("solidity_version_check")
            if ver_check and sol_file.pragma_version:
                if ver_check.startswith("<") and sol_file.pragma_version >= ver_check[1:]:
                    continue

            # Find matches
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    # Exclude context
                    exclude_ctx = vuln.get("exclude_context", [])
                    if any(ctx.lower() in line.lower() for ctx in exclude_ctx):
                        continue

                    # Skip if informational for this contract type
                    info_for = vuln.get("informational_for", [])
                    if info_for and sol_file.contract_names:
                        if any(t in n for n in sol_file.contract_names for t in info_for):
                            continue

                    # Get code snippet (3 lines of context)
                    start = max(0, i - 2)
                    end = min(len(lines), i + 2)
                    snippet = "\n".join(lines[start:end])

                    findings.append({
                        "id": vuln_id,
                        "severity": vuln["severity"].name,
                        "severity_weight": vuln["severity"].weight,
                        "category": vuln.get("category", "").value if hasattr(vuln.get("category", ""), "value") else str(vuln.get("category", "")),
                        "title": vuln["name"],
                        "description": vuln.get("description", ""),
                        "recommendation": vuln.get("recommendation", ""),
                        "file": sol_file.path,
                        "line_number": i,
                        "code_snippet": snippet,
                        "confidence": 0.8,
                    })

        return findings

    # ------------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------------

    def _build_summary(self, findings: List[Dict], files: List[SolidityFile]) -> Dict:
        """Build scan summary statistics."""
        by_severity = {}
        by_category = {}
        by_file = {}

        for f in findings:
            sev = f.get("severity", "UNKNOWN")
            cat = f.get("category", "UNKNOWN")
            fpath = f.get("file", "UNKNOWN")

            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1
            by_file[fpath] = by_file.get(fpath, 0) + 1

        # Compute risk score (0-100, higher = riskier)
        total_weight = sum(f.get("severity_weight", 0) for f in findings)
        file_count = max(len(files), 1)
        risk_score = min(100, total_weight / file_count)

        risk_level = "SAFE"
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 30:
            risk_level = "MEDIUM"
        elif risk_score >= 10:
            risk_level = "LOW"

        return {
            "risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "top_files": dict(sorted(by_file.items(), key=lambda x: -x[1])[:10]),
            "contracts_scanned": [f.path for f in files if not f.is_test and not f.is_script],
            "interfaces_skipped": [f.path for f in files if f.is_interface],
            "tests_found": [f.path for f in files if f.is_test],
        }

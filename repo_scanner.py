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
from datetime import datetime, timezone
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger("RepoScanner")


class ScanStatus(Enum):
    QUEUED = "queued"
    CLONING = "cloning"
    DISCOVERING = "discovering"
    ANALYZING = "analyzing"
    VALIDATING = "validating"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class SolidityFile:
    """A discovered Solidity source file."""
    path: str                   # Relative path within repo
    absolute_path: str          # Full filesystem path
    size_bytes: int
    language: str = "solidity"
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
    vyper_files: int = 0
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
    validated_findings: List[Dict] = field(default_factory=list)
    exploit_verifications: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    triage: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "repo": {
                "url": self.repo.url,
                "branch": self.repo.branch,
                "commit": self.repo.commit_hash,
                "framework": self.repo.framework,
                "solidity_files": self.repo.solidity_files,
                "vyper_files": self.repo.vyper_files,
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
        # Phase 2: triage results
        if self.triage:
            d["triage"] = self.triage
            # Replace raw findings with validated findings when available
            if self.validated_findings:
                d["findings"] = self.validated_findings
                d["findings_count"] = len(self.validated_findings)
        # Phase 3: exploit verification results
        if self.exploit_verifications:
            d["exploit_verifications"] = self.exploit_verifications
        return d


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
                  scope_paths: Optional[List[str]] = None,
                  run_forge_plugin: bool = True,
                  forge_plugin_dir: Optional[str] = None,
                  forge_match_contract: str = "TSI_Findings_Report",
                  forge_fork_url: Optional[str] = None) -> ScanResult:
        """
        Clone a repo and scan all Solidity files.

        Args:
            repo_url: GitHub URL or local path
            branch: Git branch to check out
            include_tests: Whether to scan test files
            scope_paths: Optional list of paths within repo to limit scan
            run_forge_plugin: When True, also run the Foundry TSI plugin (Phase 7)
            forge_plugin_dir: Override path to the Foundry TSI plugin harness
            forge_match_contract: Forge --match-contract for the plugin run
            forge_fork_url: Optional RPC URL for forked TSI execution
        Returns:
            ScanResult with all findings (analyzers + validator + verifier + forge plugin)
        """
        started = datetime.now(timezone.utc)
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

            # 3. Discover source files
            source_files = self._discover_source_files(local_path, scope_paths)
            result.repo.solidity_files = sum(1 for f in source_files if f.language == "solidity")
            result.repo.vyper_files = sum(1 for f in source_files if f.language == "vyper")

            # Filter tests/scripts unless requested
            if not include_tests:
                source_files = [f for f in source_files if not f.is_test and not f.is_script]

            # Skip Solidity interfaces by default; they generate declaration-only noise.
            source_files = [f for f in source_files if not f.is_interface]

            # 4. Analyze each file (parallel I/O + per-file analysis)
            result.status = ScanStatus.ANALYZING
            all_findings = []
            total_lines = 0
            file_sources = {}  # rel_path -> source code

            # Sort for deterministic ordering even when futures complete out-of-order.
            ordered_files = sorted(source_files, key=lambda f: f.path)

            def _analyze_one(source_file):
                source = Path(source_file.absolute_path).read_text(
                    encoding="utf-8", errors="replace"
                )
                if source_file.language == "vyper":
                    findings = self._analyze_vyper_source(source, source_file)
                else:
                    findings = self._analyze_source(source, source_file)
                    findings.extend(self._analyze_novel_per_file(source, source_file))
                return source_file, source, findings

            # ThreadPoolExecutor: regex is GIL-bound but file I/O + any subprocess
            # work (solc invocations) release the GIL. Empirically still a 2-3x win.
            max_workers = min(8, (os.cpu_count() or 2) * 2)
            results_by_path: Dict[str, Tuple[Any, str, list]] = {}
            errors_by_path: Dict[str, str] = {}

            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(_analyze_one, sf): sf for sf in ordered_files}
                for fut in as_completed(futures):
                    sf = futures[fut]
                    try:
                        source_file, source, findings = fut.result()
                        results_by_path[source_file.path] = (source_file, source, findings)
                    except Exception as e:
                        errors_by_path[sf.path] = f"{sf.path}: {e}"

            # Merge in deterministic (sorted) order.
            for sf in ordered_files:
                if sf.path in errors_by_path:
                    result.errors.append(errors_by_path[sf.path])
                    continue
                entry = results_by_path.get(sf.path)
                if entry is None:
                    continue
                _source_file, source, findings = entry
                total_lines += source.count("\n") + 1
                file_sources[sf.path] = source
                all_findings.extend(findings)
                result.files_scanned += 1

            # 4b. Project-wide novel pass: selector / storage-slot collisions.
            try:
                all_findings.extend(self._analyze_novel_project_wide(file_sources, local_path))
            except Exception as exc:
                logger.warning("Project-wide novel pass failed: %s", exc)

            result.repo.total_lines = total_lines
            result.findings = all_findings

            # 5. Validation phase — triage findings
            result.status = ScanStatus.VALIDATING
            all_source_files = self._discover_source_files(local_path, scope_paths)
            test_files = [f.absolute_path for f in all_source_files if f.is_test]
            try:
                from finding_validator import FindingValidator
                validator = FindingValidator(test_files=test_files)
                validated = validator.validate_findings(all_findings, file_sources)
                result.validated_findings = [v.to_dict() for v in validated]
                result.triage = validator.build_triage_summary(validated)
            except Exception as e:
                logger.warning(f"Validation phase failed: {e}")
                result.triage = {"error": str(e)}

            # 6. Exploit verification — semantic analysis of confirm_first findings
            try:
                from exploit_verifier import verify_all_findings
                verifications = verify_all_findings(all_findings, file_sources)
                if verifications:
                    result.exploit_verifications = [v.to_dict() for v in verifications]
                    # Enrich validated findings with verification results
                    ver_map = {v.finding_id: v for v in verifications}
                    for vf in result.validated_findings:
                        vid = vf.get("id", "")
                        if vid in ver_map:
                            vr = ver_map[vid]
                            vf["verification"] = vr.to_dict()
                            if vr.severity_adjustment:
                                vf["severity_adjustment"] = vr.severity_adjustment
            except Exception as e:
                logger.warning(f"Exploit verification phase failed: {e}")

            # Build base summary BEFORE Phase 7 so forge_plugin entry survives.
            result.summary = self._build_summary(all_findings, source_files)

            # 7. Foundry TSI plugin — runtime adapter findings (optional)
            if run_forge_plugin:
                try:
                    forge_summary = self._run_forge_plugin(
                        plugin_dir=forge_plugin_dir,
                        match_contract=forge_match_contract,
                        fork_url=forge_fork_url,
                    )
                    if forge_summary:
                        result.summary["forge_plugin"] = forge_summary
                        normalized = forge_summary.get("normalized_findings") or []
                        if normalized:
                            for nf in normalized:
                                nf.setdefault("source", "forge_plugin")
                            result.findings.extend(normalized)
                            result.validated_findings.extend(normalized)
                            logger.info(
                                "Forge plugin contributed %d finding(s) (status=%s)",
                                len(normalized), forge_summary.get("status"),
                            )
                except Exception as e:
                    logger.warning(f"Forge plugin phase failed: {e}")

            result.status = ScanStatus.COMPLETE

        except Exception as e:
            result.status = ScanStatus.FAILED
            result.errors.append(str(e))
            logger.exception(f"Scan failed for {repo_url}")

        finished = datetime.now(timezone.utc)
        result.completed_at = finished.isoformat().replace("+00:00", "Z")
        result.duration_seconds = (finished - started).total_seconds()
        return result

    def scan_local(self, directory: str, **kwargs) -> ScanResult:
        """Scan a local directory (no cloning)."""
        return self.scan_repo(directory, **kwargs)

    # ------------------------------------------------------------------
    # REPO MANAGEMENT
    # ------------------------------------------------------------------

    def _detect_default_branch(self, repo_url: str) -> str:
        """Auto-detect the default branch of a remote repo via ls-remote."""
        clone_url = self._auth_url(repo_url)
        try:
            out = self._run_git(["git", "ls-remote", "--symref", clone_url, "HEAD"])
            # Output: "ref: refs/heads/main\tHEAD\n..."
            m = re.search(r"ref:\s+refs/heads/(\S+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
        # Fallback chain
        for branch in ("main", "master", "develop"):
            try:
                self._run_git(["git", "ls-remote", "--exit-code", clone_url, branch])
                return branch
            except Exception:
                continue
        return "main"

    def _resolve_repo(self, repo_url: str, branch: str) -> str:
        """Clone repo or return local path."""
        # Local directory
        if os.path.isdir(repo_url):
            logger.info(f"Using local directory: {repo_url}")
            return os.path.abspath(repo_url)

        # Auto-detect default branch when caller used the default
        if branch == "main":
            detected = self._detect_default_branch(repo_url)
            if detected != branch:
                logger.info(f"Auto-detected default branch: {detected}")
                branch = detected

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
        if list(Path(repo_dir).rglob("*.vy")):
            return "vyper"
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
    # SOURCE FILE DISCOVERY
    # ------------------------------------------------------------------

    def _discover_source_files(self, repo_dir: str,
                               scope_paths: Optional[List[str]] = None) -> List[SolidityFile]:
        """Walk the repo and find all supported source files (.sol and .vy)."""
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
                    if not (fname.endswith(".sol") or fname.endswith(".vy")):
                        continue

                    abs_path = os.path.join(dirpath, fname)
                    rel_path = os.path.relpath(abs_path, repo_dir)
                    norm_rel_path = rel_path.replace("\\", "/")
                    language = "vyper" if fname.endswith(".vy") else "solidity"

                    sol_file = SolidityFile(
                        path=rel_path,
                        absolute_path=abs_path,
                        size_bytes=os.path.getsize(abs_path),
                        language=language,
                    )

                    # Classify
                    sol_file.is_test = any(re.search(p, norm_rel_path) for p in self.TEST_PATTERNS)
                    sol_file.is_script = any(re.search(p, norm_rel_path) for p in self.SCRIPT_PATTERNS)

                    # Parse basic info from source
                    try:
                        source = Path(abs_path).read_text(encoding="utf-8", errors="replace")
                        if language == "vyper":
                            sol_file.contract_names = [Path(abs_path).stem]
                            sol_file.imports = self._extract_vyper_imports(source)
                            sol_file.is_interface = self._is_vyper_interface(norm_rel_path, source)
                            sol_file.is_library = False
                        else:
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

    def _discover_solidity_files(self, repo_dir: str,
                                 scope_paths: Optional[List[str]] = None) -> List[SolidityFile]:
        """Backward-compatible Solidity-only discovery helper."""
        return [
            source_file for source_file in self._discover_source_files(repo_dir, scope_paths)
            if source_file.language == "solidity"
        ]

    def _extract_pragma(self, source: str) -> Optional[str]:
        m = re.search(r"pragma\s+solidity\s+([^;]+);", source)
        return m.group(1).strip() if m else None

    @staticmethod
    def _pragma_satisfies_ge(pragma: str, threshold: str) -> bool:
        """
        Return True when every version admitted by ``pragma`` is >= threshold.

        Handles caret/tilde prefixes, ``>=`` clauses, and multi-part ranges.
        Intended for version-gated filters such as ``SWC-101`` being noise on
        Solidity 0.8+ where checked arithmetic is the default.
        """
        def _tuple(v: str):
            parts = re.findall(r"\d+", v)
            return tuple(int(p) for p in parts[:3]) if parts else (0,)

        th = _tuple(threshold)
        # Lower-bound extraction: caret/tilde/>= all pin a minimum.
        cleaned = pragma.replace(" ", "")
        # Extract the first explicit version literal from the pragma.
        versions = re.findall(r"\d+(?:\.\d+){0,2}", cleaned)
        if not versions:
            return False
        lower = _tuple(versions[0])
        return lower >= th

    # Regexes used by the precision-filter stage.
    _FP_TIMESTAMP_DOWNCAST_RE = re.compile(
        r"uint(?:64|96|128|160|192|224|256)\s*\(\s*"
        r"(?:block\.(?:timestamp|number)|now)\s*\)"
    )
    _FP_EMPTY_RECEIVE_RE = re.compile(
        r"(?:receive|fallback)\s*\(\s*\)\s*"
        r"external\s+payable\s*\{\s*\}"
    )

    @classmethod
    def _is_known_false_positive(
        cls, vuln_id: str, line: str, lines: List[str], line_no: int,
    ) -> bool:
        """
        Drop well-known pattern-engine false positives.

        Precision-only filters.  Each branch encodes an invariant under
        which the generic regex is guaranteed to misfire; ambiguous cases
        fall through and remain in the report.
        """
        # TOKEN-007: uint64(block.timestamp) is safe for ~584B years.
        if vuln_id == "TOKEN-007" and cls._FP_TIMESTAMP_DOWNCAST_RE.search(line):
            return True

        # ADVANCED-002: empty receive()/fallback() with no body has no
        # state effect and no auth surface.
        if vuln_id == "ADVANCED-002":
            window = " ".join(
                lines[max(0, line_no - 2): min(len(lines), line_no + 2)]
            )
            if cls._FP_EMPTY_RECEIVE_RE.search(window):
                return True

        # ADV-UNBOUNDED-LOOP-001: line attribution bug.  If the flagged
        # line itself is a comment/import/pragma/blank (not code), the
        # detector has mis-located the match.
        if vuln_id == "ADV-UNBOUNDED-LOOP-001":
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith("//")
                or stripped.startswith("/*")
                or stripped.startswith("*")
                or stripped.startswith("import")
                or stripped.startswith("pragma")
                or stripped.startswith("using ")
            ):
                return True

        return False

    def _extract_contract_names(self, source: str) -> List[str]:
        return re.findall(
            r"(?:contract|interface|library|abstract\s+contract)\s+(\w+)", source
        )

    def _extract_imports(self, source: str) -> List[str]:
        return re.findall(r'import\s+["\']([^"\']+)["\']', source) + \
               re.findall(r'import\s+\{[^}]*\}\s+from\s+["\']([^"\']+)["\']', source)

    def _extract_vyper_imports(self, source: str) -> List[str]:
        imports = re.findall(r"(?:from\s+([^\s]+)\s+import\s+.+|import\s+([^\s]+))", source)
        return [left or right for left, right in imports]

    def _is_vyper_interface(self, rel_path: str, source: str) -> bool:
        normalized = rel_path.replace("\\", "/").lower()
        if "/interfaces/" in normalized or normalized.startswith("interfaces/"):
            return True
        stripped = source.lstrip()
        return stripped.startswith("interface ")

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

        # Populate pragma_version on demand so version-gated rules
        # (e.g. SWC-101 on Solidity <0.8.0) filter correctly even when
        # callers construct SolidityFile directly.
        if not sol_file.pragma_version:
            sol_file.pragma_version = self._extract_pragma(source)

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
                if ver_check.startswith("<") and self._pragma_satisfies_ge(
                    sol_file.pragma_version, ver_check[1:]
                ):
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

                    # Precision filters — drop well-known pattern-engine FPs
                    # before they pollute the report.
                    if self._is_known_false_positive(vuln_id, line, lines, i):
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

    def _analyze_vyper_source(self, source: str, source_file: SolidityFile) -> List[Dict]:
        """Run Vyper heuristics via SourceAnalyzer."""
        from source_analyzer import SourceAnalyzer

        analyzer = SourceAnalyzer()
        return analyzer.analyze_vyper_source(source, source_file.path)

    # ------------------------------------------------------------------
    # NOVEL ANALYZERS (CFG/guard-dominance + precompile crypto + selector
    # / storage-slot collision).  Integrated into the pipeline rather
    # than run as a separate tool.
    # ------------------------------------------------------------------

    def _analyze_novel_per_file(
        self, source: str, sol_file: SolidityFile,
    ) -> List[Dict]:
        """Per-file novel passes (guard-dominance + precompile crypto)."""
        findings: List[Dict] = []
        try:
            from novel_analyzers import (
                GuardDominanceAnalyzer,
                PrecompileCryptoAnalyzer,
                MerkleProofVerifierAnalyzer,
                CryptoAccessControlAnalyzer,
            )
        except Exception as exc:
            logger.debug("novel_analyzers unavailable: %s", exc)
            return findings
        try:
            findings.extend(
                GuardDominanceAnalyzer(source, sol_file.path).analyze()
            )
        except Exception as exc:
            logger.debug("GuardDominanceAnalyzer failed on %s: %s", sol_file.path, exc)
        try:
            findings.extend(
                PrecompileCryptoAnalyzer(source, sol_file.path).analyze()
            )
        except Exception as exc:
            logger.debug("PrecompileCryptoAnalyzer failed on %s: %s", sol_file.path, exc)
        try:
            findings.extend(
                MerkleProofVerifierAnalyzer(source, sol_file.path).analyze()
            )
        except Exception as exc:
            logger.debug("MerkleProofVerifierAnalyzer failed on %s: %s", sol_file.path, exc)
        try:
            findings.extend(
                CryptoAccessControlAnalyzer(source, sol_file.path).analyze()
            )
        except Exception as exc:
            logger.debug("CryptoAccessControlAnalyzer failed on %s: %s", sol_file.path, exc)
        # Black-hat-oriented adversarial pass (lazy import).
        try:
            from adversarial_analyzers import AdversarialAnalyzer
            findings.extend(
                AdversarialAnalyzer(source, sol_file.path).analyze()
            )
        except Exception as exc:
            logger.debug("AdversarialAnalyzer failed on %s: %s", sol_file.path, exc)

        # Apply precision FP filters to novel/adversarial findings too.
        lines = source.split("\n")
        filtered: List[Dict] = []
        for f in findings:
            vid = f.get("id") or f.get("vulnerability_id") or ""
            ln = f.get("line_number") or f.get("line") or 0
            line_text = lines[ln - 1] if 0 < ln <= len(lines) else ""
            if self._is_known_false_positive(vid, line_text, lines, ln):
                continue
            filtered.append(f)
        return filtered

    def _analyze_novel_project_wide(
        self, file_sources: Dict[str, str], repo_dir: str,
    ) -> List[Dict]:
        """Project-wide novel pass: selector + storage-slot collisions.

        Tries to reuse compiled artifacts from `forge build` when a
        Foundry project is present, and falls back to pure-source
        inspection when no artifacts can be produced.
        """
        compiled: Dict[str, Dict] = {}
        try:
            from source_analyzer import SourceAnalyzer
            sa = SourceAnalyzer()
            if sa.has_forge and os.path.isdir(os.path.join(repo_dir, "out")):
                # Reuse existing out/ directory if present (don't re-build,
                # which can be slow and may fail on downstream tests).
                compiled = sa._parse_forge_artifacts(os.path.join(repo_dir, "out"))
        except Exception as exc:
            logger.debug("forge artifact load failed: %s", exc)

        try:
            from novel_analyzers import StorageSelectorAnalyzer
            return StorageSelectorAnalyzer(
                file_sources=file_sources,
                compiled_contracts=compiled,
            ).analyze()
        except Exception as exc:
            logger.debug("StorageSelectorAnalyzer failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # FORGE TSI PLUGIN (Phase 7)
    # ------------------------------------------------------------------

    def _run_forge_plugin(
        self,
        plugin_dir: Optional[str] = None,
        match_contract: str = "TSI_Findings_Report",
        fork_url: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Invoke the Foundry TSI plugin and return its summary dict.

        Returns None when the plugin dir or `forge` binary is unavailable.
        Never raises — failures are returned in the dict so the rest of the
        scan pipeline can continue.
        """
        # Resolve plugin dir: caller override -> ./forge -> repo root /forge
        candidate = plugin_dir or os.path.join(os.getcwd(), "forge")
        plugin_path = Path(candidate)
        if not plugin_path.is_absolute():
            plugin_path = Path(os.getcwd()) / candidate
        if not plugin_path.exists():
            logger.debug("Forge plugin dir %s missing, skipping", plugin_path)
            return None
        if shutil.which("forge") is None:
            logger.debug("`forge` not on PATH, skipping plugin phase")
            return None

        try:
            scripts_dir = Path(__file__).resolve().parent / "scripts"
            import sys as _sys
            if str(scripts_dir) not in _sys.path:
                _sys.path.insert(0, str(scripts_dir))
            from tsi_plugin_runner import run_tsi_plugin  # type: ignore
        except Exception as exc:
            logger.warning("tsi_plugin_runner unavailable: %s", exc)
            return None

        outdir = Path(self.workspace_dir) / "forge_plugin_runs"
        outdir.mkdir(parents=True, exist_ok=True)
        try:
            return run_tsi_plugin(
                root_dir=Path(__file__).resolve().parent,
                outdir=outdir,
                plugin_dir=plugin_path,
                fork_url=fork_url,
                match_contract=match_contract,
            )
        except Exception as exc:
            logger.warning("Forge plugin run raised: %s", exc)
            return {"status": "error", "error": str(exc)}

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
            "languages": {
                "solidity": sum(1 for f in files if f.language == "solidity"),
                "vyper": sum(1 for f in files if f.language == "vyper"),
            },
            "interfaces_skipped": [f.path for f in files if f.is_interface],
            "tests_found": [f.path for f in files if f.is_test],
        }

#!/usr/bin/env python3
"""
Source Analyzer — Compile Solidity source with solc/forge and extract
AST-level information for deeper analysis beyond regex patterns.

Provides:
  - solc compilation with version management
  - Import resolution with remappings
  - AST extraction for cross-contract analysis
  - Forge build integration for full project compilation
"""

import os
import re
import json
import shutil
import logging
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple, Set
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# AST node-type and JSON-key constants (avoids magic strings throughout)
# ---------------------------------------------------------------------------
NODE_TYPE_SOURCE_UNIT   = "SourceUnit"
NODE_TYPE_YUL_BLOCK     = "YulBlock"

KEY_NODE_TYPE           = "nodeType"
KEY_NAME                = "name"
KEY_NODES               = "nodes"
KEY_CHILDREN            = "children"      # legacy solc (<0.4.11)
KEY_ABS_PATH            = "absolutePath"
KEY_AST                 = "ast"
KEY_LEGACY_AST          = "legacyAST"     # solc <0.8
KEY_ID                  = "id"
KEY_CONTENTS            = "contents"
KEY_CONTRACT_KIND       = "contractKind"
KEY_SRC                 = "src"
KEY_STATEMENTS          = "statements"
KEY_GENERATED_SOURCES   = "generatedSources"
KEY_EVM                 = "evm"
KEY_BYTECODE            = "bytecode"
KEY_DEPLOYED_BYTECODE   = "deployedBytecode"
KEY_OBJECT              = "object"
KEY_SOURCE_MAP          = "sourceMap"
KEY_SOURCES             = "sources"
KEY_CONTRACTS           = "contracts"

logger = logging.getLogger("SourceAnalyzer")


# ---------------------------------------------------------------------------
# Solc AST wrapper
# ---------------------------------------------------------------------------

class SolcAST:
    """
    Unified wrapper over both modern solc AST (nodeType / nodes) and the
    legacy format emitted by solc < 0.4.11 (name / children).
    """

    def __init__(self, ast: Dict[str, Any]) -> None:
        self.ast = ast

    @property
    def node_type(self) -> str:
        if KEY_NODE_TYPE in self.ast:
            return self.ast[KEY_NODE_TYPE]
        if KEY_NAME in self.ast:
            return self.ast[KEY_NAME]
        raise ValueError("AST node has neither 'nodeType' nor 'name'")

    @property
    def abs_path(self) -> Optional[str]:
        return self.ast.get(KEY_ABS_PATH)

    @property
    def nodes(self) -> List[Dict[str, Any]]:
        if KEY_NODES in self.ast:
            return self.ast[KEY_NODES]
        if KEY_CHILDREN in self.ast:
            return self.ast[KEY_CHILDREN]
        return []

    def get(self, key: str, default: Any = None) -> Any:
        return self.ast.get(key, default)

    def __getitem__(self, item: str) -> Any:
        return self.ast[item]


# ---------------------------------------------------------------------------
# Source-mapping dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SourceMapping:
    """
    One entry from a solc source map (a semicolon-delimited list).
    Encodes where in the Solidity source a given bytecode instruction came from.
    """
    solidity_file_idx: int   # index into the sources array (-1 = generated)
    offset: int              # byte offset in the source file
    length: int              # byte length
    lineno: Optional[int]    # 1-based line number (None when auto-generated)
    solc_mapping: str        # raw mapping string for this entry


@dataclass
class SourceCodeInfo:
    """Exact source location resolved from a SourceMapping."""
    filename: str
    lineno: Optional[int]
    code: str           # the Solidity snippet this mapping points to
    solc_mapping: str   # raw mapping string


@dataclass
class VyperMatch:
    """Single Vyper pattern match for non-Solidity repos."""
    pattern: str
    line_num: int
    line_content: str
    severity: str
    message: str


class SolcSourceFile:
    """
    Represents a single Solidity source file as seen by the compiler.
    Stores the filename, raw source text, and the set of source-map strings
    that correspond to top-level contract definitions (used to identify
    compiler-generated code regions).
    """

    def __init__(
        self,
        filename: str,
        data: str,
        full_contract_src_maps: Set[str],
    ) -> None:
        self.filename = filename
        self.data = data
        self.full_contract_src_maps = full_contract_src_maps


# ---------------------------------------------------------------------------
# Main compilation result
# ---------------------------------------------------------------------------
class CompilationResult:
    """Result of compiling a Solidity project or file."""
    success: bool
    compiler: str           # "solc" or "forge"
    version: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    contracts: Dict[str, Any] = field(default_factory=dict)  # name -> abi/bytecode
    ast: Optional[Dict] = None


class SourceAnalyzer:
    """Compile and analyze Solidity source code."""

    def __init__(self):
        self._solc_path = shutil.which("solc")
        self._forge_path = shutil.which("forge")

    @property
    def has_solc(self) -> bool:
        return self._solc_path is not None

    @property
    def has_forge(self) -> bool:
        return self._forge_path is not None

    # ------------------------------------------------------------------
    # FORGE BUILD (preferred for full projects)
    # ------------------------------------------------------------------

    def forge_build(self, project_dir: str,
                    extra_args: Optional[List[str]] = None) -> CompilationResult:
        """
        Run `forge build` in a project directory.
        Returns compilation result with contract ABIs.
        """
        if not self.has_forge:
            return CompilationResult(
                success=False, compiler="forge",
                errors=["forge not found in PATH"]
            )

        cmd = ["forge", "build", "--force", "--json"]
        if extra_args:
            cmd.extend(extra_args)

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=300, cwd=project_dir
            )

            errors = []
            warnings = []

            # Parse stderr for errors/warnings
            for line in proc.stderr.splitlines():
                if "error" in line.lower():
                    errors.append(line.strip())
                elif "warning" in line.lower():
                    warnings.append(line.strip())

            success = proc.returncode == 0

            # Parse contract artifacts from out/
            contracts = {}
            out_dir = os.path.join(project_dir, "out")
            if success and os.path.isdir(out_dir):
                contracts = self._parse_forge_artifacts(out_dir)

            return CompilationResult(
                success=success,
                compiler="forge",
                version=self._get_forge_version(),
                errors=errors,
                warnings=warnings,
                contracts=contracts,
            )

        except subprocess.TimeoutExpired:
            return CompilationResult(
                success=False, compiler="forge",
                errors=["forge build timed out (300s)"]
            )
        except Exception as e:
            return CompilationResult(
                success=False, compiler="forge",
                errors=[str(e)]
            )

    def _parse_forge_artifacts(self, out_dir: str) -> Dict[str, Any]:
        """Parse compiled contract artifacts from forge output."""
        contracts = {}
        for contract_dir in Path(out_dir).iterdir():
            if not contract_dir.is_dir():
                continue
            for json_file in contract_dir.glob("*.json"):
                try:
                    data = json.loads(json_file.read_text())
                    name = json_file.stem
                    contracts[name] = {
                        "abi": data.get("abi", []),
                        "bytecode": data.get("bytecode", {}).get("object", ""),
                        "deployed_bytecode": data.get("deployedBytecode", {}).get("object", ""),
                        "method_identifiers": data.get("methodIdentifiers", {}),
                    }
                except Exception:
                    continue
        return contracts

    def _get_forge_version(self) -> Optional[str]:
        try:
            result = subprocess.run(
                ["forge", "--version"], capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip().split("\n")[0]
        except Exception:
            return None

    # ------------------------------------------------------------------
    # VYPER ANALYSIS (pattern-based)
    # ------------------------------------------------------------------

    def analyze_vyper_source(self, source: str, file_path: str = "") -> List[Dict[str, Any]]:
        """
        Analyze Vyper source using lightweight heuristics.
        This is intentionally pattern-based until full Vyper AST support is added.
        """
        findings: List[Dict[str, Any]] = []
        lines = source.split("\n")
        bounded_iterables = self._extract_vyper_bounded_iterables(source)

        findings.extend(self._find_vyper_unbounded_loops(lines, file_path, bounded_iterables))
        findings.extend(self._find_vyper_unsafe_sends(source, lines, file_path))
        findings.extend(self._find_vyper_external_write_functions(source, lines, file_path))
        findings.extend(self._find_vyper_uninitialized_immutables(source, lines, file_path))
        findings.extend(self._find_vyper_bootstrap_pricing_review(source, lines, file_path))
        findings.extend(self._find_vyper_strategy_accounting_review(source, lines, file_path))

        return findings

    def _extract_vyper_bounded_iterables(self, source: str) -> Set[str]:
        """Return variable names that are explicitly bounded via DynArray[..., MAX_*]."""
        bounded: Set[str] = set()
        pattern = re.compile(
            r"(\w+)\s*:\s*(?:public\()?(?:DynArray)\[.*?,\s*([A-Z0-9_]+|\d+)\]\)?",
            re.MULTILINE,
        )
        for match in pattern.finditer(source):
            name = match.group(1)
            bound = match.group(2)
            if bound.isdigit() or bound.startswith("MAX_"):
                bounded.add(name)
                bounded.add(f"self.{name}")
        return bounded

    def _build_vyper_finding(
        self,
        finding_id: str,
        severity: str,
        severity_weight: int,
        category: str,
        title: str,
        description: str,
        recommendation: str,
        file_path: str,
        line_number: int,
        lines: List[str],
        confidence: float = 0.7,
    ) -> Dict[str, Any]:
        start = max(0, line_number - 2)
        end = min(len(lines), line_number + 2)
        snippet = "\n".join(lines[start:end])
        return {
            "id": finding_id,
            "severity": severity,
            "severity_weight": severity_weight,
            "category": category,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "file": file_path,
            "line_number": line_number,
            "code_snippet": snippet,
            "confidence": confidence,
        }

    def _find_vyper_unbounded_loops(self, lines: List[str], file_path: str, bounded_iterables: Set[str]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        loop_pattern = re.compile(r"^\s*for\s+(\w+)\s+in\s+(.+?):")
        for idx, line in enumerate(lines, 1):
            match = loop_pattern.search(line)
            if not match:
                continue
            iterable = match.group(2).strip()
            is_bounded = False
            if "range(" in iterable and re.search(r"range\((\d+)\)", iterable):
                is_bounded = True
            if "MAX_" in iterable or ("[" in iterable and "]" in iterable):
                is_bounded = True
            if iterable in bounded_iterables:
                is_bounded = True
            if iterable.startswith("self.") and iterable in bounded_iterables:
                is_bounded = True
            if is_bounded:
                continue
            findings.append(self._build_vyper_finding(
                finding_id="VYPER-LOOP-001",
                severity="MEDIUM",
                severity_weight=40,
                category="Denial of Service",
                title="Potential Unbounded Loop",
                description=f"Loop iterates over '{iterable}' without an obvious upper bound.",
                recommendation="Enforce a max queue length or split work across bounded batches.",
                file_path=file_path,
                line_number=idx,
                lines=lines,
                confidence=0.8,
            ))
        return findings

    def _find_vyper_unsafe_sends(self, source: str, lines: List[str], file_path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        call_pattern = re.compile(r"(send|raw_call)\(")
        for idx, line in enumerate(lines, 1):
            if not call_pattern.search(line):
                continue
            window_start = max(0, idx - 8)
            header = "\n".join(lines[window_start:idx])
            if "@nonreentrant" in header:
                continue
            findings.append(self._build_vyper_finding(
                finding_id="VYPER-REENTRANCY-001",
                severity="HIGH",
                severity_weight=70,
                category="Reentrancy",
                title="External Value Transfer Without Nonreentrant Guard",
                description="send/raw_call appears in a function without a nearby @nonreentrant decorator.",
                recommendation="Wrap state-changing external transfers with @nonreentrant and checks-effects-interactions.",
                file_path=file_path,
                line_number=idx,
                lines=lines,
                confidence=0.75,
            ))
        return findings

    def _find_vyper_external_write_functions(self, source: str, lines: List[str], file_path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        external_pattern = re.compile(r"^\s*@external\s*$")
        func_pattern = re.compile(r"^\s*def\s+(\w+)\(")
        standard_permissionless = {
            "permit", "balanceOf", "totalSupply", "totalAssets", "totalIdle", "totalDebt",
            "convertToShares", "previewDeposit", "previewMint", "convertToAssets", "maxDeposit",
            "maxMint", "maxWithdraw", "maxRedeem", "previewWithdraw", "previewRedeem",
            "get_default_queue", "isShutdown", "unlockedShares", "FACTORY", "apiVersion",
            "profitMaxUnlockTime", "fullProfitUnlockDate", "profitUnlockingRate",
            "lastProfitUpdate", "DOMAIN_SEPARATOR"
        }
        for idx, line in enumerate(lines, 1):
            if not external_pattern.search(line):
                continue
            if idx >= len(lines):
                continue
            func_line = lines[idx]
            func_match = func_pattern.search(func_line)
            if not func_match:
                continue
            func_name = func_match.group(1)
            if func_name == "__init__" or func_name.startswith("set_"):
                continue
            if func_name in standard_permissionless:
                continue
            decorator_window = "\n".join(lines[max(0, idx - 4):idx + 1])
            signature_window = "\n".join(lines[idx - 1:min(len(lines), idx + 8)])
            if "@view" in decorator_window or "@pure" in decorator_window or "->" in signature_window:
                continue
            body_lines: List[str] = []
            for body_line in lines[idx + 1:]:
                if body_line.startswith("def ") or body_line.startswith("@"):
                    break
                body_lines.append(body_line)
            body = "\n".join(body_lines)
            has_guard = any(token in body for token in [
                "assert", "msg.sender", "role_manager", "only", "governance", "management"
            ])
            if has_guard:
                continue
            findings.append(self._build_vyper_finding(
                finding_id="VYPER-ACCESS-001",
                severity="MEDIUM",
                severity_weight=40,
                category="Access Control",
                title="External Write Function Missing Explicit Guard",
                description=f"@external function '{func_name}' does not show an obvious access-control check.",
                recommendation="Confirm this function is intended to be permissionless or add an explicit sender/role check.",
                file_path=file_path,
                line_number=idx + 1,
                lines=lines,
                confidence=0.55,
            ))
        return findings

    def _find_vyper_uninitialized_immutables(self, source: str, lines: List[str], file_path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        immutable_pattern = re.compile(r"^(\w+):\s+immutable\((.+?)\)\s*$")
        for idx, line in enumerate(lines, 1):
            match = immutable_pattern.search(line)
            if not match:
                continue
            var_name = match.group(1)
            if re.search(rf"(?:self\.)?{re.escape(var_name)}\s*=", source):
                continue
            findings.append(self._build_vyper_finding(
                finding_id="VYPER-INIT-001",
                severity="LOW",
                severity_weight=20,
                category="Initialization",
                title="Immutable May Not Be Initialized",
                description=f"Immutable variable '{var_name}' does not appear to be assigned.",
                recommendation="Verify that the immutable is assigned in __init__ or remove the declaration.",
                file_path=file_path,
                line_number=idx,
                lines=lines,
                confidence=0.5,
            ))
        return findings

    def _find_vyper_bootstrap_pricing_review(self, source: str, lines: List[str], file_path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if "def _convert_to_shares" not in source:
            return findings
        if not re.search(r"if\s+total_supply\s*==\s*0\s*:\s*\n\s*return\s+assets", source, re.MULTILINE):
            return findings
        if any(token in source.lower() for token in ["virtual", "offset", "dead share", "dead_shares"]):
            return findings

        line_number = next((idx for idx, line in enumerate(lines, 1) if "def _convert_to_shares" in line), 1)
        findings.append(self._build_vyper_finding(
            finding_id="VYPER-ERC4626-001",
            severity="LOW",
            severity_weight=20,
            category="Token Security",
            title="ERC4626 Bootstrap Pricing Uses 1:1 Initial Mint",
            description="Initial share minting returns assets 1:1 when total supply is zero and no virtual offset is visible.",
            recommendation="Review first-depositor and donation-based inflation behavior and document whether this bootstrap model is intentional.",
            file_path=file_path,
            line_number=line_number,
            lines=lines,
            confidence=0.45,
        ))
        return findings

    def _find_vyper_strategy_accounting_review(self, source: str, lines: List[str], file_path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if "convertToAssets(strategy_shares)" not in source:
            return findings
        if "gain = unsafe_sub(total_assets, current_debt)" not in source and "loss = unsafe_sub(current_debt, total_assets)" not in source:
            return findings

        line_number = next((idx for idx, line in enumerate(lines, 1) if "convertToAssets(strategy_shares)" in line), 1)
        findings.append(self._build_vyper_finding(
            finding_id="VYPER-ACCOUNTING-001",
            severity="INFO",
            severity_weight=5,
            category="Business Logic",
            title="Strategy Accounting Depends On Live convertToAssets",
            description="Gain/loss accounting relies on strategy convertToAssets during report processing.",
            recommendation="Review whether strategy asset conversion can be manipulated intra-block or during stressed unwind conditions.",
            file_path=file_path,
            line_number=line_number,
            lines=lines,
            confidence=0.4,
        ))
        return findings

    # ------------------------------------------------------------------
    # SOLC COMPILATION (single file or stdin)
    # ------------------------------------------------------------------

    def compile_source(self, source: str, version: str = "0.8.20",
                       remappings: Optional[Dict[str, str]] = None) -> CompilationResult:
        """Compile a single Solidity source string."""
        if not self.has_solc:
            return CompilationResult(
                success=False, compiler="solc",
                errors=["solc not found in PATH"]
            )

        input_json = {
            "language": "Solidity",
            "sources": {
                "input.sol": {"content": source}
            },
            "settings": {
                "outputSelection": {
                    "*": {
                        "*": ["abi", "evm.bytecode.object", "evm.methodIdentifiers"],
                        "": ["ast"]
                    }
                }
            }
        }

        if remappings:
            input_json["settings"]["remappings"] = [
                f"{k}={v}" for k, v in remappings.items()
            ]

        try:
            proc = subprocess.run(
                ["solc", "--standard-json"],
                input=json.dumps(input_json),
                capture_output=True, text=True, timeout=60
            )

            output = json.loads(proc.stdout)
            errors = []
            warnings = []

            for err in output.get("errors", []):
                if err["severity"] == "error":
                    errors.append(err["formattedMessage"])
                else:
                    warnings.append(err["formattedMessage"])

            contracts = {}
            for fname, file_contracts in output.get("contracts", {}).items():
                for cname, cdata in file_contracts.items():
                    contracts[cname] = {
                        "abi": cdata.get("abi", []),
                        "bytecode": cdata.get("evm", {}).get("bytecode", {}).get("object", ""),
                        "method_identifiers": cdata.get("evm", {}).get("methodIdentifiers", {}),
                    }

            # Extract AST
            ast = None
            for fname, fdata in output.get("sources", {}).items():
                if "ast" in fdata:
                    ast = fdata["ast"]
                    break

            return CompilationResult(
                success=len(errors) == 0,
                compiler="solc",
                version=version,
                errors=errors,
                warnings=warnings,
                contracts=contracts,
                ast=ast,
            )

        except Exception as e:
            return CompilationResult(
                success=False, compiler="solc",
                errors=[str(e)]
            )

    # ------------------------------------------------------------------
    # AST ANALYSIS
    # ------------------------------------------------------------------

    def extract_functions(self, ast: Dict) -> List[Dict]:
        """Extract function definitions from AST."""
        functions = []
        self._walk_ast(ast, "FunctionDefinition", functions)
        return functions

    def extract_state_variables(self, ast: Dict) -> List[Dict]:
        """Extract state variable declarations from AST."""
        variables = []
        self._walk_ast(ast, "VariableDeclaration", variables)
        return [v for v in variables if v.get("stateVariable", False)]

    def find_external_calls(self, ast: Dict) -> List[Dict]:
        """Find all external call sites in AST."""
        calls = []
        self._walk_ast(ast, "FunctionCall", calls)
        return [
            c for c in calls
            if c.get("kind") == "functionCall"
            and c.get("expression", {}).get("nodeType") == "MemberAccess"
        ]

    def _walk_ast(self, node: Any, target_type: str, results: List):
        """Walk AST tree collecting nodes of target type (handles both modern and legacy AST)."""
        if isinstance(node, dict):
            # Support both modern 'nodeType' and legacy 'name' fields
            if node.get(KEY_NODE_TYPE) == target_type or node.get(KEY_NAME) == target_type:
                results.append(node)
            for value in node.values():
                self._walk_ast(value, target_type, results)
        elif isinstance(node, list):
            for item in node:
                self._walk_ast(item, target_type, results)

    # ------------------------------------------------------------------
    # CROSS-CONTRACT ANALYSIS
    # ------------------------------------------------------------------

    def analyze_call_graph(self, project_dir: str) -> Dict[str, List[str]]:
        """Build inter-contract call graph from source files."""
        call_graph = {}  # contract -> [called contracts]

        for sol_file in Path(project_dir).rglob("*.sol"):
            try:
                source = sol_file.read_text(encoding="utf-8", errors="replace")
                contracts = re.findall(
                    r"(?:contract|interface|library)\s+(\w+)", source
                )
                for contract in contracts:
                    # Find external calls: ContractName(addr).method() or IContract(addr).method()
                    calls = re.findall(
                        r"(\w+)\s*\([^)]*\)\s*\.\s*\w+\s*\(", source
                    )
                    # Filter to likely contract references
                    external_calls = [
                        c for c in calls
                        if c[0].isupper() and c not in ("IERC20", "IERC721", "Address")
                    ]
                    call_graph[contract] = list(set(external_calls))
            except Exception:
                continue

        return call_graph

    # ------------------------------------------------------------------
    # SOURCE MAP PARSING
    # ------------------------------------------------------------------

    @staticmethod
    def _get_full_contract_src_maps(ast: SolcAST) -> Set[str]:
        """
        Return the set of source-map strings ("offset:length:fileId") for all
        top-level contract definitions in a source unit.  These mark regions
        of bytecode that are compiler-generated boilerplate, not user code.
        """
        source_maps: Set[str] = set()
        if ast.node_type == NODE_TYPE_SOURCE_UNIT:
            for child in ast.nodes:
                if child.get(KEY_CONTRACT_KIND) and KEY_SRC in child:
                    source_maps.add(child[KEY_SRC])
        elif ast.node_type == NODE_TYPE_YUL_BLOCK:
            for child in ast.get(KEY_STATEMENTS, []):
                if KEY_SRC in child:
                    source_maps.add(child[KEY_SRC])
        return source_maps

    @staticmethod
    def _get_generated_sources(
        indices: Dict[int, SolcSourceFile],
        evm_section: Dict[str, Any],
    ) -> None:
        """
        Extract compiler-generated Yul sources from a bytecode section and
        insert them into *indices* so they can be looked up by file ID.
        """
        for source in evm_section.get(KEY_GENERATED_SOURCES, []):
            raw_ast = source.get(KEY_AST, {})
            wrapped = SolcAST(raw_ast)
            src_maps = SourceAnalyzer._get_full_contract_src_maps(wrapped)
            indices[source[KEY_ID]] = SolcSourceFile(
                source.get(KEY_NAME, "<generated>"),
                source.get(KEY_CONTENTS, ""),
                src_maps,
            )

    @classmethod
    def build_source_index(
        cls,
        solc_output: Dict[str, Any],
        input_file: str = "",
    ) -> Dict[int, SolcSourceFile]:
        """
        Build a mapping from source file ID (int) to :class:`SolcSourceFile`
        from a raw solc JSON output dict.

        Handles:
        * Regular source files (``sources`` key, modern + legacy AST)
        * Compiler-generated Yul sources embedded in bytecode sections

        :param solc_output: Parsed solc ``--standard-json`` output.
        :param input_file:  Path used as fallback when ``absolutePath`` is absent.
        :returns: Dict mapping source-file index → SolcSourceFile.
        """
        indices: Dict[int, SolcSourceFile] = {}

        # Generated sources embedded in each contract's EVM sections
        for file_contracts in solc_output.get(KEY_CONTRACTS, {}).values():
            for contract_data in file_contracts.values():
                evm = contract_data.get(KEY_EVM, {})
                cls._get_generated_sources(indices, evm.get(KEY_BYTECODE, {}))
                cls._get_generated_sources(indices, evm.get(KEY_DEPLOYED_BYTECODE, {}))

        # Regular source files
        for _fname, source_entry in solc_output.get(KEY_SOURCES, {}).items():
            # Prefer modern AST, fall back to legacyAST
            raw_ast = source_entry.get(KEY_AST) or source_entry.get(KEY_LEGACY_AST)
            if raw_ast is None:
                continue
            wrapped = SolcAST(raw_ast)
            src_maps = cls._get_full_contract_src_maps(wrapped)
            abs_path = wrapped.abs_path or input_file

            try:
                data = Path(abs_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                # Inline content (standard-json) is not on disk; skip file read
                data = source_entry.get(KEY_CONTENTS, "")

            file_id = source_entry.get(KEY_ID)
            if file_id is not None:
                indices[file_id] = SolcSourceFile(abs_path, data, src_maps)

        return indices

    @staticmethod
    def parse_source_map(
        srcmap_str: str,
        source_index: Dict[int, SolcSourceFile],
    ) -> List[SourceMapping]:
        """
        Parse a solc source map string into a list of :class:`SourceMapping` objects.

        The source map is a semicolon-delimited sequence of entries, each of the
        form ``offset:length:fileIndex:jumpType:modifierDepth``.  Empty fields
        inherit the value from the previous entry (per the solc specification).

        :param srcmap_str:    The raw source-map string from solc output.
        :param source_index:  Source file index built by :meth:`build_source_index`.
        :returns: List of SourceMapping, one per bytecode instruction.
        """
        mappings: List[SourceMapping] = []
        prev_parts = ["0", "0", "-1", "", ""]

        for entry in srcmap_str.split(";"):
            parts = entry.split(":")
            # Merge with previous: empty field inherits
            merged = [
                parts[i] if i < len(parts) and parts[i] != "" else prev_parts[i]
                for i in range(5)
            ]
            prev_parts = merged

            try:
                offset = int(merged[0])
                length = int(merged[1])
                idx    = int(merged[2])
            except (ValueError, IndexError):
                offset, length, idx = 0, 0, -1

            # Determine line number (None for auto-generated / unknown file)
            lineno: Optional[int] = None
            sol_file = source_index.get(idx)
            if idx != -1 and sol_file is not None:
                src_key = f"{offset}:{length}:{idx}"
                if src_key not in sol_file.full_contract_src_maps:
                    try:
                        data_bytes = sol_file.data.encode("utf-8")
                        lineno = data_bytes[:offset].count(b"\n") + 1
                    except Exception:
                        pass

            mappings.append(SourceMapping(idx, offset, length, lineno, entry))

        return mappings

    @staticmethod
    def get_source_info(
        mapping: SourceMapping,
        source_index: Dict[int, SolcSourceFile],
    ) -> Optional[SourceCodeInfo]:
        """
        Resolve a :class:`SourceMapping` to a :class:`SourceCodeInfo` object
        containing the filename, line number, and the Solidity code snippet.

        Returns ``None`` for compiler-generated / unmappable entries.
        """
        if mapping.solidity_file_idx == -1:
            return None
        sol_file = source_index.get(mapping.solidity_file_idx)
        if sol_file is None:
            return None
        try:
            data_bytes = sol_file.data.encode("utf-8")
            snippet = data_bytes[
                mapping.offset: mapping.offset + mapping.length
            ].decode("utf-8", errors="ignore")
        except Exception:
            snippet = ""
        return SourceCodeInfo(
            filename=sol_file.filename,
            lineno=mapping.lineno,
            code=snippet,
            solc_mapping=mapping.solc_mapping,
        )

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
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("SourceAnalyzer")


@dataclass
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
        """Walk AST tree collecting nodes of target type."""
        if isinstance(node, dict):
            if node.get("nodeType") == target_type:
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

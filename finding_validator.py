#!/usr/bin/env python3
"""
Finding Validator — Phase 2 of the scan pipeline.

After the pattern-matching scanner produces raw findings, this module
validates each finding with deeper semantic analysis to assign an
exploitability confidence tier:

  CONFIRM_FIRST  — High confidence, externally reachable, no guards
  NEEDS_CONTEXT  — Pattern matched but guards present or path unclear
  LIKELY_NOISE   — Protected, internal, constructor-scoped, or covered by tests

This dramatically reduces manual review effort (e.g. 265 → 20-30 actionable).
"""

import re
import logging
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("FindingValidator")


# ─────────────────────────────────────────────────────────────────────
# Confidence tiers
# ─────────────────────────────────────────────────────────────────────

class ConfidenceTier(Enum):
    CONFIRM_FIRST = "confirm_first"   # Reachable, no guards — review immediately
    NEEDS_CONTEXT = "needs_context"   # Guards present or path unclear
    LIKELY_NOISE  = "likely_noise"    # Protected, internal, or test-covered


# ─────────────────────────────────────────────────────────────────────
# High-risk callback registry
# ─────────────────────────────────────────────────────────────────────

# Functions that execute mid-operation — on-chain state is inconsistent
# during their execution. Findings inside these are auto-escalated.
HIGH_RISK_CALLBACKS: Set[str] = {
    # Uniswap V2/V3/V4
    "uniswapV2Call",
    "uniswapV3SwapCallback",
    "uniswapV3MintCallback",
    "uniswapV3FlashCallback",
    # Pancake / Algebra forks
    "pancakeV3SwapCallback",
    "pancakeV3MintCallback",
    "algebraSwapCallback",
    "algebraMintCallback",
    # Flash loans
    "onFlashLoan",             # ERC-3156
    "receiveFlashLoan",        # Balancer
    "executeOperation",        # Aave
    # Cross-chain / bridge
    "sgReceive",               # Stargate
    "lzReceive",               # LayerZero
    "_lzReceive",
    "_nonblockingLzReceive",
    "ccipReceive",             # Chainlink CCIP
    "onOFTReceived",           # LayerZero OFT
    "anySwapIn",               # Multichain
    "bridgeCallback",
    # ERC token hooks
    "onERC721Received",
    "onERC1155Received",
    "onERC1155BatchReceived",
    "tokensReceived",          # ERC-777
    "tokensToSend",            # ERC-777
    # Uniswap V4 hooks
    "beforeSwap",
    "afterSwap",
    "beforeAddLiquidity",
    "afterAddLiquidity",
    "beforeRemoveLiquidity",
    "afterRemoveLiquidity",
    # General
    "fallback",
    "receive",
}


# ─────────────────────────────────────────────────────────────────────
# Parsed structures
# ─────────────────────────────────────────────────────────────────────

@dataclass
class FunctionInfo:
    """Parsed information about a Solidity function."""
    name: str
    visibility: str          # public, external, internal, private
    modifiers: List[str]     # nonReentrant, onlyOwner, etc.
    is_payable: bool
    is_view: bool
    is_pure: bool
    line_start: int
    line_end: int
    body: str
    has_external_call: bool  # .call{, .transfer(, .send(
    state_writes: List[str]  # State variables modified
    always_reverts: bool = False       # Function always reverts (simulation)
    is_simulation: bool = False        # try/catch pattern around always-reverting call
    state_writes_after_call: bool = False  # State modified AFTER external call (CEI violation)
    is_callback: bool = False          # Function is a known high-risk callback

    @property
    def is_reachable(self) -> bool:
        """Can this function be called from outside the contract?"""
        return self.visibility in ("public", "external")

    @property
    def has_access_control(self) -> bool:
        """Does this function have any access-control modifier?"""
        access_mods = {
            "onlyowner", "onlyadmin", "onlygov", "onlygovernance",
            "onlyminter", "onlyguardian", "onlyoperator", "onlymanager",
            "onlyrole", "onlyauthorized", "onlyproxy", "onlydelegate",
            "onlyfactory", "onlypool", "onlyrouter", "onlykeeper",
            "onlyvalidator", "onlyproposer", "onlyexecutor", "whenlocked",
            "whennotpaused", "whenpaused", "initializer", "reinitializer",
        }
        return any(m.lower() in access_mods for m in self.modifiers)

    @property
    def has_reentrancy_guard(self) -> bool:
        return any(m.lower() in ("nonreentrant", "noreentrant", "lock", "mutex")
                   for m in self.modifiers)


@dataclass
class ContractInfo:
    """Parsed information about a Solidity contract."""
    name: str
    kind: str               # contract, interface, library, abstract
    bases: List[str]        # Inherited contracts
    functions: List[FunctionInfo]
    state_variables: List[str]
    line_start: int
    source: str

    @property
    def inherits_access_control(self) -> bool:
        ac_bases = {
            "ownable", "ownable2step", "accesscontrol", "accesscontroldefaultadminenumerable",
            "accesscontrolenumerable", "governor", "governorcompatibilitybravo",
            "timelockcontroller", "pausable",
        }
        return any(b.lower() in ac_bases for b in self.bases)

    @property
    def inherits_reentrancy_guard(self) -> bool:
        return any(b.lower() in ("reentrancyguard", "reentrancyguardupgradeable")
                   for b in self.bases)


@dataclass
class ValidationResult:
    """Enriched finding with validation metadata."""
    finding: Dict
    tier: ConfidenceTier
    function_name: Optional[str] = None
    visibility: Optional[str] = None
    modifiers: List[str] = field(default_factory=list)
    access_controlled: bool = False
    reentrancy_guarded: bool = False
    is_reachable: bool = True
    has_test_coverage: bool = False
    is_constructor_scoped: bool = False
    is_view_function: bool = False
    always_reverts: bool = False
    is_simulation: bool = False
    no_state_after_call: bool = False
    is_callback: bool = False
    cross_function_reentrant: bool = False
    deprioritize_reasons: List[str] = field(default_factory=list)
    prioritize_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = dict(self.finding)
        d["validation"] = {
            "tier": self.tier.value,
            "function": self.function_name,
            "visibility": self.visibility,
            "modifiers": self.modifiers,
            "access_controlled": self.access_controlled,
            "reentrancy_guarded": self.reentrancy_guarded,
            "is_reachable": self.is_reachable,
            "has_test_coverage": self.has_test_coverage,
            "is_constructor_scoped": self.is_constructor_scoped,
            "is_view_function": self.is_view_function,
            "always_reverts": self.always_reverts,
            "is_simulation": self.is_simulation,
            "no_state_after_call": self.no_state_after_call,
            "is_callback": self.is_callback,
            "cross_function_reentrant": self.cross_function_reentrant,
            "deprioritize_reasons": self.deprioritize_reasons,
            "prioritize_reasons": self.prioritize_reasons,
        }
        return d


# ─────────────────────────────────────────────────────────────────────
# Source parser — extracts contracts & functions from raw Solidity
# ─────────────────────────────────────────────────────────────────────

class SolidityParser:
    """Lightweight Solidity parser for validation (no AST/compiler needed)."""

    # Visibility keywords
    VISIBILITY_RE = re.compile(r"\b(public|external|internal|private)\b")
    # Mutability keywords
    MUTABILITY_RE = re.compile(r"\b(view|pure|payable)\b")
    # Function header
    FUNC_RE = re.compile(
        r"function\s+(\w+)\s*\(([^)]*)\)\s*([^{]*?)\{",
        re.DOTALL
    )
    # Constructor
    CONSTRUCTOR_RE = re.compile(r"constructor\s*\(([^)]*)\)\s*([^{]*?)\{", re.DOTALL)
    # Contract/interface/library declaration
    CONTRACT_RE = re.compile(
        r"(contract|interface|library|abstract\s+contract)\s+(\w+)"
        r"(?:\s+is\s+([^{]+))?\s*\{",
        re.DOTALL
    )
    # Modifier names (words after visibility/mutability that aren't keywords)
    SOLIDITY_KEYWORDS = {
        "public", "external", "internal", "private",
        "view", "pure", "payable", "virtual", "override",
        "returns", "return", "memory", "calldata", "storage",
    }
    # State variable
    STATE_VAR_RE = re.compile(
        r"^\s*(?:mapping\s*\([^)]*\)|uint\d*|int\d*|address|bool|bytes\d*|string|"
        r"I\w+|IERC\w+)\s+(?:public\s+|private\s+|internal\s+)?"
        r"(?:immutable\s+|constant\s+)?(\w+)\s*[;=]",
        re.MULTILINE
    )
    # External calls
    EXTERNAL_CALL_RE = re.compile(r"\.(call|delegatecall|staticcall)\s*[{(]|\.transfer\(|\.send\(")
    # State writes: simple assignment to state var (var = ..., var += ..., mapping[x] = ...)
    STATE_WRITE_RE = re.compile(r"(\w+(?:\[[^\]]*\])?)\s*(?:[+\-*/]?=)\s*(?!=)")
    # Always-revert patterns: assembly revert, revert(), revert ErrorName()
    ALWAYS_REVERT_RE = re.compile(
        r"(?:revert\s*\([^)]*\)\s*;|revert\s+\w+\s*\([^)]*\)\s*;|"
        r"assembly\s*\{[^}]*revert\s*\([^)]*\)[^}]*\})"
    )
    # Simulation pattern: try ... { revert() } catch
    SIMULATION_RE = re.compile(
        r"try\s+.*?\{[^}]*revert\s*\(\s*\)[^}]*\}\s*catch",
        re.DOTALL
    )

    def parse_file(self, source: str) -> List[ContractInfo]:
        """Parse a Solidity source file into contracts with functions."""
        contracts = []
        for cm in self.CONTRACT_RE.finditer(source):
            kind = cm.group(1).strip()
            name = cm.group(2)
            bases_str = cm.group(3) or ""
            bases = [b.strip().split("(")[0].strip() for b in bases_str.split(",") if b.strip()]

            # Extract contract body using brace matching
            body_start = cm.end()
            body = self._extract_braced_body(source, body_start - 1)
            if not body:
                continue

            line_start = source[:cm.start()].count("\n") + 1
            state_vars = self.STATE_VAR_RE.findall(body)
            functions = self._parse_functions(body, line_start, state_vars)

            contracts.append(ContractInfo(
                name=name,
                kind=kind,
                bases=bases,
                functions=functions,
                state_variables=state_vars,
                line_start=line_start,
                source=body,
            ))

        return contracts

    def _parse_functions(self, contract_body: str, contract_line_offset: int,
                         state_vars: List[str]) -> List[FunctionInfo]:
        """Parse all functions within a contract body."""
        functions = []
        state_var_set = set(state_vars)

        for fm in self.FUNC_RE.finditer(contract_body):
            func_name = fm.group(1)
            qualifiers = fm.group(3)

            # Extract function body
            body_start = fm.end() - 1  # points to '{'
            func_body = self._extract_braced_body(contract_body, body_start)
            if func_body is None:
                func_body = ""

            # Visibility
            vis_match = self.VISIBILITY_RE.search(qualifiers)
            visibility = vis_match.group(1) if vis_match else "public"  # Solidity default

            # Mutability
            is_view = bool(re.search(r"\bview\b", qualifiers))
            is_pure = bool(re.search(r"\bpure\b", qualifiers))
            is_payable = bool(re.search(r"\bpayable\b", qualifiers))

            # Modifiers — everything that's not a keyword, visibility, or returns clause
            mod_str = re.sub(r"returns\s*\([^)]*\)", "", qualifiers)
            words = re.findall(r"\b(\w+)\b", mod_str)
            modifiers = [w for w in words if w.lower() not in self.SOLIDITY_KEYWORDS]

            # External calls
            has_ext_call = bool(self.EXTERNAL_CALL_RE.search(func_body))

            # State writes
            writes = []
            for wm in self.STATE_WRITE_RE.finditer(func_body):
                var_name = wm.group(1).split("[")[0]  # strip mapping key
                if var_name in state_var_set:
                    writes.append(var_name)

            # Always-revert detection
            always_reverts = self._detect_always_reverts(func_body)

            # Simulation detection (try ... { revert() } catch)
            is_simulation = bool(self.SIMULATION_RE.search(func_body))

            # State writes after external call (CEI violation indicator)
            state_after_call = self._detect_state_after_call(
                func_body, state_var_set
            ) if has_ext_call else False

            line_start = contract_body[:fm.start()].count("\n") + contract_line_offset
            line_end = contract_body[:fm.end() + len(func_body)].count("\n") + contract_line_offset

            functions.append(FunctionInfo(
                name=func_name,
                visibility=visibility,
                modifiers=modifiers,
                is_payable=is_payable,
                is_view=is_view,
                is_pure=is_pure,
                line_start=line_start,
                line_end=line_end,
                body=func_body,
                has_external_call=has_ext_call,
                state_writes=writes,
                always_reverts=always_reverts,
                is_simulation=is_simulation,
                state_writes_after_call=state_after_call,
                is_callback=func_name in HIGH_RISK_CALLBACKS,
            ))

        # Also parse constructor
        for cm in self.CONSTRUCTOR_RE.finditer(contract_body):
            body_start = cm.end() - 1
            ctor_body = self._extract_braced_body(contract_body, body_start)
            if ctor_body is None:
                ctor_body = ""
            line_start = contract_body[:cm.start()].count("\n") + contract_line_offset
            line_end = contract_body[:cm.end() + len(ctor_body)].count("\n") + contract_line_offset
            functions.append(FunctionInfo(
                name="constructor",
                visibility="internal",  # constructors aren't callable post-deploy
                modifiers=[],
                is_payable=bool(re.search(r"\bpayable\b", cm.group(2))),
                is_view=False,
                is_pure=False,
                line_start=line_start,
                line_end=line_end,
                body=ctor_body,
                has_external_call=bool(self.EXTERNAL_CALL_RE.search(ctor_body)),
                state_writes=[],
            ))

        return functions

    @staticmethod
    def _extract_braced_body(source: str, open_brace_pos: int) -> Optional[str]:
        """Extract content between matching braces starting at open_brace_pos."""
        if open_brace_pos >= len(source) or source[open_brace_pos] != '{':
            return None
        depth = 1
        i = open_brace_pos + 1
        while i < len(source) and depth > 0:
            if source[i] == '{':
                depth += 1
            elif source[i] == '}':
                depth -= 1
            i += 1
        return source[open_brace_pos + 1: i - 1]

    def _detect_always_reverts(self, func_body: str) -> bool:
        """Detect if a function always reverts (simulation/dry-run pattern).

        Catches:
          - Ends with revert(), revert ErrorName(), or assert(false)
          - Contains assembly { revert(...) } as the final path
          - Calls an internal helper that always reverts (e.g. _throwRevert)
          - All code paths end in revert
        """
        stripped = func_body.strip()
        if not stripped:
            return False

        # Direct: function body ends with revert statement
        if re.search(r"revert\s*\([^)]*\)\s*;\s*$", stripped):
            return True

        # Assembly revert at end of function
        if re.search(r"assembly\s*\{[^}]*revert\s*\([^)]*\)[^}]*\}\s*$", stripped):
            return True

        # assert(false) at end
        if re.search(r"assert\s*\(\s*false\s*\)\s*;\s*$", stripped):
            return True

        # Calls a helper named *revert* / *throw* at the end
        if re.search(r"_(?:throw|force|do)(?:Revert|Throw)\s*\([^)]*\)\s*;\s*$", stripped, re.IGNORECASE):
            return True

        # All branches revert: if/else where both paths revert
        # Simplified: check if every exit point is a revert
        lines = [l.strip() for l in stripped.split("\n") if l.strip()]
        if lines:
            last_line = lines[-1].rstrip(";").strip()
            if last_line.startswith("revert") or "_throwRevert" in last_line:
                return True

        return False

    def _detect_state_after_call(self, func_body: str,
                                  state_vars: Set[str]) -> bool:
        """Detect if state variables are written AFTER an external call.

        This indicates a CEI (Checks-Effects-Interactions) violation —
        the pattern that makes reentrancy exploitable.
        If external call exists but no state is modified after it,
        reentrancy is not exploitable.
        """
        # Find the last external call position
        ext_call_positions = [
            m.start() for m in self.EXTERNAL_CALL_RE.finditer(func_body)
        ]
        if not ext_call_positions:
            return False

        last_call_pos = max(ext_call_positions)
        after_call = func_body[last_call_pos:]

        # Check for state variable writes after the call
        for wm in self.STATE_WRITE_RE.finditer(after_call):
            var_name = wm.group(1).split("[")[0]
            if var_name in state_vars:
                return True

        return False


# ─────────────────────────────────────────────────────────────────────
# Test coverage detector
# ─────────────────────────────────────────────────────────────────────

class TestCoverageDetector:
    """Detect which functions/contracts have test coverage in the repo."""

    def __init__(self, test_files: List[str]):
        """
        Args:
            test_files: List of absolute paths to test .sol files
        """
        self._test_source = ""
        for tf in test_files:
            try:
                self._test_source += Path(tf).read_text(encoding="utf-8", errors="replace") + "\n"
            except Exception:
                pass
        self._test_source_lower = self._test_source.lower()

    def is_function_tested(self, contract_name: str, function_name: str) -> bool:
        """Check if there's a test that references this function."""
        if not self._test_source:
            return False
        # Look for test functions referencing the function name
        # Common patterns: test_functionName, testFunctionName, contract.functionName(
        patterns = [
            f"test_{function_name}",
            f"test{function_name[0].upper()}{function_name[1:]}" if function_name else "",
            f".{function_name}(",
            f'"{function_name}"',
        ]
        return any(p and p.lower() in self._test_source_lower for p in patterns)

    def is_contract_tested(self, contract_name: str) -> bool:
        """Check if any test references this contract."""
        if not self._test_source:
            return False
        patterns = [
            contract_name.lower(),
            f"test{contract_name}".lower(),
            f"{contract_name}test".lower(),
        ]
        return any(p in self._test_source_lower for p in patterns)


# ─────────────────────────────────────────────────────────────────────
# The main validator
# ─────────────────────────────────────────────────────────────────────

class FindingValidator:
    """
    Phase 2: Validate raw findings with semantic analysis.

    For each finding, determines:
      1. Is the function reachable? (public/external vs internal/private)
      2. Does it have any modifier? (nonReentrant, onlyOwner, etc.)
      3. Is the vulnerable code path behind an access control gate?
      4. Is there an existing test covering this code path?

    Then assigns a confidence tier for triage.
    """

    def __init__(self, test_files: Optional[List[str]] = None):
        self.parser = SolidityParser()
        self.test_detector = TestCoverageDetector(test_files or [])
        # Cache: file path → parsed contracts
        self._parse_cache: Dict[str, List[ContractInfo]] = {}

    def validate_findings(self, findings: List[Dict],
                          file_sources: Dict[str, str]) -> List[ValidationResult]:
        """
        Validate a list of raw findings against their source files.

        Args:
            findings: Raw findings from the scanner
            file_sources: Mapping of relative file path → source code
        Returns:
            List of ValidationResult with tier assignments
        """
        # Parse all source files
        for file_path, source in file_sources.items():
            if file_path not in self._parse_cache:
                try:
                    self._parse_cache[file_path] = self.parser.parse_file(source)
                except Exception as e:
                    logger.warning(f"Failed to parse {file_path}: {e}")
                    self._parse_cache[file_path] = []

        results = []
        for finding in findings:
            result = self._validate_single(finding)
            results.append(result)

        return results

    def _validate_single(self, finding: Dict) -> ValidationResult:
        """Validate a single finding and assign a confidence tier."""
        file_path = finding.get("file", "")
        line_number = finding.get("line_number", 0)
        vuln_id = finding.get("id", "")
        severity = finding.get("severity", "")

        vr = ValidationResult(finding=finding, tier=ConfidenceTier.CONFIRM_FIRST)

        # Get parsed contracts for this file
        contracts = self._parse_cache.get(file_path, [])
        if not contracts:
            # Can't parse → stay at NEEDS_CONTEXT
            vr.tier = ConfidenceTier.NEEDS_CONTEXT
            vr.deprioritize_reasons.append("unable to parse contract structure")
            return vr

        # Find the function containing this line
        func_info, contract_info = self._find_enclosing_function(contracts, line_number)

        if func_info:
            vr.function_name = func_info.name
            vr.visibility = func_info.visibility
            vr.modifiers = func_info.modifiers
            vr.access_controlled = func_info.has_access_control
            vr.reentrancy_guarded = func_info.has_reentrancy_guard
            vr.is_reachable = func_info.is_reachable
            vr.is_view_function = func_info.is_view or func_info.is_pure
            vr.is_constructor_scoped = func_info.name == "constructor"
            vr.always_reverts = func_info.always_reverts
            vr.is_simulation = func_info.is_simulation
            vr.is_callback = func_info.is_callback
            vr.no_state_after_call = (
                func_info.has_external_call and not func_info.state_writes_after_call
            )

            # Cross-function reentrancy check
            if contract_info and func_info.has_external_call:
                vr.cross_function_reentrant = self._check_cross_function_reentrancy(
                    func_info, contract_info
                )

            # Check inherited protections from the contract level
            if contract_info:
                if contract_info.inherits_reentrancy_guard and not vr.reentrancy_guarded:
                    # Contract inherits guard but this function may not use it — flag as context
                    pass
                if contract_info.inherits_access_control and not vr.access_controlled:
                    # Contract has AC but this function may be unprotected — check modifiers
                    pass

        # Test coverage check
        if func_info and contract_info:
            vr.has_test_coverage = self.test_detector.is_function_tested(
                contract_info.name, func_info.name
            )

        # ── Tier assignment logic ──

        depri = vr.deprioritize_reasons
        pri = vr.prioritize_reasons

        # ── Callback escalation (highest priority check) ──
        # Findings inside known callback functions are auto-escalated.
        # Callbacks execute mid-operation with inconsistent state —
        # any state read, oracle query, or valuation is suspect.
        if vr.is_callback:
            pri.append(f"inside callback function '{vr.function_name}' (state may be inconsistent)")
            # TSI-category findings in callbacks are always CONFIRM_FIRST
            cat = finding.get("category", "")
            if cat == "Temporal State Inconsistency" or vuln_id.startswith("TSI-"):
                pri.append("TSI pattern inside callback — highest risk")
                vr.tier = ConfidenceTier.CONFIRM_FIRST
                return vr
            # Other findings in callbacks skip most downgrades but still
            # respect always-reverts (a simulation callback is still noise)

        # LIKELY_NOISE conditions
        if vr.is_constructor_scoped:
            depri.append("constructor-scoped (not callable post-deployment)")
            vr.tier = ConfidenceTier.LIKELY_NOISE
            return vr

        if vr.is_view_function and vuln_id not in ("SWC-107", "REENT-001", "REENT-002"):
            depri.append("view/pure function (no state changes)")
            vr.tier = ConfidenceTier.LIKELY_NOISE
            return vr

        if not vr.is_reachable:
            depri.append(f"internal/private function ({vr.visibility})")
            vr.tier = ConfidenceTier.LIKELY_NOISE
            return vr

        # Always-revert / simulation functions — no state persists
        if vr.always_reverts:
            depri.append("function always reverts (simulation/dry-run, no state persists)")
            vr.tier = ConfidenceTier.LIKELY_NOISE
            return vr

        if vr.is_simulation:
            depri.append("simulation pattern (try/catch around always-reverting call)")
            vr.tier = ConfidenceTier.LIKELY_NOISE
            return vr

        # Gas-only findings are always low priority
        if severity == "GAS":
            depri.append("gas optimization only")
            vr.tier = ConfidenceTier.LIKELY_NOISE
            return vr

        # INFO findings deprioritized unless reachable + no guards
        if severity == "INFO" and (vr.access_controlled or not vr.is_reachable):
            depri.append("informational with access control")
            vr.tier = ConfidenceTier.LIKELY_NOISE
            return vr

        # ── Callback findings that survived noise filters → CONFIRM_FIRST ──
        if vr.is_callback:
            vr.tier = ConfidenceTier.CONFIRM_FIRST
            return vr

        # NEEDS_CONTEXT conditions
        needs_context = False

        if vr.access_controlled:
            depri.append(f"access-controlled ({', '.join(vr.modifiers)})")
            needs_context = True

        if vr.reentrancy_guarded and vuln_id in ("SWC-107", "REENT-001", "REENT-002"):
            depri.append("has reentrancy guard")
            needs_context = True

        # Reentrancy with no state written after call — CEI is correct
        # BUT: check cross-function reentrancy before downgrading
        if vr.no_state_after_call and vuln_id in ("SWC-107", "REENT-001", "REENT-002"):
            if vr.cross_function_reentrant:
                # CEI within this function, but other public functions
                # read shared state → still exploitable via cross-function reentry
                pri.append(
                    "CEI correct in this function, but other public/external "
                    "functions read the same state variables — cross-function "
                    "reentrancy still possible during the external call"
                )
                # Do NOT downgrade — leave at CONFIRM_FIRST
            else:
                depri.append("no state modifications after external call (CEI pattern correct)")
                needs_context = True

        if vr.has_test_coverage:
            depri.append("function has test coverage")
            needs_context = True

        # Check if the contract inherits protection relevant to this finding
        if contract_info:
            cat = finding.get("category", "")
            if cat == "Reentrancy" and contract_info.inherits_reentrancy_guard:
                depri.append(f"contract inherits ReentrancyGuard via {contract_info.bases}")
                needs_context = True
            if cat == "Access Control" and contract_info.inherits_access_control:
                depri.append(f"contract inherits access control via {contract_info.bases}")
                needs_context = True

        if needs_context:
            vr.tier = ConfidenceTier.NEEDS_CONTEXT
            return vr

        # CONFIRM_FIRST — reachable, no guards, no tests
        pri.append("externally reachable")
        pri.append("no access control modifier")
        if not vr.has_test_coverage:
            pri.append("no test coverage detected")
        if severity in ("CRITICAL", "HIGH"):
            pri.append(f"{severity} severity")
        if func_info and func_info.has_external_call:
            pri.append("contains external call")
        if func_info and func_info.state_writes:
            pri.append(f"modifies state: {', '.join(func_info.state_writes[:3])}")

        vr.tier = ConfidenceTier.CONFIRM_FIRST
        return vr

    def _find_enclosing_function(
        self, contracts: List[ContractInfo], line_number: int
    ) -> Tuple[Optional[FunctionInfo], Optional[ContractInfo]]:
        """Find the function that contains the given line number."""
        for contract in contracts:
            for func in contract.functions:
                if func.line_start <= line_number <= func.line_end:
                    return func, contract
        # If no exact match, find closest function before the line
        best_func = None
        best_contract = None
        best_dist = float("inf")
        for contract in contracts:
            for func in contract.functions:
                if func.line_start <= line_number:
                    dist = line_number - func.line_start
                    if dist < best_dist:
                        best_dist = dist
                        best_func = func
                        best_contract = contract
        return best_func, best_contract

    def _check_cross_function_reentrancy(
        self, func: FunctionInfo, contract: ContractInfo
    ) -> bool:
        """Check for cross-function reentrancy exposure.

        Even if a function follows CEI (state updated before call),
        reentrancy can still be exploitable if:
          - Function A writes state S then calls external
          - Function B (public/external) reads state S
          - During the reentrant call from A, attacker calls B
            which now sees the updated-but-not-finalized state

        The classic example:
            function withdraw() {
                balances[msg.sender] = 0;   // CEI: state before call ✓
                msg.sender.call{value: amount}("");  // call last ✓
                // BUT: another function reads balances during reentry
            }
            function getBalance() view returns (uint) {
                return balances[msg.sender]; // reads stale/manipulated state
            }

        Returns True if other public functions read state that this
        function writes before its external call.
        """
        if not func.has_external_call or not func.state_writes:
            return False

        # Get state vars written by this function
        written_vars = set(func.state_writes)

        # Check other public/external functions in the same contract
        for other_func in contract.functions:
            if other_func.name == func.name:
                continue
            if not other_func.is_reachable:
                continue
            # Skip if the other function also has a reentrancy guard
            if other_func.has_reentrancy_guard:
                continue

            # Check if the other function reads any of the written vars
            # Look for variable references in the function body
            for var in written_vars:
                # Match: var as standalone identifier or mapping read var[...]
                var_read_re = re.compile(
                    r"\b" + re.escape(var) + r"\b(?!\s*(?:[+\-*/]?=))"
                )
                if var_read_re.search(other_func.body):
                    return True

        return False

    # ──────────────────────────────────────────────────────────────
    # SUMMARY
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def build_triage_summary(results: List[ValidationResult]) -> Dict:
        """Build a triage summary from validated results."""
        tiers = {t.value: [] for t in ConfidenceTier}
        for r in results:
            tiers[r.tier.value].append(r.to_dict())

        confirm = tiers[ConfidenceTier.CONFIRM_FIRST.value]
        context = tiers[ConfidenceTier.NEEDS_CONTEXT.value]
        noise = tiers[ConfidenceTier.LIKELY_NOISE.value]

        # Severity breakdown within confirm_first
        confirm_by_sev = {}
        for f in confirm:
            sev = f.get("severity", "UNKNOWN")
            confirm_by_sev[sev] = confirm_by_sev.get(sev, 0) + 1

        return {
            "total_findings": len(results),
            "triage": {
                "confirm_first": len(confirm),
                "needs_context": len(context),
                "likely_noise": len(noise),
            },
            "reduction_percent": round(
                (1 - len(confirm) / max(len(results), 1)) * 100, 1
            ),
            "confirm_first_by_severity": confirm_by_sev,
            "findings_by_tier": tiers,
        }

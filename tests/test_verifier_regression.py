"""
Regression tests for exploit_verifier.

Each test feeds a tiny synthetic contract through `verify_all_findings`
and asserts the verifier disposition (CONFIRMED / DISPROVEN / etc.) for
both a positive (truly vulnerable) and a negative (properly guarded)
fixture. This prevents the kind of false-CONFIRMED we just fixed in
CRYPTO-RPL from re-emerging.

Run with:
    pytest -q tests/test_verifier_regression.py
"""

from __future__ import annotations

import pytest

from exploit_verifier import (
    ExploitConfidence,
    ExploitVerifier,
    verify_all_findings,
)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _run(vuln_id: str, source: str, line_number: int, *, file_path: str = "Test.sol"):
    """Run the full verifier chain on a single synthetic finding."""
    finding = {
        "id": vuln_id,
        "file": file_path,
        "line_number": line_number,
        "severity": "HIGH",
        "title": f"test {vuln_id}",
        "description": "synthetic regression fixture",
        "code_snippet": "",
    }
    results = verify_all_findings([finding], {file_path: source})
    return results[0] if results else None


# ──────────────────────────────────────────────────────────────────────
# Smoke: VERIFIER_MAP is non-empty and every entry has a method
# ──────────────────────────────────────────────────────────────────────

def test_verifier_map_methods_exist():
    v = ExploitVerifier()
    assert ExploitVerifier.VERIFIER_MAP, "VERIFIER_MAP must not be empty"
    for vuln_id, name in ExploitVerifier.VERIFIER_MAP.items():
        method = getattr(v, f"_verify_{name}", None)
        assert method is not None, f"Missing _verify_{name} for {vuln_id}"


# ──────────────────────────────────────────────────────────────────────
# CRYPTO-MAL-001 (signature malleability)
# ──────────────────────────────────────────────────────────────────────

_MAL_VULN = """
pragma solidity ^0.8.0;
contract Mal {
    function permit(address owner, bytes32 d, uint8 v, bytes32 r, bytes32 s) external {
        // line 5 — vulnerable: no s-bound check
        address signer = ecrecover(d, v, r, s);
        require(signer == owner, "bad sig");
    }
}
"""

_MAL_SAFE = """
pragma solidity ^0.8.0;
contract MalGuard {
    function permit(address owner, bytes32 d, uint8 v, bytes32 r, bytes32 s) external {
        // line 5 — protected: enforces low-s
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "high-s");
        address signer = ecrecover(d, v, r, s);
        require(signer == owner, "bad sig");
    }
}
"""


def test_crypto_mal_001_unguarded_is_confirmed():
    r = _run("CRYPTO-MAL-001", _MAL_VULN, line_number=5)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.CONFIRMED, r.explanation


def test_crypto_mal_001_low_s_guarded_is_not_confirmed():
    r = _run("CRYPTO-MAL-001", _MAL_SAFE, line_number=6)
    assert r is not None
    assert r.exploit_class != ExploitConfidence.CONFIRMED, r.explanation


# ──────────────────────────────────────────────────────────────────────
# CRYPTO-RPL-001 (replay without nonce) — the bug we just fixed
# ──────────────────────────────────────────────────────────────────────

_RPL_VULN = """
pragma solidity ^0.8.0;
contract Rpl {
    function claim(bytes32 d, uint8 v, bytes32 r, bytes32 s) external {
        // line 5 — vulnerable: no nonce, no usedHashes mapping
        address signer = ecrecover(d, v, r, s);
        require(signer != address(0), "bad sig");
    }
}
"""

# Multiple representations of "nonce was consumed" that the verifier MUST
# treat as protected (covers the regex patterns we just expanded).
_RPL_SAFE_VARIANTS = [
    # Underscore-prefixed mapping write (the AToken radiant-v2 case).
    """
pragma solidity ^0.8.0;
contract A {
    mapping(address => uint256) internal _nonces;
    function permit(address owner, uint8 v, bytes32 r, bytes32 s) external {
        uint256 currentValidNonce = _nonces[owner];
        bytes32 d = keccak256(abi.encode(owner, currentValidNonce));
        address signer = ecrecover(d, v, r, s);
        _nonces[owner] = currentValidNonce + 1;
        require(signer == owner);
    }
}
""",
    # OZ _useNonce sink.
    """
pragma solidity ^0.8.0;
contract B {
    function _useNonce(address) internal returns (uint256) { return 1; }
    function permit(address owner, bytes32 d, uint8 v, bytes32 r, bytes32 s) external {
        _useNonce(owner);
        address signer = ecrecover(d, v, r, s);
        require(signer == owner);
    }
}
""",
    # usedHashes sink.
    """
pragma solidity ^0.8.0;
contract C {
    mapping(bytes32 => bool) public usedHashes;
    function claim(bytes32 d, uint8 v, bytes32 r, bytes32 s) external {
        require(!usedHashes[d], "replay");
        address signer = ecrecover(d, v, r, s);
        usedHashes[d] = true;
        require(signer != address(0));
    }
}
""",
]


def test_crypto_rpl_001_unguarded_is_confirmed():
    r = _run("CRYPTO-RPL-001", _RPL_VULN, line_number=5)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.CONFIRMED, r.explanation


@pytest.mark.parametrize("src", _RPL_SAFE_VARIANTS, ids=["_nonces+1", "_useNonce", "usedHashes"])
def test_crypto_rpl_001_nonce_or_usedhashes_is_not_confirmed(src):
    # Find ecrecover line dynamically so fixtures are robust to edits.
    line = next(i + 1 for i, ln in enumerate(src.splitlines()) if "ecrecover(" in ln)
    r = _run("CRYPTO-RPL-001", src, line_number=line)
    assert r is not None
    assert r.exploit_class != ExploitConfidence.CONFIRMED, (
        f"replay verifier wrongly CONFIRMED a guarded fixture:\n{r.explanation}"
    )


# ──────────────────────────────────────────────────────────────────────
# CRYPTO-DSM-001 (Domain-Separator Mutability / Semantic Mismatch)
# ──────────────────────────────────────────────────────────────────────

_DSM_VULN_MUTABLE = """
pragma solidity ^0.8.0;
contract V {
    bytes32 public DOMAIN_SEPARATOR;
    function init(bytes32 ds) external { DOMAIN_SEPARATOR = ds; }
}
"""

_DSM_VULN_CONSTANT = """
pragma solidity ^0.8.0;
contract V {
    bytes32 public constant DOMAIN_SEPARATOR =
        0x1111111111111111111111111111111111111111111111111111111111111111;
}
"""

_DSM_VULN_BUILDER = """
pragma solidity ^0.8.0;
contract V {
    function domain(address verifyingContract) public view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,address verifyingContract)"),
            keccak256(bytes("X")),
            verifyingContract
        ));
    }
}
"""

_DSM_SAFE_IMMUTABLE = """
pragma solidity ^0.8.0;
contract S {
    bytes32 public immutable DOMAIN_SEPARATOR;
    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
            block.chainid,
            address(this)
        ));
    }
}
"""

_DSM_SAFE_OZ = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
contract S is EIP712 {
    constructor() EIP712("S", "1") {}
    bytes32 public DOMAIN_SEPARATOR;
}
"""


def test_crypto_dsm_001_mutable_storage_is_confirmed():
    r = _run("CRYPTO-DSM-001", _DSM_VULN_MUTABLE, line_number=4)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.CONFIRMED, r.explanation
    assert r.attack_vector == "domain_separator_mutable"


def test_crypto_dsm_001_constant_literal_is_conditional():
    r = _run("CRYPTO-DSM-001", _DSM_VULN_CONSTANT, line_number=4)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.CONDITIONAL, r.explanation
    assert r.attack_vector == "domain_separator_fork_replay"


def test_crypto_dsm_001_builder_missing_identity_is_confirmed():
    line = next(
        i + 1
        for i, ln in enumerate(_DSM_VULN_BUILDER.splitlines())
        if "keccak256(abi.encode(" in ln
    )
    r = _run("CRYPTO-DSM-001", _DSM_VULN_BUILDER, line_number=line)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.CONFIRMED, r.explanation
    assert r.attack_vector == "domain_builder_missing_identity"


def test_crypto_dsm_001_immutable_constructor_is_not_confirmed():
    r = _run("CRYPTO-DSM-001", _DSM_SAFE_IMMUTABLE, line_number=4)
    assert r is not None
    assert r.exploit_class != ExploitConfidence.CONFIRMED, r.explanation


def test_crypto_dsm_001_oz_eip712_is_disproven():
    r = _run("CRYPTO-DSM-001", _DSM_SAFE_OZ, line_number=5)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.DISPROVEN, r.explanation
    assert r.attack_vector == "domain_oz_eip712"


# ──────────────────────────────────────────────────────────────────────
# INTENT-RDR-001 / INTENT-PMT-001 (intent / permit authorization gaps)
# ──────────────────────────────────────────────────────────────────────

from novel_analyzers import IntentAuthAnalyzer  # noqa: E402


def _run_intent(vuln_id_filter: str, source: str, *, file_path: str = "Test.sol"):
    """Run IntentAuthAnalyzer end-to-end through the verifier chain."""
    findings = [
        f for f in IntentAuthAnalyzer(source, file_path).analyze()
        if f["id"] == vuln_id_filter
    ]
    if not findings:
        return None
    results = verify_all_findings(findings, {file_path: source})
    return results[0] if results else None


_RDR_VULN_CRITICAL = """
pragma solidity ^0.8.0;
contract V {
    function fill(bytes calldata orderData) external {
        (address recipient, uint256 amount, address filler) =
            abi.decode(orderData, (address recipient, uint256 amount, address filler));
        // recipient + filler unbound
        require(amount > 0);
    }
}
"""

_RDR_SAFE = """
pragma solidity ^0.8.0;
contract S {
    function fill(bytes calldata orderData) external {
        (address recipient, uint256 amount, address filler) =
            abi.decode(orderData, (address recipient, uint256 amount, address filler));
        require(recipient != address(0));
        require(filler == msg.sender);
        require(amount > 0);
        payable(recipient).transfer(amount);
    }
}
"""

_PMT_VULN = """
pragma solidity ^0.8.0;
interface IERC20Permit {
    function permit(address,address,uint256,uint256,uint8,bytes32,bytes32) external;
    function transferFrom(address,address,uint256) external;
}
contract V {
    function pull(IERC20Permit token, address from, uint256 amt,
                  uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        token.permit(from, address(this), amt, deadline, v, r, s);
        token.transferFrom(from, address(this), amt);
    }
}
"""

_PMT_SAFE_TRY = """
pragma solidity ^0.8.0;
interface IERC20Permit {
    function permit(address,address,uint256,uint256,uint8,bytes32,bytes32) external;
    function transferFrom(address,address,uint256) external;
    function allowance(address,address) external view returns (uint256);
}
contract S {
    function pull(IERC20Permit token, address from, uint256 amt,
                  uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        try token.permit(from, address(this), amt, deadline, v, r, s) {} catch {}
        require(token.allowance(from, address(this)) >= amt, "NO_ALLOWANCE");
        token.transferFrom(from, address(this), amt);
    }
}
"""


def test_intent_rdr_001_critical_unbound_is_confirmed():
    r = _run_intent("INTENT-RDR-001", _RDR_VULN_CRITICAL)
    assert r is not None, "analyzer failed to fire"
    assert r.exploit_class == ExploitConfidence.CONFIRMED, r.explanation
    assert r.attack_vector == "intent_redirection_critical"
    assert r.severity_adjustment == "upgrade_to_HIGH"


def test_intent_rdr_001_all_bound_is_not_flagged():
    r = _run_intent("INTENT-RDR-001", _RDR_SAFE)
    assert r is None, "safe fixture should not produce a finding"


def test_intent_pmt_001_unguarded_is_conditional():
    r = _run_intent("INTENT-PMT-001", _PMT_VULN)
    assert r is not None, "analyzer failed to fire"
    assert r.exploit_class == ExploitConfidence.CONDITIONAL, r.explanation
    assert r.attack_vector == "ghost_permit_bypass"


def test_intent_pmt_001_try_catch_plus_allowance_is_not_flagged():
    r = _run_intent("INTENT-PMT-001", _PMT_SAFE_TRY)
    assert r is None, "safe fixture should not produce a finding"


# ──────────────────────────────────────────────────────────────────────
# SWC-107 (reentrancy CEI violation)
# ──────────────────────────────────────────────────────────────────────

_REENT_VULN = """
pragma solidity ^0.8.0;
contract V {
    mapping(address => uint256) public bal;
    function withdraw() external {
        uint256 amt = bal[msg.sender];
        // line 6 — external call BEFORE state update
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        bal[msg.sender] = 0;
    }
}
"""

_REENT_SAFE = """
pragma solidity ^0.8.0;
contract Guard {
    mapping(address => uint256) public bal;
    bool internal _locked;
    modifier nonReentrant() { require(!_locked); _locked = true; _; _locked = false; }
    function withdraw() external nonReentrant {
        uint256 amt = bal[msg.sender];
        bal[msg.sender] = 0;
        // line 9 — guarded by nonReentrant + CEI respected
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}
"""


def test_swc_107_unguarded_is_confirmed_or_likely():
    r = _run("SWC-107", _REENT_VULN, line_number=6)
    assert r is not None
    # Reentrancy verifier may emit CONFIRMED or LIKELY depending on heuristics
    assert r.exploit_class in {
        ExploitConfidence.CONFIRMED,
        ExploitConfidence.LIKELY,
    }, r.explanation


def test_swc_107_nonreentrant_guarded_is_not_confirmed():
    r = _run("SWC-107", _REENT_SAFE, line_number=9)
    assert r is not None
    assert r.exploit_class != ExploitConfidence.CONFIRMED, r.explanation


# ──────────────────────────────────────────────────────────────────────
# Calibration regressions — radiant-v2 false-positive lessons
# ──────────────────────────────────────────────────────────────────────

# (a) ECDSA malleability is neutralized when the signed digest binds an
#     in-contract nonce that the function consumes in the same body.
#     Mirrors radiant-capital/v2 contracts/lending/tokenization/AToken.sol
#     permit() exactly — was wrongly CONFIRMED before this fix.
_MAL_NEUTRALIZED_BY_NONCE = """
pragma solidity ^0.8.0;
contract A {
    bytes32 public constant PERMIT_TYPEHASH = keccak256("Permit(address,uint256,uint256)");
    bytes32 public DOMAIN_SEPARATOR;
    mapping(address => uint256) public _nonces;
    function permit(address owner, uint256 value, uint8 v, bytes32 r, bytes32 s) external {
        uint256 currentValidNonce = _nonces[owner];
        bytes32 digest = keccak256(abi.encodePacked(
            "\\x19\\x01", DOMAIN_SEPARATOR,
            keccak256(abi.encode(PERMIT_TYPEHASH, owner, value, currentValidNonce))
        ));
        require(owner == ecrecover(digest, v, r, s), "INVALID_SIGNATURE");
        _nonces[owner] = currentValidNonce + 1;
    }
}
"""


def test_crypto_mal_001_neutralized_by_in_contract_nonce():
    """When the function consumes an in-contract nonce in the same body,
    the malleated twin cannot replay on-chain — verifier must NOT CONFIRM."""
    line = next(
        i + 1
        for i, ln in enumerate(_MAL_NEUTRALIZED_BY_NONCE.splitlines())
        if "ecrecover(" in ln
    )
    r = _run("CRYPTO-MAL-001", _MAL_NEUTRALIZED_BY_NONCE, line_number=line)
    assert r is not None
    assert r.exploit_class != ExploitConfidence.CONFIRMED, r.explanation
    # Verifier should still surface the residual off-chain risk via the
    # CONDITIONAL class with downgraded severity, not silently DISPROVE.
    assert r.attack_vector in {
        "malleability_neutralized_by_nonce",
        "malleability_protected",
    }, r.attack_vector


# (b) Stateless multicall-style forwarders: reentrancy on contracts that
#     hold no value-bearing storage and forward to caller-supplied
#     targets cannot corrupt anything. Mirrors radiant-capital/v2
#     contracts/radiant/accessories/Multicall3.sol — wrongly CONFIRMED
#     before this fix.
_MULTICALL3_LIKE = """
pragma solidity 0.8.12;
contract Multicall3 {
    struct Call3Value { address target; bool allowFailure; uint256 value; bytes callData; }
    struct Result { bool success; bytes returnData; }
    function aggregate3Value(Call3Value[] calldata calls) public payable returns (Result[] memory returnData) {
        uint256 length = calls.length;
        returnData = new Result[](length);
        Call3Value calldata calli;
        for (uint256 i = 0; i < length; ) {
            Result memory result = returnData[i];
            calli = calls[i];
            (result.success, result.returnData) = calli.target.call{value: calli.value}(calli.callData);
            unchecked { ++i; }
        }
    }
}
"""


def test_swc_107_stateless_multicall_forwarder_is_disproven():
    """Multicall3-shaped forwarders have no value-bearing storage and
    forward to caller-supplied targets. Reentrancy is moot — verifier
    must DISPROVE, not CONFIRM."""
    line = next(
        i + 1
        for i, ln in enumerate(_MULTICALL3_LIKE.splitlines())
        if ".target.call" in ln
    )
    r = _run(
        "SWC-107",
        _MULTICALL3_LIKE,
        line_number=line,
        file_path="contracts/radiant/accessories/Multicall3.sol",
    )
    assert r is not None
    assert r.exploit_class == ExploitConfidence.DISPROVEN, r.explanation
    assert r.attack_vector == "stateless_forwarder", r.attack_vector


# (c) Negative control: the stateless-forwarder gate must NOT silence a
#     real reentrancy on a value-bearing contract that happens to use a
#     forwarding pattern.
_VALUE_BEARING_FORWARDER = """
pragma solidity ^0.8.0;
contract Bank {
    mapping(address => uint256) public balance;
    function withdraw(address target) external {
        uint256 amt = balance[msg.sender];
        (bool ok, ) = target.call{value: amt}("");
        require(ok);
        balance[msg.sender] = 0;
    }
}
"""


def test_swc_107_value_bearing_forwarder_still_confirmed():
    line = next(
        i + 1
        for i, ln in enumerate(_VALUE_BEARING_FORWARDER.splitlines())
        if "target.call" in ln
    )
    r = _run("SWC-107", _VALUE_BEARING_FORWARDER, line_number=line)
    assert r is not None
    assert r.exploit_class in {
        ExploitConfidence.CONFIRMED,
        ExploitConfidence.LIKELY,
    }, r.explanation
    assert r.attack_vector != "stateless_forwarder", r.attack_vector

# ──────────────────────────────────────────────────────────────────────
# On-chain calibration regressions (FiatToken-style + EIP-1967 proxy)
# ──────────────────────────────────────────────────────────────────────

# (d) PAUSE-001 must DISPROVE on FiatToken-style admin emergency paths
#     (rescueERC20 onlyRescuer, configureMinter onlyMasterMinter, etc).
_FIATTOKEN_LIKE = """
pragma solidity 0.6.12;
contract FiatTokenV2_2 {
    bool public paused;
    address public masterMinter;
    address public rescuer;
    modifier whenNotPaused() { require(!paused, "paused"); _; }
    modifier onlyMasterMinter() { require(msg.sender == masterMinter, "x"); _; }
    modifier onlyRescuer() { require(msg.sender == rescuer, "x"); _; }
    function transfer(address to, uint256 v) public whenNotPaused returns (bool) { return true; }
    function configureMinter(address minter, uint256 cap) external onlyMasterMinter returns (bool) {
        return true;
    }
    function rescueERC20(address tokenContract, address to, uint256 amount) external onlyRescuer {
        // emergency rescue path — must remain callable while paused.
    }
}
"""


def test_pause_001_fiattoken_admin_emergency_path_is_disproven():
    line = next(
        i + 1
        for i, ln in enumerate(_FIATTOKEN_LIKE.splitlines())
        if "rescueERC20" in ln and "function" in ln
    )
    r = _run("PAUSE-001", _FIATTOKEN_LIKE, line_number=line)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.DISPROVEN, r.explanation
    assert r.attack_vector == "admin_emergency_path", r.attack_vector


def test_pause_001_fiattoken_minter_admin_path_is_disproven():
    line = next(
        i + 1
        for i, ln in enumerate(_FIATTOKEN_LIKE.splitlines())
        if "configureMinter" in ln and "function" in ln
    )
    r = _run("PAUSE-001", _FIATTOKEN_LIKE, line_number=line)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.DISPROVEN, r.explanation
    assert r.attack_vector == "admin_emergency_path", r.attack_vector


# (e) ASM-002 / delegatecall: EIP-1967 proxy delegate is admin-controlled,
#     must DISPROVE.
_EIP1967_PROXY = """
pragma solidity 0.6.12;
contract FiatTokenProxy {
    bytes32 private constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    function _implementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { impl := sload(slot) }
    }
    fallback() external payable {
        address _impl = _implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), _impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
}
"""


def test_asm_002_eip1967_proxy_delegate_is_disproven():
    line = next(
        i + 1
        for i, ln in enumerate(_EIP1967_PROXY.splitlines())
        if "delegatecall(" in ln
    )
    r = _run("ASM-002", _EIP1967_PROXY, line_number=line)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.DISPROVEN, r.explanation
    assert r.attack_vector == "eip1967_proxy_delegate", r.attack_vector


# (f) SWC-107 / REENT-GRAPH-001 on the proxy contract itself must
#     DISPROVE — reentrancy lives in the implementation, not the proxy.
def test_reent_graph_001_on_proxy_contract_is_disproven():
    line = next(
        i + 1
        for i, ln in enumerate(_EIP1967_PROXY.splitlines())
        if "delegatecall(" in ln
    )
    r = _run("REENT-GRAPH-001", _EIP1967_PROXY, line_number=line)
    assert r is not None
    assert r.exploit_class == ExploitConfidence.DISPROVEN, r.explanation
    assert r.attack_vector == "eip1967_proxy_contract", r.attack_vector

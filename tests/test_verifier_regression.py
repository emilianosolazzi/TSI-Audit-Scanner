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

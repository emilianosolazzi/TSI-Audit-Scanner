CONTENT_MARKER_V3 = True

import logging
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("NovelAnalyzers")


def _line_number(source, index):
    return source.count("\n", 0, index) + 1


def _snippet(source, line_number, radius=2):
    lines = source.splitlines()
    start = max(0, line_number - radius - 1)
    end = min(len(lines), line_number + radius)
    return "\n".join(lines[start:end])


def _finding(*, vuln_id, title, description, file_path, line_number, source,
             severity="HIGH", confidence=0.9, recommendation="", category="logic", extra=None):
    f = {
        "id": vuln_id, "severity": severity, "category": category,
        "title": title, "description": description,
        "recommendation": recommendation, "file": file_path,
        "line_number": line_number,
        "code_snippet": _snippet(source, line_number),
        "confidence": confidence,
    }
    if extra:
        f.update(extra)
    return f


@dataclass
class GuardDominanceAnalyzer:
    source: str
    file_path: str
    def analyze(self): return []


@dataclass
class PrecompileCryptoAnalyzer:
    source: str
    file_path: str
    def analyze(self): return []


class StorageSelectorAnalyzer:
    def __init__(self, file_sources, compiled_contracts=None):
        self.file_sources = file_sources or {}
        self.compiled_contracts = compiled_contracts or {}
    def analyze(self): return []


@dataclass
class _FunctionBlock:
    name: str
    header_line: int
    start: int
    end: int
    params: str
    body: str


class MerkleProofVerifierAnalyzer:
    _FN_HEADER_RE = re.compile(
        r"function\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)[^{;]*\{",
        re.MULTILINE,
    )
    _EXT_FN_HEADER_RE = re.compile(
        r"function\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)"
        r"(?:(?!\{).)*\b(?:external|public)\b(?:(?!\{).)*\{",
        re.DOTALL,
    )
    _INDEX_EQ_EARLY_EXIT_RE = re.compile(
        r"if\s*\([^)]*\b(?:index|leafIndex|k_index|pos)\b[^)]*==[^)]*"
        r"\b(?:count|layerCount|layerLen|layer_len|siblings?\.length)\b[^)]*\)"
        r"\s*\{[^}]*\b(?:break|continue|return)\b",
        re.IGNORECASE | re.DOTALL,
    )
    _LAYER_SHORTCUT_RE = re.compile(
        r"for\s*\([^)]*\)\s*\{[^}]*?\b(?:break|continue)\b[^}]*?"
        r"\b(?:index|leafIndex|pos)\b",
        re.IGNORECASE | re.DOTALL,
    )
    _BOUND_ASSERT_RE = re.compile(
        r"require\s*\([^)]*\b(?:index|leafIndex|leaves?\.length|indices?\.length)\b"
        r"[^)]*[<>]=?[^)]*\)",
        re.IGNORECASE,
    )
    _BOUND_REVERT_RE = re.compile(
        r"revert\s+\w*(?:OutOfBounds|InvalidIndex|InvalidLeaves|BadProof)\w*",
        re.IGNORECASE,
    )
    _VERIFIER_CALL_RE = re.compile(
        r"(?P<call>(?:MerkleMountainRange|MerkleMultiProof|MerkleMultiProofLib)"
        r"\s*\.\s*(?:VerifyProof|verifyProof|verifyMultiProof|CalculateRoot)\s*\()",
    )
    _USER_FIELD_RE = re.compile(
        r"\b(?:leaves|leafIndex|index|indices|kIndex|k_index|pos|proof)\b",
        re.IGNORECASE,
    )

    def __init__(self, source, file_path):
        self.source = source or ""
        self.file_path = file_path

    def analyze(self):
        out = []
        try:
            out.extend(self._check_library_verifier())
        except Exception:
            logger.exception("_check_library_verifier failed")
        try:
            out.extend(self._check_caller_bounds())
        except Exception:
            logger.exception("_check_caller_bounds failed")
        return out

    def _iter_functions(self, external_only=False):
        src = self.source
        regex = self._EXT_FN_HEADER_RE if external_only else self._FN_HEADER_RE
        for m in regex.finditer(src):
            start = m.end() - 1
            depth = 0
            i = start
            while i < len(src):
                c = src[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        yield _FunctionBlock(
                            name=m.group("name"),
                            header_line=_line_number(src, m.start()),
                            start=m.start(),
                            end=i,
                            params=m.group("params") or "",
                            body=src[start:i + 1],
                        )
                        break
                i += 1

    def _check_library_verifier(self):
        results = []
        fname = self.file_path.lower()
        if not any(n in fname for n in ("merkle", "mmr", "multiproof")):
            return results
        for fn in self._iter_functions():
            body = fn.body
            early = self._INDEX_EQ_EARLY_EXIT_RE.search(body)
            if early:
                line_no = fn.header_line + body.count("\n", 0, early.start())
                results.append(_finding(
                    vuln_id="MMR-001", severity="CRITICAL",
                    title="Merkle verifier early-exits on attacker-controlled index equality",
                    description="Hyperbridge MMR bypass pattern: short-circuit on index==count.",
                    recommendation="Require index < count strictly.",
                    file_path=self.file_path, line_number=line_no,
                    source=self.source, confidence=0.92, category="merkle-verifier",
                ))
            shortcut = self._LAYER_SHORTCUT_RE.search(body)
            if shortcut and not early:
                line_no = fn.header_line + body.count("\n", 0, shortcut.start())
                results.append(_finding(
                    vuln_id="MMR-002", severity="HIGH",
                    title="Merkle layer loop breaks on user-controlled index",
                    description="Per-layer loop exits based on user-influenced index.",
                    recommendation="Bound loop by proof structure only.",
                    file_path=self.file_path, line_number=line_no,
                    source=self.source, confidence=0.75, category="merkle-verifier",
                ))
        return results

    def _check_caller_bounds(self):
        results = []
        for fn in self._iter_functions(external_only=True):
            body = fn.body
            call = self._VERIFIER_CALL_RE.search(body)
            if not call:
                continue
            if not self._USER_FIELD_RE.search(fn.params + " " + body[:call.start()]):
                continue
            pre = body[:call.start()]
            if self._BOUND_ASSERT_RE.search(pre) or self._BOUND_REVERT_RE.search(pre):
                continue
            line_no = fn.header_line + body.count("\n", 0, call.start())
            results.append(_finding(
                vuln_id="INPUT-BOUNDS-001", severity="HIGH",
                title="Merkle verifier invoked without bounds check on user inputs",
                description="External function forwards user leaves/indices to verifier without bounds check.",
                recommendation="Require every index < committed leaf count before verify.",
                file_path=self.file_path, line_number=line_no,
                source=self.source, confidence=0.85, category="input-validation",
            ))
        return results


class CryptoAccessControlAnalyzer:
    """Cryptographic access-control "Definitive Check" detector.

    Four failure modes against the binding between a signature primitive and
    contract authorization state:

      * CRYPTO-IDM-001 — Identity Mismatch.  Authority is decided by a
        truncated identity hash (e.g. ``bytes20(keccak256(pubkey))``) that
        does not bind the full public key, enabling shadowing.

      * CRYPTO-MAL-001 — Signature Malleability.  Raw ``ecrecover`` used
        without canonical ``s`` bound and without OZ ``ECDSA.recover``,
        permitting alternate ``(r, s', v')`` for the same authorized signer.

      * CRYPTO-CTX-001 — Context-Injection.  Signed digest built via
        ``keccak256(abi.encode(...))`` and consumed by ``ecrecover`` /
        ``isValidSignature`` while omitting both ``block.chainid`` and
        ``address(this)`` and providing no EIP-712 domain separator.

      * CRYPTO-RPL-001 — Replay / Missing Nonce.  External function calls
        ``ecrecover`` (or wrappers) without a per-signer nonce read+write
        and without a ``usedHashes[h] / isUsed[h]`` guard.
    """

    _ECRECOVER_RE = re.compile(r"\becrecover\s*\(", re.IGNORECASE)
    _OZ_ECDSA_RE = re.compile(
        r"\bECDSA\s*\.\s*recover\s*\(|@openzeppelin/.+/ECDSA\.sol|"
        r"\bECDSA\s+for\s+bytes32\b",
        re.IGNORECASE,
    )
    _S_BOUND_RE = re.compile(
        # Canonical-s bound or explicit secp256k1 half-order.
        r"require\s*\([^)]*\bs\b[^)]*<=?[^)]*\)|"
        r"require\s*\([^)]*\buint256\(\s*s\s*\)[^)]*<=?[^)]*\)|"
        r"0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
        re.IGNORECASE,
    )
    _DOMAIN_SEP_RE = re.compile(
        r"\bDOMAIN_SEPARATOR\b|\b_hashTypedDataV4\s*\(|\bEIP712\b|"
        r"\b_domainSeparatorV4\s*\(",
    )
    _CHAINID_RE = re.compile(r"\bblock\.chainid\b|\bchainid\s*\(\s*\)")
    _SELF_ADDR_RE = re.compile(r"\baddress\s*\(\s*this\s*\)")
    _DIGEST_BUILD_RE = re.compile(
        r"keccak256\s*\(\s*abi\.encode(?:Packed)?\s*\(",
    )
    _NONCE_USE_RE = re.compile(
        # Any identifier containing 'nonce'/'nonces' (handles bare nonces,
        # _nonces, userNonces, s_nonce, sigNonces, etc.) being incremented
        # or written, plus standard usedHashes / isUsed / OZ _useNonce sinks.
        r"(?:^|[^A-Za-z0-9_])[A-Za-z0-9_]*[Nn]onces?\s*"
        r"(?:\[[^\]]+\])?\s*(?:\+\+|--|\+=|=(?!=))|"
        r"(?:^|[^A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*\s*=\s*"
        r"[A-Za-z0-9_]*[Nn]onces?\s*(?:\[[^\]]+\])?\s*\.add\s*\(|"
        r"\bused(?:Hashes?|Sigs?|Digests?|Signatures?|Nonces?)\s*"
        r"\[[^\]]+\]\s*=\s*true|"
        r"\bisUsed\s*\[[^\]]+\]\s*=\s*true|"
        r"\b_useNonce\s*\(|"
        r"\b_useCheckedNonce\s*\(",
        re.IGNORECASE,
    )
    # Identity-truncation patterns: bytes20(keccak256(...)),
    # uint160(uint256(keccak256(...))), address(uint160(...)).  These are
    # only flagged when used as a stored authority / mapping key.
    _IDM_TRUNC_RE = re.compile(
        r"bytes20\s*\(\s*keccak256\s*\(|"
        r"uint160\s*\(\s*uint256\s*\(\s*keccak256\s*\(|"
        r"address\s*\(\s*uint160\s*\(\s*uint256\s*\(\s*keccak256\s*\(",
        re.IGNORECASE,
    )
    _IDM_AUTHORITY_RE = re.compile(
        r"\b(?:owner|operator|signer|guardian|validator|authority|admin|"
        r"isAuthorized|authorized|roles?)\b",
        re.IGNORECASE,
    )
    _FN_HEADER_RE = re.compile(
        r"function\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)[^{;]*\{",
        re.MULTILINE,
    )
    _EXT_FN_HEADER_RE = re.compile(
        r"function\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)"
        r"(?:(?!\{).)*\b(?:external|public)\b(?:(?!\{).)*\{",
        re.DOTALL,
    )

    def __init__(self, source, file_path):
        self.source = source or ""
        self.file_path = file_path

    def analyze(self):
        out = []
        # Skip files that obviously have no signature surface — keeps the
        # FP rate ~0 on non-crypto code (which is most of any repo).
        if not self._ECRECOVER_RE.search(self.source) and \
           not self._IDM_TRUNC_RE.search(self.source):
            return out
        try:
            out.extend(self._check_identity_mismatch())
        except Exception:
            logger.exception("crypto IDM check failed")
        try:
            out.extend(self._check_malleability())
        except Exception:
            logger.exception("crypto MAL check failed")
        try:
            out.extend(self._check_context_injection())
        except Exception:
            logger.exception("crypto CTX check failed")
        try:
            out.extend(self._check_replay())
        except Exception:
            logger.exception("crypto RPL check failed")
        return out

    def _iter_functions(self, external_only=False):
        src = self.source
        regex = self._EXT_FN_HEADER_RE if external_only else self._FN_HEADER_RE
        for m in regex.finditer(src):
            start = m.end() - 1
            depth = 0
            i = start
            while i < len(src):
                c = src[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        yield _FunctionBlock(
                            name=m.group("name"),
                            header_line=_line_number(src, m.start()),
                            start=m.start(),
                            end=i,
                            params=m.group("params") or "",
                            body=src[start:i + 1],
                        )
                        break
                i += 1

    # ── CRYPTO-IDM ───────────────────────────────────────────────
    def _check_identity_mismatch(self):
        results = []
        for m in self._IDM_TRUNC_RE.finditer(self.source):
            # Look at a 200-char window around the match for an authority
            # role keyword; this is what separates "truncated identity used
            # as authority" from "address derived from constructor args".
            window_start = max(0, m.start() - 120)
            window_end = min(len(self.source), m.end() + 120)
            window = self.source[window_start:window_end]
            if not self._IDM_AUTHORITY_RE.search(window):
                continue
            line_no = _line_number(self.source, m.start())
            results.append(_finding(
                vuln_id="CRYPTO-IDM-001", severity="HIGH",
                title="Truncated identity hash used as cryptographic authority",
                description=(
                    "Authority field is set from a truncated keccak256 of a "
                    "public key / seed (bytes20 / uint160). The truncation "
                    "breaks the identity-collision-resistance assumption "
                    "H(P_u) = H(P_o) <=> P_u = P_o, allowing key-substitution."
                ),
                recommendation=(
                    "Bind authority to the full public key (store the 32-byte "
                    "hash) or use the recovered ECDSA address from a signed "
                    "challenge instead of an externally supplied seed."
                ),
                file_path=self.file_path, line_number=line_no,
                source=self.source, confidence=0.7,
                category="crypto-access-control",
            ))
        return results

    # ── CRYPTO-MAL ───────────────────────────────────────────────
    def _check_malleability(self):
        results = []
        if self._OZ_ECDSA_RE.search(self.source):
            return results  # OZ wrapper handles canonical-s + v.
        for m in self._ECRECOVER_RE.finditer(self.source):
            # Look at 400 chars before for an `s <= ...` bound.
            window = self.source[max(0, m.start() - 400):m.start()]
            if self._S_BOUND_RE.search(window):
                continue
            line_no = _line_number(self.source, m.start())
            results.append(_finding(
                vuln_id="CRYPTO-MAL-001", severity="HIGH",
                title="ecrecover used without canonical-s malleability bound",
                description=(
                    "Raw ecrecover is invoked without enforcing s <= "
                    "secp256k1n/2 and without OpenZeppelin ECDSA.recover. "
                    "An attacker can derive a second valid (r, s', v') for "
                    "the same signer/message, breaking signature uniqueness "
                    "and any 'used signature' replay guard keyed on (r,s,v)."
                ),
                recommendation=(
                    "Use OpenZeppelin ECDSA.recover, or add "
                    "`require(uint256(s) <= 0x7FFF...A0, \"malleable\");` "
                    "and `require(v == 27 || v == 28);` before ecrecover."
                ),
                file_path=self.file_path, line_number=line_no,
                source=self.source, confidence=0.85,
                category="crypto-access-control",
            ))
        return results

    # ── CRYPTO-CTX ───────────────────────────────────────────────
    def _check_context_injection(self):
        results = []
        if self._DOMAIN_SEP_RE.search(self.source):
            return results  # EIP-712 already bakes chainId + verifyingContract.
        for fn in self._iter_functions():
            if not self._ECRECOVER_RE.search(fn.body):
                continue
            digest = self._DIGEST_BUILD_RE.search(fn.body)
            if not digest:
                continue
            has_chainid = bool(self._CHAINID_RE.search(fn.body))
            has_self = bool(self._SELF_ADDR_RE.search(fn.body))
            if has_chainid and has_self:
                continue
            line_no = fn.header_line + fn.body.count("\n", 0, digest.start())
            missing = []
            if not has_chainid:
                missing.append("block.chainid")
            if not has_self:
                missing.append("address(this)")
            results.append(_finding(
                vuln_id="CRYPTO-CTX-001", severity="HIGH",
                title="Signed digest omits chain/contract context",
                description=(
                    "Signature digest is built via keccak256(abi.encode(...)) "
                    "and consumed by ecrecover, but omits "
                    + " and ".join(missing) +
                    ". The signature is valid across other chains and/or "
                    "other deployments of the same contract — a signature "
                    "captured on testnet/forked chain is replayable on "
                    "mainnet (Nomad/Wormhole-class)."
                ),
                recommendation=(
                    "Adopt EIP-712 (OZ EIP712 + _hashTypedDataV4) so the "
                    "digest binds chainId, verifyingContract, name, version. "
                    "If keeping the manual digest, include block.chainid and "
                    "address(this) inside the abi.encode payload."
                ),
                file_path=self.file_path, line_number=line_no,
                source=self.source, confidence=0.85,
                category="crypto-access-control",
                extra={"missing_context": missing},
            ))
        return results

    # ── CRYPTO-RPL ───────────────────────────────────────────────
    def _check_replay(self):
        results = []
        for fn in self._iter_functions(external_only=True):
            if not self._ECRECOVER_RE.search(fn.body):
                continue
            if self._NONCE_USE_RE.search(fn.body):
                continue
            ec = self._ECRECOVER_RE.search(fn.body)
            line_no = fn.header_line + fn.body.count("\n", 0, ec.start())
            results.append(_finding(
                vuln_id="CRYPTO-RPL-001", severity="HIGH",
                title="Signature verifier lacks nonce / used-hash guard",
                description=(
                    "External function recovers a signer via ecrecover but "
                    "never reads-and-updates a per-signer nonce or marks the "
                    "message hash as used. The same signature can be replayed "
                    "indefinitely against the same (signer, message)."
                ),
                recommendation=(
                    "Increment a per-signer nonce inside the signed payload "
                    "(`nonces[signer]++`) or set `usedHashes[digest] = true` "
                    "and require it was previously false."
                ),
                file_path=self.file_path, line_number=line_no,
                source=self.source, confidence=0.8,
                category="crypto-access-control",
            ))
        return results


__all__ = [
    "GuardDominanceAnalyzer",
    "PrecompileCryptoAnalyzer",
    "MerkleProofVerifierAnalyzer",
    "StorageSelectorAnalyzer",
    "CryptoAccessControlAnalyzer",
]


# ─────────────────────────────────────────────────────────────────
# Synthetic self-tests — `python novel_analyzers.py`
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    SAMPLES = {
        "IDM_vuln": """
            pragma solidity ^0.8.0;
            contract V {
                mapping(bytes20 => bool) public isAuthorized;
                function register(bytes calldata pubkey) external {
                    isAuthorized[bytes20(keccak256(pubkey))] = true;
                }
            }
        """,
        "IDM_safe": """
            pragma solidity ^0.8.0;
            contract S {
                mapping(bytes32 => bool) public isAuthorized;
                function register(bytes calldata pubkey) external {
                    isAuthorized[keccak256(pubkey)] = true;
                }
            }
        """,
        "MAL_vuln": """
            pragma solidity ^0.8.0;
            contract V {
                function exec(bytes32 h, uint8 v, bytes32 r, bytes32 s) external {
                    address signer = ecrecover(h, v, r, s);
                    require(signer != address(0));
                }
            }
        """,
        "MAL_safe": """
            pragma solidity ^0.8.0;
            import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
            contract S {
                using ECDSA for bytes32;
                function exec(bytes32 h, bytes calldata sig) external {
                    address signer = ECDSA.recover(h, sig);
                    require(signer != address(0));
                }
            }
        """,
        "CTX_vuln": """
            pragma solidity ^0.8.0;
            contract V {
                mapping(address => uint256) public nonces;
                function exec(address to, uint256 amt, uint8 v, bytes32 r, bytes32 s) external {
                    bytes32 d = keccak256(abi.encode(to, amt, nonces[msg.sender]++));
                    address signer = ecrecover(d, v, r, s);
                    require(signer == owner());
                }
                function owner() internal view returns (address) { return address(0); }
            }
        """,
        "CTX_safe": """
            pragma solidity ^0.8.0;
            contract S {
                mapping(address => uint256) public nonces;
                function exec(address to, uint256 amt, uint8 v, bytes32 r, bytes32 s) external {
                    bytes32 d = keccak256(abi.encode(
                        block.chainid, address(this), to, amt, nonces[msg.sender]++
                    ));
                    address signer = ecrecover(d, v, r, s);
                    require(signer == owner());
                }
                function owner() internal view returns (address) { return address(0); }
            }
        """,
        "RPL_vuln": """
            pragma solidity ^0.8.0;
            contract V {
                function exec(bytes32 h, uint8 v, bytes32 r, bytes32 s) external {
                    address signer = ecrecover(h, v, r, s);
                    require(signer == owner());
                }
                function owner() internal view returns (address) { return address(0); }
            }
        """,
        "RPL_safe": """
            pragma solidity ^0.8.0;
            contract S {
                mapping(address => uint256) public nonces;
                function exec(bytes32 h, uint8 v, bytes32 r, bytes32 s) external {
                    address signer = ecrecover(h, v, r, s);
                    nonces[signer]++;
                    require(signer == owner());
                }
                function owner() internal view returns (address) { return address(0); }
            }
        """,
    }

    EXPECT = {
        "IDM_vuln": ("CRYPTO-IDM-001", True),
        "IDM_safe": ("CRYPTO-IDM-001", False),
        "MAL_vuln": ("CRYPTO-MAL-001", True),
        "MAL_safe": ("CRYPTO-MAL-001", False),
        "CTX_vuln": ("CRYPTO-CTX-001", True),
        "CTX_safe": ("CRYPTO-CTX-001", False),
        "RPL_vuln": ("CRYPTO-RPL-001", True),
        "RPL_safe": ("CRYPTO-RPL-001", False),
    }

    failed = 0
    for name, src in SAMPLES.items():
        ids = {f["id"] for f in CryptoAccessControlAnalyzer(src, name + ".sol").analyze()}
        want_id, want_present = EXPECT[name]
        got = want_id in ids
        ok = (got == want_present)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}: {want_id} present={got} expected={want_present} all={sorted(ids)}")
        if not ok:
            failed += 1

    print(f"\n{len(SAMPLES) - failed}/{len(SAMPLES)} crypto-acl self-tests passed")
    sys.exit(1 if failed else 0)

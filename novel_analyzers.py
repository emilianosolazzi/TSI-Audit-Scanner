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

      * CRYPTO-DSM-001 — Domain-Separator Mutability / Semantic Mismatch.
        ``DOMAIN_SEPARATOR`` is exposed but is **not** isolated from the
        instance: it lives in mutable storage (proxy-settable), is a
        hardcoded constant literal (chainId baked at compile time → fork
        replay), or is built from a ``verifyingContract`` resolved through
        a registry / proxy lookup rather than ``address(this)``.  When the
        identity that the digest binds is mutable, signatures can cross
        between deployments / upgrades — the "semantic mismatch" class
        (cross-protocol impersonation, hard-fork replay).
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
    # ── DSM (Domain-Separator Mutability) patterns ────────────────
    # OZ EIP712 base contract handles cached-domain rebuild on fork — skip.
    _DSM_OZ_EIP712_RE = re.compile(
        r"@openzeppelin/.+/EIP712(?:Upgradeable)?\.sol|"
        r"\bcontract\s+\w+[^{]*\bis\b[^{]*\bEIP712(?:Upgradeable)?\b",
        re.IGNORECASE,
    )
    # Mutable storage declaration: `bytes32 [public|internal|private]
    # DOMAIN_SEPARATOR;` WITHOUT `immutable` and WITHOUT `constant`.
    _DSM_MUTABLE_DECL_RE = re.compile(
        r"^[ \t]*bytes32\s+(?!.*\b(?:immutable|constant)\b)"
        r"(?:public\s+|internal\s+|private\s+|external\s+)?"
        r"(?:DOMAIN_SEPARATOR|_DOMAIN_SEPARATOR|domainSeparator)\s*"
        r"(?:=|;)",
        re.MULTILINE,
    )
    # Constant hardcoded literal: chainId baked at compile time → fork replay.
    _DSM_CONST_LITERAL_RE = re.compile(
        r"bytes32\s+(?:public\s+|internal\s+|private\s+)?constant\s+"
        r"(?:DOMAIN_SEPARATOR|_DOMAIN_SEPARATOR|domainSeparator)\s*=\s*"
        r"0x[0-9a-fA-F]{64}\s*;",
    )
    # Setter / writer to DOMAIN_SEPARATOR after construction
    # (proxy-upgrade / re-init re-wire vector).
    _DSM_SETTER_RE = re.compile(
        r"function\s+(?P<name>\w+)[^{]*\{[^}]*\b"
        r"(?:DOMAIN_SEPARATOR|_DOMAIN_SEPARATOR|domainSeparator)\s*=\s*",
        re.DOTALL,
    )
    # `verifyingContract` field bound to a getter / parameter rather than
    # `address(this)` — the "semantic mismatch" surface (signatures meant
    # for one deployment accepted by another).  We look for the EIP-712
    # domain typehash header and then check whether `address(this)` appears
    # in the same builder; the absence is checked in code.
    _DSM_DOMAIN_BUILDER_RE = re.compile(
        r"keccak256\s*\(\s*abi\.encode\s*\(\s*"
        r"(?:EIP712_?DOMAIN_?TYPEHASH|EIP_?712_?DOMAIN|TYPE_?HASH|"
        r"keccak256\s*\(\s*[\"']EIP712Domain[^\"']*[\"']\s*\))",
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
           not self._IDM_TRUNC_RE.search(self.source) and \
           not self._DSM_MUTABLE_DECL_RE.search(self.source) and \
           not self._DSM_CONST_LITERAL_RE.search(self.source) and \
           not self._DSM_DOMAIN_BUILDER_RE.search(self.source):
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
        try:
            out.extend(self._check_domain_separator_mutability())
        except Exception:
            logger.exception("crypto DSM check failed")
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

    # ── CRYPTO-DSM ───────────────────────────────────────────────
    def _check_domain_separator_mutability(self):
        """Detect domain-separator shapes that allow semantic mismatch.

        Three vulnerable shapes:
          (a) Mutable storage slot (proxy-settable / re-init re-wire).
          (b) `bytes32 constant` literal — chainId frozen at compile time,
              so a chain hard-fork (or any fork-chainId mismatch) makes
              every signature replayable across the split.
          (c) Domain built by EIP-712 typehash encoding without
              `address(this)` and without `block.chainid` in the same
              builder expression (i.e. the verifyingContract or chainId
              field is hard-coded or read from a registry/proxy).

        Skip when the file inherits OZ `EIP712` — that base contract
        caches the separator and rebuilds on chainId mismatch.
        """
        results = []
        if self._DSM_OZ_EIP712_RE.search(self.source):
            return results

        # (a) Mutable storage slot.
        for m in self._DSM_MUTABLE_DECL_RE.finditer(self.source):
            line_no = _line_number(self.source, m.start())
            results.append(_finding(
                vuln_id="CRYPTO-DSM-001", severity="HIGH",
                title="DOMAIN_SEPARATOR is mutable storage (semantic mismatch)",
                description=(
                    "`DOMAIN_SEPARATOR` is declared as a regular state "
                    "variable (no `immutable`, no `constant`). Its value "
                    "can be overwritten by a setter, an initializer "
                    "re-call on a proxy, or a storage-collision upgrade. "
                    "Once the domain is mutable the contract can be made "
                    "to accept signatures issued against another "
                    "deployment / chain — the cross-protocol impersonation "
                    "(semantic mismatch) class."
                ),
                recommendation=(
                    "Inherit OpenZeppelin `EIP712` (handles cached domain "
                    "with fork rebuild via `_domainSeparatorV4`) or store "
                    "the separator in an `immutable` slot computed in the "
                    "constructor from `block.chainid` and `address(this)`."
                ),
                file_path=self.file_path, line_number=line_no,
                source=self.source, confidence=0.8,
                category="crypto-access-control",
                extra={"dsm_shape": "mutable_storage"},
            ))

        # (b) Hardcoded constant literal (chainId frozen).
        for m in self._DSM_CONST_LITERAL_RE.finditer(self.source):
            line_no = _line_number(self.source, m.start())
            results.append(_finding(
                vuln_id="CRYPTO-DSM-001", severity="MEDIUM",
                title="DOMAIN_SEPARATOR is a hardcoded constant (fork replay)",
                description=(
                    "`DOMAIN_SEPARATOR` is a `bytes32 constant` literal. "
                    "Whatever chainId / verifyingContract was used at "
                    "compile time is frozen in the bytecode, so the "
                    "separator does not change if the chain forks (or if "
                    "the contract is redeployed at the same address on a "
                    "different chain via CREATE2). Signatures collected "
                    "before a fork remain valid on both sides — the "
                    "Uniswap V2 hard-fork replay class."
                ),
                recommendation=(
                    "Compute the separator in the constructor from "
                    "`block.chainid` and `address(this)`, cache it in an "
                    "`immutable`, and rebuild when `block.chainid` "
                    "differs from the cached value (OZ `EIP712` does "
                    "exactly this)."
                ),
                file_path=self.file_path, line_number=line_no,
                source=self.source, confidence=0.85,
                category="crypto-access-control",
                extra={"dsm_shape": "constant_literal"},
            ))

        # (c) Builder expression that omits address(this) AND/OR
        #     block.chainid in the EIP-712 domain typehash encode call.
        for m in self._DSM_DOMAIN_BUILDER_RE.finditer(self.source):
            # Slice out the encode(...) call — count parens to find the
            # matching close, capped at 1 KB to keep the regex tight.
            start = m.start()
            window = self.source[start:start + 1024]
            depth = 0
            end = None
            for i, c in enumerate(window):
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if end is None:
                continue
            builder = window[:end + 1]
            has_self = bool(self._SELF_ADDR_RE.search(builder))
            has_chainid = bool(self._CHAINID_RE.search(builder))
            if has_self and has_chainid:
                continue
            line_no = _line_number(self.source, start)
            missing = []
            if not has_self:
                missing.append("address(this)")
            if not has_chainid:
                missing.append("block.chainid")
            results.append(_finding(
                vuln_id="CRYPTO-DSM-001", severity="HIGH",
                title="EIP-712 domain omits chain/contract identity",
                description=(
                    "EIP-712 domain separator is built via "
                    "`keccak256(abi.encode(DOMAIN_TYPEHASH, ...))` but "
                    "the encode payload omits "
                    + " and ".join(missing) +
                    ". The verifyingContract (or chainId) is bound to a "
                    "value other than the live `address(this)` / "
                    "`block.chainid` — typically a registry/proxy lookup, "
                    "a constructor parameter, or a hardcoded literal. A "
                    "signature accepted by this contract is replayable "
                    "against any other deployment that shares the same "
                    "logic + cached identity (semantic mismatch)."
                ),
                recommendation=(
                    "Always bind `address(this)` and `block.chainid` "
                    "directly in the encode call. Do not resolve "
                    "`verifyingContract` through a mutable AddressProvider "
                    "or proxy lookup. Prefer OZ `EIP712` which handles the "
                    "cached-domain + fork rebuild for you."
                ),
                file_path=self.file_path, line_number=line_no,
                source=self.source, confidence=0.75,
                category="crypto-access-control",
                extra={"dsm_shape": "builder_missing_identity",
                       "missing_context": missing},
            ))

        return results


class IntentAuthAnalyzer:
    """Authorization-gap detector for 2026 intent-based architectures.

    Two failure modes:

      * INTENT-RDR-001 — Intent Redirection (ERC-7683 family). A
        ``resolve()`` / ``open()`` / ``fill()`` / ``initiateOrder()``
        function decodes a signed ``orderData`` blob via
        ``abi.decode(orderData, (...))`` but at least one decoded field is
        never read by a ``require`` / ``assert`` / ``if (... ) revert``
        and never passed as a positional argument inside the same body.
        The unbound field is an implicit-parameter-injection surface — a
        solver can reshape that field while the signed payload still
        verifies.

      * INTENT-PMT-001 — Ghost-Permit Bypass. A function calls
        ``IERC20Permit.permit(...)`` and then ``transferFrom`` /
        ``safeTransferFrom`` without an intervening allowance assertion
        and without ``try/catch`` on the permit call. A front-runner
        (or a no-op signature) consumes / invalidates the permit
        between block submission and execution; the contract proceeds
        as if the permit succeeded. Severity is CONDITIONAL by default
        (requires a public mempool + race window).
    """

    _DECODE_RE = re.compile(
        r"abi\.decode\s*\(\s*(?P<src>[A-Za-z_]\w*)\s*,\s*\((?P<types>[^)]*)\)\s*\)",
    )
    _INTENT_FN_RE = re.compile(
        r"function\s+(?P<name>open|resolve|resolveFor|fill|fillOrder|"
        r"initiateOrder|initiate|settle|execute7683|crossChainOrder)"
        r"\s*\([^)]*\)",
        re.IGNORECASE,
    )
    # Param names that indicate intent payload byte blobs.
    _ORDER_PARAM_RE = re.compile(
        r"\b(?:bytes\s+(?:calldata|memory)?\s*)"
        r"(?P<name>orderData|order|fillerData|signedOrder|intent|"
        r"extraData|encodedOrder|payload)\b",
        re.IGNORECASE,
    )
    # Field names that imply asset-routing — flag HIGH when missing.
    _CRITICAL_FIELD_RE = re.compile(
        r"^(?:recipient|to|receiver|filler|fillerAddress|target|"
        r"destination|destChainId|destinationChainId|chainId|amount|"
        r"minAmount|outputAmount|inputAmount|token|asset|outputToken|"
        r"inputToken|deadline|nonce)$",
        re.IGNORECASE,
    )
    _PERMIT_CALL_RE = re.compile(
        r"\.\s*permit\s*\(",
    )
    _TRANSFER_FROM_RE = re.compile(
        r"\.\s*(?:transferFrom|safeTransferFrom)\s*\(",
    )
    _ALLOWANCE_CHECK_RE = re.compile(
        r"\.\s*allowance\s*\([^)]*\)\s*[<>]=?",
    )
    _TRY_PERMIT_RE = re.compile(
        r"try\s+\w+\s*\.\s*permit\s*\(",
    )
    _FN_HEADER_RE = re.compile(
        r"function\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)[^{;]*\{",
        re.MULTILINE,
    )

    def __init__(self, source, file_path):
        self.source = source or ""
        self.file_path = file_path

    def analyze(self):
        out = []
        if not self._INTENT_FN_RE.search(self.source) and \
           not self._PERMIT_CALL_RE.search(self.source):
            return out
        try:
            out.extend(self._check_intent_redirection())
        except Exception:
            logger.exception("intent RDR check failed")
        try:
            out.extend(self._check_ghost_permit())
        except Exception:
            logger.exception("intent PMT check failed")
        return out

    def _iter_functions(self):
        src = self.source
        for m in self._FN_HEADER_RE.finditer(src):
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

    @staticmethod
    def _decoded_identifiers(types_str):
        """Best-effort extract identifier names from a decode tuple.

        We only care about named tuple components, e.g.
        ``abi.decode(data, (address recipient, uint256 amount))``.
        Tuple components without a name (``(uint256, address)``) cannot
        be statically tracked and are skipped — keeps FP rate low.
        """
        names = []
        for part in types_str.split(","):
            tokens = part.strip().split()
            if len(tokens) >= 2 and tokens[-1].isidentifier():
                names.append(tokens[-1])
        return names

    # ── INTENT-RDR ───────────────────────────────────────────────
    def _check_intent_redirection(self):
        results = []
        for fn in self._iter_functions():
            # Only intent-shaped entrypoints.
            if not self._INTENT_FN_RE.search(
                f"function {fn.name}({fn.params})"
            ):
                continue
            if not self._ORDER_PARAM_RE.search(fn.params):
                continue
            for dec in self._DECODE_RE.finditer(fn.body):
                names = self._decoded_identifiers(dec.group("types"))
                if not names:
                    continue
                # Body slice AFTER the decode — that's where bindings
                # must appear.  Anything before is irrelevant.
                tail = fn.body[dec.end():]
                unused = []
                critical_unused = []
                for name in names:
                    word = re.compile(rf"\b{re.escape(name)}\b")
                    refs = word.findall(tail)
                    # `name` itself appears once on the LHS of the decode
                    # destructure — we need usage AFTER that.
                    if len(refs) == 0:
                        unused.append(name)
                        if self._CRITICAL_FIELD_RE.match(name):
                            critical_unused.append(name)
                        continue
                    # Reference exists — check it's also consumed by a
                    # check (require/assert/revert) OR passed as an arg
                    # to a downstream call.  If neither, treat as
                    # informational rather than a finding.
                    has_check = bool(re.search(
                        rf"(?:require|assert|if)\s*\([^)]*\b{re.escape(name)}\b",
                        tail,
                    ))
                    has_call_arg = bool(re.search(
                        rf"\b\w+\s*\([^)]*\b{re.escape(name)}\b[^)]*\)",
                        tail,
                    ))
                    if not has_check and not has_call_arg:
                        unused.append(name)
                        if self._CRITICAL_FIELD_RE.match(name):
                            critical_unused.append(name)
                if not unused:
                    continue
                severity = "HIGH" if critical_unused else "MEDIUM"
                line_no = fn.header_line + fn.body.count("\n", 0, dec.start())
                results.append(_finding(
                    vuln_id="INTENT-RDR-001", severity=severity,
                    title="Signed intent field decoded but not bound",
                    description=(
                        "Intent entrypoint `" + fn.name + "` decodes a "
                        "signed payload but never binds "
                        + ", ".join(unused) +
                        " to a `require` / `assert` / `revert` check or "
                        "to a downstream call. A solver can vary that "
                        "field while the user's signature still verifies "
                        "(implicit-parameter-injection / intent "
                        "redirection — the ERC-7683 fillerData / "
                        "extraData class)."
                        + (" Critical fields involved: " +
                           ", ".join(critical_unused) + "."
                           if critical_unused else "")
                    ),
                    recommendation=(
                        "Bind every decoded field of the signed struct: "
                        "either include it in the digest the user signed, "
                        "or assert it equals an expected value. Reject "
                        "any orderData whose decoded layout is wider "
                        "than what the entrypoint enforces."
                    ),
                    file_path=self.file_path, line_number=line_no,
                    source=self.source, confidence=0.7,
                    category="intent-authorization",
                    extra={"unbound_fields": unused,
                           "critical_unbound_fields": critical_unused,
                           "intent_function": fn.name},
                ))
        return results

    # ── INTENT-PMT ───────────────────────────────────────────────
    def _check_ghost_permit(self):
        results = []
        for fn in self._iter_functions():
            permit = self._PERMIT_CALL_RE.search(fn.body)
            if not permit:
                continue
            tail = fn.body[permit.end():]
            xfer = self._TRANSFER_FROM_RE.search(tail)
            if not xfer:
                continue
            between = tail[:xfer.start()]
            # Skip if the call is wrapped in try/catch — caller is
            # explicitly tolerating permit failure.
            if self._TRY_PERMIT_RE.search(fn.body):
                continue
            # Skip if an allowance comparison sits between permit and
            # transferFrom — that's the canonical fix.
            if self._ALLOWANCE_CHECK_RE.search(between):
                continue
            line_no = fn.header_line + fn.body.count("\n", 0, permit.start())
            results.append(_finding(
                vuln_id="INTENT-PMT-001", severity="MEDIUM",
                title="Permit-and-pull without allowance verification",
                description=(
                    "Function `" + fn.name + "` calls `permit(...)` and "
                    "then `transferFrom` without an intervening "
                    "`allowance(...) >=` check and without wrapping the "
                    "permit in try/catch. A front-runner can submit the "
                    "same permit signature first (or any tx that "
                    "consumes the user's nonce), causing the in-tx "
                    "permit call to revert; the contract still proceeds "
                    "to transferFrom, which either fails (DoS / wasted "
                    "gas) or — in patterns that swallow the permit "
                    "revert via a catch-all — pulls funds against an "
                    "allowance the user never granted (Ghost-Permit / "
                    "Permit2-phishing class)."
                ),
                recommendation=(
                    "Wrap permit in `try { ... } catch { /* ignore */ }` "
                    "and immediately assert "
                    "`require(IERC20(token).allowance(owner, address(this)) "
                    ">= amount, \"NO_ALLOWANCE\")` before calling "
                    "transferFrom. Better: rely on Permit2's "
                    "permitTransferFrom which is atomic."
                ),
                file_path=self.file_path, line_number=line_no,
                source=self.source, confidence=0.7,
                category="intent-authorization",
                extra={"permit_function": fn.name},
            ))
        return results


__all__ = [
    "GuardDominanceAnalyzer",
    "PrecompileCryptoAnalyzer",
    "MerkleProofVerifierAnalyzer",
    "StorageSelectorAnalyzer",
    "CryptoAccessControlAnalyzer",
    "IntentAuthAnalyzer",
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
        "DSM_vuln_mutable": """
            pragma solidity ^0.8.0;
            contract V {
                bytes32 public DOMAIN_SEPARATOR;
                function init(bytes32 ds) external { DOMAIN_SEPARATOR = ds; }
            }
        """,
        "DSM_vuln_constant": """
            pragma solidity ^0.8.0;
            contract V {
                bytes32 public constant DOMAIN_SEPARATOR =
                    0x1111111111111111111111111111111111111111111111111111111111111111;
            }
        """,
        "DSM_vuln_builder": """
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
        """,
        "DSM_safe_immutable": """
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
        """,
        "DSM_safe_oz": """
            pragma solidity ^0.8.0;
            import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
            contract S is EIP712 {
                constructor() EIP712("S", "1") {}
                bytes32 public DOMAIN_SEPARATOR;
            }
        """,
        "RDR_vuln_critical": """
            pragma solidity ^0.8.0;
            contract V {
                function fill(bytes calldata orderData) external {
                    (address recipient, uint256 amount, address filler) =
                        abi.decode(orderData, (address recipient, uint256 amount, address filler));
                    // recipient + filler are NEVER read or asserted
                    require(amount > 0);
                }
            }
        """,
        "RDR_safe_all_bound": """
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
        """,
        "PMT_vuln": """
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
        """,
        "PMT_safe_try": """
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
        "DSM_vuln_mutable":  ("CRYPTO-DSM-001", True),
        "DSM_vuln_constant": ("CRYPTO-DSM-001", True),
        "DSM_vuln_builder":  ("CRYPTO-DSM-001", True),
        "DSM_safe_immutable": ("CRYPTO-DSM-001", False),
        "DSM_safe_oz":        ("CRYPTO-DSM-001", False),
        "RDR_vuln_critical":  ("INTENT-RDR-001", True),
        "RDR_safe_all_bound": ("INTENT-RDR-001", False),
        "PMT_vuln":           ("INTENT-PMT-001", True),
        "PMT_safe_try":       ("INTENT-PMT-001", False),
    }

    failed = 0
    for name, src in SAMPLES.items():
        ids = {f["id"] for f in CryptoAccessControlAnalyzer(src, name + ".sol").analyze()}
        ids |= {f["id"] for f in IntentAuthAnalyzer(src, name + ".sol").analyze()}
        want_id, want_present = EXPECT[name]
        got = want_id in ids
        ok = (got == want_present)
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}: {want_id} present={got} expected={want_present} all={sorted(ids)}")
        if not ok:
            failed += 1

    print(f"\n{len(SAMPLES) - failed}/{len(SAMPLES)} crypto-acl self-tests passed")
    sys.exit(1 if failed else 0)

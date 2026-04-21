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


__all__ = [
    "GuardDominanceAnalyzer",
    "PrecompileCryptoAnalyzer",
    "MerkleProofVerifierAnalyzer",
    "StorageSelectorAnalyzer",
]
"""Novel analyzer stubs - emits MMR findings only."""

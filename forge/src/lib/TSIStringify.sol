// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {FindingKind, TSISeverity} from "src/core/TSITypes.sol";

library TSIStringify {
    function findingKindToString(FindingKind kind) internal pure returns (string memory) {
        if (kind == FindingKind.TemporalStateInconsistency) return "TemporalStateInconsistency";
        if (kind == FindingKind.SnapshotFinalizationMismatch) return "SnapshotFinalizationMismatch";
        if (kind == FindingKind.ReplayClaimMismatch) return "ReplayClaimMismatch";
        if (kind == FindingKind.SameBlockStateInvalidation) return "SameBlockStateInvalidation";
        if (kind == FindingKind.CrossDomainValidationGap) return "CrossDomainValidationGap";
        if (kind == FindingKind.MultiObserverRead) return "MultiObserverRead";
        if (kind == FindingKind.CausalityInversion) return "CausalityInversion";
        if (kind == FindingKind.ReadOnlyReentrancy) return "ReadOnlyReentrancy";
        if (kind == FindingKind.CEIPatternViolation) return "CEIPatternViolation";
        if (kind == FindingKind.RebaseIntegrationMismatch) return "RebaseIntegrationMismatch";
        return "OracleCompositionVulnerability";
    }

    function severityToString(TSISeverity severity) internal pure returns (string memory) {
        if (severity == TSISeverity.CRITICAL) return "CRITICAL";
        if (severity == TSISeverity.HIGH) return "HIGH";
        if (severity == TSISeverity.MEDIUM) return "MEDIUM";
        if (severity == TSISeverity.LOW) return "LOW";
        return "INFO";
    }
}
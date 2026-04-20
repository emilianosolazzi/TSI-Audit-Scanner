// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

enum FindingKind {
    TemporalStateInconsistency,
    SnapshotFinalizationMismatch,
    ReplayClaimMismatch,
    SameBlockStateInvalidation,
    CrossDomainValidationGap,
    MultiObserverRead,
    CausalityInversion,
    ReadOnlyReentrancy,
    CEIPatternViolation,
    RebaseIntegrationMismatch,
    OracleCompositionVulnerability
}

enum TSISeverity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}

enum ContradictionPhase {
    None,
    Opening,
    Active,
    Closing,
    Closed
}

struct Observation {
    string label;
    uint256 blockNumber;
    bytes32 stateHash;
    int256 numericValue;
    bytes extraData;
}

struct Contradiction {
    FindingKind kind;
    Observation tau1;
    Observation tau2;
    bool contradiction;
    string rationale;
}

struct ContradictionScore {
    uint256 magnitude;
    uint256 relativeDeviationBps;
    uint8 confidenceScore;
    uint8 severityWeight;
    bool isProfitable;
}

struct FrozenState {
    bytes32 paramsHash;
    uint256 frozenBlock;
    uint256 nonce;
    bool executed;
}

struct ReplayClaim {
    bytes32 claimId;
    bool alreadyConsumed;
    bytes32 executionHash;
}

struct ImpactRecord {
    int256 attackerDelta;
    int256 victimDelta;
    int256 downstreamDelta;
    string units;
    string note;
}

struct TSIFinding {
    string id;
    string title;
    string adapterName;
    string adapterPath;
    FindingKind kind;
    TSISeverity severity;
    uint8 confidenceScore;
    uint8 severityWeight;
    bool forkRequired;
    bool contradiction;
    string status;
    string rationale;
    string tau1Label;
    uint256 tau1BlockNumber;
    int256 tau1Value;
    string tau2Label;
    uint256 tau2BlockNumber;
    int256 tau2Value;
    uint256 magnitude;
    uint256 relativeDeviationBps;
    bool isProfitable;
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice What a destination chain knows about Solidus credentials, and nothing else.
///
/// ⚠ NO PROXY, NO INITIALIZER, NO OWNER, NO UPGRADE PATH, AND IT CAN HOLD NO ETHER. Replacing a
/// mirror is a governance action on OUR chain: `RegisterDomain` names the inbox address per domain,
/// so a fixed contract is deployed and the domain is repointed. Integrators read
/// `SolidusRegistry.mirrorOf(domain)` rather than hardcoding an address.
interface ISolidusCredentialMirror {
    struct ExportRecord {
        bytes32 issuerDidHash;
        bytes32 credentialTypeHash;
        bytes32 holder;
        uint8 status;
        uint64 validUntil;
        uint64 solidusHeight;
    }

    struct HeartbeatRecord {
        uint64 solidusTimestamp;
        uint64 solidusHeight;
        bytes32 globalRoot;
    }

    function solidusChainId() external view returns (uint64);
    function solidusDomain() external view returns (uint32);
    /// This chain's domain, bound into the digest, which is what stops a signature for one
    /// destination being replayed on another.
    function localDomain() external view returns (uint32);
    function nextDomainSeq() external view returns (uint64);
    function exportOf(bytes32 exportId) external view returns (ExportRecord memory);
    function latestExport(bytes32 gateKey) external view returns (bytes32 exportId);
    function issuerAccredited(bytes32 issuerDidHash) external view returns (bool);
    function lastHeartbeat() external view returns (HeartbeatRecord memory);

    event CredentialStatusApplied(
        bytes32 indexed exportId, bytes32 indexed holder, uint8 status, uint64 domainSeq, uint64 solidusHeight
    );
    event IssuerStatusApplied(bytes32 indexed issuerDidHash, bool accredited, uint64 domainSeq);
    event HeartbeatApplied(uint64 solidusTimestamp, uint64 solidusHeight, uint64 domainSeq);

    error OutOfSequence(uint64 expected, uint64 got);
}

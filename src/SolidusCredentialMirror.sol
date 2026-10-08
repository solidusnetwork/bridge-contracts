// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ISolidusInbox} from "./interfaces/ISolidusInbox.sol";
import {ISolidusCredentialMirror} from "./interfaces/ISolidusCredentialMirror.sol";
import {AttestationLib} from "./lib/AttestationLib.sol";
import {BridgeMessageCodec} from "./lib/BridgeMessageCodec.sol";

/// @title SolidusCredentialMirror
/// @notice What one destination chain knows about Solidus credentials. Anyone may deliver; the
///         signatures are the authority.
///
/// ⛔ IMMUTABLE BY CONSTRUCTION. No proxy, no initializer, no owner, no upgrade path, no `payable`
/// entry point and no `receive`. The worst outcome of a bug in phase 1 is therefore a wrong
/// credential status, and that bound is deliberate: the fund-holding contracts arrive in phases 3
/// and 5 and are scheduled separately. Replacement is a new deployment plus a registry repoint,
/// never a `delegatecall` into new code behind the same address.
contract SolidusCredentialMirror is ISolidusInbox, ISolidusCredentialMirror {
    uint64 public immutable solidusChainId;
    uint32 public immutable solidusDomain;
    uint32 public immutable localDomain;
    uint8 public immutable threshold;

    uint64 public nextDomainSeq;

    mapping(address => bool) private _isValidator;
    address[] private _validators;
    mapping(bytes32 => ExportRecord) private _exports;
    mapping(bytes32 => bytes32) private _latestExport;
    mapping(bytes32 => bool) private _issuerAccredited;
    HeartbeatRecord private _lastHeartbeat;

    error BadThreshold(uint8 threshold, uint256 validatorCount);
    error DuplicateValidator(address validator);
    error ZeroValidator();

    /// @param startSeq the sequence this mirror continues from.
    ///
    /// ⚠ `startSeq` IS NOT ALWAYS 1, AND THAT IS THE WHOLE REPLACEMENT STORY. A fresh mirror has to
    /// continue the sequence the previous one reached, or Solidus and this chain disagree forever.
    /// The deploy script reads it from the chain rather than defaulting.
    constructor(
        uint64 _solidusChainId,
        uint32 _solidusDomain,
        uint32 _localDomain,
        uint64 startSeq,
        address[] memory validators_,
        uint8 _threshold
    ) {
        if (_threshold == 0 || _threshold > validators_.length) {
            revert BadThreshold(_threshold, validators_.length);
        }
        for (uint256 i; i < validators_.length; i++) {
            address v = validators_[i];
            if (v == address(0)) revert ZeroValidator();
            if (_isValidator[v]) revert DuplicateValidator(v);
            _isValidator[v] = true;
            _validators.push(v);
        }
        solidusChainId = _solidusChainId;
        solidusDomain = _solidusDomain;
        localDomain = _localDomain;
        threshold = _threshold;
        nextDomainSeq = startSeq;
    }

    // ------------------------------------------------------------------ inbox

    /// ⚠ THE ORDER OF THE TWO CHECKS IS A GAS CHOICE AND NOTHING MORE. The sequence is read first so
    /// a duplicate delivery — the common, honest case, two relayers racing — costs one comparison
    /// instead of three `ecrecover`s.
    ///
    /// ⛔ IT IS **NOT** WHAT KEEPS A REFUSED MESSAGE FROM CONSUMING A SEQUENCE NUMBER. The revert
    /// does that: every write in this call is rolled back whichever check fails. Measured on
    /// 2026-09-25 by moving `nextDomainSeq = expected + 1` ABOVE the signature check — the test
    /// asserting "a refused message must not consume a sequence number" still PASSED. Do not read
    /// that test as protecting this ordering; if you reorder these lines for some other reason, the
    /// suite will not stop you, and the only thing you will change is the gas a duplicate costs.
    function submit(bytes calldata message, bytes calldata signatures) external {
        BridgeMessageCodec.Header memory h = BridgeMessageCodec.header(message);
        uint64 expected = nextDomainSeq;
        if (h.domainSeq != expected) revert OutOfSequence(expected, h.domainSeq);

        bytes32 d = AttestationLib.digest(solidusChainId, localDomain, h.domainSeq, keccak256(message), h.solidusHeight);
        AttestationLib.verify(d, signatures, _isValidator, threshold);

        nextDomainSeq = expected + 1;

        if (h.kind == BridgeMessageCodec.KIND_CREDENTIAL_STATUS) {
            _applyCredentialStatus(message, h);
        } else if (h.kind == BridgeMessageCodec.KIND_ISSUER_STATUS) {
            _applyIssuerStatus(message, h);
        } else {
            _applyHeartbeat(message, h);
        }
    }

    function attestationDigest(bytes calldata message) external view returns (bytes32) {
        BridgeMessageCodec.Header memory h = BridgeMessageCodec.header(message);
        return AttestationLib.digest(solidusChainId, localDomain, h.domainSeq, keccak256(message), h.solidusHeight);
    }

    // ------------------------------------------------------------------ reads

    function validators() external view returns (address[] memory) {
        return _validators;
    }

    function exportOf(bytes32 exportId) external view returns (ExportRecord memory) {
        return _exports[exportId];
    }

    function latestExport(bytes32 gateKey) external view returns (bytes32) {
        return _latestExport[gateKey];
    }

    function issuerAccredited(bytes32 issuerDidHash) external view returns (bool) {
        return _issuerAccredited[issuerDidHash];
    }

    function lastHeartbeat() external view returns (HeartbeatRecord memory) {
        return _lastHeartbeat;
    }

    // ------------------------------------------------------------------ apply

    function _applyCredentialStatus(bytes calldata message, BridgeMessageCodec.Header memory h) private {
        BridgeMessageCodec.CredentialStatus memory c = BridgeMessageCodec.credentialStatus(message);

        _exports[c.exportId] = ExportRecord({
            issuerDidHash: c.issuerDidHash,
            credentialTypeHash: c.credentialTypeHash,
            holder: c.holder,
            status: c.status,
            validUntil: c.validUntil,
            solidusHeight: h.solidusHeight
        });

        // ⛔ THE POINTER MOVES ONLY TO AN ACTIVE EXPORT. If it followed every message, revoking a
        // stale export would close the gate on a holder whose current credential is fine.
        if (c.status == BridgeMessageCodec.STATUS_ACTIVE) {
            _latestExport[BridgeMessageCodec.gateKey(c.holder, c.credentialTypeHash, c.issuerDidHash)] = c.exportId;
        }

        _issuerAccredited[c.issuerDidHash] = c.issuerAccredited;

        emit CredentialStatusApplied(c.exportId, c.holder, c.status, h.domainSeq, h.solidusHeight);
    }

    function _applyIssuerStatus(bytes calldata message, BridgeMessageCodec.Header memory h) private {
        BridgeMessageCodec.IssuerStatus memory s = BridgeMessageCodec.issuerStatus(message);
        _issuerAccredited[s.issuerDidHash] = s.accredited;
        emit IssuerStatusApplied(s.issuerDidHash, s.accredited, h.domainSeq);
    }

    function _applyHeartbeat(bytes calldata message, BridgeMessageCodec.Header memory h) private {
        BridgeMessageCodec.Heartbeat memory b = BridgeMessageCodec.heartbeat(message);
        _lastHeartbeat = HeartbeatRecord({
            solidusTimestamp: b.solidusTimestamp, solidusHeight: h.solidusHeight, globalRoot: b.globalRoot
        });
        emit HeartbeatApplied(b.solidusTimestamp, h.solidusHeight, h.domainSeq);
    }
}

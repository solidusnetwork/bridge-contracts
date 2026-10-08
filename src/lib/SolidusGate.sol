// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {BridgeMessageCodec} from "./BridgeMessageCodec.sol";
import {ISolidusCredentialMirror} from "../interfaces/ISolidusCredentialMirror.sol";

/// Why a gate said no. A caller acts on this, so the values are part of the interface and never
/// renumbered.
library GateReason {
    uint8 internal constant OK = 0;
    uint8 internal constant NO_EXPORT = 1;
    uint8 internal constant NOT_ACTIVE = 2;
    uint8 internal constant ISSUER_NOT_ACCREDITED = 3;
    uint8 internal constant EXPIRED = 4;
    uint8 internal constant STALE = 5;
}

/// @title SolidusGate
/// @notice The only thing a dApp on a destination chain calls: may this holder act?
///
/// ⚠ NO STORAGE, NO OWNER, NO CONSTRUCTOR. It reads a mirror and returns a number, so an integrator
/// can embed it without inheriting anything of ours that could later change under them.
library SolidusGate {
    error CredentialRequired(bytes32 holder, bytes32 credentialTypeHash, bytes32 issuerDidHash, uint8 reason);

    /// ⛔ THE ORDER IS PART OF THE ANSWER. The first thing wrong is the thing reported, most
    /// actionable first: a holder with no export can go and get one; a holder behind our own silence
    /// can only wait. Reordering these changes what integrators tell their users.
    function check(
        ISolidusCredentialMirror mirror,
        bytes32 holder,
        bytes32 credentialTypeHash,
        bytes32 issuerDidHash,
        uint64 maxAge
    ) internal view returns (uint8) {
        bytes32 exportId = mirror.latestExport(BridgeMessageCodec.gateKey(holder, credentialTypeHash, issuerDidHash));
        if (exportId == bytes32(0)) return GateReason.NO_EXPORT;

        ISolidusCredentialMirror.ExportRecord memory r = mirror.exportOf(exportId);
        if (r.status != BridgeMessageCodec.STATUS_ACTIVE) return GateReason.NOT_ACTIVE;

        if (!mirror.issuerAccredited(issuerDidHash)) return GateReason.ISSUER_NOT_ACCREDITED;

        // `validUntil == 0` is "no expiry", which is why this is not a bare comparison.
        // A proposer can move `block.timestamp` by seconds; both windows here are day-scale, so
        // the manipulation buys nothing a credential's own expiry did not already allow.
        // forge-lint: disable-next-line(block-timestamp)
        if (r.validUntil != 0 && r.validUntil <= block.timestamp) return GateReason.EXPIRED;

        ISolidusCredentialMirror.HeartbeatRecord memory hb = mirror.lastHeartbeat();
        // ⚠ WRITTEN AS AN ADDITION, DELIBERATELY. Solidus and this chain have independent clocks, so
        // a heartbeat timestamped ahead of `block.timestamp` is normal. The subtraction form
        // (`block.timestamp - solidusTimestamp > maxAge`) underflows on that ordinary case and
        // reverts, closing every gate on the chain until the clocks converge.
        // forge-lint: disable-next-line(block-timestamp)
        if (hb.solidusTimestamp == 0 || hb.solidusTimestamp + maxAge < block.timestamp) return GateReason.STALE;

        return GateReason.OK;
    }

    function requireCredential(
        ISolidusCredentialMirror mirror,
        bytes32 holder,
        bytes32 credentialTypeHash,
        bytes32 issuerDidHash,
        uint64 maxAge
    ) internal view {
        uint8 reason = check(mirror, holder, credentialTypeHash, issuerDidHash, maxAge);
        if (reason != GateReason.OK) revert CredentialRequired(holder, credentialTypeHash, issuerDidHash, reason);
    }

    /// An EVM address as a Solidus holder key: left-padded, which is the same convention the chain
    /// uses when it exports one.
    function holderOf(address account) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(account)));
    }
}

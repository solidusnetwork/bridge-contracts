// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {BridgeMessageCodec} from "../src/lib/BridgeMessageCodec.sol";
import {GateReason, SolidusGate} from "../src/lib/SolidusGate.sol";
import {ISolidusCredentialMirror} from "../src/interfaces/ISolidusCredentialMirror.sol";
import {Messages} from "./helpers/Messages.sol";
import {MirrorFixture} from "./helpers/MirrorFixture.sol";

/// The gate is the only thing a dApp on the destination chain actually calls. It answers one
/// question — may this account act — and the ORDER of its refusals is the part worth testing,
/// because a caller acts on the reason.
contract SolidusGateTest is MirrorFixture {
    bytes32 internal constant ISSUER = keccak256("did:solidus:testnet:verify");
    bytes32 internal constant KYC_L2 = keccak256("KycL2");
    bytes32 internal constant EXPORT_A = keccak256("export-a");

    address internal constant ALICE = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    bytes32 internal constant HOLDER = bytes32(uint256(uint160(ALICE)));

    uint64 internal constant NOW = 1_758_000_000;
    uint64 internal constant MAX_AGE = 1 days;

    uint64 internal seq = 1;

    function setUp() public {
        vm.warp(NOW);
        _deployMirror();
    }

    // ------------------------------------------------------------------ each reason, in order

    /// ⛔ EVERY CASE HERE IS WRONG IN MORE THAN ONE WAY, ON PURPOSE. A check order is only observable
    /// when several checks would fire: if each case were wrong in exactly one way, reordering the
    /// implementation would not change a single assertion and this test would prove nothing.
    function test_each_reason_in_order() public {
        // Nothing delivered at all: no export AND no heartbeat. NO_EXPORT is what a caller needs to
        // hear first, because it is the only one they can do something about.
        assertEq(_check(), GateReason.NO_EXPORT);

        // ⚠ NOT_ACTIVE IS ONLY REACHABLE AFTER AN EXPORT WAS ONCE ACTIVE, which is not obvious and
        // is a direct consequence of the mirror's pointer rule: `latestExport` moves only to an
        // ACTIVE export, so a credential delivered already-revoked leaves no pointer and reads as
        // NO_EXPORT. Writing this test the other way round is what surfaced it.
        _deliverStatus(EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, NOW - 1, false);
        // Revoked, issuer unaccredited, long expired, and still no heartbeat. NOT_ACTIVE wins.
        _deliverStatus(EXPORT_A, BridgeMessageCodec.STATUS_REVOKED, NOW - 1, false);
        assertEq(_check(), GateReason.NOT_ACTIVE);

        // Active again, but the issuer lost accreditation and the credential is expired and there
        // is still no heartbeat. ISSUER_NOT_ACCREDITED wins: the credential is fine, its issuer is
        // not.
        _deliverStatus(EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, NOW - 1, false);
        assertEq(_check(), GateReason.ISSUER_NOT_ACCREDITED);

        // Issuer restored. Expired and no heartbeat remain. EXPIRED wins over STALE, because it is
        // a fact about this credential rather than about our delivery.
        _deliverIssuer(true);
        assertEq(_check(), GateReason.EXPIRED);

        // Not expired any more. Only our own silence is left.
        _deliverStatus(EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, NOW + 1 days, true);
        assertEq(_check(), GateReason.STALE);

        // A heartbeat inside maxAge, and everything is in order.
        _deliverHeartbeat(NOW);
        assertEq(_check(), GateReason.OK);
    }

    // ------------------------------------------------------------------ staleness

    function test_the_maxAge_boundary_on_both_sides() public {
        _activeCredential();

        // Exactly at the boundary: heartbeat + maxAge == now. The comparison is `<`, so this passes.
        _deliverHeartbeat(NOW - MAX_AGE);
        assertEq(_check(), GateReason.OK, "a heartbeat exactly maxAge old is still fresh");

        // One second past it.
        vm.warp(NOW + 1);
        assertEq(_check(), GateReason.STALE, "one second past maxAge is stale");
    }

    /// ⚠ THE STALENESS TEST IS AN ADDITION AND NOT A SUBTRACTION, and this is the case that proves
    /// why. Solidus and the destination chain have independent clocks; a heartbeat timestamped
    /// ahead of this chain's `block.timestamp` is normal. Written as
    /// `block.timestamp - solidusTimestamp > maxAge` it would underflow and revert on an unsigned
    /// subtraction, closing every gate on the chain until the clocks converged.
    function test_a_heartbeat_from_the_future_is_fresh_and_does_not_underflow() public {
        _activeCredential();
        _deliverHeartbeat(NOW + 10 days);
        assertEq(_check(), GateReason.OK);
    }

    function test_no_heartbeat_at_all_is_stale_rather_than_fresh() public {
        _activeCredential();
        assertEq(_check(), GateReason.STALE, "silence must close the gate, not open it");
    }

    // ------------------------------------------------------------------ expiry

    function test_validUntil_zero_never_expires() public {
        _deliverStatus(EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0, true);
        _deliverHeartbeat(NOW);
        assertEq(_check(), GateReason.OK);

        vm.warp(NOW + 3650 days);
        _deliverHeartbeat(uint64(block.timestamp));
        assertEq(_check(), GateReason.OK, "validUntil == 0 means no expiry, ten years later too");
    }

    function test_validUntil_equal_to_now_is_already_expired() public {
        _deliverStatus(EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, NOW, true);
        _deliverHeartbeat(NOW);
        assertEq(_check(), GateReason.EXPIRED, "validUntil <= block.timestamp, so the boundary expires");
    }

    // ------------------------------------------------------------------ requireCredential

    /// ⚠ THROUGH A HARNESS, BECAUSE `requireCredential` IS AN INTERNAL LIBRARY FUNCTION. Called
    /// directly from a test it is not a CALL, so `expectRevert` never sees it and the test reports
    /// "next call did not revert as expected" — which reads like the library is broken.
    function test_requireCredential_reverts_with_the_reason() public {
        GateHarness harness = new GateHarness();
        vm.expectRevert(
            abi.encodeWithSelector(
                SolidusGate.CredentialRequired.selector, HOLDER, KYC_L2, ISSUER, GateReason.NO_EXPORT
            )
        );
        harness.requireCredential(ISolidusCredentialMirror(address(mirror)), HOLDER, KYC_L2, ISSUER, MAX_AGE);

        _activeCredential();
        _deliverHeartbeat(NOW);
        harness.requireCredential(ISolidusCredentialMirror(address(mirror)), HOLDER, KYC_L2, ISSUER, MAX_AGE);
    }

    function test_holderOf_is_the_left_padded_address() public pure {
        assertEq(SolidusGate.holderOf(ALICE), HOLDER);
        assertEq(SolidusGate.holderOf(address(0)), bytes32(0));
    }

    // ------------------------------------------------------------------ helpers

    function _check() internal view returns (uint8) {
        return SolidusGate.check(ISolidusCredentialMirror(address(mirror)), HOLDER, KYC_L2, ISSUER, MAX_AGE);
    }

    function _activeCredential() internal {
        _deliverStatus(EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, NOW + 3650 days, true);
    }

    function _deliverStatus(bytes32 exportId, uint8 status, uint64 validUntil, bool accredited) internal {
        deliver(Messages.credentialStatus(seq++, 900, exportId, ISSUER, KYC_L2, HOLDER, status, validUntil, accredited));
    }

    function _deliverIssuer(bool accredited) internal {
        deliver(Messages.issuerStatus(seq++, 900, ISSUER, accredited));
    }

    function _deliverHeartbeat(uint64 solidusTimestamp) internal {
        deliver(Messages.heartbeat(seq++, 900, solidusTimestamp, keccak256("root")));
    }
}

/// A call boundary, so `expectRevert` can see an internal library revert.
contract GateHarness {
    function requireCredential(
        ISolidusCredentialMirror mirror,
        bytes32 holder,
        bytes32 credentialTypeHash,
        bytes32 issuerDidHash,
        uint64 maxAge
    ) external view {
        SolidusGate.requireCredential(mirror, holder, credentialTypeHash, issuerDidHash, maxAge);
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {SolidusCredentialMirror} from "../src/SolidusCredentialMirror.sol";
import {ISolidusCredentialMirror} from "../src/interfaces/ISolidusCredentialMirror.sol";
import {AttestationLib} from "../src/lib/AttestationLib.sol";
import {BridgeMessageCodec} from "../src/lib/BridgeMessageCodec.sol";
import {Messages} from "./helpers/Messages.sol";
import {MirrorFixture} from "./helpers/MirrorFixture.sol";

/// The mirror is what a destination chain believes. Everything here is about the two ways that
/// belief can be wrong: a message applied that nobody signed, and a message applied in the wrong
/// order.
contract SolidusCredentialMirrorTest is MirrorFixture {
    bytes32 internal constant ISSUER = keccak256("did:solidus:testnet:verify");
    bytes32 internal constant KYC_L2 = keccak256("KycL2");
    bytes32 internal constant HOLDER = bytes32(uint256(uint160(0x70997970C51812dc3A010C7d01b50e0d17dc79C8)));
    bytes32 internal constant EXPORT_A = keccak256("export-a");
    bytes32 internal constant EXPORT_B = keccak256("export-b");

    function setUp() public {
        _deployMirror();
    }

    // ------------------------------------------------------------------ 1: initial state

    function test_initial_state_is_what_the_constructor_was_given() public view {
        assertEq(mirror.solidusChainId(), CHAIN_ID);
        assertEq(mirror.solidusDomain(), SOLIDUS_DOMAIN);
        assertEq(mirror.localDomain(), LOCAL_DOMAIN);
        assertEq(mirror.nextDomainSeq(), START_SEQ);
        assertEq(mirror.threshold(), 3);

        address[] memory vs = mirror.validators();
        assertEq(vs.length, 4);
        for (uint256 i; i < 4; i++) {
            assertEq(vs[i], vm.addr(keys[i]), "validators() must return them in the order given");
        }
    }

    // ------------------------------------------------------------------ 2 and 3: the sequence

    /// ⛔ STRICT IN BOTH DIRECTIONS. A gap would let a revocation be skipped; a replay would let one
    /// be undone. `nextDomainSeq` is the only thing standing between the two.
    function test_a_gap_reverts_and_the_sequence_then_continues() public {
        bytes memory second = _status(2, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0);
        vm.expectRevert(abi.encodeWithSelector(ISolidusCredentialMirror.OutOfSequence.selector, uint64(1), uint64(2)));
        deliver(second);

        deliver(_status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0));
        assertEq(mirror.nextDomainSeq(), 2);
        deliver(_status(2, EXPORT_B, BridgeMessageCodec.STATUS_ACTIVE, 0));
        assertEq(mirror.nextDomainSeq(), 3);
    }

    function test_replaying_a_consumed_sequence_reverts() public {
        bytes memory first = _status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0);
        bytes memory signatures = _signatures(first, 3);
        mirror.submit(first, signatures);
        vm.expectRevert(abi.encodeWithSelector(ISolidusCredentialMirror.OutOfSequence.selector, uint64(2), uint64(1)));
        mirror.submit(first, signatures);
    }

    /// ⚠ THE SEQUENCE IS INSIDE THE DIGEST, so this is not a second check of the same thing. A
    /// message validly signed for slot 5 does not "apply at the wrong slot" — its signatures do not
    /// verify at all against the digest for slot 1.
    function test_signatures_for_another_sequence_do_not_verify_at_this_one() public {
        bytes memory forSlot5 = _status(5, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0);
        bytes memory good = _signatures(forSlot5, 3);
        // Re-label the body as slot 1 so the ordering check passes and the signatures are reached.
        bytes memory forSlot1 = _status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0);
        vm.expectPartialRevert(AttestationLib.UnknownSigner.selector);
        mirror.submit(forSlot1, good);
    }

    // ------------------------------------------------------------------ 4 and 5: refusals cost nothing

    /// ⚠ THE TWO STATE ASSERTIONS HERE ARE FREE AND THIS COMMENT IS THE HONEST LABEL ON THEM. A
    /// revert rolls back every write in the call, so "nothing changed" cannot fail whatever
    /// `submit` does internally — proved on 2026-09-25 by moving the sequence write above the
    /// signature check and watching this test still pass. They are kept because they state the
    /// property a reader needs; the line that can actually fail is the last one, which shows the
    /// slot is still deliverable afterwards.
    function test_below_the_threshold_changes_nothing() public {
        bytes memory m = _status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0);
        vm.expectRevert(abi.encodeWithSelector(AttestationLib.NotEnoughSignatures.selector, uint256(2), uint256(3)));
        mirror.submit(m, _signatures(m, 2));
        assertEq(mirror.nextDomainSeq(), 1, "a refused message must not consume a sequence number");
        assertEq(mirror.exportOf(EXPORT_A).solidusHeight, 0, "nothing was written");

        // The slot was not burned: the same message, properly attested, still applies at seq 1.
        deliver(m);
        assertEq(mirror.nextDomainSeq(), 2);
        assertEq(mirror.exportOf(EXPORT_A).solidusHeight, 900);
    }

    function test_a_malformed_message_consumes_no_sequence_number() public {
        bytes memory truncated = hex"0101";
        vm.expectPartialRevert(BridgeMessageCodec.BadLength.selector);
        mirror.submit(truncated, "");
        assertEq(mirror.nextDomainSeq(), 1);
    }

    // ------------------------------------------------------------------ 6 to 9: what gets applied

    function test_credential_status_writes_the_record_the_pointer_and_the_accreditation() public {
        bytes32 gateKey = BridgeMessageCodec.gateKey(HOLDER, KYC_L2, ISSUER);
        vm.expectEmit(true, true, true, true, address(mirror));
        emit ISolidusCredentialMirror.CredentialStatusApplied(
            EXPORT_A, HOLDER, BridgeMessageCodec.STATUS_ACTIVE, 1, 900
        );
        deliver(_status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 1_900_000_000));

        ISolidusCredentialMirror.ExportRecord memory r = mirror.exportOf(EXPORT_A);
        assertEq(r.issuerDidHash, ISSUER);
        assertEq(r.credentialTypeHash, KYC_L2);
        assertEq(r.holder, HOLDER);
        assertEq(r.status, BridgeMessageCodec.STATUS_ACTIVE);
        assertEq(r.validUntil, 1_900_000_000);
        assertEq(r.solidusHeight, 900);

        assertEq(mirror.latestExport(gateKey), EXPORT_A);
        assertTrue(mirror.issuerAccredited(ISSUER), "the message carries the issuer's standing");
    }

    function test_revoking_the_current_export_keeps_the_pointer() public {
        bytes32 gateKey = BridgeMessageCodec.gateKey(HOLDER, KYC_L2, ISSUER);
        deliver(_status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0));
        deliver(_status(2, EXPORT_A, BridgeMessageCodec.STATUS_REVOKED, 0));

        assertEq(mirror.latestExport(gateKey), EXPORT_A, "the pointer stays, the status changes");
        assertEq(mirror.exportOf(EXPORT_A).status, BridgeMessageCodec.STATUS_REVOKED);
    }

    /// ⛔ THE ATTACK THIS CLOSES. If the pointer moved on every message, revoking a stale export
    /// would drop the gate for a holder whose current credential is fine. `latestExport` moves only
    /// to an export whose new status is ACTIVE.
    function test_revoking_an_older_export_does_not_hide_a_newer_active_one() public {
        bytes32 gateKey = BridgeMessageCodec.gateKey(HOLDER, KYC_L2, ISSUER);
        deliver(_status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0));
        deliver(_status(2, EXPORT_B, BridgeMessageCodec.STATUS_ACTIVE, 0));
        assertEq(mirror.latestExport(gateKey), EXPORT_B);

        deliver(_status(3, EXPORT_A, BridgeMessageCodec.STATUS_REVOKED, 0));
        assertEq(mirror.latestExport(gateKey), EXPORT_B, "the newer active export must still be pointed at");
        assertEq(mirror.exportOf(EXPORT_A).status, BridgeMessageCodec.STATUS_REVOKED);
        assertEq(mirror.exportOf(EXPORT_B).status, BridgeMessageCodec.STATUS_ACTIVE);
    }

    function test_issuer_status_toggles_accreditation() public {
        deliver(_status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0));
        assertTrue(mirror.issuerAccredited(ISSUER));

        vm.expectEmit(true, true, true, true, address(mirror));
        emit ISolidusCredentialMirror.IssuerStatusApplied(ISSUER, false, 2);
        deliver(Messages.issuerStatus(2, 901, ISSUER, false));
        assertFalse(mirror.issuerAccredited(ISSUER));

        deliver(Messages.issuerStatus(3, 902, ISSUER, true));
        assertTrue(mirror.issuerAccredited(ISSUER));
    }

    function test_heartbeat_writes_the_record_and_emits() public {
        bytes32 root = keccak256("global root");
        vm.expectEmit(true, true, true, true, address(mirror));
        emit ISolidusCredentialMirror.HeartbeatApplied(1_758_000_000, 900, 1);
        deliver(Messages.heartbeat(1, 900, 1_758_000_000, root));

        ISolidusCredentialMirror.HeartbeatRecord memory h = mirror.lastHeartbeat();
        assertEq(h.solidusTimestamp, 1_758_000_000);
        assertEq(h.solidusHeight, 900);
        assertEq(h.globalRoot, root);
    }

    // ------------------------------------------------------------------ 10: nothing to capture

    /// ⛔ THE BOUND ON A PHASE 1 BUG. The worst outcome here is a wrong credential status, and that
    /// bound only holds while the contract cannot hold value and nobody can reach into it.
    function test_the_mirror_has_no_owner_and_cannot_receive_ether() public {
        (bool ok,) = address(mirror).call{value: 1 ether}("");
        assertFalse(ok, "a plain value transfer must revert: no receive, no fallback, no payable");
        assertEq(address(mirror).balance, 0);

        (bool found,) = address(mirror).call(abi.encodeWithSignature("owner()"));
        assertFalse(found, "there is no owner()");
        (found,) = address(mirror).call(abi.encodeWithSignature("upgradeTo(address)", address(1)));
        assertFalse(found, "there is no upgrade entry point");
        (found,) = address(mirror).call(abi.encodeWithSignature("initialize()"));
        assertFalse(found, "there is no initializer");
    }

    // ------------------------------------------------------------------ the constructor refuses

    function test_the_constructor_refuses_a_zero_threshold() public {
        address[] memory vs = _four();
        vm.expectRevert(abi.encodeWithSelector(SolidusCredentialMirror.BadThreshold.selector, uint8(0), uint256(4)));
        new SolidusCredentialMirror(CHAIN_ID, SOLIDUS_DOMAIN, LOCAL_DOMAIN, START_SEQ, vs, 0);
    }

    function test_the_constructor_refuses_a_threshold_above_the_validator_count() public {
        address[] memory vs = _four();
        vm.expectRevert(abi.encodeWithSelector(SolidusCredentialMirror.BadThreshold.selector, uint8(5), uint256(4)));
        new SolidusCredentialMirror(CHAIN_ID, SOLIDUS_DOMAIN, LOCAL_DOMAIN, START_SEQ, vs, 5);
    }

    function test_the_constructor_refuses_a_duplicate_validator() public {
        address[] memory vs = _four();
        vs[3] = vs[1];
        vm.expectRevert(abi.encodeWithSelector(SolidusCredentialMirror.DuplicateValidator.selector, vs[1]));
        new SolidusCredentialMirror(CHAIN_ID, SOLIDUS_DOMAIN, LOCAL_DOMAIN, START_SEQ, vs, 3);
    }

    function test_the_constructor_refuses_the_zero_address() public {
        address[] memory vs = _four();
        vs[2] = address(0);
        vm.expectRevert(SolidusCredentialMirror.ZeroValidator.selector);
        new SolidusCredentialMirror(CHAIN_ID, SOLIDUS_DOMAIN, LOCAL_DOMAIN, START_SEQ, vs, 3);
    }

    /// ⚠ `startSeq` EXISTS BECAUSE REPLACEMENT IS THE UPGRADE PATH. A fresh mirror must continue the
    /// sequence the previous one reached, or Solidus and the destination disagree forever.
    function test_a_replacement_mirror_continues_the_sequence() public {
        address[] memory vs = _four();
        SolidusCredentialMirror successor =
            new SolidusCredentialMirror(CHAIN_ID, SOLIDUS_DOMAIN, LOCAL_DOMAIN, 42, vs, 3);
        assertEq(successor.nextDomainSeq(), 42);
    }

    function test_attestationDigest_is_the_digest_the_signatures_are_checked_against() public view {
        bytes memory m = _status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 0);
        assertEq(
            mirror.attestationDigest(m),
            AttestationLib.digest(CHAIN_ID, LOCAL_DOMAIN, 1, keccak256(m), 900),
            "an integrator must be able to reproduce it without reading the source"
        );
    }

    // ------------------------------------------------------------------ cost

    /// ⚠ THE WHOLE-DELIVERY COST, WHICH IS THE ONE THAT MATTERS: the transport pays it for every
    /// heartbeat on every chain forever. The verify is the small half.
    function test_gas_of_a_3_of_4_status_and_heartbeat_delivery() public {
        bytes memory status = _status(1, EXPORT_A, BridgeMessageCodec.STATUS_ACTIVE, 1_900_000_000);
        bytes memory statusSigs = _signatures(status, 3);
        uint256 before = gasleft();
        mirror.submit(status, statusSigs);
        uint256 statusGas = before - gasleft();

        bytes memory beat = Messages.heartbeat(2, 901, 1_758_000_000, keccak256("root"));
        bytes memory beatSigs = _signatures(beat, 3);
        before = gasleft();
        mirror.submit(beat, beatSigs);
        uint256 beatGas = before - gasleft();

        console.log("submit credential status 3-of-4 gas", statusGas);
        console.log("submit heartbeat 3-of-4 gas", beatGas);

        // Bounds, not pins: they catch a rewrite that adds a storage write, not a 10-gas drift.
        // A cold SSTORE is 20.000, so the headroom here is about one and a half extra slots.
        assertLt(statusGas, 200_000, "a status delivery got expensive");
        assertLt(beatGas, 90_000, "a heartbeat got expensive");
        assertGt(statusGas, beatGas, "a status writes more than a heartbeat");
    }

    // ------------------------------------------------------------------ helpers

    function _status(uint64 seq, bytes32 exportId, uint8 status, uint64 validUntil)
        internal
        pure
        returns (bytes memory)
    {
        return Messages.credentialStatus(seq, 900, exportId, ISSUER, KYC_L2, HOLDER, status, validUntil, true);
    }

    function _four() internal view returns (address[] memory vs) {
        vs = new address[](4);
        for (uint256 i; i < 4; i++) {
            vs[i] = vm.addr(keys[i]);
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {GatedUsdcReceiver} from "../src/GatedUsdcReceiver.sol";
import {IMessageTransmitterV2} from "../src/interfaces/ICctp.sol";
import {IGatedUsdcReceiver} from "../src/interfaces/IGatedUsdcReceiver.sol";
import {ISolidusCredentialMirror} from "../src/interfaces/ISolidusCredentialMirror.sol";
import {BridgeMessageCodec} from "../src/lib/BridgeMessageCodec.sol";
import {GateReason} from "../src/lib/SolidusGate.sol";
import {CctpMock, MockUsdc} from "./helpers/CctpMock.sol";
import {CodecHarness} from "./helpers/CodecHarness.sol";
import {Messages} from "./helpers/Messages.sol";
import {MirrorFixture} from "./helpers/MirrorFixture.sol";

/// Tries to re-enter `release` from inside the USDC transfer that pays it, and records what happened.
contract Reentrant {
    GatedUsdcReceiver public receiver;
    bytes32 public target;
    bytes public reentryError;
    bool public tried;

    function arm(GatedUsdcReceiver r, bytes32 h) external {
        receiver = r;
        target = h;
    }

    function onUsdcReceived() external {
        if (tried) return;
        tried = true;
        try receiver.release(target) {} catch (bytes memory err) {
            reentryError = err;
        }
    }
}

contract GatedUsdcReceiverTest is MirrorFixture {
    bytes32 internal constant ISSUER = keccak256("did:solidus:testnet:verify");
    bytes32 internal constant KYC_L2 = keccak256("KycL2");
    bytes8 internal constant REF = bytes8("partner1");

    address internal constant ALICE = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    address internal constant BOB = 0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC;
    address internal constant TIMELOCK = address(0x7111e);

    uint64 internal constant NOW = 1_758_000_000;
    uint64 internal constant DEADLINE = NOW + 7 days;
    uint256 internal constant AMOUNT = 1_000_000; // 1 USDC
    uint256 internal constant FEE = 100; // 1 bps, as measured Sepolia -> Fuji

    MockUsdc internal usdc;
    CctpMock internal cctp;
    GatedUsdcReceiver internal receiver;
    CodecHarness internal codec;
    uint64 internal seq = 1;
    uint256 internal nonce = 1;

    function setUp() public {
        vm.warp(NOW);
        _deployMirror();
        usdc = new MockUsdc();
        cctp = new CctpMock(usdc);
        usdc.setMinter(address(cctp));
        GatedUsdcReceiver impl =
            new GatedUsdcReceiver(IMessageTransmitterV2(address(cctp)), IERC20(address(usdc)), ISolidusCredentialMirror(address(mirror)));
        receiver = GatedUsdcReceiver(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(GatedUsdcReceiver.initialize, (TIMELOCK))))
        );
        codec = new CodecHarness();
        _heartbeat(NOW);
    }

    // ------------------------------------------------------------------ 1. delivered

    function test_1_a_credentialed_recipient_is_paid_and_the_event_carries_the_referral() public {
        _credential(_holder(ALICE), BridgeMessageCodec.STATUS_ACTIVE, "export-alice");
        bytes memory m = _message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE);

        vm.expectEmit(true, true, false, true, address(receiver));
        emit IGatedUsdcReceiver.UsdcDelivered(keccak256(m), ALICE, AMOUNT - FEE, FEE, REF);
        receiver.relay(m, hex"01");

        assertEq(usdc.balanceOf(ALICE), AMOUNT - FEE, "the recipient is paid what Circle minted");
        assertEq(usdc.balanceOf(address(receiver)), 0, "nothing is left behind");
        assertEq(receiver.escrowOf(keccak256(m)).state, 0, "a delivered transfer is not an escrow");
    }

    // ------------------------------------------------------------------ 2. escrowed

    function test_2_a_recipient_with_no_export_is_escrowed_with_the_hook_deadline() public {
        bytes memory m = _message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE);
        vm.expectEmit(true, true, false, true, address(receiver));
        emit IGatedUsdcReceiver.UsdcEscrowed(keccak256(m), _holder(ALICE), AMOUNT - FEE, GateReason.NO_EXPORT, DEADLINE);
        bytes32 h = receiver.relay(m, hex"01");

        IGatedUsdcReceiver.Escrow memory e = receiver.escrowOf(h);
        assertEq(e.state, 1);
        assertEq(e.amount, AMOUNT - FEE);
        assertEq(e.deadline, DEADLINE);
        assertEq(e.refundAddress, _holder(BOB));
        assertEq(e.referralCode, REF);
        assertEq(usdc.balanceOf(address(receiver)), AMOUNT - FEE, "the contract holds the escrowed USDC");
        assertEq(usdc.balanceOf(ALICE), 0);
    }

    // ------------------------------------------------------------------ 3, 4. release

    function test_3_release_before_the_export_exists_reverts_with_the_gate_reason() public {
        bytes32 h = receiver.relay(_message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE), hex"01");
        vm.expectRevert(abi.encodeWithSelector(IGatedUsdcReceiver.GateStillFails.selector, h, GateReason.NO_EXPORT));
        receiver.release(h);
    }

    function test_4_after_the_export_arrives_release_pays_the_final_recipient() public {
        bytes32 h = receiver.relay(_message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE), hex"01");
        _credential(_holder(ALICE), BridgeMessageCodec.STATUS_ACTIVE, "export-alice");

        vm.expectEmit(true, true, false, true, address(receiver));
        emit IGatedUsdcReceiver.UsdcReleased(h, ALICE, AMOUNT - FEE);
        vm.prank(address(0xCAFE)); // anyone may release
        receiver.release(h);

        assertEq(usdc.balanceOf(ALICE), AMOUNT - FEE);
        assertEq(receiver.escrowOf(h).state, 2);
        vm.expectRevert(abi.encodeWithSelector(IGatedUsdcReceiver.NotHeld.selector, h));
        receiver.release(h);
    }

    function test_5_release_after_the_deadline_reverts() public {
        bytes32 h = receiver.relay(_message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE), hex"01");
        vm.warp(DEADLINE + 1);
        _heartbeat(DEADLINE + 1);
        _credential(_holder(ALICE), BridgeMessageCodec.STATUS_ACTIVE, "export-alice");
        vm.expectRevert(abi.encodeWithSelector(IGatedUsdcReceiver.DeadlinePassed.selector, h));
        receiver.release(h);
    }

    // ------------------------------------------------------------------ 6. refund

    function test_6_refund_waits_for_the_deadline_then_pays_the_refund_address() public {
        bytes32 h = receiver.relay(_message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE), hex"01");
        vm.expectRevert(abi.encodeWithSelector(IGatedUsdcReceiver.DeadlineNotPassed.selector, h));
        receiver.refund(h);

        vm.warp(DEADLINE); // the deadline itself still belongs to release
        vm.expectRevert(abi.encodeWithSelector(IGatedUsdcReceiver.DeadlineNotPassed.selector, h));
        receiver.refund(h);

        vm.warp(DEADLINE + 1);
        vm.expectEmit(true, true, false, true, address(receiver));
        emit IGatedUsdcReceiver.UsdcRefunded(h, BOB, AMOUNT - FEE);
        receiver.refund(h);
        assertEq(usdc.balanceOf(BOB), AMOUNT - FEE);
        assertEq(receiver.escrowOf(h).state, 3);
        vm.expectRevert(abi.encodeWithSelector(IGatedUsdcReceiver.NotHeld.selector, h));
        receiver.refund(h);
    }

    // ------------------------------------------------------------------ 7. unknown

    function test_7_release_and_refund_on_an_unknown_hash_revert_NotHeld() public {
        bytes32 h = keccak256("never relayed");
        vm.expectRevert(abi.encodeWithSelector(IGatedUsdcReceiver.NotHeld.selector, h));
        receiver.release(h);
        vm.expectRevert(abi.encodeWithSelector(IGatedUsdcReceiver.NotHeld.selector, h));
        receiver.refund(h);
    }

    // ------------------------------------------------------------------ 8. replay

    function test_8_a_replayed_message_reverts_and_creates_no_second_escrow() public {
        bytes memory m = _message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE);
        bytes32 h = receiver.relay(m, hex"01");
        vm.expectRevert(bytes("Nonce already used"));
        receiver.relay(m, hex"01");
        assertEq(receiver.escrowOf(h).amount, AMOUNT - FEE, "the first escrow is unchanged");
        assertEq(usdc.balanceOf(address(receiver)), AMOUNT - FEE, "nothing was minted twice");
    }

    function test_8b_a_failed_receiveMessage_records_nothing() public {
        bytes memory m = _message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE);
        cctp.setFailNext(true);
        vm.expectRevert(bytes("attestation rejected"));
        receiver.relay(m, hex"01");
        assertEq(receiver.escrowOf(keccak256(m)).state, 0);
        assertEq(usdc.balanceOf(address(receiver)), 0);
    }

    // ------------------------------------------------------------------ 9. blocklist

    function test_9_a_blocklisted_recipient_keeps_the_escrow_held_and_refund_still_works() public {
        bytes32 h = receiver.relay(_message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE), hex"01");
        _credential(_holder(ALICE), BridgeMessageCodec.STATUS_ACTIVE, "export-alice");
        usdc.setBlocked(ALICE, true);

        vm.expectRevert(abi.encodeWithSelector(MockUsdc.Blocklisted.selector, ALICE));
        receiver.release(h);
        assertEq(receiver.escrowOf(h).state, 1, "the escrow is still held");
        assertEq(usdc.balanceOf(address(receiver)), AMOUNT - FEE, "the funds are still here");

        vm.warp(DEADLINE + 1);
        receiver.refund(h);
        assertEq(usdc.balanceOf(BOB), AMOUNT - FEE);
    }

    function test_9b_a_blocklisted_recipient_at_relay_time_escrows_instead_of_reverting() public {
        _credential(_holder(ALICE), BridgeMessageCodec.STATUS_ACTIVE, "export-alice");
        usdc.setBlocked(ALICE, true);
        bytes memory m = _message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE);

        vm.expectEmit(true, true, false, true, address(receiver));
        emit IGatedUsdcReceiver.UsdcEscrowed(keccak256(m), _holder(ALICE), AMOUNT - FEE, 6, DEADLINE);
        bytes32 h = receiver.relay(m, hex"01");
        assertEq(receiver.escrowOf(h).state, 1);
        assertTrue(cctp.usedNonce(bytes32(uint256(1))), "Circle's nonce is consumed: the delivery happened");
    }

    // ------------------------------------------------------------------ 10. reentrancy

    function test_10_a_reentrant_recipient_cannot_re_enter_release() public {
        Reentrant attacker = new Reentrant();
        bytes32 h = receiver.relay(_message(_hook(address(attacker), BOB, DEADLINE), AMOUNT, FEE), hex"01");
        _credential(_holder(address(attacker)), BridgeMessageCodec.STATUS_ACTIVE, "export-attacker");
        attacker.arm(receiver, h);

        receiver.release(h);

        assertTrue(attacker.tried(), "the attacker did attempt the re-entry");
        assertEq(
            bytes4(attacker.reentryError()),
            ReentrancyGuard.ReentrancyGuardReentrantCall.selector,
            "the re-entry was refused by the guard, not by something else"
        );
        assertEq(usdc.balanceOf(address(attacker)), AMOUNT - FEE, "paid exactly once");
        assertEq(usdc.balanceOf(address(receiver)), 0);
    }

    // ------------------------------------------------------------------ 11. hook shape

    function test_11_a_hook_of_the_wrong_length_reverts_and_escrows_nothing() public {
        bytes memory hook = _hook(ALICE, BOB, DEADLINE);
        bytes memory short = new bytes(144);
        for (uint256 i; i < 144; i++) {
            short[i] = hook[i];
        }
        bytes memory m = _message(short, AMOUNT, FEE);
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadLength.selector, uint256(145), uint256(144)));
        receiver.relay(m, hex"01");
        assertEq(usdc.balanceOf(address(receiver)), 0);
        assertFalse(cctp.usedNonce(bytes32(uint256(1))), "Circle's nonce is untouched");
    }

    function test_11b_a_hook_with_another_version_reverts_and_escrows_nothing() public {
        bytes memory hook = _hook(ALICE, BOB, DEADLINE);
        hook[0] = 0x02;
        bytes memory m = _message(hook, AMOUNT, FEE);
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadVersion.selector, uint8(2)));
        receiver.relay(m, hex"01");
        assertEq(receiver.escrowOf(keccak256(m)).state, 0);
    }

    // ------------------------------------------------------------------ boundaries the plan implies

    function test_a_message_minting_to_someone_else_is_refused() public {
        bytes memory m = _messageTo(bytes32(uint256(uint160(BOB))), _hook(ALICE, BOB, DEADLINE), AMOUNT, FEE);
        vm.expectRevert(abi.encodeWithSelector(GatedUsdcReceiver.NotForThisReceiver.selector, bytes32(uint256(uint160(BOB)))));
        receiver.relay(m, hex"01");
    }

    function test_a_recipient_that_is_not_an_evm_address_is_refused() public {
        bytes memory hook = abi.encodePacked(uint8(1), bytes32(type(uint256).max), KYC_L2, ISSUER, _holder(BOB), DEADLINE, REF);
        vm.expectRevert(abi.encodeWithSelector(GatedUsdcReceiver.NotAnEvmAddress.selector, bytes32(type(uint256).max)));
        receiver.relay(_message(hook, AMOUNT, FEE), hex"01");
    }

    // ------------------------------------------------------------------ 12. pause (mainnet readiness)

    address internal constant GUARDIAN = address(0x6a12d);

    function _paused() internal {
        vm.prank(TIMELOCK);
        receiver.setGuardian(GUARDIAN);
        vm.prank(GUARDIAN);
        receiver.pause();
    }

    function test_12_paused_still_mints_but_escrows_a_credentialed_recipient_with_reason_PAUSED() public {
        _credential(_holder(ALICE), BridgeMessageCodec.STATUS_ACTIVE, "export-alice");
        _paused();
        bytes memory m = _message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE);
        vm.expectEmit(true, true, false, true, address(receiver));
        emit IGatedUsdcReceiver.UsdcEscrowed(keccak256(m), _holder(ALICE), AMOUNT - FEE, receiver.PAUSED(), DEADLINE);
        bytes32 h = receiver.relay(m, hex"01");
        assertEq(usdc.balanceOf(ALICE), 0, "a paused receiver pays nobody");
        assertEq(usdc.balanceOf(address(receiver)), AMOUNT - FEE, "the burn is not stranded: the funds are held");
        assertEq(receiver.escrowOf(h).state, 1);
    }

    function test_12b_paused_blocks_release_but_never_refund() public {
        bytes32 h = receiver.relay(_message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE), hex"01");
        _credential(_holder(ALICE), BridgeMessageCodec.STATUS_ACTIVE, "export-alice");
        _paused();
        vm.expectRevert(GatedUsdcReceiver.IsPaused.selector);
        receiver.release(h);

        vm.warp(DEADLINE + 1);
        receiver.refund(h);
        assertEq(usdc.balanceOf(BOB), AMOUNT - FEE, "the sender's way out survives a pause");
    }

    function test_12c_after_unpause_a_held_escrow_releases() public {
        bytes32 h = receiver.relay(_message(_hook(ALICE, BOB, DEADLINE), AMOUNT, FEE), hex"01");
        _credential(_holder(ALICE), BridgeMessageCodec.STATUS_ACTIVE, "export-alice");
        _paused();
        vm.prank(TIMELOCK);
        receiver.unpause();
        receiver.release(h);
        assertEq(usdc.balanceOf(ALICE), AMOUNT - FEE);
    }

    function test_12d_only_the_guardian_or_owner_pauses_and_only_the_owner_unpauses_or_names_a_guardian() public {
        vm.prank(TIMELOCK);
        receiver.setGuardian(GUARDIAN);

        vm.expectRevert(abi.encodeWithSelector(GatedUsdcReceiver.NotGuardian.selector, address(0xBAD)));
        vm.prank(address(0xBAD));
        receiver.pause();

        vm.prank(GUARDIAN);
        receiver.pause();
        assertTrue(receiver.paused());

        vm.expectRevert(abi.encodeWithSelector(GatedUsdcReceiver.NotOwner.selector, GUARDIAN));
        vm.prank(GUARDIAN);
        receiver.unpause();

        vm.expectRevert(abi.encodeWithSelector(GatedUsdcReceiver.NotOwner.selector, GUARDIAN));
        vm.prank(GUARDIAN);
        receiver.setGuardian(GUARDIAN);

        vm.prank(TIMELOCK);
        receiver.unpause();
        assertFalse(receiver.paused());
    }

    function test_12e_a_fresh_receiver_is_unpaused_with_no_guardian() public view {
        assertFalse(receiver.paused());
        assertEq(receiver.guardian(), address(0));
    }

    function test_only_the_owner_may_upgrade() public {
        GatedUsdcReceiver next =
            new GatedUsdcReceiver(IMessageTransmitterV2(address(cctp)), IERC20(address(usdc)), ISolidusCredentialMirror(address(mirror)));
        vm.expectRevert(abi.encodeWithSelector(GatedUsdcReceiver.NotOwner.selector, address(this)));
        receiver.upgradeToAndCall(address(next), "");
        vm.prank(TIMELOCK);
        receiver.upgradeToAndCall(address(next), "");
    }

    function test_the_hook_decoder_matches_the_shared_vector() public view {
        string memory json = vm.readFile("test-fixtures/bridge/usdc-hook-v1.json");
        BridgeMessageCodec.UsdcHook memory u = codec.usdcHook(vm.parseJsonBytes(json, ".cases[0].hex"));
        assertEq(u.finalRecipient, vm.parseJsonBytes32(json, ".cases[0].finalRecipient"));
        assertEq(u.credentialTypeHash, vm.parseJsonBytes32(json, ".cases[0].credentialTypeHash"));
        assertEq(u.issuerDidHash, vm.parseJsonBytes32(json, ".cases[0].issuerDidHash"));
        assertEq(u.refundAddress, vm.parseJsonBytes32(json, ".cases[0].refundAddress"));
        assertEq(uint256(u.deadline), vm.parseUint(vm.parseJsonString(json, ".cases[0].deadline")));
    }

    function testFuzz_the_recipient_receives_exactly_what_Circle_minted(uint256 amount, uint256 fee) public {
        amount = bound(amount, 1, 10_000_000e6); // up to the $10M burn cap
        fee = bound(fee, 0, amount - 1);
        _credential(_holder(ALICE), BridgeMessageCodec.STATUS_ACTIVE, "export-alice");
        receiver.relay(_message(_hook(ALICE, BOB, DEADLINE), amount, fee), hex"01");
        assertEq(usdc.balanceOf(ALICE), amount - fee);
        assertEq(usdc.balanceOf(address(receiver)), 0);
    }

    // ------------------------------------------------------------------ helpers

    function _holder(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _hook(address recipient, address refundTo, uint64 deadline) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(1), _holder(recipient), KYC_L2, ISSUER, _holder(refundTo), deadline, REF);
    }

    function _message(bytes memory hook, uint256 amount, uint256 fee) internal returns (bytes memory) {
        return _messageTo(_holder(address(receiver)), hook, amount, fee);
    }

    /// A CCTP v2 burn message, laid out as records/cctp-v2.md measured it.
    function _messageTo(bytes32 mintRecipient, bytes memory hook, uint256 amount, uint256 fee)
        internal
        returns (bytes memory)
    {
        bytes memory body = abi.encodePacked(
            uint32(1), // body version
            _holder(address(0xBEEF)), // burnToken on the source chain
            mintRecipient,
            amount,
            _holder(ALICE), // messageSender
            fee, // maxFee
            fee, // feeExecuted
            uint256(0), // expirationBlock
            hook
        );
        return abi.encodePacked(
            uint32(1), // version
            uint32(0), // sourceDomain: Sepolia
            uint32(1), // destinationDomain: Fuji
            bytes32(nonce++),
            _holder(address(0x5E4D)), // sender: the source TokenMessenger
            _holder(address(0x4EC1)), // recipient: this chain's TokenMessenger
            _holder(address(receiver)), // destinationCaller
            uint32(1000),
            uint32(1000),
            body
        );
    }

    function _credential(bytes32 holder, uint8 status, string memory exportTag) internal {
        deliver(Messages.credentialStatus(seq++, 900, keccak256(bytes(exportTag)), ISSUER, KYC_L2, holder, status, NOW + 3650 days, true));
    }

    function _heartbeat(uint64 ts) internal {
        deliver(Messages.heartbeat(seq++, 900, ts, keccak256("root")));
    }
}

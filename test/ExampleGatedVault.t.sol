// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {BridgeMessageCodec} from "../src/lib/BridgeMessageCodec.sol";
import {ExampleGatedVault} from "../src/examples/ExampleGatedVault.sol";
import {GateReason, SolidusGate} from "../src/lib/SolidusGate.sol";
import {ISolidusCredentialMirror} from "../src/interfaces/ISolidusCredentialMirror.sol";
import {Messages} from "./helpers/Messages.sol";
import {MirrorFixture} from "./helpers/MirrorFixture.sol";

/// What an integrator actually writes. The vault is four lines of gating on top of an ordinary
/// contract, and the point of the test is that losing a credential closes the door WITHOUT anybody
/// on this chain doing anything.
contract ExampleGatedVaultTest is MirrorFixture {
    bytes32 internal constant ISSUER = keccak256("did:solidus:testnet:verify");
    bytes32 internal constant KYC_L2 = keccak256("KycL2");
    bytes32 internal constant EXPORT_A = keccak256("export-a");

    address internal constant ALICE = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    bytes32 internal constant HOLDER = bytes32(uint256(uint160(ALICE)));

    uint64 internal constant NOW = 1_758_000_000;

    ExampleGatedVault internal vault;
    uint64 internal seq = 1;

    function setUp() public {
        vm.warp(NOW);
        _deployMirror();
        vault = new ExampleGatedVault(ISolidusCredentialMirror(address(mirror)), ISSUER);
        vm.deal(ALICE, 10 ether);
    }

    function test_a_deposit_without_a_credential_is_refused() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                SolidusGate.CredentialRequired.selector, HOLDER, KYC_L2, ISSUER, GateReason.NO_EXPORT
            )
        );
        vm.prank(ALICE);
        vault.deposit{value: 1 ether}();
        assertEq(address(vault).balance, 0);
    }

    function test_a_credentialed_holder_can_deposit_and_withdraw() public {
        _credential(BridgeMessageCodec.STATUS_ACTIVE);
        _heartbeat(NOW);

        vm.prank(ALICE);
        vault.deposit{value: 3 ether}();
        assertEq(vault.balanceOf(ALICE), 3 ether);
        assertEq(address(vault).balance, 3 ether);

        vm.prank(ALICE);
        vault.withdraw(1 ether);
        assertEq(vault.balanceOf(ALICE), 2 ether);
        assertEq(ALICE.balance, 8 ether);
    }

    /// ⚠ WITHDRAWAL IS NOT GATED, AND THAT IS A DESIGN DECISION RATHER THAN AN OVERSIGHT. Gating the
    /// exit would mean a revocation — or our own gateway going quiet — traps somebody's funds in a
    /// contract they can no longer reach. The credential decides who may ENTER.
    function test_withdrawal_still_works_after_the_credential_is_revoked() public {
        _credential(BridgeMessageCodec.STATUS_ACTIVE);
        _heartbeat(NOW);
        vm.prank(ALICE);
        vault.deposit{value: 2 ether}();

        _credential(BridgeMessageCodec.STATUS_REVOKED);

        vm.prank(ALICE);
        vault.withdraw(2 ether);
        assertEq(vault.balanceOf(ALICE), 0);
        assertEq(ALICE.balance, 10 ether);
    }

    function test_revocation_closes_the_gate_with_no_action_on_this_chain() public {
        _credential(BridgeMessageCodec.STATUS_ACTIVE);
        _heartbeat(NOW);
        vm.prank(ALICE);
        vault.deposit{value: 1 ether}();

        _credential(BridgeMessageCodec.STATUS_REVOKED);

        vm.expectRevert(
            abi.encodeWithSelector(
                SolidusGate.CredentialRequired.selector, HOLDER, KYC_L2, ISSUER, GateReason.NOT_ACTIVE
            )
        );
        vm.prank(ALICE);
        vault.deposit{value: 1 ether}();
    }

    /// ⛔ SILENCE MUST CLOSE THE GATE, NOT LEAVE IT OPEN. If our gateway stops delivering, the
    /// destination has no way to learn about a revocation, so the honest answer is to stop trusting
    /// the last thing it heard. A gate that fails open turns an outage into an authorisation bug.
    function test_silence_closes_the_gate_after_maxAge() public {
        _credential(BridgeMessageCodec.STATUS_ACTIVE);
        _heartbeat(NOW);

        vm.warp(NOW + 1 days + 1);
        vm.expectRevert(
            abi.encodeWithSelector(SolidusGate.CredentialRequired.selector, HOLDER, KYC_L2, ISSUER, GateReason.STALE)
        );
        vm.prank(ALICE);
        vault.deposit{value: 1 ether}();
    }

    // ------------------------------------------------------------------ helpers

    function _credential(uint8 status) internal {
        deliver(Messages.credentialStatus(seq++, 900, EXPORT_A, ISSUER, KYC_L2, HOLDER, status, NOW + 3650 days, true));
    }

    function _heartbeat(uint64 ts) internal {
        deliver(Messages.heartbeat(seq++, 900, ts, keccak256("root")));
    }
}

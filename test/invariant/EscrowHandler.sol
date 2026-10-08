// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {GatedUsdcReceiver} from "../../src/GatedUsdcReceiver.sol";
import {IMessageTransmitterV2} from "../../src/interfaces/ICctp.sol";
import {IGatedUsdcReceiver} from "../../src/interfaces/IGatedUsdcReceiver.sol";
import {ISolidusCredentialMirror} from "../../src/interfaces/ISolidusCredentialMirror.sol";
import {BridgeMessageCodec} from "../../src/lib/BridgeMessageCodec.sol";
import {CctpMock, MockUsdc} from "../helpers/CctpMock.sol";
import {Messages} from "../helpers/Messages.sol";
import {MirrorFixture} from "../helpers/MirrorFixture.sol";

/// Drives the receiver through random relays, gate changes, blocklist changes, time, releases and
/// refunds, and keeps the ghost totals the invariants compare against.
///
/// ⚠ REFUND ADDRESSES ARE NEVER BLOCKLISTED. Invariant 4 says a held escrow past its deadline can always
/// be refunded; a blocklisted refund address is the one case Circle's token makes impossible, and it is
/// out of scope for this contract by construction (the design names the recipient, not the refunder).
contract EscrowHandler is MirrorFixture {
    bytes32 internal constant ISSUER = keccak256("did:solidus:testnet:verify");
    bytes32 internal constant KYC_L2 = keccak256("KycL2");

    MockUsdc public usdc;
    CctpMock public cctp;
    GatedUsdcReceiver public receiver;

    address[3] internal recipients = [address(0xA11CE), address(0xB0B), address(0xCA401)];
    address[2] internal refunders = [address(0xFEED1), address(0xFEED2)];

    uint64 internal seq = 1;
    uint256 internal nonce = 1;
    uint256 internal exportRound;

    bytes32[] public hashes;
    mapping(bytes32 => uint256) public exits;
    uint256 public sumEverHeld;
    uint256 public sumReleased;
    uint256 public sumRefunded;
    uint256 public refundLivenessFailures;
    uint256 public paidWhilePaused;

    constructor() {
        vm.warp(1_758_000_000);
        _deployMirror();
        usdc = new MockUsdc();
        cctp = new CctpMock(usdc);
        usdc.setMinter(address(cctp));
        GatedUsdcReceiver impl = new GatedUsdcReceiver(
            IMessageTransmitterV2(address(cctp)), IERC20(address(usdc)), ISolidusCredentialMirror(address(mirror))
        );
        receiver = GatedUsdcReceiver(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(GatedUsdcReceiver.initialize, (address(this)))))
        );
        deliver(Messages.heartbeat(seq++, 900, uint64(block.timestamp), keccak256("root")));
    }

    function hashCount() external view returns (uint256) {
        return hashes.length;
    }

    // ------------------------------------------------------------------ actions

    function relay(uint256 who, uint256 refunder, uint256 amount, uint256 fee, uint256 life) external {
        amount = bound(amount, 1, 1_000_000e6);
        fee = bound(fee, 0, amount - 1);
        uint64 deadline = uint64(block.timestamp + bound(life, 0, 10 days));
        address to = recipients[who % 3];
        bytes memory hook = abi.encodePacked(
            uint8(1), _h(to), KYC_L2, ISSUER, _h(refunders[refunder % 2]), deadline, bytes8(0)
        );
        bool wasPaused = receiver.paused();
        uint256 before = usdc.balanceOf(to);
        bytes32 h = receiver.relay(_message(hook, amount, fee), hex"01");
        if (wasPaused && usdc.balanceOf(to) != before) paidWhilePaused++;
        IGatedUsdcReceiver.Escrow memory e = receiver.escrowOf(h);
        if (e.state == 1) {
            hashes.push(h);
            sumEverHeld += e.amount;
        }
    }

    function setCredential(uint256 who, bool active) external {
        deliver(
            Messages.credentialStatus(
                seq++,
                900,
                keccak256(abi.encode("export", who % 3, exportRound++)),
                ISSUER,
                KYC_L2,
                _h(recipients[who % 3]),
                active ? BridgeMessageCodec.STATUS_ACTIVE : BridgeMessageCodec.STATUS_REVOKED,
                uint64(block.timestamp + 3650 days),
                true
            )
        );
    }

    function setBlocked(uint256 who, bool blocked) external {
        usdc.setBlocked(recipients[who % 3], blocked);
    }

    function passTime(uint256 secs) external {
        vm.warp(block.timestamp + bound(secs, 0, 3 days));
        deliver(Messages.heartbeat(seq++, 900, uint64(block.timestamp), keccak256("root")));
    }

    /// The handler is the owner, so it can both pause and unpause.
    function setPaused(bool on) external {
        if (on) receiver.pause();
        else receiver.unpause();
    }

    function release(uint256 i) external {
        if (hashes.length == 0) return;
        bytes32 h = hashes[i % hashes.length];
        uint256 amount = receiver.escrowOf(h).amount;
        bool wasPaused = receiver.paused();
        try receiver.release(h) {
            exits[h]++;
            sumReleased += amount;
            if (wasPaused) paidWhilePaused++;
        } catch {}
    }

    function refund(uint256 i) external {
        if (hashes.length == 0) return;
        bytes32 h = hashes[i % hashes.length];
        IGatedUsdcReceiver.Escrow memory e = receiver.escrowOf(h);
        bool mustSucceed = e.state == 1 && block.timestamp > e.deadline;
        try receiver.refund(h) {
            exits[h]++;
            sumRefunded += e.amount;
        } catch {
            if (mustSucceed) refundLivenessFailures++;
        }
    }

    // ------------------------------------------------------------------ helpers

    function _h(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _message(bytes memory hook, uint256 amount, uint256 fee) internal returns (bytes memory) {
        bytes memory body = abi.encodePacked(
            uint32(1), _h(address(0xBEEF)), _h(address(receiver)), amount, _h(address(0xA11CE)), fee, fee, uint256(0), hook
        );
        return abi.encodePacked(
            uint32(1), uint32(0), uint32(1), bytes32(nonce++), _h(address(0x5E4D)), _h(address(0x4EC1)),
            _h(address(receiver)), uint32(1000), uint32(1000), body
        );
    }
}

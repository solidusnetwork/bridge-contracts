// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {EscrowHandler} from "./EscrowHandler.sol";

/// The four escrow invariants, over random sequences of relays, gate and blocklist
/// changes, time, releases and refunds.
contract EscrowInvariantsTest is Test {
    EscrowHandler internal handler;

    function setUp() public {
        handler = new EscrowHandler();
        targetContract(address(handler));
    }

    /// 1. The receiver always holds at least what its held escrows promise.
    function invariant_balance_covers_every_held_escrow() public view {
        uint256 held;
        uint256 n = handler.hashCount();
        for (uint256 i; i < n; i++) {
            bytes32 h = handler.hashes(i);
            if (handler.receiver().escrowOf(h).state == 1) held += handler.receiver().escrowOf(h).amount;
        }
        assertGe(handler.usdc().balanceOf(address(handler.receiver())), held);
    }

    /// 2. Nothing leaves that was not held.
    function invariant_paid_out_never_exceeds_ever_held() public view {
        assertLe(handler.sumReleased() + handler.sumRefunded(), handler.sumEverHeld());
    }

    /// 3. An escrow exits at most once, so it is never both released and refunded.
    function invariant_an_escrow_exits_at_most_once() public view {
        uint256 n = handler.hashCount();
        for (uint256 i; i < n; i++) {
            assertLe(handler.exits(handler.hashes(i)), 1);
        }
    }

    /// 4. A held escrow past its deadline can always be refunded.
    /// A paused receiver pays no recipient, by relay or by release.
    function invariant_a_paused_receiver_pays_no_recipient() public view {
        assertEq(handler.paidWhilePaused(), 0);
    }

    function invariant_an_expired_escrow_can_always_be_refunded() public view {
        assertEq(handler.refundLivenessFailures(), 0);
    }
}

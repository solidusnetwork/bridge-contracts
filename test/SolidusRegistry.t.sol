// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ISolidusRegistry} from "../src/interfaces/ISolidusRegistry.sol";
import {SolidusRegistry} from "../src/SolidusRegistry.sol";

/// The registry is twelve lines and one setter. Everything here is about who may call it.
contract SolidusRegistryTest is Test {
    SolidusRegistry internal registry;

    address internal constant TIMELOCK = address(0x71);
    address internal constant STRANGER = address(0xBEEF);
    address internal constant MIRROR_A = address(0xA11CE);
    address internal constant MIRROR_B = address(0xB0B);

    uint32 internal constant SEPOLIA = 11_155_111;

    function setUp() public {
        registry = new SolidusRegistry(TIMELOCK);
    }

    function test_an_unregistered_domain_reads_as_the_zero_address() public view {
        assertEq(registry.mirrorOf(SEPOLIA), address(0));
        assertEq(registry.mirrorOf(0), address(0));
    }

    function test_the_timelock_can_set_a_mirror_and_it_emits() public {
        vm.expectEmit(true, true, true, true, address(registry));
        emit ISolidusRegistry.MirrorSet(SEPOLIA, MIRROR_A);
        vm.prank(TIMELOCK);
        registry.setMirror(SEPOLIA, MIRROR_A);
        assertEq(registry.mirrorOf(SEPOLIA), MIRROR_A);
    }

    function test_nobody_else_can() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, STRANGER));
        vm.prank(STRANGER);
        registry.setMirror(SEPOLIA, MIRROR_A);
        assertEq(registry.mirrorOf(SEPOLIA), address(0));
    }

    /// ⚠ THE WHOLE REPLACEMENT STORY IN ONE TEST. Setting twice keeps the newest, which is how a
    /// mirror is replaced: deploy a fresh immutable one, repoint the domain, and integrators who
    /// read `mirrorOf` follow without changing a line.
    function test_setting_twice_keeps_the_newest() public {
        vm.startPrank(TIMELOCK);
        registry.setMirror(SEPOLIA, MIRROR_A);
        registry.setMirror(SEPOLIA, MIRROR_B);
        vm.stopPrank();
        assertEq(registry.mirrorOf(SEPOLIA), MIRROR_B);
    }

    function test_domains_do_not_collide() public {
        vm.startPrank(TIMELOCK);
        registry.setMirror(SEPOLIA, MIRROR_A);
        registry.setMirror(43_113, MIRROR_B);
        vm.stopPrank();
        assertEq(registry.mirrorOf(SEPOLIA), MIRROR_A);
        assertEq(registry.mirrorOf(43_113), MIRROR_B);
    }
}

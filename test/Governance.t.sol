// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ISolidusCredentialMirror} from "../src/interfaces/ISolidusCredentialMirror.sol";
import {SolidusRegistry} from "../src/SolidusRegistry.sol";
import {MirrorFixture} from "./helpers/MirrorFixture.sol";

/// What an attacker who captures the Safe can and cannot do. The answer the design wants is: they
/// can point NEW integrators at a different contract, after 48 hours, in public — and they cannot
/// touch a single credential already written.
contract GovernanceTest is MirrorFixture {
    TimelockController internal timelock;
    SolidusRegistry internal registry;

    address internal constant PROPOSER = address(0x9401);
    uint256 internal constant MIN_DELAY = 2 days;

    function setUp() public {
        _deployMirror();

        address[] memory proposers = new address[](1);
        proposers[0] = PROPOSER;
        address[] memory executors = new address[](1);
        executors[0] = address(0); // anyone may execute once the delay has passed

        // ⚠ THE ZERO ADMIN IS THE POINT. Passing a real admin here leaves an account that can grant
        // itself the proposer role and bypass the delay entirely, which would make the timelock
        // decorative.
        timelock = new TimelockController(MIN_DELAY, proposers, executors, address(0));
        registry = new SolidusRegistry(address(timelock));
    }

    /// ⚠ "NO ADMIN" MEANS NO **EXTERNAL** ADMIN, AND THE DIFFERENCE IS NOT PEDANTRY. OpenZeppelin 5
    /// always grants `DEFAULT_ADMIN_ROLE` to the timelock ITSELF — measured here, not assumed, after
    /// this test first asserted otherwise and failed. That is correct and is what the zero admin
    /// argument buys: role changes are still possible, but only as a proposal that waits out the
    /// same delay in public. An external admin could grant itself proposer and skip the delay
    /// entirely, which would make the timelock decorative.
    function test_the_timelock_has_no_external_admin() public view {
        bytes32 admin = timelock.DEFAULT_ADMIN_ROLE();
        assertFalse(timelock.hasRole(admin, address(this)), "the deployer must not keep admin");
        assertFalse(timelock.hasRole(admin, PROPOSER), "a proposer is not an admin");
        assertTrue(timelock.hasRole(admin, address(timelock)), "it administers itself, through its own delay");
    }

    function test_setMirror_before_the_delay_reverts_and_after_it_applies() public {
        bytes memory data = abi.encodeCall(SolidusRegistry.setMirror, (LOCAL_DOMAIN, address(mirror)));

        vm.prank(PROPOSER);
        timelock.schedule(address(registry), 0, data, bytes32(0), bytes32(0), MIN_DELAY);

        // One second short of the delay.
        vm.warp(block.timestamp + MIN_DELAY - 1);
        vm.expectRevert();
        timelock.execute(address(registry), 0, data, bytes32(0), bytes32(0));
        assertEq(registry.mirrorOf(LOCAL_DOMAIN), address(0), "nothing applied early");

        vm.warp(block.timestamp + 1);
        timelock.execute(address(registry), 0, data, bytes32(0), bytes32(0));
        assertEq(registry.mirrorOf(LOCAL_DOMAIN), address(mirror));
    }

    function test_scheduling_below_the_minimum_delay_is_refused() public {
        bytes memory data = abi.encodeCall(SolidusRegistry.setMirror, (LOCAL_DOMAIN, address(mirror)));
        vm.expectRevert();
        vm.prank(PROPOSER);
        timelock.schedule(address(registry), 0, data, bytes32(0), bytes32(0), MIN_DELAY - 1);
    }

    /// ⛔ THE MIRROR HAS NO FUNCTION THE TIMELOCK CAN CALL, and that is the bound on a captured
    /// Safe. Governance can repoint the registry so NEW integrators resolve elsewhere; it cannot
    /// rewrite a credential, pause delivery, or change a validator set. Anyone holding the mirror's
    /// address directly is unaffected by the capture entirely.
    function test_governance_cannot_reach_into_the_mirror() public {
        string[6] memory attempts = [
            "owner()",
            "transferOwnership(address)",
            "upgradeTo(address)",
            "upgradeToAndCall(address,bytes)",
            "initialize()",
            "pause()"
        ];
        for (uint256 i; i < attempts.length; i++) {
            vm.prank(address(timelock));
            (bool found,) = address(mirror).call(abi.encodeWithSignature(attempts[i], address(timelock)));
            assertFalse(found, attempts[i]);
        }

        // And the credential it already holds is untouched by any of that.
        assertEq(mirror.nextDomainSeq(), START_SEQ);
        assertEq(mirror.threshold(), 3);
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// Does the project reach the two things every later task needs: the vectors on disk, and
/// OpenZeppelin 5? Neither is a contract behaviour, which is why they are asserted once here and
/// never again. `fs_permissions` is the part that fails silently otherwise: a read outside the
/// allowed path reverts inside the cheatcode, and the test that needed the vector looks like a
/// decoding bug.
contract ToolchainTest is Test {
    function test_vectors_are_readable_from_the_project() public view {
        string memory dir = string.concat(vm.projectRoot(), "/test-fixtures/bridge/");
        assertEq(vm.parseJsonUint(vm.readFile(string.concat(dir, "messages-v1.json")), ".version"), 1);
        assertEq(vm.parseJsonUint(vm.readFile(string.concat(dir, "ids-v1.json")), ".version"), 1);
        assertEq(vm.parseJsonUint(vm.readFile(string.concat(dir, "attestation-v2.json")), ".version"), 1);
    }

    function test_openzeppelin_major_version_is_5() public pure {
        assertTrue(TimelockController.getOperationState.selector != bytes4(0));
    }
}

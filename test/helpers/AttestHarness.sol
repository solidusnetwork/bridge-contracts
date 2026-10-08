// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {AttestationLib} from "../../src/lib/AttestationLib.sol";

/// `verify` takes a `mapping storage`, which only a contract can own, and `bytes calldata`, which a
/// test cannot produce from memory. This holds both.
contract AttestHarness {
    mapping(address => bool) public isValidator;

    constructor(address[] memory validators) {
        for (uint256 i; i < validators.length; i++) {
            isValidator[validators[i]] = true;
        }
    }

    function digest(
        uint64 solidusChainId,
        uint32 destinationDomain,
        uint64 domainSeq,
        bytes32 messageId,
        uint64 solidusHeight
    ) external pure returns (bytes32) {
        return AttestationLib.digest(solidusChainId, destinationDomain, domainSeq, messageId, solidusHeight);
    }

    function ethSigned(bytes32 d) external pure returns (bytes32) {
        return AttestationLib.ethSigned(d);
    }

    function verify(bytes32 d, bytes calldata signatures, uint8 threshold) external view {
        AttestationLib.verify(d, signatures, isValidator, threshold);
    }
}

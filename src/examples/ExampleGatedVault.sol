// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ISolidusCredentialMirror} from "../interfaces/ISolidusCredentialMirror.sol";
import {SolidusGated} from "../SolidusGated.sol";

/// @title ExampleGatedVault
/// @notice The smallest honest integration: a vault only a KYC-L2 holder may enter.
///
/// ⚠ DEPOSIT IS GATED AND WITHDRAWAL IS NOT, WHICH IS THE WHOLE LESSON OF THIS EXAMPLE. Gating the
/// exit would mean a revocation — or our own gateway going quiet for longer than `maxAge` — traps
/// somebody's funds in a contract they can no longer reach. A credential decides who may ENTER.
///
/// It is an example. It is not audited, it is not deployed to mainnet, and phase 1 deploys it only
/// so the end-to-end flow has something real on the far side.
contract ExampleGatedVault is SolidusGated {
    bytes32 public constant KYC_L2 = keccak256("KycL2");
    uint64 public constant MAX_AGE = 1 days;

    bytes32 public immutable issuerDidHash;
    mapping(address => uint256) public balanceOf;

    error InsufficientBalance(uint256 have, uint256 want);
    error TransferFailed();

    constructor(ISolidusCredentialMirror mirror_, bytes32 issuerDidHash_) SolidusGated(mirror_) {
        issuerDidHash = issuerDidHash_;
    }

    function deposit() external payable onlyCredentialed(KYC_L2, issuerDidHash, MAX_AGE) {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        uint256 balance = balanceOf[msg.sender];
        if (amount > balance) revert InsufficientBalance(balance, amount);
        balanceOf[msg.sender] = balance - amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }
}

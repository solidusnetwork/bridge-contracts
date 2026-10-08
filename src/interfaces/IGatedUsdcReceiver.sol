// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice The interface of the gated USDC receiver.
interface IGatedUsdcReceiver {
    struct Escrow {
        bytes32 finalRecipient;
        bytes32 refundAddress;
        uint256 amount;
        uint64 deadline;
        bytes32 credentialTypeHash;
        bytes32 issuerDidHash;
        bytes8 referralCode;
        uint8 state; // 1 held, 2 released, 3 refunded
    }

    function relay(bytes calldata message, bytes calldata attestation) external returns (bytes32 hash);
    function release(bytes32 hash) external;
    function refund(bytes32 hash) external;
    function escrowOf(bytes32 hash) external view returns (Escrow memory);

    event UsdcDelivered(bytes32 indexed hash, address indexed recipient, uint256 amount, uint256 fee, bytes8 referralCode);
    event UsdcEscrowed(bytes32 indexed hash, bytes32 indexed finalRecipient, uint256 amount, uint8 reason, uint64 deadline);
    event UsdcReleased(bytes32 indexed hash, address indexed recipient, uint256 amount);
    event UsdcRefunded(bytes32 indexed hash, address indexed refundAddress, uint256 amount);

    error NotHeld(bytes32 hash);
    error DeadlinePassed(bytes32 hash);
    error DeadlineNotPassed(bytes32 hash);
    error GateStillFails(bytes32 hash, uint8 reason);
}

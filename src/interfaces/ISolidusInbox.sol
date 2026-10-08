// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice Anyone may deliver. There is no privileged caller, because the signatures are the
///         authority and not the sender.
///
/// ⚠ THAT IS A LIVENESS PROPERTY, NOT A CONVENIENCE. If only our gateway could submit, our gateway
/// going down would stop every destination. Anyone can fetch the signatures from a public RPC and
/// pay the gas, so a stalled script delays a message and cannot forge or block one.
interface ISolidusInbox {
    /// @param message the message body, exactly as the chain queued it
    /// @param signatures N x 65 bytes, r‖s‖v, ordered by ASCENDING signer address (the order IS the
    ///        duplicate check: each recovered address must be strictly greater than the previous)
    function submit(bytes calldata message, bytes calldata signatures) external;

    function validators() external view returns (address[] memory);
    function threshold() external view returns (uint8);
    function attestationDigest(bytes calldata message) external view returns (bytes32);

    error NotEnoughSignatures(uint256 got, uint256 need);
    error UnknownSigner(address signer);
    error SignersOutOfOrder(address previous, address next);
    error BadSignatureLength(uint256 length);
}

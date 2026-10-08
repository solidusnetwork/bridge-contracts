// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice The one Circle CCTP v2 call the receiver makes, as read from Circle's CCTP v2 documentation and the
/// `circlefin/evm-cctp-contracts` v2 source.
/// The same address on Sepolia, Fuji and Arc: `0xE737e5cEBEEBa77EFE34D4aa090756590b1CE275`.
interface IMessageTransmitterV2 {
    /// Marks the message's nonce used and mints to `mintRecipient` (minus the executed fee). When the
    /// message names a `destinationCaller`, only that address may call this.
    function receiveMessage(bytes calldata message, bytes calldata attestation) external returns (bool success);
}

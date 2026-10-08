// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {BridgeMessageCodec} from "../../src/lib/BridgeMessageCodec.sol";

/// ⚠ THE HARNESS IS NOT CEREMONY. The library reads `bytes calldata`, and a test cannot hand a
/// `memory` value to a `calldata` parameter; the decoders also have to be reached through a real
/// call for `expectRevert` to see their custom errors at all. An internal library call that reverts
/// inside the test contract unwinds the test itself.
contract CodecHarness {
    function header(bytes calldata body) external pure returns (BridgeMessageCodec.Header memory) {
        return BridgeMessageCodec.header(body);
    }

    function credentialStatus(bytes calldata body) external pure returns (BridgeMessageCodec.CredentialStatus memory) {
        return BridgeMessageCodec.credentialStatus(body);
    }

    function issuerStatus(bytes calldata body) external pure returns (BridgeMessageCodec.IssuerStatus memory) {
        return BridgeMessageCodec.issuerStatus(body);
    }

    function token(bytes calldata body) external pure returns (BridgeMessageCodec.Token memory) {
        return BridgeMessageCodec.token(body);
    }

    function encodeToken(BridgeMessageCodec.Token memory t) external pure returns (bytes memory) {
        return BridgeMessageCodec.encodeToken(t);
    }

    function heartbeat(bytes calldata body) external pure returns (BridgeMessageCodec.Heartbeat memory) {
        return BridgeMessageCodec.heartbeat(body);
    }

    function exportId(string calldata credentialId, uint32 domain, bytes32 holder) external pure returns (bytes32) {
        return BridgeMessageCodec.exportId(credentialId, domain, holder);
    }

    function gateKey(bytes32 holder, bytes32 credentialTypeHash, bytes32 issuerDidHash)
        external
        pure
        returns (bytes32)
    {
        return BridgeMessageCodec.gateKey(holder, credentialTypeHash, issuerDidHash);
    }

    function usdcHook(bytes calldata h) external pure returns (BridgeMessageCodec.UsdcHook memory) {
        return BridgeMessageCodec.usdcHook(h);
    }
}

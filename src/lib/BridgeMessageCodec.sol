// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @title BridgeMessageCodec
/// @notice Decodes the status message body exactly as the Solidus chain queued it, and derives the two
///         identifiers a mirror stores records under.
///
/// ⛔ THE LAYOUT IS PINNED BY `test-fixtures/bridge/messages-v1.json`, NOT BY THIS COMMENT. Both sides
/// are generated against the same file; a layout re-derived from prose agrees with the other side
/// until the prose is ambiguous, and then it disagrees on a live chain where the only symptom is a
/// credential that reads as absent.
///
/// All integers are big-endian, which is what `calldataload` gives for free: a 32-byte word read at
/// the field's offset holds the value in its HIGH bytes, so a right shift by (32 - width) * 8 is the
/// whole decode. No `abi.decode`, because the body is packed and has no 32-byte alignment.
///
/// | kind | layout |
/// |---|---|
/// | header (18) | `version u8 ‖ kind u8 ‖ domainSeq u64 ‖ solidusHeight u64` |
/// | credential status (156) | header ‖ `exportId 32 ‖ issuerDidHash 32 ‖ credentialTypeHash 32 ‖ holder 32 ‖ status u8 ‖ validUntil u64 ‖ issuerAccredited u8` |
/// | issuer status (51) | header ‖ `issuerDidHash 32 ‖ accredited u8` |
/// | heartbeat (58) | header ‖ `solidusTimestamp u64 ‖ globalRoot 32` |
library BridgeMessageCodec {
    uint8 internal constant VERSION = 1;
    uint8 internal constant KIND_CREDENTIAL_STATUS = 0x01;
    uint8 internal constant KIND_ISSUER_STATUS = 0x02;
    uint8 internal constant KIND_HEARTBEAT = 0x03;
    /// Phase 4, the SLDS TOKEN channel. ⛔ `header()` still REFUSES it: the mirror dispatches anything that
    /// is not a credential or issuer message as a heartbeat, so a token message must never pass `header()`.
    /// Token messages are read only through `token()`, on the route adapter.
    uint8 internal constant KIND_TOKEN = 0x04;
    uint256 internal constant TOKEN_LEN = 18 + 97;

    uint8 internal constant STATUS_ACTIVE = 1;
    uint8 internal constant STATUS_REVOKED = 2;
    uint8 internal constant STATUS_EXPIRED = 3;
    uint8 internal constant STATUS_UNBOUND = 4;

    uint256 internal constant HEADER_LEN = 18;
    uint256 internal constant CREDENTIAL_STATUS_LEN = 156;
    uint256 internal constant ISSUER_STATUS_LEN = 51;
    uint256 internal constant HEARTBEAT_LEN = 58;

    struct Header {
        uint8 version;
        uint8 kind;
        uint64 domainSeq;
        uint64 solidusHeight;
    }

    struct CredentialStatus {
        bytes32 exportId;
        bytes32 issuerDidHash;
        bytes32 credentialTypeHash;
        bytes32 holder;
        uint8 status;
        uint64 validUntil;
        bool issuerAccredited;
    }

    struct IssuerStatus {
        bytes32 issuerDidHash;
        bool accredited;
    }

    struct Heartbeat {
        uint64 solidusTimestamp;
        bytes32 globalRoot;
    }

    /// `UsdcHookData`, the hook a gated USDC burn carries (phase 3).
    struct UsdcHook {
        bytes32 finalRecipient;
        bytes32 credentialTypeHash;
        bytes32 issuerDidHash;
        bytes32 refundAddress;
        uint64 deadline;
        bytes8 referralCode;
    }

    uint8 internal constant USDC_HOOK_VERSION = 1;
    uint256 internal constant USDC_HOOK_LEN = 145;

    error BadVersion(uint8 version);
    error UnknownKind(uint8 kind);
    error BadLength(uint256 expected, uint256 got);
    error BadStatus(uint8 status);
    error BadBool(uint8 value);

    // ------------------------------------------------------------------ header

    function header(bytes calldata body) internal pure returns (Header memory h) {
        if (body.length < HEADER_LEN) revert BadLength(HEADER_LEN, body.length);
        h.version = uint8(body[0]);
        if (h.version != VERSION) revert BadVersion(h.version);
        h.kind = uint8(body[1]);
        if (h.kind != KIND_CREDENTIAL_STATUS && h.kind != KIND_ISSUER_STATUS && h.kind != KIND_HEARTBEAT) {
            revert UnknownKind(h.kind);
        }
        h.domainSeq = _u64(body, 2);
        h.solidusHeight = _u64(body, 10);
    }

    /// recipient (32) ‖ amount u128 BE (16) ‖ TransferMeta (49: version ‖ transferId ‖ referral ‖ deadline).
    struct Token {
        uint64 seq;
        uint64 solidusHeight;
        bytes32 recipient;
        uint128 amount;
        bytes32 transferId;
        bytes8 referralCode;
        uint64 deadline;
    }

    error BadMetaVersion(uint8 version);

    function token(bytes calldata body) internal pure returns (Token memory t) {
        _expect(body, KIND_TOKEN, TOKEN_LEN);
        t.seq = _u64(body, 2);
        t.solidusHeight = _u64(body, 10);
        t.recipient = bytes32(body[18:50]);
        t.amount = uint128(bytes16(body[50:66]));
        if (uint8(body[66]) != 1) revert BadMetaVersion(uint8(body[66]));
        t.transferId = bytes32(body[67:99]);
        t.referralCode = bytes8(body[99:107]);
        t.deadline = _u64(body, 107);
    }

    /// The bytes the chain's `encode(BridgeMessage::token(..))` produces, for a Solidus-bound message.
    function encodeToken(Token memory t) internal pure returns (bytes memory) {
        return abi.encodePacked(
            VERSION,
            KIND_TOKEN,
            t.seq,
            t.solidusHeight,
            t.recipient,
            t.amount,
            uint8(1),
            t.transferId,
            t.referralCode,
            t.deadline
        );
    }

    // ------------------------------------------------------------------ bodies

    function credentialStatus(bytes calldata body) internal pure returns (CredentialStatus memory c) {
        _expect(body, KIND_CREDENTIAL_STATUS, CREDENTIAL_STATUS_LEN);
        c.exportId = bytes32(body[18:50]);
        c.issuerDidHash = bytes32(body[50:82]);
        c.credentialTypeHash = bytes32(body[82:114]);
        c.holder = bytes32(body[114:146]);
        c.status = uint8(body[146]);
        if (c.status < STATUS_ACTIVE || c.status > STATUS_UNBOUND) revert BadStatus(c.status);
        c.validUntil = _u64(body, 147);
        c.issuerAccredited = _bool(uint8(body[155]));
    }

    function issuerStatus(bytes calldata body) internal pure returns (IssuerStatus memory s) {
        _expect(body, KIND_ISSUER_STATUS, ISSUER_STATUS_LEN);
        s.issuerDidHash = bytes32(body[18:50]);
        s.accredited = _bool(uint8(body[50]));
    }

    function heartbeat(bytes calldata body) internal pure returns (Heartbeat memory b) {
        _expect(body, KIND_HEARTBEAT, HEARTBEAT_LEN);
        b.solidusTimestamp = _u64(body, 18);
        b.globalRoot = bytes32(body[26:58]);
    }

    // ------------------------------------------------------------------ ids

    /// keccak256(credentialId utf8 ‖ domain u32 BE ‖ holder)
    function exportId(string calldata credentialId, uint32 domain, bytes32 holder) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(credentialId, domain, holder));
    }

    /// keccak256(holder ‖ credentialTypeHash ‖ issuerDidHash)
    function gateKey(bytes32 holder, bytes32 credentialTypeHash, bytes32 issuerDidHash)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(holder, credentialTypeHash, issuerDidHash));
    }

    /// version u8 ‖ finalRecipient ‖ credentialTypeHash ‖ issuerDidHash ‖ refundAddress ‖ deadline u64 BE
    /// ‖ referralCode, 145 bytes. Pinned by `test-fixtures/bridge/usdc-hook-v1.json`.
    /// ⚠ LENGTH BEFORE VERSION: a hook shorter than one byte has no version to report.
    function usdcHook(bytes calldata h) internal pure returns (UsdcHook memory u) {
        if (h.length != USDC_HOOK_LEN) revert BadLength(USDC_HOOK_LEN, h.length);
        uint8 version = uint8(h[0]);
        if (version != USDC_HOOK_VERSION) revert BadVersion(version);
        u.finalRecipient = bytes32(h[1:33]);
        u.credentialTypeHash = bytes32(h[33:65]);
        u.issuerDidHash = bytes32(h[65:97]);
        u.refundAddress = bytes32(h[97:129]);
        u.deadline = _u64(h, 129);
        u.referralCode = bytes8(h[137:145]);
    }

    // ------------------------------------------------------------------ internals

    /// ⚠ THE ORDER OF THESE THREE CHECKS IS LOAD-BEARING, and `BridgeMessageCodec.t.sol` pins it.
    /// Length-before-kind would report an issuer-status body handed to `credentialStatus` as
    /// `BadLength(156, 51)`: true, useless, and it sends whoever reads the revert hunting a
    /// truncation that is not there. The minimum-header check comes first only because a body
    /// shorter than 18 bytes has no kind to report.
    function _expect(bytes calldata body, uint8 kind, uint256 length) private pure {
        if (body.length < HEADER_LEN) revert BadLength(length, body.length);
        uint8 version = uint8(body[0]);
        if (version != VERSION) revert BadVersion(version);
        uint8 got = uint8(body[1]);
        if (got != kind) revert UnknownKind(got);
        if (body.length != length) revert BadLength(length, body.length);
    }

    function _u64(bytes calldata body, uint256 offset) private pure returns (uint64 v) {
        // A 32-byte word read at `offset` holds the 8 bytes we want in its high end.
        assembly ("memory-safe") {
            v := shr(192, calldataload(add(body.offset, offset)))
        }
    }

    /// A packed bool is one byte and the chain only ever writes 0 or 1. Anything else is a message
    /// this library did not produce, and guessing which way it meant is how a revoked credential
    /// reads as active.
    function _bool(uint8 value) private pure returns (bool) {
        if (value > 1) revert BadBool(value);
        return value == 1;
    }
}

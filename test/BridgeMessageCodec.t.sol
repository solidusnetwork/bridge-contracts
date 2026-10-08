// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {BridgeMessageCodec} from "../src/lib/BridgeMessageCodec.sol";
import {CodecHarness} from "./helpers/CodecHarness.sol";

/// What the vector file cannot say: that a decoder refuses a body of ANOTHER kind, that one trailing
/// byte is fatal, and that no input at all produces a panic instead of a codec error.
///
/// ⚠ A PANIC IS A DIFFERENT FAILURE FROM A REVERT, AND THE DIFFERENCE MATTERS ON CHAIN. An array
/// bounds panic means the library read past the data it was given and the inbox saw `Panic(0x32)`
/// rather than a named refusal. The fuzz test below exists to make that distinction observable.
contract BridgeMessageCodecTest is Test {
    CodecHarness internal harness;

    // The three well-formed bodies, built here rather than read, so this file stands alone.
    bytes internal credential;
    bytes internal issuer;
    bytes internal beat;

    function setUp() public {
        harness = new CodecHarness();
        credential = abi.encodePacked(
            uint8(1), // version
            uint8(1), // kind
            uint64(7), // domainSeq
            uint64(1234), // solidusHeight
            bytes32(uint256(0x11)), // exportId
            bytes32(uint256(0x22)), // issuerDidHash
            bytes32(uint256(0x33)), // credentialTypeHash
            bytes32(uint256(0x44)), // holder
            uint8(1), // status = ACTIVE
            uint64(1900000000), // validUntil
            uint8(1) // issuerAccredited
        );
        issuer = abi.encodePacked(uint8(1), uint8(2), uint64(2), uint64(1235), bytes32(uint256(0x99)), uint8(0));
        beat = abi.encodePacked(uint8(1), uint8(3), uint64(4), uint64(0), uint64(1758000000), bytes32(uint256(0xab)));
    }

    function test_the_three_lengths_are_what_the_registry_says() public view {
        assertEq(credential.length, BridgeMessageCodec.CREDENTIAL_STATUS_LEN);
        assertEq(issuer.length, BridgeMessageCodec.ISSUER_STATUS_LEN);
        assertEq(beat.length, BridgeMessageCodec.HEARTBEAT_LEN);
        assertEq(BridgeMessageCodec.CREDENTIAL_STATUS_LEN, 156);
        assertEq(BridgeMessageCodec.ISSUER_STATUS_LEN, 51);
        assertEq(BridgeMessageCodec.HEARTBEAT_LEN, 58);
        assertEq(BridgeMessageCodec.HEADER_LEN, 18);
    }

    // ------------------------------------------------- a decoder refuses another kind

    function test_credentialStatus_refuses_an_issuer_status_body() public {
        vm.expectRevert(
            abi.encodeWithSelector(BridgeMessageCodec.UnknownKind.selector, BridgeMessageCodec.KIND_ISSUER_STATUS)
        );
        harness.credentialStatus(issuer);
    }

    function test_issuerStatus_refuses_a_heartbeat_body() public {
        vm.expectRevert(
            abi.encodeWithSelector(BridgeMessageCodec.UnknownKind.selector, BridgeMessageCodec.KIND_HEARTBEAT)
        );
        harness.issuerStatus(beat);
    }

    function test_heartbeat_refuses_a_credential_status_body() public {
        vm.expectRevert(
            abi.encodeWithSelector(BridgeMessageCodec.UnknownKind.selector, BridgeMessageCodec.KIND_CREDENTIAL_STATUS)
        );
        harness.heartbeat(credential);
    }

    /// ⚠ THE KIND IS CHECKED BEFORE THE LENGTH, and this test is what pins that order. The other way
    /// round, an issuer-status body handed to `credentialStatus` reports `BadLength(156, 51)` — true,
    /// useless, and it sends whoever reads the revert looking for a truncation that is not there.
    function test_the_wrong_kind_is_reported_as_a_kind_error_not_a_length_error() public {
        vm.expectPartialRevert(BridgeMessageCodec.UnknownKind.selector);
        harness.credentialStatus(issuer);
    }

    // ------------------------------------------------- trailing bytes

    function test_one_trailing_byte_on_a_heartbeat_reverts_BadLength_58_59() public {
        bytes memory tooLong = abi.encodePacked(beat, uint8(0));
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadLength.selector, uint256(58), uint256(59)));
        harness.heartbeat(tooLong);
    }

    function test_one_missing_byte_on_a_credential_status_reverts_BadLength_156_155() public {
        bytes memory tooShort = new bytes(155);
        for (uint256 i = 0; i < 155; i++) {
            tooShort[i] = credential[i];
        }
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadLength.selector, uint256(156), uint256(155)));
        harness.credentialStatus(tooShort);
    }

    /// Shorter than a header is the case where a careless implementation reads past its input.
    function test_a_body_shorter_than_the_header_reverts_BadLength_not_a_panic() public {
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadLength.selector, uint256(156), uint256(3)));
        harness.credentialStatus(hex"010100");
    }

    function test_an_empty_body_reverts_BadLength() public {
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadLength.selector, uint256(156), uint256(0)));
        harness.credentialStatus("");
    }

    // ------------------------------------------------- header

    function test_header_reads_every_kind() public view {
        assertEq(harness.header(credential).kind, BridgeMessageCodec.KIND_CREDENTIAL_STATUS);
        assertEq(harness.header(issuer).kind, BridgeMessageCodec.KIND_ISSUER_STATUS);
        assertEq(harness.header(beat).kind, BridgeMessageCodec.KIND_HEARTBEAT);
        assertEq(harness.header(credential).domainSeq, 7);
        assertEq(harness.header(issuer).solidusHeight, 1235);
    }

    function test_header_refuses_a_kind_no_decoder_claims() public {
        bytes memory unknown = credential;
        unknown[1] = bytes1(uint8(9));
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.UnknownKind.selector, uint8(9)));
        harness.header(unknown);
    }

    function test_header_refuses_a_future_version() public {
        bytes memory v2 = credential;
        v2[0] = bytes1(uint8(2));
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadVersion.selector, uint8(2)));
        harness.header(v2);
    }

    // ------------------------------------------------- enumerations

    function test_status_zero_and_five_are_both_refused() public {
        bytes memory zero = credential;
        zero[146] = bytes1(uint8(0));
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadStatus.selector, uint8(0)));
        harness.credentialStatus(zero);

        bytes memory five = credential;
        five[146] = bytes1(uint8(5));
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadStatus.selector, uint8(5)));
        harness.credentialStatus(five);
    }

    function test_every_defined_status_is_accepted() public view {
        for (uint8 s = BridgeMessageCodec.STATUS_ACTIVE; s <= BridgeMessageCodec.STATUS_UNBOUND; s++) {
            bytes memory b = credential;
            b[146] = bytes1(s);
            assertEq(harness.credentialStatus(b).status, s);
        }
    }

    function test_a_bool_that_is_not_zero_or_one_is_refused() public {
        bytes memory b = credential;
        b[155] = bytes1(uint8(2));
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadBool.selector, uint8(2)));
        harness.credentialStatus(b);

        bytes memory s = issuer;
        s[50] = bytes1(uint8(0xff));
        vm.expectRevert(abi.encodeWithSelector(BridgeMessageCodec.BadBool.selector, uint8(0xff)));
        harness.issuerStatus(s);
    }

    // ------------------------------------------------- fuzz

    /// ⛔ EVERY FAILURE MUST BE A CODEC ERROR, NEVER A PANIC. `Panic(0x32)` — array out of bounds —
    /// is the signature of a decoder that read past its input, and on an inbox it is indistinguishable
    /// from a bug in the caller. This is the assertion that says the library never does that,
    /// whatever it is handed.
    function testFuzz_decoding_never_accepts_a_wrong_length(bytes calldata raw) public view {
        try harness.credentialStatus(raw) returns (BridgeMessageCodec.CredentialStatus memory) {
            assertEq(raw.length, BridgeMessageCodec.CREDENTIAL_STATUS_LEN, "accepted a body of the wrong length");
        } catch (bytes memory err) {
            assertGe(err.length, 4, "an empty revert tells the caller nothing");
            // casting to 'bytes4' is safe because the selector IS the first four bytes of revert
            // data, and the line above proved there are at least four.
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 sel = bytes4(err);
            assertTrue(
                sel == BridgeMessageCodec.BadLength.selector || sel == BridgeMessageCodec.BadVersion.selector
                    || sel == BridgeMessageCodec.UnknownKind.selector || sel == BridgeMessageCodec.BadStatus.selector
                    || sel == BridgeMessageCodec.BadBool.selector,
                "failed with something that is not a codec error (a panic reads as 0x4e487b71)"
            );
        }
    }

    function testFuzz_a_wrong_length_is_never_a_heartbeat(bytes calldata raw) public view {
        vm.assume(raw.length != BridgeMessageCodec.HEARTBEAT_LEN);
        try harness.heartbeat(raw) returns (BridgeMessageCodec.Heartbeat memory) {
            revert("accepted a heartbeat of the wrong length");
        } catch (bytes memory err) {
            assertGe(err.length, 4);
            // casting to 'bytes4' is safe because the selector IS the first four bytes of revert
            // data, and the line above proved there are at least four.
            // forge-lint: disable-next-line(unsafe-typecast)
            bytes4 sel = bytes4(err);
            assertTrue(
                sel == BridgeMessageCodec.BadLength.selector || sel == BridgeMessageCodec.BadVersion.selector
                    || sel == BridgeMessageCodec.UnknownKind.selector
            );
        }
    }
}

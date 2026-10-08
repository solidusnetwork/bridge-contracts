// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {AttestationLib} from "../src/lib/AttestationLib.sol";
import {AttestHarness} from "./helpers/AttestHarness.sol";

/// The signature check is the whole security of the transport in phase 1: a mirror applies whatever
/// enough validators signed, so every way of faking "enough" has to be closed here.
///
/// ⛔ TWO OF THESE ARE THE ATTACKS AND THE REST ARE HYGIENE. Signing the same digest twice is how
/// one stolen key pads a 2-of-4 into a pass, and a signature over another chain's digest is how a
/// Sepolia message gets replayed on Fuji. Both are closed by things that look like bookkeeping —
/// ascending signer order, and the destination domain inside the digest — which is exactly why they
/// need a test that says what they are for.
contract AttestationLibTest is Test {
    AttestHarness internal harness;

    // Anvil accounts 0 to 3. Published test keys: they hold nothing, anywhere, ever.
    uint256 internal constant K0 = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 internal constant K1 = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 internal constant K2 = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 internal constant K3 = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;
    /// Not a validator anywhere. Anvil account 9.
    uint256 internal constant K_STRANGER = 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6;

    /// secp256k1 group order, for flipping a signature into its high-s twin.
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint64 internal constant CHAIN_ID = 50_002;
    uint32 internal constant SEPOLIA = 11_155_111;
    uint32 internal constant FUJI = 43_113;

    /// Sorted ascending by address, because ascending order is what `verify` requires.
    uint256[4] internal keys;

    string internal vectors;

    function setUp() public {
        uint256[4] memory k = [K0, K1, K2, K3];
        // Insertion sort by derived address. Four elements; clarity beats cleverness.
        for (uint256 i = 1; i < 4; i++) {
            uint256 cur = k[i];
            uint256 j = i;
            while (j > 0 && vm.addr(k[j - 1]) > vm.addr(cur)) {
                k[j] = k[j - 1];
                j--;
            }
            k[j] = cur;
        }
        keys = k;

        address[] memory validators = new address[](4);
        for (uint256 i; i < 4; i++) {
            validators[i] = vm.addr(keys[i]);
        }
        harness = new AttestHarness(validators);

        vectors = vm.readFile(string.concat(vm.projectRoot(), "/test-fixtures/bridge/attestation-v2.json"));
    }

    // ------------------------------------------------------------------ 1 and 2: the vectors

    function test_the_digest_and_eth_signed_hash_match_the_vectors() public view {
        uint256 seen;
        for (uint256 i = 0; vm.keyExistsJson(vectors, _at(i, "name")); i++) {
            string memory name = vm.parseJsonString(vectors, _at(i, "name"));
            bytes32 got = harness.digest(
                uint64(vm.parseUint(vm.parseJsonString(vectors, _at(i, "chainId")))),
                uint32(vm.parseJsonUint(vectors, _at(i, "domain"))),
                uint64(vm.parseUint(vm.parseJsonString(vectors, _at(i, "domainSeq")))),
                vm.parseJsonBytes32(vectors, _at(i, "messageId")),
                uint64(vm.parseUint(vm.parseJsonString(vectors, _at(i, "solidusHeight"))))
            );
            assertEq(got, vm.parseJsonBytes32(vectors, _at(i, "digest")), name);
            assertEq(harness.ethSigned(got), vm.parseJsonBytes32(vectors, _at(i, "ethSigned")), name);
            seen++;
        }
        assertEq(seen, 4, "attestation-v2.json case count changed");
    }

    /// ⚠ THE HASHES AGREEING IS NOT ENOUGH. Four languages produce this file's signatures and read
    /// them back; a side that frames or orders the 65 bytes differently still computes the same
    /// digest and then recovers a stranger. This is the assertion that catches that.
    function test_every_committed_signature_recovers_to_the_vector_signer() public view {
        uint256 seen;
        for (uint256 i = 0; vm.keyExistsJson(vectors, _at(i, "name")); i++) {
            string memory name = vm.parseJsonString(vectors, _at(i, "name"));
            bytes memory sig = vm.parseJsonBytes(vectors, _at(i, "signature"));
            assertEq(sig.length, 65, name);
            bytes32 ethSigned = vm.parseJsonBytes32(vectors, _at(i, "ethSigned"));

            bytes32 r;
            bytes32 s;
            uint8 v;
            assembly {
                r := mload(add(sig, 32))
                s := mload(add(sig, 64))
                v := byte(0, mload(add(sig, 96)))
            }
            address recovered = ecrecover(ethSigned, v, r, s);
            assertEq(recovered, _toAddress(vm.parseJsonString(vectors, _at(i, "signer"))), name);
            seen++;
        }
        assertEq(seen, 4);
    }

    // ------------------------------------------------------------------ 3: the happy path

    function test_three_configured_validators_with_threshold_two_passes() public view {
        bytes32 d = _digest(SEPOLIA, 1);
        harness.verify(d, _sign(d, 0, 3), 2);
    }

    function test_exactly_the_threshold_passes() public view {
        bytes32 d = _digest(SEPOLIA, 1);
        harness.verify(d, _sign(d, 0, 2), 2);
    }

    // ------------------------------------------------------------------ 4 and 5: order

    /// ⛔ THE PADDING ATTACK. One key that signs twice is two signatures and one validator. Ascending
    /// order IS the duplicate check: a repeat is never strictly greater than itself.
    function test_the_same_validator_signing_twice_reverts_SignersOutOfOrder() public {
        bytes32 d = _digest(SEPOLIA, 1);
        bytes memory one = _sign(d, 0, 1);
        bytes memory twice = bytes.concat(one, one);
        address signer = vm.addr(keys[0]);
        vm.expectRevert(abi.encodeWithSelector(AttestationLib.SignersOutOfOrder.selector, signer, signer));
        harness.verify(d, twice, 2);
    }

    function test_descending_order_reverts_even_though_every_signer_is_configured() public {
        bytes32 d = _digest(SEPOLIA, 1);
        bytes memory a = _sign(d, 0, 1);
        bytes memory b = _sign(d, 1, 1);
        vm.expectRevert(
            abi.encodeWithSelector(AttestationLib.SignersOutOfOrder.selector, vm.addr(keys[1]), vm.addr(keys[0]))
        );
        harness.verify(d, bytes.concat(b, a), 2);
    }

    // ------------------------------------------------------------------ 6 and 7: who signed

    function test_an_unknown_signer_reverts_even_beside_a_configured_one() public {
        bytes32 d = _digest(SEPOLIA, 1);
        bytes memory mine = _sign(d, 0, 1);
        bytes memory theirs = _signWith(K_STRANGER, d);
        // Ordered so the strangeness, not the ordering, is what fails.
        bytes memory both =
            vm.addr(keys[0]) < vm.addr(K_STRANGER) ? bytes.concat(mine, theirs) : bytes.concat(theirs, mine);
        vm.expectRevert(abi.encodeWithSelector(AttestationLib.UnknownSigner.selector, vm.addr(K_STRANGER)));
        harness.verify(d, both, 2);
    }

    /// ⛔ THIS IS WHAT BINDS A SIGNATURE TO ONE CHAIN. The destination domain is inside the digest,
    /// so a Sepolia signature checked against a Fuji digest does not "fail to match" — it recovers a
    /// completely different address, which is then not a validator. Remove the domain from the
    /// digest and the same bytes are valid on every destination at once.
    function test_a_signature_for_another_destination_domain_recovers_a_stranger() public {
        bytes32 sepolia = _digest(SEPOLIA, 1);
        bytes32 fuji = _digest(FUJI, 1);
        assertTrue(sepolia != fuji, "the domain must be inside the digest");
        vm.expectPartialRevert(AttestationLib.UnknownSigner.selector);
        harness.verify(fuji, _sign(sepolia, 0, 2), 2);
    }

    // ------------------------------------------------------------------ 8 to 11: malformed input

    function test_a_length_that_is_not_a_multiple_of_65_reverts_BadSignatureLength() public {
        bytes32 d = _digest(SEPOLIA, 1);
        bytes memory ragged = bytes.concat(_sign(d, 0, 1), hex"00");
        vm.expectRevert(abi.encodeWithSelector(AttestationLib.BadSignatureLength.selector, uint256(66)));
        harness.verify(d, ragged, 1);
    }

    function test_an_empty_signature_list_reverts_NotEnoughSignatures() public {
        bytes32 d = _digest(SEPOLIA, 1);
        vm.expectRevert(abi.encodeWithSelector(AttestationLib.NotEnoughSignatures.selector, uint256(0), uint256(1)));
        harness.verify(d, "", 1);
    }

    /// EIP-2: (r, s) and (r, N - s) are the same signature with a flipped v. Accepting both would
    /// let one signature be presented as two different 65-byte strings.
    function test_a_high_s_signature_reverts_HighS() public {
        bytes32 d = _digest(SEPOLIA, 1);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[0], AttestationLib.ethSigned(d));
        bytes32 highS = bytes32(N - uint256(s));
        uint8 flipped = v == 27 ? 28 : 27;
        vm.expectRevert(abi.encodeWithSelector(AttestationLib.HighS.selector, uint256(0)));
        harness.verify(d, abi.encodePacked(r, highS, flipped), 1);
    }

    function test_a_v_of_29_reverts_BadSignature() public {
        bytes32 d = _digest(SEPOLIA, 1);
        (, bytes32 r, bytes32 s) = vm.sign(keys[0], AttestationLib.ethSigned(d));
        vm.expectRevert(abi.encodeWithSelector(AttestationLib.BadSignature.selector, uint256(0)));
        harness.verify(d, abi.encodePacked(r, s, uint8(29)), 1);
    }

    /// ⚠ THE COUNT IS CHECKED BEFORE ANY RECOVERY, and the assertion is that the garbage signature
    /// below is never looked at. If the order were reversed this would revert `BadSignature(0)`,
    /// and a caller who simply sent too few would be told their signature was malformed.
    function test_too_few_signatures_reverts_before_a_single_recovery_is_attempted() public {
        bytes32 d = _digest(SEPOLIA, 1);
        bytes memory garbage = new bytes(65); // all zeroes: recovers to address(0)
        vm.expectRevert(abi.encodeWithSelector(AttestationLib.NotEnoughSignatures.selector, uint256(1), uint256(3)));
        harness.verify(d, garbage, 3);
    }

    // ------------------------------------------------------------------ cost

    /// ⚠ THIS IS THE PER-MESSAGE COST OF THE WHOLE TRANSPORT, so it is measured rather than assumed.
    /// The warm-up call is not optional: the FIRST `ecrecover` in a transaction pays EIP-2929 cold
    /// account access for the precompile, which made a 1-signer verify measure HIGHER than a
    /// 2-signer one in the plan-03 cost probe.
    function test_gas_of_a_2_of_2_and_a_3_of_4_verify() public view {
        bytes32 d = _digest(SEPOLIA, 1);
        bytes memory two = _sign(d, 0, 2);
        bytes memory three = _sign(d, 0, 3);

        // ⚠ WARM WITH ALL FOUR, NOT WITH TWO. A warm-up that only touches two validators leaves the
        // third's `_isValidator` slot cold, and the 3-of-4 reading then carries a 2.100-gas cold
        // SLOAD that has nothing to do with a third signature. Measured: 17.357 warmed with two,
        // 15.410 warmed with four, and the gap is the cold slot almost exactly.
        harness.verify(d, _sign(d, 0, 4), 4);

        uint256 before = gasleft();
        harness.verify(d, two, 2);
        uint256 twoOfTwo = before - gasleft();

        before = gasleft();
        harness.verify(d, three, 3);
        uint256 threeOfFour = before - gasleft();

        console.log("verify 2-of-2 gas", twoOfTwo);
        console.log("verify 3-of-4 gas", threeOfFour);

        // The whole curve, so the marginal cost of one more validator is a measurement and not a
        // subtraction of two numbers taken under different conditions.
        for (uint8 n = 1; n <= 4; n++) {
            bytes memory sigs = _sign(d, 0, n);
            harness.verify(d, sigs, n); // warm this call's own slots
            uint256 mark = gasleft();
            harness.verify(d, sigs, n);
            console.log("verify signers, gas", n, mark - gasleft());
        }

        // Not a pinned number: a bound that catches a rewrite turning one pass into an allocation.
        assertLt(twoOfTwo, 20_000, "2-of-2 verify got expensive");
        assertLt(threeOfFour, 25_000, "3-of-4 verify got expensive");
        assertGt(threeOfFour, twoOfTwo, "a third signature must cost something");
    }

    // ------------------------------------------------------------------ helpers

    function _at(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(i), "].", field);
    }

    function _digest(uint32 domain, uint64 seq) internal view returns (bytes32) {
        return harness.digest(CHAIN_ID, domain, seq, keccak256("a message"), 900);
    }

    /// `count` signatures starting at validator `from`, in the ascending order `verify` requires.
    function _sign(bytes32 d, uint256 from, uint256 count) internal view returns (bytes memory out) {
        bytes32 h = AttestationLib.ethSigned(d);
        for (uint256 i = from; i < from + count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], h);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }

    function _signWith(uint256 key, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, AttestationLib.ethSigned(d));
        return abi.encodePacked(r, s, v);
    }

    /// The vector writes the signer as a 20-byte hex string, which `parseBytes32` refuses by length.
    function _toAddress(string memory hex20) internal pure returns (address) {
        return vm.parseAddress(hex20);
    }
}

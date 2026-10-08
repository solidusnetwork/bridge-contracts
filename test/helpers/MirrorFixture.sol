// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {SolidusCredentialMirror} from "../../src/SolidusCredentialMirror.sol";
import {AttestationLib} from "../../src/lib/AttestationLib.sol";

/// Deploys a mirror with four known anvil keys as validators and threshold 3, and signs for it.
abstract contract MirrorFixture is Test {
    SolidusCredentialMirror internal mirror;

    uint64 internal constant CHAIN_ID = 50_002;
    uint32 internal constant SOLIDUS_DOMAIN = 50_002;
    uint32 internal constant LOCAL_DOMAIN = 11_155_111; // Sepolia
    uint64 internal constant START_SEQ = 1;

    // Anvil accounts 0 to 3. Published test keys: they hold nothing, anywhere, ever.
    uint256 internal constant K0 = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 internal constant K1 = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 internal constant K2 = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;
    uint256 internal constant K3 = 0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6;

    /// Sorted ascending by address, because ascending order is what `verify` requires.
    uint256[4] internal keys;

    function _deployMirror() internal {
        keys = _sortedKeys();
        address[] memory vs = new address[](4);
        for (uint256 i; i < 4; i++) {
            vs[i] = vm.addr(keys[i]);
        }
        mirror = new SolidusCredentialMirror(CHAIN_ID, SOLIDUS_DOMAIN, LOCAL_DOMAIN, START_SEQ, vs, 3);
    }

    function _sortedKeys() internal pure returns (uint256[4] memory k) {
        k = [K0, K1, K2, K3];
        for (uint256 i = 1; i < 4; i++) {
            uint256 cur = k[i];
            uint256 j = i;
            while (j > 0 && vm.addr(k[j - 1]) > vm.addr(cur)) {
                k[j] = k[j - 1];
                j--;
            }
            k[j] = cur;
        }
    }

    /// Signs `message` for THIS mirror with the first three validators and submits it.
    function deliver(bytes memory message) internal {
        mirror.submit(message, _signatures(message, 3));
    }

    /// ⚠ The digest is built from the MESSAGE's own sequence and height, not from the mirror's
    /// expectation, so a test can sign a validly-attested message for the wrong slot.
    function _signatures(bytes memory message, uint256 count) internal view returns (bytes memory out) {
        uint64 domainSeq;
        uint64 solidusHeight;
        assembly {
            let word := mload(add(message, 32))
            domainSeq := shr(192, shl(16, word))
            solidusHeight := shr(192, shl(80, word))
        }
        bytes32 d = AttestationLib.digest(CHAIN_ID, LOCAL_DOMAIN, domainSeq, keccak256(message), solidusHeight);
        bytes32 h = AttestationLib.ethSigned(d);
        for (uint256 i; i < count; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], h);
            out = bytes.concat(out, abi.encodePacked(r, s, v));
        }
    }
}

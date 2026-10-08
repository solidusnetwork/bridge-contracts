// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ISolidusCredentialMirror} from "./interfaces/ISolidusCredentialMirror.sol";
import {SolidusGate} from "./lib/SolidusGate.sol";

/// @title SolidusGated
/// @notice Inherit this and put `onlyCredentialed` on the entry points that need one.
///
/// ⚠ THE MIRROR IS IMMUTABLE HERE ON PURPOSE. A settable mirror would be an upgrade path in
/// disguise: whoever could change it could point the contract at a mirror they control and mint
/// themselves a credential. An integrator who needs to follow a replacement reads
/// `SolidusRegistry.mirrorOf(domain)` at the call site instead.
abstract contract SolidusGated {
    ISolidusCredentialMirror public immutable mirror;

    constructor(ISolidusCredentialMirror mirror_) {
        mirror = mirror_;
    }

    /// Reverts `SolidusGate.CredentialRequired` with the reason, so the caller learns WHY.
    modifier onlyCredentialed(bytes32 credentialTypeHash, bytes32 issuerDidHash, uint64 maxAge) {
        SolidusGate.requireCredential(
            mirror, SolidusGate.holderOf(msg.sender), credentialTypeHash, issuerDidHash, maxAge
        );
        _;
    }
}

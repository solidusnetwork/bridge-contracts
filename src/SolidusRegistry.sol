// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ISolidusRegistry} from "./interfaces/ISolidusRegistry.sol";

/// @title SolidusRegistry
/// @notice domain → mirror, behind a 48-hour timelock. Integrators read it so a mirror can be
///         replaced without them changing a line.
///
/// ⛔ THE LIMIT OF WHAT GOVERNANCE CAN DO IS IN THIS FILE, AND IT IS SHORT ON PURPOSE. An attacker
/// who captures the owning Safe can point NEW integrators at a different contract, after the delay,
/// in public. They cannot rewrite a credential, pause delivery or change a validator set, because
/// the mirror has no function this contract's owner can call. That is the whole reason this is a
/// registry and not a proxy.
contract SolidusRegistry is ISolidusRegistry, Ownable {
    mapping(uint32 => address) private _mirrors;

    constructor(address timelock) Ownable(timelock) {}

    function mirrorOf(uint32 solidusDomain) external view returns (address) {
        return _mirrors[solidusDomain];
    }

    /// ⚠ NO ZERO CHECK AND NO ONE-SHOT GUARD, DELIBERATELY. Setting a domain to the zero address is
    /// how a compromised mirror is withdrawn, and setting it twice is how one is replaced. Both are
    /// governance decisions that already cost 48 hours in public.
    function setMirror(uint32 solidusDomain, address mirror) external onlyOwner {
        _mirrors[solidusDomain] = mirror;
        emit MirrorSet(solidusDomain, mirror);
    }
}

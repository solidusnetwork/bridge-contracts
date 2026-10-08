// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// @notice A stable address for integrators, so a mirror can be replaced without anything on this
///         chain needing `delegatecall`, an initializer or a storage layout to preserve.
///
/// ⚠ THIS REPLACED A UUPS PROXY. The earlier design put the mirror behind an upgradeable proxy,
/// which added an upgrade-abuse surface to a contract that holds no funds. Twelve lines of storage
/// and one setter behind a 48-hour timelock buys the same stability and cannot rewrite history.
interface ISolidusRegistry {
    function mirrorOf(uint32 solidusDomain) external view returns (address);
    /// Timelock only.
    function setMirror(uint32 solidusDomain, address mirror) external;

    event MirrorSet(uint32 indexed solidusDomain, address indexed mirror);
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {ISolidusCredentialMirror} from "../src/interfaces/ISolidusCredentialMirror.sol";
import {SolidusCredentialMirror} from "../src/SolidusCredentialMirror.sol";
import {SolidusRegistry} from "../src/SolidusRegistry.sol";
import {ExampleGatedVault} from "../src/examples/ExampleGatedVault.sol";

/// Deploys the phase 1 set to one EVM chain and writes `deployments/<network>/<chainId>.json`.
///
/// ⛔ `START_SEQ` HAS NO DEFAULT AND MUST NOT GET ONE. It is read from the Solidus chain: a
/// replacement mirror continues the sequence the previous one reached, and a silent default of 1
/// would make the destination refuse every message forever while looking like a configuration
/// typo. An unset variable failing loudly is the behaviour we want.
///
/// Environment: `DEPLOY_NETWORK`, `SOLIDUS_CHAIN_ID`, `SOLIDUS_DOMAIN`, `LOCAL_DOMAIN`, `START_SEQ`,
/// `VALIDATORS` (comma-separated), `THRESHOLD`, `ISSUER_DID_HASH`, `TIMELOCK_PROPOSER`,
/// `TIMELOCK_MIN_DELAY` (default 172800), `PRIVATE_KEY`.
contract DeployPhase1 is Script {
    /// ⚠ A STRUCT AND NOT ELEVEN LOCALS. Eleven environment variables plus four deployed addresses
    /// overflows the EVM's 16-slot stack window, and `solc` reports it as "Stack too deep" pointing
    /// at whichever line happened to be last. Grouping them costs nothing and keeps the script
    /// compilable without `via-ir`.
    struct Config {
        string network;
        uint64 solidusChainId;
        uint32 solidusDomain;
        uint32 localDomain;
        uint64 startSeq;
        address[] validators;
        uint8 threshold;
        bytes32 issuerDidHash;
        address proposer;
        uint256 minDelay;
        uint256 deployerKey;
    }

    function _config() private view returns (Config memory c) {
        c.network = vm.envString("DEPLOY_NETWORK");
        c.solidusChainId = uint64(vm.envUint("SOLIDUS_CHAIN_ID"));
        c.solidusDomain = uint32(vm.envUint("SOLIDUS_DOMAIN"));
        c.localDomain = uint32(vm.envUint("LOCAL_DOMAIN"));
        c.startSeq = uint64(vm.envUint("START_SEQ"));
        c.validators = vm.envAddress("VALIDATORS", ",");
        c.threshold = uint8(vm.envUint("THRESHOLD"));
        c.issuerDidHash = vm.envBytes32("ISSUER_DID_HASH");
        c.proposer = vm.envAddress("TIMELOCK_PROPOSER");
        c.minDelay = vm.envOr("TIMELOCK_MIN_DELAY", uint256(172800));
        c.deployerKey = vm.envUint("PRIVATE_KEY");
    }

    function run() external {
        Config memory c = _config();

        vm.startBroadcast(c.deployerKey);

        address[] memory proposers = new address[](1);
        proposers[0] = c.proposer;
        // ⚠ AN EMPTY EXECUTOR ADDRESS MEANS ANYONE MAY EXECUTE once the delay has passed. That is
        // deliberate: the delay is the protection, and requiring a named executor adds a party who
        // can stall a decision that has already been made in public.
        address[] memory executors = new address[](1);
        executors[0] = address(0);
        // The zero admin: nobody outside can grant themselves a role and skip the delay.
        TimelockController timelock = new TimelockController(c.minDelay, proposers, executors, address(0));

        SolidusRegistry registry = new SolidusRegistry(address(timelock));
        SolidusCredentialMirror mirror = new SolidusCredentialMirror(
            c.solidusChainId, c.solidusDomain, c.localDomain, c.startSeq, c.validators, c.threshold
        );
        ExampleGatedVault vault = new ExampleGatedVault(ISolidusCredentialMirror(address(mirror)), c.issuerDidHash);

        // ⚠ ONLY ON A CHAIN WHERE THE DEPLOYER IS THE PROPOSER, which in practice means local. On a
        // testnet the Safe proposes and the record below says the mirror is not registered yet,
        // rather than the script quietly granting itself a role to finish the job.
        bool registered = false;
        if (vm.addr(c.deployerKey) == c.proposer) {
            bytes memory data = abi.encodeCall(SolidusRegistry.setMirror, (c.localDomain, address(mirror)));
            timelock.schedule(address(registry), 0, data, bytes32(0), bytes32(0), c.minDelay);
            if (c.minDelay == 0) {
                timelock.execute(address(registry), 0, data, bytes32(0), bytes32(0));
                registered = true;
            }
        }

        vm.stopBroadcast();

        _write(c, timelock, registry, mirror, vault, registered);
    }

    function _write(
        Config memory c,
        TimelockController timelock,
        SolidusRegistry registry,
        SolidusCredentialMirror mirror,
        ExampleGatedVault vault,
        bool registered
    ) private {
        string memory json = string.concat(
            "{\n",
            '  "network": "',
            c.network,
            '",\n',
            '  "chainId": ',
            vm.toString(block.chainid),
            ",\n",
            '  "timelock": "',
            vm.toString(address(timelock)),
            '",\n',
            '  "registry": "',
            vm.toString(address(registry)),
            '",\n',
            '  "mirror": "',
            vm.toString(address(mirror)),
            '",\n',
            '  "exampleGatedVault": "',
            vm.toString(address(vault)),
            '",\n',
            '  "startSeq": ',
            vm.toString(uint256(c.startSeq)),
            ",\n",
            '  "threshold": ',
            vm.toString(uint256(c.threshold)),
            ",\n",
            '  "registeredInRegistry": ',
            registered ? "true" : "false",
            "\n",
            "}\n"
        );
        string memory path = string.concat("deployments/", c.network, "/", vm.toString(block.chainid), ".json");
        vm.writeFile(path, json);
        console.log("wrote", path);
    }
}

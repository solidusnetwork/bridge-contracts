// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {GatedUsdcReceiver} from "../src/GatedUsdcReceiver.sol";
import {IMessageTransmitterV2} from "../src/interfaces/ICctp.sol";
import {ISolidusCredentialMirror} from "../src/interfaces/ISolidusCredentialMirror.sol";

/// Deploys `GatedUsdcReceiver` behind an ERC-1967 proxy owned by the phase 1 timelock, reads every
/// constructor and initializer value back, and writes `deployments/<network>/<chainId>.phase3.json`.
///
/// Environment: `DEPLOY_NETWORK`, `MESSAGE_TRANSMITTER`, `USDC`, `MIRROR`, `OWNER`, `PRIVATE_KEY`.
/// ⚠ ALL FOUR ADDRESSES ARE MEASURED VALUES (records/cctp-v2.md, deployments/<network>/<chainId>.json),
/// never typed defaults: a receiver bound to the wrong transmitter can never complete a transfer, and
/// one bound to the wrong USDC would pay out a token Circle never sent it.
contract DeployPhase3 is Script {
    error ReadbackMismatch(string field);

    function run() external {
        string memory network = vm.envString("DEPLOY_NETWORK");
        IMessageTransmitterV2 transmitter = IMessageTransmitterV2(vm.envAddress("MESSAGE_TRANSMITTER"));
        IERC20 usdc = IERC20(vm.envAddress("USDC"));
        ISolidusCredentialMirror mirror = ISolidusCredentialMirror(vm.envAddress("MIRROR"));
        address owner = vm.envAddress("OWNER");
        uint256 key = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(key);
        GatedUsdcReceiver impl = new GatedUsdcReceiver(transmitter, usdc, mirror);
        GatedUsdcReceiver receiver = GatedUsdcReceiver(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(GatedUsdcReceiver.initialize, (owner))))
        );
        vm.stopBroadcast();

        // Read back THROUGH THE PROXY, which is what every caller will see.
        if (address(receiver.transmitter()) != address(transmitter)) revert ReadbackMismatch("transmitter");
        if (address(receiver.usdc()) != address(usdc)) revert ReadbackMismatch("usdc");
        if (address(receiver.mirror()) != address(mirror)) revert ReadbackMismatch("mirror");
        if (receiver.owner() != owner) revert ReadbackMismatch("owner");

        string memory json = string.concat(
            "{\n",
            '  "network": "', network, '",\n',
            '  "chainId": ', vm.toString(block.chainid), ",\n",
            '  "usdcReceiver": "', vm.toString(address(receiver)), '",\n',
            '  "usdcReceiverImplementation": "', vm.toString(address(impl)), '",\n',
            '  "messageTransmitter": "', vm.toString(address(transmitter)), '",\n',
            '  "usdc": "', vm.toString(address(usdc)), '",\n',
            '  "mirror": "', vm.toString(address(mirror)), '",\n',
            '  "owner": "', vm.toString(owner), '"\n',
            "}\n"
        );
        vm.writeFile(string.concat("deployments/", network, "/", vm.toString(block.chainid), ".phase3.json"), json);
    }
}

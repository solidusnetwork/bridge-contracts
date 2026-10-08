# Solidus Bridge contracts

Solidity contracts for [Solidus Bridge](https://bridge.solidus.network). Bridge carries the status of a Solidus
credential to other chains, so a contract there can check a condition without seeing the credential. These
contracts run on testnets: Ethereum Sepolia, Avalanche Fuji and Arc testnet.

## What is here

| path | what it is |
|---|---|
| `src/SolidusCredentialMirror.sol` | Stores credential status on a destination chain: one record per export, one flag per issuer and the latest heartbeat. `submit(message, signatures)` applies a message that enough known validators signed. It has no owner and no admin function. |
| `src/SolidusRegistry.sol` | Maps a destination domain to its mirror. Its owner is a timelock. |
| `src/SolidusGated.sol`, `src/lib/SolidusGate.sol` | The gate an integrator inherits. `onlyCredentialed(...)` reverts with a reason number when the check fails. |
| `src/GatedUsdcReceiver.sol` | USDC (Circle CCTP v2) that only a credentialed recipient can receive. Testnet USDC only. |
| `src/lib/` | `AttestationLib` (the signed digest and the signature check) and `BridgeMessageCodec` (the message bodies). |
| `src/examples/ExampleGatedVault.sol` | The smallest real use of the gate. |
| `test/`, `script/` | Foundry tests and the deployment scripts. `test-fixtures/` holds the vectors the tests read. |
| `deployments/testnet/` | The addresses below, as JSON. |

## Use the gate

```solidity
import {SolidusGated} from "./SolidusGated.sol";

contract Vault is SolidusGated {
    function deposit() external payable onlyCredentialed(KYC_L2, issuerDidHash, MAX_AGE) { /* ... */ }
}
```

[How to gate a function on a credential](https://bridge.solidus.network/learn/check-a-condition-without-seeing-the-data)
walks through it, including how to choose `maxAge`.

## Build and test

You need [Foundry](https://book.getfoundry.sh/).

```bash
npm install
forge build
forge test
```

## Testnet deployments

| chain | chain id | mirror | registry | registry owner (timelock) | USDC receiver |
|---|---|---|---|---|---|
| Ethereum Sepolia | 11155111 | `0x0a5a0d19206f436d67B7b87BF4c889d5b769517A` | `0x19aF92b387200827E0540f516FEd1468B09806A5` | `0x23A8E34E422A9c2E88c1F205070758b84191d294` | `0x98F2e527A75ec252F70D68DE35AD7D8189241109` |
| Avalanche Fuji | 43113 | `0x0a5a0d19206f436d67B7b87BF4c889d5b769517A` | `0x19aF92b387200827E0540f516FEd1468B09806A5` | `0x23A8E34E422A9c2E88c1F205070758b84191d294` | `0x70Aa006Faff8Ca243cfb66DeAd122f85Fe31F880` |
| Arc testnet | 5042002 | `0x0a5a0d19206f436d67B7b87BF4c889d5b769517A` | `0x19aF92b387200827E0540f516FEd1468B09806A5` | `0x23A8E34E422A9c2E88c1F205070758b84191d294` | `0x70Aa006Faff8Ca243cfb66DeAd122f85Fe31F880` |

Read the live addresses from the `/v1/routes` endpoint of the Bridge API, documented at
https://docs.solidus.network/api/bridge.

## More

- [Developers](https://bridge.solidus.network/developers) and the [API reference](https://docs.solidus.network/api/bridge)
- [Read the mirror contract](https://bridge.solidus.network/learn/read-the-mirror-contract-from-solidity) and
  [what the mirror cannot do](https://bridge.solidus.network/learn/what-the-mirror-cannot-do), with the on-chain checks

## License

Apache-2.0. See `LICENSE`.

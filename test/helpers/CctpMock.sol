// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import {IMessageTransmitterV2} from "../../src/interfaces/ICctp.sol";

/// A 6-decimal USDC with Circle's blocklist, and an optional callback on receipt so a test can try to
/// re-enter the receiver through the token, the one external call it makes to a third party.
contract MockUsdc is ERC20 {
    mapping(address => bool) public blocked;
    address public minter;

    error Blocklisted(address account);

    constructor() ERC20("USD Coin", "USDC") {
        minter = msg.sender;
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    function setMinter(address m) external {
        minter = m;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "not minter");
        _mint(to, amount);
    }

    function setBlocked(address a, bool b) external {
        blocked[a] = b;
    }

    function _update(address from, address to, uint256 value) internal override {
        if (blocked[from]) revert Blocklisted(from);
        if (blocked[to]) revert Blocklisted(to);
        super._update(from, to, value);
        if (to.code.length > 0 && from != address(0)) {
            // Ignore failure and a missing function; only a deliberate re-entry is under test.
            (bool ok,) = to.call(abi.encodeWithSignature("onUsdcReceived()"));
            ok;
        }
    }
}

/// The measured `receiveMessage` shape (records/cctp-v2.md): enforces `destinationCaller`, marks the
/// nonce used, mints `amount - feeExecuted` to `mintRecipient`, returns true.
contract CctpMock is IMessageTransmitterV2 {
    MockUsdc public immutable usdc;
    mapping(bytes32 => bool) public usedNonce;
    bool public failNext;

    constructor(MockUsdc usdc_) {
        usdc = usdc_;
    }

    function setFailNext(bool f) external {
        failNext = f;
    }

    function receiveMessage(bytes calldata message, bytes calldata) external returns (bool) {
        if (failNext) revert("attestation rejected");
        bytes32 nonce = bytes32(message[12:44]);
        require(!usedNonce[nonce], "Nonce already used");
        usedNonce[nonce] = true;
        bytes32 caller = bytes32(message[108:140]);
        require(caller == bytes32(0) || caller == bytes32(uint256(uint160(msg.sender))), "Invalid caller for message");
        address to = address(uint160(uint256(bytes32(message[184:216]))));
        uint256 amount = uint256(bytes32(message[216:248]));
        uint256 fee = uint256(bytes32(message[312:344]));
        usdc.mint(to, amount - fee);
        return true;
    }
}

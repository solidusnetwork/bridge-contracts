// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {IMessageTransmitterV2} from "./interfaces/ICctp.sol";
import {IGatedUsdcReceiver} from "./interfaces/IGatedUsdcReceiver.sol";
import {ISolidusCredentialMirror} from "./interfaces/ISolidusCredentialMirror.sol";
import {BridgeMessageCodec} from "./lib/BridgeMessageCodec.sol";
import {GateReason, SolidusGate} from "./lib/SolidusGate.sol";

/// @notice USDC that only a credentialed recipient can receive.
///
/// A sender burns with CCTP v2 `depositForBurnWithHook`, naming THIS contract as both `mintRecipient`
/// and `destinationCaller`, so Circle lets no one else complete the transfer. Anyone then calls
/// `relay` with Circle's attestation. The gate decides: a credentialed `finalRecipient` is paid at
/// once, anyone else's USDC waits in escrow until the gate passes (`release`) or the hook's deadline
/// passes (`refund`).
///
/// ⛔ THIS CONTRACT HOLDS USER FUNDS. Every external entry point is `nonReentrant`, no loop is
/// unbounded, there is no `delegatecall` beyond the UUPS upgrade path, and the upgrade path belongs to
/// the 48-hour timelock alone.
///
/// ⚠ A HOOK THE CODEC REJECTS REVERTS THE WHOLE RELAY, and because only this contract may complete
/// the transfer, that burn can then never be minted. The hook is built by our SDK
/// (`encodeUsdcHook`, pinned by `usdc-hook-v1.json`), so a malformed one is a client defect, and the
/// alternative (escrow with no valid refund address) has nowhere to send the funds either.
contract GatedUsdcReceiver is IGatedUsdcReceiver, Initializable, UUPSUpgradeable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint64 public constant GATE_MAX_AGE = 1 days;

    /// The gate passed but the token refused the transfer (a blocklisted recipient). Not a gate
    /// reason, so it sits after `GateReason.STALE` (5).
    uint8 public constant TRANSFER_FAILED = 6;

    /// The receiver was paused when the transfer arrived: minted, held, never paid out (see `pause`).
    uint8 public constant PAUSED = 7;

    uint8 internal constant HELD = 1;
    uint8 internal constant RELEASED = 2;
    uint8 internal constant REFUNDED = 3;

    // CCTP v2 offsets in the FULL message (records/cctp-v2.md): a 148-byte header, then the burn body.
    uint256 internal constant MINT_RECIPIENT_AT = 148 + 36;
    uint256 internal constant FEE_EXECUTED_AT = 148 + 164;
    uint256 internal constant HOOK_AT = 148 + 228;

    IMessageTransmitterV2 public immutable transmitter;
    IERC20 public immutable usdc;
    ISolidusCredentialMirror public immutable mirror;

    address public owner;
    mapping(bytes32 hash => Escrow) private _escrows;
    // ⚠ UPGRADE-SAFE ORDER: appended after `_escrows`, which the deployed proxies already lay out.
    address public guardian;
    bool public paused;

    error NotOwner(address caller);
    error MessageTooShort(uint256 length);
    error NotForThisReceiver(bytes32 mintRecipient);
    error NotAnEvmAddress(bytes32 value);
    error ZeroRefundAddress();
    error ReceiveFailed();
    error NothingMinted();
    error NotGuardian(address caller);
    error IsPaused();

    event GuardianSet(address indexed guardian);
    event PausedSet(bool paused, address indexed by);

    /// @param usdc_ the token Circle mints on THIS chain. On Arc it is the 6-decimal ERC-20 interface
    /// `0x3600…0000`, measured from TokenMinterV2, never the 18-decimal native balance.
    constructor(IMessageTransmitterV2 transmitter_, IERC20 usdc_, ISolidusCredentialMirror mirror_) {
        transmitter = transmitter_;
        usdc = usdc_;
        mirror = mirror_;
        _disableInitializers();
    }

    function initialize(address owner_) external initializer {
        owner = owner_;
    }

    // ------------------------------------------------------------------ relay

    function relay(bytes calldata message, bytes calldata attestation) external nonReentrant returns (bytes32 hash) {
        // 1. Anyone may relay. Circle enforces `destinationCaller == this`, which is what makes
        //    an open entry point safe: no one can mint this transfer anywhere else.

        // 2. Shape before Circle, so a message that cannot be ours fails with a reason that names it.
        if (message.length < HOOK_AT) revert MessageTooShort(message.length);
        bytes32 mintRecipient = bytes32(message[MINT_RECIPIENT_AT:MINT_RECIPIENT_AT + 32]);
        if (mintRecipient != bytes32(uint256(uint160(address(this))))) revert NotForThisReceiver(mintRecipient);
        BridgeMessageCodec.UsdcHook memory h = BridgeMessageCodec.usdcHook(message[HOOK_AT:]);
        address recipient = _evmAddress(h.finalRecipient);
        if (_evmAddress(h.refundAddress) == address(0)) revert ZeroRefundAddress();

        // 3. Circle mints. Its revert (a replayed nonce, a bad attestation) unwinds everything here.
        uint256 before = usdc.balanceOf(address(this));
        if (!transmitter.receiveMessage(message, attestation)) revert ReceiveFailed();

        // 4. ⛔ THE BALANCE DELTA, NOT THE MESSAGE'S AMOUNT. Circle mints `amount - feeExecuted`, and
        //    what this contract can pay out is exactly what arrived. Trusting a field instead would let
        //    an escrow promise more than the contract holds.
        uint256 amount = usdc.balanceOf(address(this)) - before;
        if (amount == 0) revert NothingMinted();
        uint256 fee = uint256(bytes32(message[FEE_EXECUTED_AT:FEE_EXECUTED_AT + 32]));

        hash = keccak256(message);

        // 5. The gate, with the same library the example vault uses: one implementation of the rules.
        //    ⛔ PAUSED STILL MINTS. Reverting here would strand the burn (only this contract can
        //    complete it), so a paused receiver takes the funds into escrow and pays nobody.
        uint8 reason = paused
            ? PAUSED
            : SolidusGate.check(mirror, h.finalRecipient, h.credentialTypeHash, h.issuerDidHash, GATE_MAX_AGE);
        if (reason == GateReason.OK) {
            // ⚠ A REFUSED TRANSFER MUST NOT REVERT THE DELIVERY: Circle's nonce would roll
            //   back with it, and since only this contract can complete the transfer, a blocklisted
            //   recipient would strand the funds forever. It escrows instead, refundable after the deadline.
            //   No state is written before this call; the only external target is the USDC token.
            if (_tryTransfer(recipient, amount)) {
                emit UsdcDelivered(hash, recipient, amount, fee, h.referralCode);
                return hash;
            }
            reason = TRANSFER_FAILED;
        }

        _escrows[hash] = Escrow({
            finalRecipient: h.finalRecipient,
            refundAddress: h.refundAddress,
            amount: amount,
            deadline: h.deadline,
            credentialTypeHash: h.credentialTypeHash,
            issuerDidHash: h.issuerDidHash,
            referralCode: h.referralCode,
            state: HELD
        });
        emit UsdcEscrowed(hash, h.finalRecipient, amount, reason, h.deadline);
    }

    // ------------------------------------------------------------------ release / refund

    function release(bytes32 hash) external nonReentrant {
        Escrow storage e = _escrows[hash];
        if (e.state != HELD) revert NotHeld(hash);
        if (paused) revert IsPaused();
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp > e.deadline) revert DeadlinePassed(hash);
        uint8 reason = SolidusGate.check(mirror, e.finalRecipient, e.credentialTypeHash, e.issuerDidHash, GATE_MAX_AGE);
        if (reason != GateReason.OK) revert GateStillFails(hash, reason);

        // Effects before the interaction.
        e.state = RELEASED;
        address to = address(uint160(uint256(e.finalRecipient)));
        uint256 amount = e.amount;
        usdc.safeTransfer(to, amount);
        emit UsdcReleased(hash, to, amount);
    }

    /// ⛔ NOT PAUSABLE, ON PURPOSE. A refund pays only the address the sender named, after the
    /// sender's own deadline, so it cannot be the exploit a pause exists to stop, and it is the one
    /// way out that must survive a pause that is never lifted.
    function refund(bytes32 hash) external nonReentrant {
        Escrow storage e = _escrows[hash];
        if (e.state != HELD) revert NotHeld(hash);
        // forge-lint: disable-next-line(block-timestamp)
        if (block.timestamp <= e.deadline) revert DeadlineNotPassed(hash);

        e.state = REFUNDED;
        address to = address(uint160(uint256(e.refundAddress)));
        uint256 amount = e.amount;
        usdc.safeTransfer(to, amount);
        emit UsdcRefunded(hash, to, amount);
    }

    function escrowOf(bytes32 hash) external view returns (Escrow memory) {
        return _escrows[hash];
    }

    // ------------------------------------------------------------------ pause (mainnet readiness)

    /// The guardian (a hot multisig, faster than the 48-hour timelock) can stop money LEAVING to
    /// recipients: new transfers escrow with reason `PAUSED`, and `release` reverts. It cannot move
    /// funds, unpause, or name a guardian. Refunds stay open.
    function pause() external {
        if (msg.sender != guardian && msg.sender != owner) revert NotGuardian(msg.sender);
        paused = true;
        emit PausedSet(true, msg.sender);
    }

    /// Unpausing is the owner's alone, so a compromised guardian can stop the bridge but never restart it.
    function unpause() external {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        paused = false;
        emit PausedSet(false, msg.sender);
    }

    function setGuardian(address guardian_) external {
        if (msg.sender != owner) revert NotOwner(msg.sender);
        guardian = guardian_;
        emit GuardianSet(guardian_);
    }

    // ------------------------------------------------------------------ internals

    function _authorizeUpgrade(address) internal view override {
        if (msg.sender != owner) revert NotOwner(msg.sender);
    }

    /// A Solidus holder key for an EVM account is the address left-padded (`SolidusGate.holderOf`).
    /// Anything with bits above the low 20 bytes names an account on another VM and cannot be paid here.
    function _evmAddress(bytes32 value) internal pure returns (address) {
        if (uint256(value) >> 160 != 0) revert NotAnEvmAddress(value);
        return address(uint160(uint256(value)));
    }

    /// `transfer` without reverting: true only for a call that succeeded and returned true or nothing.
    function _tryTransfer(address to, uint256 amount) internal returns (bool) {
        (bool ok, bytes memory ret) = address(usdc).call(abi.encodeCall(IERC20.transfer, (to, amount)));
        return ok && (ret.length == 0 || abi.decode(ret, (bool)));
    }
}

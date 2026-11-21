// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {CronosBootstrapEscrow} from "../../contracts/cronos/bridge/CronosBootstrapEscrow.sol";
import {MockERC20} from "../../contracts/test/MockERC20.sol";

// Local EVM simulations only. Signing keys 1, 2 and 3 are public synthetic
// test keys; no RPC, network or deployed contract is involved.

interface Vm {
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function warp(uint256) external;
}

contract EscrowTimeoutFuzzTest {
    Vm internal constant vm =
        Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant START = 1_700_000_000;
    uint256 internal constant AMOUNT = 20_000_100 ether;
    uint256 internal constant DEADLINE = 4_000_000_000;
    address internal constant VAULT = address(0xA11CE);
    address internal constant REFUND = address(0xB0B);
    bytes32 internal constant GENESIS = keccak256("synthetic-genesis");

    MockERC20 internal token;
    CronosBootstrapEscrow internal escrow;
    uint256 internal timeout;

    function setUp() public {
        vm.warp(START);
        token = new MockERC20("Synthetic", "TEST");
        escrow = new CronosBootstrapEscrow(
            token,
            VAULT,
            REFUND,
            address(this),
            GENESIS,
            AMOUNT,
            [vm.addr(1), vm.addr(2), vm.addr(3)]
        );
        token.mint(address(this), AMOUNT);
        token.approve(address(escrow), AMOUNT);
        escrow.fund();
        timeout = escrow.REFUND_TIMEOUT();
        require(timeout == 180 days, "timeout constant");
        require(escrow.fundedAt() == START, "funding time");
    }

    function _bound(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        return min + (x % (max - min + 1));
    }

    function _decision(bytes32 action) internal returns (bytes[] memory sigs) {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(escrow.EIP712_NAME())),
                keccak256(bytes(escrow.EIP712_VERSION())),
                block.chainid,
                address(escrow)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(escrow.DECISION_TYPEHASH(), action, GENESIS, AMOUNT, escrow.decisionNonce(), DEADLINE)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
        sigs = new bytes[](2);
        for (uint256 i; i < 2; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 1, digest);
            sigs[i] = abi.encodePacked(r, s, v);
        }
    }

    function _call(bytes memory data) internal returns (bool ok, bytes4 selector) {
        bytes memory reason;
        (ok, reason) = address(escrow).call(data);
        if (!ok && reason.length >= 4) selector = bytes4(reason);
    }

    function _activate() internal returns (bool, bytes4) {
        bytes[] memory sigs = _decision(escrow.ACTION_ACTIVATE());
        return _call(abi.encodeCall(escrow.activate, (escrow.decisionNonce(), DEADLINE, sigs)));
    }

    function _cancel() internal returns (bool, bytes4) {
        bytes[] memory sigs = _decision(escrow.ACTION_CANCEL());
        return _call(abi.encodeCall(escrow.cancel, (escrow.decisionNonce(), DEADLINE, sigs)));
    }

    function _refund() internal returns (bool, bytes4) {
        return _call(abi.encodeCall(escrow.refundAfterTimeout, ()));
    }

    /// Exactly one regime applies at any time: before fundedAt + REFUND_TIMEOUT
    /// only quorum decisions work; from that instant only the timeout refund.
    function testFuzz_timeoutBoundarySeparatesDecisionAndRefund(uint256 elapsedSeed, bool tryCancel) public {
        uint256 elapsed = _bound(elapsedSeed, 0, 2 * timeout);
        vm.warp(START + elapsed);
        bool afterTimeout = elapsed >= timeout;

        (bool refunded, bytes4 refundError) = _refund();
        require(refunded == afterTimeout, "refund boundary");
        if (!refunded) {
            require(refundError == CronosBootstrapEscrow.RefundTimeoutNotReached.selector, "refund error");
            (bool decided, ) = tryCancel ? _cancel() : _activate();
            require(decided, "decision before timeout");
            (refunded, refundError) = _refund();
            require(!refunded && refundError == CronosBootstrapEscrow.InvalidState.selector, "refund after decision");
        } else {
            require(token.balanceOf(REFUND) == AMOUNT && token.balanceOf(VAULT) == 0, "refund payout");
            (bool decided, bytes4 decisionError) = tryCancel ? _cancel() : _activate();
            require(!decided && decisionError == CronosBootstrapEscrow.InvalidState.selector, "decision after refund");
        }
    }

    /// After the timeout and before anyone refunds, a quorum approval signed
    /// earlier (with a far deadline) can no longer activate or cancel.
    function testFuzz_staleQuorumCannotDecideAfterTimeout(uint256 lateSeed) public {
        bytes[] memory activation = _decision(escrow.ACTION_ACTIVATE());
        bytes[] memory cancellation = _decision(escrow.ACTION_CANCEL());
        vm.warp(START + timeout + _bound(lateSeed, 0, 3650 days));

        (bool ok, bytes4 err) = _call(abi.encodeCall(escrow.activate, (0, DEADLINE, activation)));
        require(!ok && err == CronosBootstrapEscrow.RefundTimeoutElapsed.selector, "late activation");
        (ok, err) = _call(abi.encodeCall(escrow.cancel, (0, DEADLINE, cancellation)));
        require(!ok && err == CronosBootstrapEscrow.RefundTimeoutElapsed.selector, "late cancellation");
        require(uint8(escrow.state()) == 1 && escrow.decisionNonce() == 0, "state unchanged");
        require(token.balanceOf(address(escrow)) == AMOUNT, "custody unchanged");

        (ok, ) = _refund();
        require(ok && token.balanceOf(REFUND) == AMOUNT, "refund remains available");
    }

    /// Stateful sequence: random interleavings of decisions, refunds, warps,
    /// donations and forwarding never reach two terminal outcomes and only
    /// ever pay the one fixed recipient of the outcome that was reached.
    function testFuzz_terminalOutcomesStayExclusive(uint256 seed) public {
        uint256 donated;
        uint8 outcomes;
        for (uint256 i; i < 12; ++i) {
            uint256 step = uint256(keccak256(abi.encode(seed, i)));
            uint256 kind = step % 6;
            bool ok;
            if (kind == 0) (ok, ) = _activate();
            else if (kind == 1) (ok, ) = _cancel();
            else if (kind == 2) (ok, ) = _refund();
            else if (kind == 3) vm.warp(block.timestamp + _bound(step >> 8, 0, 120 days));
            else if (kind == 4) {
                uint256 amount = _bound(step >> 8, 1, 1 ether);
                token.mint(address(escrow), amount);
                donated += amount;
            } else {
                (ok, ) = _call(abi.encodeCall(escrow.forwardTerminalBalance, ()));
                ok = false; // forwarding is not a terminal decision
            }
            if (ok) ++outcomes;
        }
        require(outcomes <= 1, "two terminal outcomes");
        uint8 state = uint8(escrow.state());
        require((outcomes == 1) == (state == 2 || state == 3), "state matches outcome");
        uint256 total = AMOUNT + donated;
        require(
            token.balanceOf(address(escrow)) + token.balanceOf(VAULT) + token.balanceOf(REFUND) == total,
            "conservation"
        );
        if (state == 2) require(token.balanceOf(REFUND) == 0, "refund paid after activation");
        if (state == 3) require(token.balanceOf(VAULT) == 0, "vault paid after cancellation");
        if (state == 1) {
            require(token.balanceOf(VAULT) == 0 && token.balanceOf(REFUND) == 0, "paid without outcome");
        }
    }
}

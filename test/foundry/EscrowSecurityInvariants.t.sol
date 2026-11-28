// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {CronosBootstrapEscrow} from "../../contracts/cronos/bridge/CronosBootstrapEscrow.sol";
import {MockERC20} from "../../contracts/test/MockERC20.sol";
import {BridgeTestBase} from "./utils/BridgeTestBase.sol";

// Stateful attack simulation of CronosBootstrapEscrow. The fuzzer funds the
// escrow (as the funding account or an outsider), submits honest and forged
// activation and cancellation approvals, pre-signs approvals and submits
// them later (including after the timeout), calls the permissionless timeout
// refund and terminal forwarding from arbitrary accounts, donates tokens, and
// moves time, including to the exact timeout boundary.

struct EscrowFuzzSelector {
    address addr;
    bytes4[] selectors;
}

library EscrowProperty {
    uint8 internal constant RECIPIENT = 1; // funds reached a non-fixed address
    uint8 internal constant TERMINAL = 2; // two terminal outcomes, or a state regression
    uint8 internal constant TIMEOUT = 3; // decision at/after the timeout, or refund before it
    uint8 internal constant AUTH = 4; // a decision without 2 configured signers
    uint8 internal constant SPEC = 5; // acceptance differs from the specification
    uint8 internal constant ATOMIC = 6; // a failed call changed state
    uint8 internal constant CROSS = 7; // a signature for another escrow, chain or domain counted
}

contract EscrowSecurityHandler is BridgeTestBase {
    uint8 internal constant AWAITING = 0;
    uint8 internal constant FUNDED = 1;
    uint8 internal constant ACTIVATED = 2;
    uint8 internal constant CANCELLED = 3;
    uint256 internal constant ACTORS = 4;
    uint256 internal constant MAX_STORED = 16;

    CronosBootstrapEscrow public immutable escrow;
    CronosBootstrapEscrow public immutable otherEscrow;
    MockERC20 public immutable token;
    address public immutable permanentVault;
    address public immutable refundRecipient;
    address public immutable funder;
    uint256 public immutable amount;
    uint256 public immutable timeout;

    uint256 public currentTime;
    uint8 public ghostState;
    uint256 public ghostFundedAt;
    uint256 public ghostDonated;
    uint256 public ghostDecisions;
    mapping(uint8 property => string reason) public violation;

    bytes[] internal _stored;
    uint256 internal _storedCursor;

    /// Signatures are expensive in the test runner. Decisions only ever use
    /// nonce 0 while the escrow is funded, so every approval that does not
    /// depend on a fuzzed key is signed once here.
    uint256 internal constant EXPIRED_DEADLINE = 1;
    mapping(bool activate => mapping(uint256 key => bytes signature)) internal _honest;
    mapping(uint256 kind => mapping(bool activate => bytes[] signatures)) internal _forged;

    uint256 public decisionsAccepted;
    uint256 public timeoutRefunds;
    uint256 public rejectedForgeries;

    constructor(
        CronosBootstrapEscrow targetEscrow,
        CronosBootstrapEscrow replayTargetEscrow,
        MockERC20 targetToken,
        uint256 startTime
    ) {
        escrow = targetEscrow;
        otherEscrow = replayTargetEscrow;
        token = targetToken;
        permanentVault = targetEscrow.permanentVault();
        refundRecipient = targetEscrow.refundRecipient();
        funder = targetEscrow.fundingAccount();
        amount = targetEscrow.expectedAmount();
        timeout = targetEscrow.REFUND_TIMEOUT();
        currentTime = startTime;
        for (uint256 a; a < 2; ++a) {
            bool activate = a == 0;
            bytes32 digest = _decisionDigest(escrow, _action(activate), escrow.genesisHash(), amount, block.chainid, FAR_DEADLINE);
            for (uint256 key = 1; key <= 3; ++key) _honest[activate][key] = _sign(key, digest);
            for (uint256 kind = 2; kind < 14; ++kind) {
                bytes[] memory sigs = _buildForged(kind, activate, digest);
                for (uint256 i; i < sigs.length; ++i) _forged[kind][activate].push(sigs[i]);
            }
        }
    }

    function _action(bool activate) internal view returns (bytes32) {
        return activate ? escrow.ACTION_ACTIVATE() : escrow.ACTION_CANCEL();
    }

    function _decisionDigest(
        CronosBootstrapEscrow target,
        bytes32 action,
        bytes32 genesis,
        uint256 expected,
        uint256 chainId,
        uint256 deadline
    ) internal view returns (bytes32) {
        return _typedDigest(
            _domain(target.EIP712_NAME(), target.EIP712_VERSION(), chainId, address(target)),
            _decisionStruct(action, genesis, expected, 0, deadline)
        );
    }

    /// Forged approval sets that do not depend on a fuzzed key (kinds 2-13).
    function _buildForged(uint256 kind, bool activate, bytes32 digest) internal returns (bytes[] memory sigs) {
        bytes32 action = _action(activate);
        bytes32 genesis = escrow.genesisHash();
        if (kind == 2 || kind == 3) {
            bytes memory one = _sign(kind == 2 ? 1 : 2, digest);
            sigs = new bytes[](2);
            sigs[0] = one;
            sigs[1] = kind == 2 ? one : _malleate(one);
        } else if (kind == 4) {
            sigs = _sign2(1, 2, _decisionDigest(escrow, action, keccak256("another genesis"), amount, block.chainid, FAR_DEADLINE));
        } else if (kind == 5) {
            sigs = _sign2(2, 3, _decisionDigest(escrow, action, genesis, amount + 1, block.chainid, FAR_DEADLINE));
        } else if (kind == 6) {
            sigs = _sign2(1, 3, _decisionDigest(otherEscrow, action, genesis, amount, block.chainid, FAR_DEADLINE));
        } else if (kind == 7) {
            sigs = _sign3(1, 2, 3, digest); // valid here, submitted to the other escrow
        } else if (kind == 8) {
            sigs = _sign2(1, 2, _decisionDigest(escrow, action, genesis, amount, block.chainid == 25 ? 338 : 25, FAR_DEADLINE));
        } else if (kind == 9) {
            // A bridge vault approval (other domain name and type) reused here.
            sigs = _sign2(1, 2, _typedDigest(
                _domain("Xitcoin Cronos Bridge Vault", "1", block.chainid, address(escrow)),
                _controlStruct(action, genesis, 0, 1, FAR_DEADLINE)
            ));
        } else if (kind == 10) {
            sigs = _sign2(1, 2, _decisionDigest(escrow, _action(!activate), genesis, amount, block.chainid, FAR_DEADLINE));
        } else if (kind == 11) {
            sigs = new bytes[](1);
            sigs[0] = _sign(3, digest);
        } else if (kind == 12) {
            sigs = _sign2(1, 2, _decisionDigest(escrow, action, genesis, amount, block.chainid, EXPIRED_DEADLINE));
        } else {
            sigs = _sign2(1, 2, digest);
            sigs[0] = _compact(sigs[0]);
            sigs[1] = _compact(sigs[1]);
        }
    }

    function actor(uint256 seed) public pure returns (address) {
        return address(uint160(0xA0 + (seed % ACTORS)));
    }

    function actorCount() external pure returns (uint256) {
        return ACTORS;
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    function fund(bool asFunder, uint256 actorSeed) external {
        _sync();
        address caller = asFunder ? funder : actor(actorSeed);
        bool expected = asFunder && ghostState == AWAITING;
        Snapshot memory before = _snapshot();
        (bool ok, ) = _tryAs(caller, address(escrow), abi.encodeCall(escrow.fund, ()));
        if (ok) {
            if (!asFunder) _fail(EscrowProperty.AUTH, "outsider funded the escrow");
            if (!expected) _fail(EscrowProperty.SPEC, "fund accepted twice");
            if (token.balanceOf(address(escrow)) != before.escrowBalance + amount) {
                _fail(EscrowProperty.SPEC, "fund did not pull the exact amount");
            }
            ghostState = FUNDED;
            ghostFundedAt = currentTime;
        } else {
            if (expected) _fail(EscrowProperty.SPEC, "valid funding rejected");
            _requireUnchanged(before, "failed fund changed state");
        }
    }

    /// An honest decision signed by 2 or 3 configured signers for the current
    /// nonce, submitted by an arbitrary account; then the same calldata again.
    function decide(bool activate, uint256 signerSeed, uint256 relayerSeed) external {
        _sync();
        bytes memory callData = _honestDecision(activate, signerSeed);
        _submitDecision(callData, activate, actor(relayerSeed), true);
        _submitDecision(callData, activate, actor(relayerSeed + 1), true);
    }

    /// Signs a decision now and keeps it for later submission.
    function presignDecision(bool activate, uint256 signerSeed) external {
        _sync();
        bytes memory callData = _honestDecision(activate, signerSeed);
        if (_stored.length < MAX_STORED) _stored.push(callData);
        else _stored[_storedCursor++ % MAX_STORED] = callData;
    }

    /// Submits a stored approval: valid only before the timeout and only while
    /// no decision has been taken.
    function submitStored(uint256 indexSeed, uint256 relayerSeed) external {
        _sync();
        if (_stored.length == 0) return;
        bytes memory callData = _stored[indexSeed % _stored.length];
        bool activate = bytes4(callData) == escrow.activate.selector;
        _submitDecision(callData, activate, actor(relayerSeed), true);
    }

    function refund(uint256 actorSeed) external {
        _sync();
        bool expected = ghostState == FUNDED && currentTime >= ghostFundedAt + timeout;
        Snapshot memory before = _snapshot();
        (bool ok, ) = _tryAs(actor(actorSeed), address(escrow), abi.encodeCall(escrow.refundAfterTimeout, ()));
        if (ok) {
            if (ghostState == FUNDED && currentTime < ghostFundedAt + timeout) {
                _fail(EscrowProperty.TIMEOUT, "refund before the timeout");
            }
            if (!expected) _fail(EscrowProperty.TERMINAL, "refund after a terminal state");
            if (token.balanceOf(refundRecipient) != before.refundBalance + before.escrowBalance) {
                _fail(EscrowProperty.RECIPIENT, "refund did not pay the whole balance to the refund recipient");
            }
            ghostState = CANCELLED;
            ++timeoutRefunds;
        } else {
            if (expected) _fail(EscrowProperty.SPEC, "valid timeout refund rejected");
            _requireUnchanged(before, "failed refund changed state");
        }
    }

    function forward(uint256 actorSeed) external {
        _sync();
        uint256 held = token.balanceOf(address(escrow));
        bool terminal = ghostState == ACTIVATED || ghostState == CANCELLED;
        bool expected = terminal && held > 0;
        address fixedRecipient = ghostState == ACTIVATED ? permanentVault : refundRecipient;
        Snapshot memory before = _snapshot();
        (bool ok, ) = _tryAs(actor(actorSeed), address(escrow), abi.encodeCall(escrow.forwardTerminalBalance, ()));
        if (ok) {
            if (!expected) _fail(EscrowProperty.SPEC, "forward accepted outside a terminal state");
            if (token.balanceOf(fixedRecipient) != (fixedRecipient == permanentVault ? before.vaultBalance : before.refundBalance) + held) {
                _fail(EscrowProperty.RECIPIENT, "forward did not pay the fixed recipient");
            }
        } else {
            if (expected) _fail(EscrowProperty.SPEC, "valid forward rejected");
            _requireUnchanged(before, "failed forward changed state");
        }
    }

    function donate(uint256 amountSeed) external {
        _sync();
        uint256 donation = _bound(amountSeed, 1, 1 ether);
        token.mint(address(escrow), donation);
        ghostDonated += donation;
    }

    function warp(uint256 secondsSeed) external {
        currentTime += _bound(secondsSeed, 0, 60 days);
        vm.warp(currentTime);
    }

    /// Jumps to within two seconds of the timeout boundary.
    function warpToBoundary(uint256 offsetSeed) external {
        if (ghostState == AWAITING) return;
        uint256 boundary = ghostFundedAt + timeout;
        uint256 target = boundary - 2 + (offsetSeed % 5);
        if (target > currentTime) currentTime = target;
        vm.warp(currentTime);
    }

    /// Decision approvals that must never count: outsiders, duplicates,
    /// malleated or compact signatures, a wrong genesis hash or amount, another
    /// escrow, chain or domain, the opposite decision, a single signature and
    /// an expired deadline.
    function attackDecision(uint256 kindSeed, uint256 keySeed, bool activate, uint256 relayerSeed) external {
        _sync();
        uint256 kind = kindSeed % 14;
        uint8 property = kind >= 6 && kind <= 9 ? EscrowProperty.CROSS : EscrowProperty.AUTH;
        bytes[] memory sigs;
        if (kind < 2) {
            bytes32 digest = _decisionDigest(escrow, _action(activate), escrow.genesisHash(), amount, block.chainid, FAR_DEADLINE);
            sigs = kind == 0
                ? _sign2(1 + (keySeed % 3), _outsiderKey(keySeed), digest)
                : _sign2(_outsiderKey(keySeed), _outsiderKey(keySeed + 3), digest);
        } else {
            bytes[] storage stored = _forged[kind][activate];
            sigs = new bytes[](stored.length);
            for (uint256 i; i < stored.length; ++i) sigs[i] = stored[i];
        }
        uint256 deadline = kind == 12 ? EXPIRED_DEADLINE : FAR_DEADLINE;
        bytes memory callData = activate
            ? abi.encodeCall(escrow.activate, (0, deadline, sigs))
            : abi.encodeCall(escrow.cancel, (0, deadline, sigs));

        if (kind == 7) {
            (bool crossOk, ) = _tryAs(actor(relayerSeed), address(otherEscrow), callData);
            if (crossOk) _fail(property, "decision for another escrow accepted");
            else ++rejectedForgeries;
            return;
        }
        Snapshot memory before = _snapshot();
        (bool ok, ) = _tryAs(actor(relayerSeed), address(escrow), callData);
        if (ok) _fail(property, "forged decision accepted");
        else {
            ++rejectedForgeries;
            _requireUnchanged(before, "rejected decision changed state");
        }
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    struct Snapshot {
        uint8 state;
        uint256 nonce;
        uint256 fundedAt;
        uint256 escrowBalance;
        uint256 vaultBalance;
        uint256 refundBalance;
        uint256 funderBalance;
    }

    function _honestDecision(bool activate, uint256 signerSeed) internal view returns (bytes memory) {
        uint256 pick = signerSeed % 4;
        bytes[] memory sigs;
        if (pick == 3) {
            sigs = new bytes[](3);
            sigs[0] = _honest[activate][3];
            sigs[1] = _honest[activate][1];
            sigs[2] = _honest[activate][2];
        } else {
            sigs = new bytes[](2);
            sigs[0] = _honest[activate][1 + pick];
            sigs[1] = _honest[activate][1 + ((pick + 1) % 3)];
        }
        return activate
            ? abi.encodeCall(escrow.activate, (0, FAR_DEADLINE, sigs))
            : abi.encodeCall(escrow.cancel, (0, FAR_DEADLINE, sigs));
    }

    function _submitDecision(bytes memory callData, bool activate, address relayer, bool honest) internal {
        bool beforeTimeout = ghostState != AWAITING && currentTime < ghostFundedAt + timeout;
        bool expected = honest && ghostState == FUNDED && beforeTimeout;
        Snapshot memory before = _snapshot();
        (bool ok, ) = _tryAs(relayer, address(escrow), callData);
        if (!ok) {
            if (expected) _fail(EscrowProperty.SPEC, "valid decision rejected");
            _requireUnchanged(before, "failed decision changed state");
            return;
        }
        if (!honest) _fail(EscrowProperty.AUTH, "forged decision accepted");
        if (ghostState == FUNDED && !beforeTimeout) _fail(EscrowProperty.TIMEOUT, "decision at or after the timeout");
        if (ghostState != FUNDED) _fail(EscrowProperty.TERMINAL, "decision outside the funded state");
        address paid = activate ? permanentVault : refundRecipient;
        uint256 paidBefore = activate ? before.vaultBalance : before.refundBalance;
        if (token.balanceOf(paid) != paidBefore + before.escrowBalance || token.balanceOf(address(escrow)) != 0) {
            _fail(EscrowProperty.RECIPIENT, "decision did not move the whole balance to its fixed recipient");
        }
        ghostState = activate ? ACTIVATED : CANCELLED;
        ++ghostDecisions;
        ++decisionsAccepted;
    }

    function _snapshot() internal view returns (Snapshot memory s) {
        s.state = uint8(escrow.state());
        s.nonce = escrow.decisionNonce();
        s.fundedAt = escrow.fundedAt();
        s.escrowBalance = token.balanceOf(address(escrow));
        s.vaultBalance = token.balanceOf(permanentVault);
        s.refundBalance = token.balanceOf(refundRecipient);
        s.funderBalance = token.balanceOf(funder);
    }

    function _requireUnchanged(Snapshot memory before, string memory why) internal {
        if (keccak256(abi.encode(_snapshot())) != keccak256(abi.encode(before))) {
            _fail(EscrowProperty.ATOMIC, why);
        }
    }

    function _sync() internal {
        vm.warp(currentTime);
    }

    function _fail(uint8 property, string memory why) internal {
        if (bytes(violation[property]).length == 0) violation[property] = why;
    }
}

contract EscrowSecurityInvariantTest is BridgeTestBase {
    uint256 internal constant START = 1_700_000_000;
    uint256 internal constant AMOUNT = 20_000_100 ether;
    address internal constant VAULT = address(0xA11CE);
    address internal constant REFUND = address(0xB0B);
    address internal constant FUNDER = address(0xF00D);
    address internal constant OTHER_FUNDER = address(0xF00E);
    bytes32 internal constant GENESIS = keccak256("synthetic-genesis");

    MockERC20 internal token;
    CronosBootstrapEscrow internal escrow;
    CronosBootstrapEscrow internal otherEscrow;
    EscrowSecurityHandler internal handler;

    function setUp() public {
        vm.warp(START);
        token = new MockERC20("Synthetic", "TEST");
        address[3] memory signers = [vm.addr(1), vm.addr(2), vm.addr(3)];
        escrow = new CronosBootstrapEscrow(token, VAULT, REFUND, FUNDER, GENESIS, AMOUNT, signers);
        // Identical parameters, same signers: only the verifying contract differs.
        otherEscrow = new CronosBootstrapEscrow(token, VAULT, REFUND, OTHER_FUNDER, GENESIS, AMOUNT, signers);
        token.mint(FUNDER, AMOUNT);
        vm.prank(FUNDER);
        token.approve(address(escrow), type(uint256).max);
        token.mint(OTHER_FUNDER, AMOUNT);
        vm.prank(OTHER_FUNDER);
        token.approve(address(otherEscrow), AMOUNT);
        vm.prank(OTHER_FUNDER);
        otherEscrow.fund();
        handler = new EscrowSecurityHandler(escrow, otherEscrow, token, START);
    }

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function targetSelectors() public view returns (EscrowFuzzSelector[] memory selectors) {
        bytes4[] memory actions = new bytes4[](10);
        actions[0] = EscrowSecurityHandler.fund.selector;
        actions[1] = EscrowSecurityHandler.decide.selector;
        actions[2] = EscrowSecurityHandler.presignDecision.selector;
        actions[3] = EscrowSecurityHandler.submitStored.selector;
        actions[4] = EscrowSecurityHandler.refund.selector;
        actions[5] = EscrowSecurityHandler.forward.selector;
        actions[6] = EscrowSecurityHandler.donate.selector;
        actions[7] = EscrowSecurityHandler.warp.selector;
        actions[8] = EscrowSecurityHandler.warpToBoundary.selector;
        actions[9] = EscrowSecurityHandler.attackDecision.selector;
        selectors = new EscrowFuzzSelector[](1);
        selectors[0] = EscrowFuzzSelector(address(handler), actions);
    }

    function _noViolation(uint8 property) internal view {
        string memory reason = handler.violation(property);
        require(bytes(reason).length == 0, reason);
    }

    /// All escrow properties, checked after every handler call. Each check
    /// names the property it enforces in its failure message.
    function invariant_escrowSecurityProperties() public view {
        _fundsOnlyToFixedRecipients();
        _terminalStatesExclusive();
        _timeoutHolds();
        _onlyQuorumDecides();
        _acceptanceMatchesSpecification();
    }

    /// Escrowed tokens only ever sit in the escrow or reach the permanent
    /// vault or the refund recipient; no relayer, attacker or other address
    /// receives any.
    function _fundsOnlyToFixedRecipients() internal view {
        _noViolation(EscrowProperty.RECIPIENT);
        uint256 funded = handler.ghostState() == 0 ? 0 : AMOUNT;
        require(
            token.balanceOf(address(escrow)) + token.balanceOf(VAULT) + token.balanceOf(REFUND) ==
                funded + handler.ghostDonated(),
            "recipients: escrowed funds left the fixed recipients"
        );
        require(token.balanceOf(FUNDER) == AMOUNT - funded, "recipients: funding account balance");
        uint256 count = handler.actorCount();
        for (uint256 i; i < count; ++i) {
            require(token.balanceOf(handler.actor(i)) == 0, "recipients: relayer or attacker holds tokens");
        }
        require(token.balanceOf(address(handler)) == 0, "recipients: handler holds tokens");
        require(token.totalSupply() == 2 * AMOUNT + handler.ghostDonated(), "recipients: tokens outside the known holders");
    }

    /// At most one terminal outcome, never two; the state never moves back;
    /// the recipient of the other outcome receives nothing.
    function _terminalStatesExclusive() internal view {
        _noViolation(EscrowProperty.TERMINAL);
        uint8 state = uint8(escrow.state());
        require(state == handler.ghostState(), "terminal: state differs from the model");
        require(escrow.decisionNonce() == handler.ghostDecisions(), "terminal: decision nonce");
        require(escrow.decisionNonce() <= 1, "terminal: more than one decision");
        if (state == 2) require(token.balanceOf(REFUND) == 0, "terminal: refund recipient paid after activation");
        if (state == 3) require(token.balanceOf(VAULT) == 0, "terminal: vault paid after cancellation");
        if (state < 2) {
            require(token.balanceOf(VAULT) == 0 && token.balanceOf(REFUND) == 0, "terminal: paid without an outcome");
        }
    }

    /// Decisions only before fundedAt + 180 days; the permissionless refund
    /// only from that instant.
    function _timeoutHolds() internal view {
        _noViolation(EscrowProperty.TIMEOUT);
        require(escrow.REFUND_TIMEOUT() == 180 days, "timeout: constant");
        require(escrow.fundedAt() == handler.ghostFundedAt(), "timeout: funding time");
        uint256 expected = handler.ghostState() == 0 ? 0 : handler.ghostFundedAt() + 180 days;
        require(escrow.refundAvailableAt() == expected, "timeout: refund availability");
    }

    /// Only 2 of the 3 configured signers decide; signatures for another
    /// escrow, chain or domain never count.
    function _onlyQuorumDecides() internal view {
        _noViolation(EscrowProperty.AUTH);
        _noViolation(EscrowProperty.CROSS);
        require(uint8(otherEscrow.state()) == 1 && otherEscrow.decisionNonce() == 0, "authorization: other escrow decided");
        require(token.balanceOf(address(otherEscrow)) == AMOUNT, "authorization: other escrow balance changed");
    }

    /// Acceptance matches the specification exactly, and a rejected call
    /// changes no state.
    function _acceptanceMatchesSpecification() internal view {
        _noViolation(EscrowProperty.SPEC);
        _noViolation(EscrowProperty.ATOMIC);
    }
}

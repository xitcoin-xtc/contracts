// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {CronosBridgeVault} from "../../contracts/cronos/bridge/CronosBridgeVault.sol";
import {MockERC20} from "../../contracts/test/MockERC20.sol";
import {BridgeTestBase} from "./utils/BridgeTestBase.sol";

// Stateful attack simulation of CronosBridgeVault. The fuzzer calls the
// handler below in random order with random arguments: deposits, donations,
// honest releases, replays and front-runs of earlier approvals, forged
// releases, honest and forged control actions (including signer rotation),
// pre-signed approvals executed after a rotation, guardian and outsider
// pauses, foreign-token and canonical-token rescues, and time jumps. After
// every call the invariants at the bottom of this file must hold.

struct VaultFuzzSelector {
    address addr;
    bytes4[] selectors;
}

/// Property identifiers used to record the first violation seen by the handler.
library VaultProperty {
    uint8 internal constant REPLAY = 1; // a burn ID paid more than once
    uint8 internal constant LIMITS = 2; // a release above a limit in force
    uint8 internal constant SPEC = 3; // acceptance differs from the specification
    uint8 internal constant AUTH = 4; // a release or control without 2 current signers
    uint8 internal constant PAUSE = 5; // XTC moved while paused, or pause by a non-guardian
    uint8 internal constant RESCUE = 6; // rescue moved XTC
    uint8 internal constant RECIPIENT = 7; // XTC paid to anyone but the approved recipient
    uint8 internal constant ATOMIC = 8; // a failed call changed state
    uint8 internal constant CROSS = 9; // a signature for another chain, vault or domain counted
}

contract VaultSecurityHandler is BridgeTestBase {
    uint256 internal constant KEY_POOL = 7; // candidate signer keys are 1..7
    uint256 internal constant BURN_POOL = 16;
    uint256 internal constant ACTORS = 4;
    uint256 internal constant MAX_STORED = 24;

    bytes32 internal constant ACTION_RESUME = keccak256("RESUME");
    bytes32 internal constant ACTION_ROTATE_SIGNERS = keccak256("ROTATE_SIGNERS");
    bytes32 internal constant ACTION_UPDATE_LIMITS = keccak256("UPDATE_LIMITS");
    bytes32 internal constant ACTION_CHANGE_GUARDIAN = keccak256("CHANGE_GUARDIAN");
    bytes32 internal constant ACTION_RESCUE_FOREIGN_TOKEN = keccak256("RESCUE_FOREIGN_TOKEN");
    bytes32 internal constant ACTION_UPDATE_DEPOSIT_LIMITS = keccak256("UPDATE_DEPOSIT_LIMITS");

    address internal constant DEPOSIT_DESTINATION = address(0xD357);
    address internal constant RESCUE_RECIPIENT = address(0x5E5C);

    struct Approval {
        bytes32 burn;
        address recipient;
        uint64 version;
        uint256 amount;
        uint256 deadline;
        bytes[] sigs;
    }

    struct Presigned {
        bool isGuardianChange;
        uint64 version;
        uint256 a;
        uint256 b;
        uint256 nonce;
        bytes callData;
    }

    struct VaultState {
        uint256 vaultBalance;
        uint256 governanceNonce;
        uint64 signerSetVersion;
        address guardian;
        bool paused;
        uint256 maxRelease;
        uint256 dailyRelease;
        uint256 releaseDay;
        uint256 releasedToday;
        uint256 maxDeposit;
        uint256 dailyDeposit;
        uint256 maxLocked;
        uint256 depositNonce;
        bytes32 signersHash;
    }

    CronosBridgeVault public immutable vault;
    CronosBridgeVault public immutable otherVault;
    MockERC20 public immutable token;
    MockERC20 public immutable foreign;

    uint256 public currentTime;
    uint256[3] internal _keys;
    address public guardianNow;

    uint256 public initialBalance;
    uint256 public otherVaultInitialBalance;
    uint256 public ghostDeposited;
    uint256 public ghostDonated;
    uint256 public ghostReleased;
    uint256 public ghostDepositCount;
    uint256 public ghostForeignDonated;
    uint256 public ghostForeignRescued;
    uint256 public ghostControlCount;
    uint256 public ghostRotations;
    bool public ghostPaused;
    uint256 public loweredBelowUsageDay = type(uint256).max;

    mapping(bytes32 burn => uint256 count) public releaseCount;
    mapping(uint256 day => uint256 amount) public releasedOnDay;
    mapping(address recipient => uint256 amount) public paidTo;
    mapping(uint8 property => string reason) public violation;
    /// vm.addr is slow in the test runner, so key addresses are computed once.
    mapping(uint256 key => address signer) public keyAddress;

    Approval[] internal _approvals;
    uint256 internal _approvalCursor;
    bytes[] internal _executedControls;
    uint256 internal _executedCursor;
    Presigned[] internal _presigned;
    uint256 internal _presignedCursor;

    // Call statistics, to check that the campaign reaches the interesting paths.
    uint256 public successfulReleases;
    uint256 public rejectedForgeries;
    uint256 public successfulRotations;

    constructor(
        CronosBridgeVault targetVault,
        CronosBridgeVault replayTargetVault,
        MockERC20 targetToken,
        MockERC20 foreignToken,
        uint256 startTime,
        address initialGuardian
    ) {
        vault = targetVault;
        otherVault = replayTargetVault;
        token = targetToken;
        foreign = foreignToken;
        currentTime = startTime;
        _keys = [uint256(1), 2, 3];
        for (uint256 key = 1; key <= KEY_POOL; ++key) keyAddress[key] = vm.addr(key);
        for (uint256 key = 901; key <= 903; ++key) keyAddress[key] = vm.addr(key);
        guardianNow = initialGuardian;
        initialBalance = targetToken.balanceOf(address(targetVault));
        otherVaultInitialBalance = targetToken.balanceOf(address(replayTargetVault));
    }

    // ------------------------------------------------------------------
    // Views used by the invariants
    // ------------------------------------------------------------------

    function currentKeys() external view returns (uint256[3] memory) {
        return _keys;
    }

    function isCurrentKey(uint256 key) public view returns (bool) {
        return key == _keys[0] || key == _keys[1] || key == _keys[2];
    }

    function burnId(uint256 index) public pure returns (bytes32) {
        return keccak256(abi.encode("vault-security-burn", index % BURN_POOL));
    }

    function burnPoolSize() external pure returns (uint256) {
        return BURN_POOL;
    }

    function actor(uint256 seed) public pure returns (address) {
        return address(uint160(0xA0 + (seed % ACTORS))); // relayers and attackers: never hold XTC
    }

    function recipient(uint256 seed) public pure returns (address) {
        return address(uint160(0xE0 + (seed % ACTORS))); // approved release recipients
    }

    function depositor(uint256 seed) public pure returns (address) {
        return address(uint160(0xC0 + (seed % ACTORS)));
    }

    function actorCount() external pure returns (uint256) {
        return ACTORS;
    }

    // ------------------------------------------------------------------
    // Deposits and donations
    // ------------------------------------------------------------------

    function deposit(uint256 amountSeed, uint256 depositorSeed) external {
        _sync();
        address from = depositor(depositorSeed);
        uint256 maximum = vault.maxDepositAmount();
        // Mostly within the per-deposit maximum, sometimes above it.
        uint256 amount = _bound(amountSeed >> 2, 1, amountSeed % 4 == 0 ? 2 * maximum : maximum);
        uint256 balanceBefore = token.balanceOf(address(vault));
        uint256 usedBefore = vault.depositDay() == currentTime / 1 days ? vault.depositedToday() : 0;
        bool paused = vault.paused();
        bool expected = !paused &&
            amount <= maximum &&
            usedBefore + amount <= vault.dailyDepositLimit() &&
            balanceBefore + amount <= vault.maxLockedAmount();

        token.mint(from, amount);
        vm.prank(from);
        token.approve(address(vault), amount);
        uint256 nonceBefore = vault.depositNonce();
        (bool ok, ) = _tryAs(from, address(vault), abi.encodeCall(vault.deposit, (amount, DEPOSIT_DESTINATION)));
        if (ok) {
            if (paused) _fail(VaultProperty.PAUSE, "deposit accepted while paused");
            if (!expected) _fail(VaultProperty.SPEC, "deposit outside limits accepted");
            if (token.balanceOf(address(vault)) != balanceBefore + amount) {
                _fail(VaultProperty.SPEC, "deposit did not lock the exact amount");
            }
            ghostDeposited += amount;
            ++ghostDepositCount;
        } else {
            if (expected) _fail(VaultProperty.SPEC, "deposit within limits rejected");
            if (token.balanceOf(address(vault)) != balanceBefore || vault.depositNonce() != nonceBefore) {
                _fail(VaultProperty.ATOMIC, "failed deposit changed state");
            }
        }
    }

    function donate(uint256 amountSeed) external {
        _sync();
        uint256 amount = _bound(amountSeed, 1, 3_000);
        token.mint(address(vault), amount);
        ghostDonated += amount;
    }

    function donateForeign(uint256 amountSeed) external {
        _sync();
        uint256 amount = _bound(amountSeed, 1, 3_000);
        foreign.mint(address(vault), amount);
        ghostForeignDonated += amount;
    }

    function warp(uint256 secondsSeed) external {
        currentTime += _bound(secondsSeed, 0, 2 days);
        vm.warp(currentTime);
    }

    // ------------------------------------------------------------------
    // Releases
    // ------------------------------------------------------------------

    /// An honest release approval (2 or 3 current signers), submitted by an
    /// arbitrary relayer. It may still be rejected by limits, pause, replay
    /// or liquidity; the handler predicts the outcome.
    function release(
        uint256 burnSeed,
        uint256 amountSeed,
        uint256 recipientSeed,
        uint256 relayerSeed,
        uint256 signerSeed
    ) external {
        _sync();
        Approval memory approval = _honestRelease(burnSeed, amountSeed, recipientSeed, signerSeed);
        _store(approval);
        _submitRelease(approval, actor(relayerSeed), true);
    }

    /// Anyone copies the calldata of a pending approval and submits it first.
    /// The approved recipient is paid once; the original submission and a
    /// recipient substitution by the front-runner both fail.
    function frontRunRelease(
        uint256 burnSeed,
        uint256 amountSeed,
        uint256 recipientSeed,
        uint256 attackerSeed,
        uint256 signerSeed
    ) external {
        _sync();
        Approval memory approval = _honestRelease(burnSeed, amountSeed, recipientSeed, signerSeed);
        address attacker = actor(attackerSeed);

        Approval memory redirected = _copy(approval);
        redirected.recipient = attacker;
        _submitRelease(redirected, attacker, false);

        _submitRelease(approval, attacker, true);
        _submitRelease(approval, actor(attackerSeed + 1), true);
    }

    /// Re-submits a stored approval exactly, reordered, or mutated.
    function replayApproval(uint256 indexSeed, uint256 relayerSeed, uint256 mutationSeed) external {
        _sync();
        if (_approvals.length == 0) return;
        Approval memory approval = _load(indexSeed % _approvals.length);
        address relayer = actor(relayerSeed);
        uint256 mutation = mutationSeed % 11;
        bool honest = mutation == 0 || mutation == 10;

        if (mutation == 1) approval.recipient = relayer;
        else if (mutation == 2) approval.amount += 1;
        else if (mutation == 3) approval.burn = keccak256(abi.encode(approval.burn));
        else if (mutation == 4) {
            approval.version = approval.version == vault.signerSetVersion()
                ? approval.version + 1
                : vault.signerSetVersion();
        } else if (mutation == 5) approval.deadline += 1;
        else if (mutation == 6) {
            bytes[] memory one = new bytes[](1);
            one[0] = approval.sigs[0];
            approval.sigs = one;
        } else if (mutation == 7) approval.sigs[1] = approval.sigs[0];
        else if (mutation == 8) approval.sigs[1] = _malleate(approval.sigs[1]);
        else if (mutation == 9) approval.sigs = _append(approval.sigs, _sign(_outsiderKey(mutationSeed), bytes32(0)));
        else if (mutation == 10) {
            bytes memory first = approval.sigs[0];
            approval.sigs[0] = approval.sigs[approval.sigs.length - 1];
            approval.sigs[approval.sigs.length - 1] = first;
        }
        _submitRelease(approval, relayer, honest);
    }

    /// Release approvals that must never count.
    function attackRelease(
        uint256 kindSeed,
        uint256 burnSeed,
        uint256 amountSeed,
        uint256 recipientSeed,
        uint256 keySeed
    ) external {
        _sync();
        uint256 kind = kindSeed % 13;
        bytes32 burn = burnId(burnSeed);
        address to = recipient(recipientSeed);
        uint256 amount = _bound(amountSeed, 1, vault.maxReleaseAmount());
        uint64 version = vault.signerSetVersion();
        bytes32 structHash = _releaseStruct(burn, to, amount, version, FAR_DEADLINE);
        bytes32 digest = _typedDigest(_vaultDomain(vault), structHash);
        bytes[] memory sigs;
        CronosBridgeVault target = vault;

        if (kind == 0) {
            sigs = _sign2(_keys[keySeed % 3], _outsiderKey(keySeed), digest);
        } else if (kind == 1) {
            sigs = _sign2(_outsiderKey(keySeed), _outsiderKey(keySeed + 1), digest);
        } else if (kind == 2) {
            (uint256 a, uint256 b) = _nonCurrentPair(keySeed);
            sigs = _sign2(a, b, digest);
        } else if (kind == 3) {
            uint256 otherChain = block.chainid == 25 ? 338 : 25;
            bytes32 foreignDigest = _typedDigest(
                _domain(vault.EIP712_NAME(), vault.EIP712_VERSION(), otherChain, address(vault)),
                structHash
            );
            sigs = _sign2(_keys[0], _keys[1], foreignDigest);
            _expectReleaseRejected(vault, burn, to, amount, version, sigs, VaultProperty.CROSS);
            return;
        } else if (kind == 4) {
            sigs = _sign2(_keys[0], _keys[1], _typedDigest(_vaultDomain(otherVault), structHash));
            _expectReleaseRejected(vault, burn, to, amount, version, sigs, VaultProperty.CROSS);
            return;
        } else if (kind == 5) {
            // Signed for this vault, submitted to another vault that shares signers 1, 2 and 3.
            sigs = _sign3(1, 2, 3, _typedDigest(_vaultDomain(vault), _releaseStruct(burn, to, amount, 1, FAR_DEADLINE)));
            target = otherVault;
            _expectReleaseRejected(target, burn, to, amount, 1, sigs, VaultProperty.CROSS);
            return;
        } else if (kind == 6) {
            bytes32 escrowDomain = _domain("Xitcoin Cronos Bootstrap Escrow", "1", block.chainid, address(vault));
            sigs = _sign2(_keys[0], _keys[2], _typedDigest(escrowDomain, structHash));
            _expectReleaseRejected(vault, burn, to, amount, version, sigs, VaultProperty.CROSS);
            return;
        } else if (kind == 7) {
            bytes32 controlDigest = _typedDigest(
                _vaultDomain(vault),
                _controlStruct(burn, bytes32(uint256(uint160(to))), amount, version, FAR_DEADLINE)
            );
            sigs = _sign2(_keys[1], _keys[2], controlDigest);
        } else if (kind == 8) {
            bytes memory one = _sign(_keys[keySeed % 3], digest);
            sigs = new bytes[](2);
            sigs[0] = one;
            sigs[1] = one;
        } else if (kind == 9) {
            bytes memory one = _sign(_keys[keySeed % 3], digest);
            sigs = new bytes[](2);
            sigs[0] = one;
            sigs[1] = _malleate(one);
        } else if (kind == 10) {
            sigs = _sign2(_keys[0], _keys[1], digest);
            sigs[0] = _compact(sigs[0]);
            sigs[1] = _compact(sigs[1]);
        } else if (kind == 11) {
            sigs = _sign2(_keys[0], _keys[1], digest);
            sigs[keySeed % 2] = _withV(sigs[keySeed % 2], uint8(_bound(keySeed, 0, 26)));
        } else {
            sigs = new bytes[](2);
            sigs[0] = abi.encodePacked(keccak256(abi.encode(keySeed)), keccak256(abi.encode(burnSeed)), uint8(27));
            sigs[1] = abi.encodePacked(keccak256(abi.encode(amountSeed)), keccak256(abi.encode(kindSeed)), uint8(28));
        }

        Approval memory forged = Approval(burn, to, version, amount, FAR_DEADLINE, sigs);
        _submitRelease(forged, actor(keySeed), false);
    }

    // ------------------------------------------------------------------
    // Guardian
    // ------------------------------------------------------------------

    /// The guardian pauses in a quarter of the calls; otherwise an outsider tries.
    function pause(uint256 actorSeed) external {
        _sync();
        bool asGuardian = actorSeed % 4 == 0;
        address caller = asGuardian ? guardianNow : actor(actorSeed >> 2);
        bool pausedBefore = vault.paused();
        (bool ok, ) = _tryAs(caller, address(vault), abi.encodeCall(vault.pause, ()));
        if (ok) {
            if (!asGuardian) _fail(VaultProperty.PAUSE, "non-guardian paused the vault");
            if (pausedBefore) _fail(VaultProperty.SPEC, "pause accepted while already paused");
            ghostPaused = true;
        } else if (asGuardian && !pausedBefore) {
            _fail(VaultProperty.SPEC, "guardian pause rejected");
        }
        if (!ok && vault.paused() != pausedBefore) _fail(VaultProperty.ATOMIC, "failed pause changed state");
    }

    // ------------------------------------------------------------------
    // Control actions
    // ------------------------------------------------------------------

    /// An honest control action signed by 2 of the current 3 signers with the
    /// current nonce. Action 6 attempts to rescue canonical XTC with a valid
    /// quorum, which must always fail.
    function control(
        uint256 actionSeed,
        uint256 seedA,
        uint256 seedB,
        uint256 signerSeed,
        uint256 relayerSeed
    ) external {
        _sync();
        // A paused vault is resumed in half of the control calls, so that the
        // campaign does not stay paused.
        uint256 action = vault.paused() && actionSeed % 2 == 0 ? 0 : (actionSeed >> 1) % 7;
        _control(action, seedA, seedB, signerSeed, relayerSeed);
    }

    /// An honest signer rotation to three keys drawn from 1..7.
    function rotate(uint256 keysSeed, uint256 signerSeed, uint256 relayerSeed) external {
        _sync();
        _control(1, keysSeed, 0, signerSeed, relayerSeed);
    }

    function _control(
        uint256 action,
        uint256 seedA,
        uint256 seedB,
        uint256 signerSeed,
        uint256 relayerSeed
    ) internal {
        uint256 nonce = vault.governanceNonce();
        bytes memory callData;
        bool expected = true;
        uint256[3] memory newKeys;
        address newGuardian = _guardian(seedA);

        if (action == 0) {
            bytes[] memory sigs = _controlSigs(ACTION_RESUME, bytes32(0), nonce, signerSeed);
            callData = abi.encodeCall(vault.resume, (nonce, FAR_DEADLINE, sigs));
            expected = vault.paused();
        } else if (action == 1) {
            newKeys = _pickKeys(seedA);
            address[3] memory newSigners = [keyAddress[newKeys[0]], keyAddress[newKeys[1]], keyAddress[newKeys[2]]];
            bytes[] memory sigs = _controlSigs(ACTION_ROTATE_SIGNERS, keccak256(abi.encode(newSigners)), nonce, signerSeed);
            callData = abi.encodeCall(vault.rotateSigners, (newSigners, nonce, FAR_DEADLINE, sigs));
        } else if (action == 2) {
            (uint256 maximum, uint256 daily) = _releaseLimits(seedA, seedB);
            bytes[] memory sigs = _controlSigs(ACTION_UPDATE_LIMITS, keccak256(abi.encode(maximum, daily)), nonce, signerSeed);
            callData = abi.encodeCall(vault.updateLimits, (maximum, daily, nonce, FAR_DEADLINE, sigs));
        } else if (action == 3) {
            uint256 maximum = _bound(seedA, 1, 3_000);
            uint256 daily = _bound(seedB, maximum, 20_000);
            uint256 locked = _bound(seedA ^ seedB, maximum, 200_000);
            bytes[] memory sigs = _controlSigs(
                ACTION_UPDATE_DEPOSIT_LIMITS,
                keccak256(abi.encode(maximum, daily, locked)),
                nonce,
                signerSeed
            );
            callData = abi.encodeCall(vault.updateDepositLimits, (maximum, daily, locked, nonce, FAR_DEADLINE, sigs));
        } else if (action == 4) {
            bytes[] memory sigs = _controlSigs(ACTION_CHANGE_GUARDIAN, keccak256(abi.encode(newGuardian)), nonce, signerSeed);
            callData = abi.encodeCall(vault.changeGuardian, (newGuardian, nonce, FAR_DEADLINE, sigs));
        } else if (action == 5) {
            uint256 held = foreign.balanceOf(address(vault));
            uint256 amount = _bound(seedA, 1, held + 10);
            bytes[] memory sigs = _controlSigs(
                ACTION_RESCUE_FOREIGN_TOKEN,
                keccak256(abi.encode(address(foreign), RESCUE_RECIPIENT, amount)),
                nonce,
                signerSeed
            );
            callData = abi.encodeCall(vault.rescueForeignToken, (foreign, RESCUE_RECIPIENT, amount, nonce, FAR_DEADLINE, sigs));
            expected = amount <= held;
        } else {
            uint256 amount = _bound(seedA, 1, token.balanceOf(address(vault)) + 1);
            bytes[] memory sigs = _controlSigs(
                ACTION_RESCUE_FOREIGN_TOKEN,
                keccak256(abi.encode(address(token), RESCUE_RECIPIENT, amount)),
                nonce,
                signerSeed
            );
            callData = abi.encodeCall(vault.rescueForeignToken, (token, RESCUE_RECIPIENT, amount, nonce, FAR_DEADLINE, sigs));
            expected = false;
        }

        VaultState memory before = _state(vault);
        uint256 foreignBefore = foreign.balanceOf(address(vault));
        (bool ok, ) = _tryAs(actor(relayerSeed), address(vault), callData);

        if (!ok) {
            if (expected) _fail(VaultProperty.SPEC, "valid control action rejected");
            _requireUnchanged(vault, before, "failed control changed state");
            return;
        }
        if (action == 6) {
            _fail(VaultProperty.RESCUE, "rescue of canonical XTC accepted");
            return;
        }
        if (!expected) _fail(VaultProperty.SPEC, "invalid control action accepted");
        if (vault.governanceNonce() != nonce + 1) _fail(VaultProperty.SPEC, "control did not consume one nonce");
        if (token.balanceOf(address(vault)) != before.vaultBalance) {
            _fail(VaultProperty.RESCUE, "control action moved XTC");
        }
        ++ghostControlCount;
        _remember(callData);

        if (action == 0) {
            ghostPaused = false;
        } else if (action == 1) {
            _keys = newKeys;
            ++ghostRotations;
            ++successfulRotations;
        } else if (action == 2) {
            _noteLoweredReleaseLimit();
        } else if (action == 4) {
            guardianNow = newGuardian;
        } else if (action == 5) {
            uint256 moved = foreignBefore - foreign.balanceOf(address(vault));
            ghostForeignRescued += moved;
        }
    }

    /// Control approvals that must never count. The forged action is the most
    /// valuable one: rotating the signer set to attacker keys.
    function attackControl(uint256 kindSeed, uint256 seedA, uint256 keySeed, uint256 relayerSeed) external {
        _sync();
        uint256 kind = kindSeed % 17;
        CronosBridgeVault target = vault;
        uint8 property = kind >= 6 && kind <= 8 ? VaultProperty.CROSS : VaultProperty.AUTH;
        bytes memory callData;

        if (kind == 8) {
            target = otherVault;
            callData = _rotationForOtherVaultSignedForThisVault();
        } else if (kind == 15) {
            if (_executedControls.length == 0) return;
            callData = _executedControls[seedA % _executedControls.length];
        } else if (kind == 3 || kind == 4 || kind == 14) {
            callData = _rotationWithStaleParameters(kind, seedA);
        } else {
            callData = abi.encodeCall(
                vault.rotateSigners,
                (_attackerSigners(), vault.governanceNonce(), FAR_DEADLINE, _forgedControlSigs(kind, keySeed))
            );
        }

        VaultState memory before = _state(target);
        (bool ok, ) = _tryAs(actor(relayerSeed), address(target), callData);
        if (ok) {
            _fail(property, "forged control action accepted");
        } else {
            ++rejectedForgeries;
            _requireUnchanged(target, before, "rejected control changed state");
        }
    }

    function _attackerSigners() internal view returns (address[3] memory) {
        return [keyAddress[901], keyAddress[902], keyAddress[903]];
    }

    function _attackerRotationStruct(uint256 nonce, uint64 version, uint256 deadline) internal view returns (bytes32) {
        return _controlStruct(ACTION_ROTATE_SIGNERS, keccak256(abi.encode(_attackerSigners())), nonce, version, deadline);
    }

    /// Signatures over the attacker rotation for the current nonce that must
    /// not count: wrong signers, wrong version, wrong chain or vault, wrong
    /// action or type, duplicates, malleated, compact or single signatures.
    function _forgedControlSigs(uint256 kind, uint256 keySeed) internal returns (bytes[] memory sigs) {
        uint256 nonce = vault.governanceNonce();
        uint64 version = vault.signerSetVersion();
        bytes32 digest = _typedDigest(_vaultDomain(vault), _attackerRotationStruct(nonce, version, FAR_DEADLINE));

        if (kind == 0) return _sign2(_keys[keySeed % 3], _outsiderKey(keySeed), digest);
        if (kind == 1) return _sign2(_outsiderKey(keySeed), _outsiderKey(keySeed + 7), digest);
        if (kind == 2) {
            (uint256 a, uint256 b) = _nonCurrentPair(keySeed);
            return _sign2(a, b, digest);
        }
        if (kind == 5) {
            uint64 wrongVersion = version == 1 ? 2 : version - 1;
            return _sign2(_keys[1], _keys[2], _typedDigest(
                _vaultDomain(vault),
                _attackerRotationStruct(nonce, wrongVersion, FAR_DEADLINE)
            ));
        }
        if (kind == 6) {
            uint256 otherChain = block.chainid == 1 ? 25 : 1;
            return _sign2(_keys[0], _keys[2], _typedDigest(
                _domain(vault.EIP712_NAME(), vault.EIP712_VERSION(), otherChain, address(vault)),
                _attackerRotationStruct(nonce, version, FAR_DEADLINE)
            ));
        }
        if (kind == 7) {
            return _sign2(_keys[0], _keys[1], _typedDigest(
                _vaultDomain(otherVault),
                _attackerRotationStruct(nonce, version, FAR_DEADLINE)
            ));
        }
        if (kind == 9 || kind == 10) {
            bytes memory one = _sign(_keys[keySeed % 3], digest);
            sigs = new bytes[](2);
            sigs[0] = one;
            sigs[1] = kind == 9 ? one : _malleate(one);
            return sigs;
        }
        if (kind == 11) {
            // An approval for a guardian change, submitted as a signer rotation.
            return _sign2(_keys[0], _keys[1], _typedDigest(
                _vaultDomain(vault),
                _controlStruct(ACTION_CHANGE_GUARDIAN, keccak256(abi.encode(keyAddress[901])), nonce, version, FAR_DEADLINE)
            ));
        }
        if (kind == 12) {
            // A release approval reused as a control approval.
            return _sign2(_keys[0], _keys[1], _typedDigest(
                _vaultDomain(vault),
                _releaseStruct(ACTION_ROTATE_SIGNERS, keyAddress[901], nonce, version, FAR_DEADLINE)
            ));
        }
        if (kind == 13) {
            sigs = new bytes[](1);
            sigs[0] = _sign(_keys[keySeed % 3], digest);
            return sigs;
        }
        sigs = _sign2(_keys[0], _keys[1], digest);
        sigs[0] = _compact(sigs[0]);
        sigs[1] = _compact(sigs[1]);
    }

    /// Current signers, but a used or future nonce (kinds 3 and 4) or an
    /// expired deadline (kind 14).
    function _rotationWithStaleParameters(uint256 kind, uint256 seedA) internal returns (bytes memory) {
        uint256 nonce = vault.governanceNonce();
        uint256 deadline = FAR_DEADLINE;
        if (kind == 14) {
            deadline = currentTime - 1;
        } else if (kind == 4 || nonce == 0) {
            nonce = nonce + 1 + (seedA % 3);
        } else {
            nonce = nonce - 1 - (seedA % nonce);
        }
        bytes[] memory sigs = _sign2(_keys[0], _keys[1], _typedDigest(
            _vaultDomain(vault),
            _attackerRotationStruct(nonce, vault.signerSetVersion(), deadline)
        ));
        return abi.encodeCall(vault.rotateSigners, (_attackerSigners(), nonce, deadline, sigs));
    }

    /// The other vault's own signers (keys 1, 2, 3) sign for this vault's
    /// domain; the approval is submitted to the other vault.
    function _rotationForOtherVaultSignedForThisVault() internal returns (bytes memory) {
        uint256 otherNonce = otherVault.governanceNonce();
        bytes[] memory sigs = _sign3(1, 2, 3, _typedDigest(
            _vaultDomain(vault),
            _attackerRotationStruct(otherNonce, 1, FAR_DEADLINE)
        ));
        return abi.encodeCall(otherVault.rotateSigners, (_attackerSigners(), otherNonce, FAR_DEADLINE, sigs));
    }

    /// Signs a limit or guardian change for the current or a future nonce under
    /// the current signer set, without executing it.
    function presignControl(uint256 seedA, uint256 seedB, uint256 signerSeed, uint256 nonceOffsetSeed) external {
        _sync();
        uint256 nonce = vault.governanceNonce() + (nonceOffsetSeed % 3);
        Presigned memory p;
        p.isGuardianChange = seedA % 2 == 0;
        p.nonce = nonce;
        p.version = vault.signerSetVersion();
        if (p.isGuardianChange) {
            address newGuardian = _guardian(seedB);
            p.a = uint256(uint160(newGuardian));
            bytes[] memory sigs = _controlSigs(ACTION_CHANGE_GUARDIAN, keccak256(abi.encode(newGuardian)), nonce, signerSeed);
            p.callData = abi.encodeCall(vault.changeGuardian, (newGuardian, nonce, FAR_DEADLINE, sigs));
        } else {
            (p.a, p.b) = _releaseLimits(seedA, seedB);
            bytes[] memory sigs = _controlSigs(ACTION_UPDATE_LIMITS, keccak256(abi.encode(p.a, p.b)), nonce, signerSeed);
            p.callData = abi.encodeCall(vault.updateLimits, (p.a, p.b, nonce, FAR_DEADLINE, sigs));
        }
        if (_presigned.length < MAX_STORED) {
            _presigned.push(p);
        } else {
            _presigned[_presignedCursor++ % MAX_STORED] = p;
        }
    }

    /// Executes a pre-signed approval. It is valid only for the exact nonce and
    /// the signer-set version under which it was signed: a rotation in between
    /// invalidates it even when the same keys remain signers.
    function submitPresigned(uint256 indexSeed, uint256 relayerSeed) external {
        _sync();
        if (_presigned.length == 0) return;
        Presigned memory p = _presigned[indexSeed % _presigned.length];
        bool expected = p.nonce == vault.governanceNonce() && p.version == vault.signerSetVersion();
        VaultState memory before = _state(vault);
        (bool ok, ) = _tryAs(actor(relayerSeed), address(vault), p.callData);
        if (!ok) {
            if (expected) _fail(VaultProperty.SPEC, "valid pre-signed control rejected");
            _requireUnchanged(vault, before, "failed pre-signed control changed state");
            return;
        }
        if (!expected) {
            _fail(
                p.version != before.signerSetVersion ? VaultProperty.AUTH : VaultProperty.SPEC,
                "stale pre-signed control accepted"
            );
        }
        ++ghostControlCount;
        _remember(p.callData);
        if (p.isGuardianChange) guardianNow = address(uint160(p.a));
        else _noteLoweredReleaseLimit();
    }

    // ------------------------------------------------------------------
    // Internal: releases
    // ------------------------------------------------------------------

    function _honestRelease(uint256 burnSeed, uint256 amountSeed, uint256 recipientSeed, uint256 signerSeed)
        internal
        returns (Approval memory approval)
    {
        approval.burn = burnId(burnSeed);
        approval.recipient = recipient(recipientSeed);
        uint256 maximum = vault.maxReleaseAmount();
        // Mostly within the per-release limit, sometimes above it.
        approval.amount = _bound(amountSeed >> 2, 1, amountSeed % 4 == 0 ? 2 * maximum : maximum);
        approval.version = vault.signerSetVersion();
        approval.deadline = FAR_DEADLINE;
        bytes32 digest = _typedDigest(
            _vaultDomain(vault),
            _releaseStruct(approval.burn, approval.recipient, approval.amount, approval.version, approval.deadline)
        );
        uint256 pick = signerSeed % 4;
        if (pick == 3) {
            approval.sigs = _sign3(_keys[0], _keys[1], _keys[2], digest);
        } else {
            approval.sigs = _sign2(_keys[pick], _keys[(pick + 1) % 3], digest);
        }
    }

    function _releaseExpected(Approval memory a) internal view returns (bool) {
        if (vault.paused()) return false;
        if (vault.processedBurns(a.burn)) return false;
        if (a.version != vault.signerSetVersion()) return false;
        if (block.timestamp > a.deadline) return false;
        if (a.amount > vault.maxReleaseAmount()) return false;
        uint256 used = vault.releaseDay() == block.timestamp / 1 days ? vault.releasedToday() : 0;
        if (used + a.amount > vault.dailyReleaseLimit()) return false;
        return token.balanceOf(address(vault)) >= a.amount;
    }

    function _submitRelease(Approval memory a, address relayer, bool honest) internal {
        bool expected = honest && _releaseExpected(a);
        bool processedBefore = vault.processedBurns(a.burn);
        VaultState memory before = _state(vault);
        uint256 recipientBefore = token.balanceOf(a.recipient);
        uint256 relayerBefore = token.balanceOf(relayer);

        vm.prank(relayer);
        try vault.release(a.burn, a.recipient, a.amount, a.version, a.deadline, a.sigs) {
            if (!honest) _fail(VaultProperty.AUTH, "forged release accepted");
            if (!expected) _fail(VaultProperty.SPEC, "release outside the specification accepted");
            if (before.paused) _fail(VaultProperty.PAUSE, "release accepted while paused");
            if (processedBefore || releaseCount[a.burn] != 0) _fail(VaultProperty.REPLAY, "burn released twice");
            if (a.amount > before.maxRelease) _fail(VaultProperty.LIMITS, "release above the per-transfer limit");
            if (vault.releasedToday() > before.dailyRelease) _fail(VaultProperty.LIMITS, "release above the daily limit");
            if (token.balanceOf(a.recipient) != recipientBefore + a.amount) {
                _fail(VaultProperty.RECIPIENT, "recipient not paid the exact amount");
            }
            if (token.balanceOf(relayer) != relayerBefore) _fail(VaultProperty.RECIPIENT, "relayer received XTC");
            if (token.balanceOf(address(vault)) + a.amount != before.vaultBalance) {
                _fail(VaultProperty.RECIPIENT, "vault debit differs from the approved amount");
            }
            ++releaseCount[a.burn];
            ghostReleased += a.amount;
            releasedOnDay[block.timestamp / 1 days] += a.amount;
            paidTo[a.recipient] += a.amount;
            ++successfulReleases;
        } catch {
            if (expected) _fail(VaultProperty.SPEC, "valid release rejected");
            if (!honest) ++rejectedForgeries;
            if (vault.processedBurns(a.burn) != processedBefore) _fail(VaultProperty.ATOMIC, "failed release marked the burn");
            if (token.balanceOf(a.recipient) != recipientBefore) _fail(VaultProperty.ATOMIC, "failed release paid the recipient");
            _requireUnchanged(vault, before, "failed release changed state");
        }
    }

    function _expectReleaseRejected(
        CronosBridgeVault target,
        bytes32 burn,
        address to,
        uint256 amount,
        uint64 version,
        bytes[] memory sigs,
        uint8 property
    ) internal {
        VaultState memory before = _state(target);
        bool processedBefore = target.processedBurns(burn);
        (bool ok, ) = _try(
            address(target),
            abi.encodeCall(target.release, (burn, to, amount, version, FAR_DEADLINE, sigs))
        );
        if (ok) {
            _fail(property, "release signed for another chain, vault or domain accepted");
            if (target == vault) {
                ++releaseCount[burn];
                ghostReleased += amount;
                releasedOnDay[block.timestamp / 1 days] += amount;
                paidTo[to] += amount;
            }
            return;
        }
        ++rejectedForgeries;
        if (target.processedBurns(burn) != processedBefore) _fail(VaultProperty.ATOMIC, "rejected release marked the burn");
        _requireUnchanged(target, before, "rejected release changed state");
    }

    function _store(Approval memory approval) internal {
        Approval storage slot;
        if (_approvals.length < MAX_STORED) {
            slot = _approvals.push();
        } else {
            slot = _approvals[_approvalCursor++ % MAX_STORED];
            delete slot.sigs;
        }
        slot.burn = approval.burn;
        slot.recipient = approval.recipient;
        slot.amount = approval.amount;
        slot.version = approval.version;
        slot.deadline = approval.deadline;
        for (uint256 i; i < approval.sigs.length; ++i) slot.sigs.push(approval.sigs[i]);
    }

    function _load(uint256 index) internal view returns (Approval memory approval) {
        Approval storage slot = _approvals[index];
        approval.burn = slot.burn;
        approval.recipient = slot.recipient;
        approval.amount = slot.amount;
        approval.version = slot.version;
        approval.deadline = slot.deadline;
        approval.sigs = new bytes[](slot.sigs.length);
        for (uint256 i; i < slot.sigs.length; ++i) approval.sigs[i] = slot.sigs[i];
    }

    function _copy(Approval memory a) internal pure returns (Approval memory c) {
        c = Approval(a.burn, a.recipient, a.version, a.amount, a.deadline, new bytes[](a.sigs.length));
        for (uint256 i; i < a.sigs.length; ++i) c.sigs[i] = a.sigs[i];
    }

    function _append(bytes[] memory sigs, bytes memory extra) internal pure returns (bytes[] memory out) {
        out = new bytes[](sigs.length + 1);
        for (uint256 i; i < sigs.length; ++i) out[i] = sigs[i];
        out[sigs.length] = extra;
    }

    // ------------------------------------------------------------------
    // Internal: control helpers
    // ------------------------------------------------------------------

    function _controlSigs(bytes32 action, bytes32 payloadHash, uint256 nonce, uint256 signerSeed)
        internal
        returns (bytes[] memory)
    {
        bytes32 digest = _typedDigest(
            _vaultDomain(vault),
            _controlStruct(action, payloadHash, nonce, vault.signerSetVersion(), FAR_DEADLINE)
        );
        uint256 pick = signerSeed % 4;
        if (pick == 3) return _sign3(_keys[0], _keys[1], _keys[2], digest);
        return _sign2(_keys[pick], _keys[(pick + 1) % 3], digest);
    }

    function _releaseLimits(uint256 seedA, uint256 seedB) internal pure returns (uint256 maximum, uint256 daily) {
        maximum = _bound(seedA, 1, 5_000);
        daily = _bound(seedB, maximum, 20_000);
    }

    function _noteLoweredReleaseLimit() internal {
        uint256 today = currentTime / 1 days;
        if (vault.releaseDay() == today && vault.releasedToday() > vault.dailyReleaseLimit()) {
            loweredBelowUsageDay = today;
        }
    }

    function _guardian(uint256 seed) internal pure returns (address) {
        return address(uint160(0x6A00 + (seed % 3)));
    }

    /// Three distinct keys from 1..KEY_POOL.
    function _pickKeys(uint256 seed) internal pure returns (uint256[3] memory picked) {
        uint256[KEY_POOL] memory pool;
        for (uint256 i; i < KEY_POOL; ++i) pool[i] = i + 1;
        for (uint256 i; i < 3; ++i) {
            uint256 j = i + (uint256(keccak256(abi.encode(seed, i))) % (KEY_POOL - i));
            (pool[i], pool[j]) = (pool[j], pool[i]);
            picked[i] = pool[i];
        }
    }

    /// Two distinct keys from 1..KEY_POOL that are not current signers
    /// (retired signers or candidates that were never configured).
    function _nonCurrentPair(uint256 seed) internal view returns (uint256 a, uint256 b) {
        uint256[KEY_POOL] memory others;
        uint256 count;
        for (uint256 key = 1; key <= KEY_POOL; ++key) {
            if (!isCurrentKey(key)) others[count++] = key;
        }
        uint256 first = seed % count;
        a = others[first];
        b = others[(first + 1 + (seed >> 8) % (count - 1)) % count];
    }

    function _remember(bytes memory callData) internal {
        if (_executedControls.length < MAX_STORED) {
            _executedControls.push(callData);
        } else {
            _executedControls[_executedCursor++ % MAX_STORED] = callData;
        }
    }

    // ------------------------------------------------------------------
    // Internal: state snapshots
    // ------------------------------------------------------------------

    function _state(CronosBridgeVault target) internal view returns (VaultState memory s) {
        s.vaultBalance = token.balanceOf(address(target));
        s.governanceNonce = target.governanceNonce();
        s.signerSetVersion = target.signerSetVersion();
        s.guardian = target.guardian();
        s.paused = target.paused();
        s.maxRelease = target.maxReleaseAmount();
        s.dailyRelease = target.dailyReleaseLimit();
        s.releaseDay = target.releaseDay();
        s.releasedToday = target.releasedToday();
        s.maxDeposit = target.maxDepositAmount();
        s.dailyDeposit = target.dailyDepositLimit();
        s.maxLocked = target.maxLockedAmount();
        s.depositNonce = target.depositNonce();
        s.signersHash = keccak256(abi.encode(target.signers()));
    }

    function _requireUnchanged(CronosBridgeVault target, VaultState memory before, string memory why) internal {
        VaultState memory afterState = _state(target);
        if (keccak256(abi.encode(afterState)) != keccak256(abi.encode(before))) {
            _fail(VaultProperty.ATOMIC, why);
        }
    }

    function _sync() internal {
        vm.warp(currentTime);
    }

    function _fail(uint8 property, string memory why) internal {
        if (bytes(violation[property]).length == 0) violation[property] = why;
    }
}

/// Invariants checked after every handler call.
contract VaultSecurityInvariantTest is BridgeTestBase {
    uint256 internal constant START = 1_700_000_000;
    uint256 internal constant INITIAL_BALANCE = 20_000;
    uint256 internal constant OTHER_VAULT_BALANCE = 7_777;
    address internal constant GUARDIAN = address(0x6A00);

    MockERC20 internal token;
    MockERC20 internal foreign;
    CronosBridgeVault internal vault;
    CronosBridgeVault internal otherVault;
    VaultSecurityHandler internal handler;

    function setUp() public {
        vm.warp(START);
        token = new MockERC20("Synthetic", "TEST");
        foreign = new MockERC20("Synthetic foreign", "FOREIGN");
        address[3] memory signers = [vm.addr(1), vm.addr(2), vm.addr(3)];
        vault = new CronosBridgeVault(
            token, keccak256("synthetic-route"), signers, GUARDIAN,
            1_000, 5_000, 1_000, 5_000, 100_000, false
        );
        // Same chain, same asset, same route and same initial signers: only the
        // EIP-712 verifying contract differs.
        otherVault = new CronosBridgeVault(
            token, keccak256("synthetic-route"), signers, GUARDIAN,
            1_000, 5_000, 1_000, 5_000, 100_000, false
        );
        token.mint(address(vault), INITIAL_BALANCE);
        token.mint(address(otherVault), OTHER_VAULT_BALANCE);
        handler = new VaultSecurityHandler(vault, otherVault, token, foreign, START, GUARDIAN);
    }

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function targetSelectors() public view returns (VaultFuzzSelector[] memory selectors) {
        bytes4[] memory actions = new bytes4[](14);
        actions[0] = VaultSecurityHandler.deposit.selector;
        actions[1] = VaultSecurityHandler.donate.selector;
        actions[2] = VaultSecurityHandler.donateForeign.selector;
        actions[3] = VaultSecurityHandler.warp.selector;
        actions[4] = VaultSecurityHandler.release.selector;
        actions[5] = VaultSecurityHandler.frontRunRelease.selector;
        actions[6] = VaultSecurityHandler.replayApproval.selector;
        actions[7] = VaultSecurityHandler.attackRelease.selector;
        actions[8] = VaultSecurityHandler.pause.selector;
        actions[9] = VaultSecurityHandler.control.selector;
        actions[10] = VaultSecurityHandler.attackControl.selector;
        actions[11] = VaultSecurityHandler.presignControl.selector;
        actions[12] = VaultSecurityHandler.submitPresigned.selector;
        actions[13] = VaultSecurityHandler.rotate.selector;
        selectors = new VaultFuzzSelector[](1);
        selectors[0] = VaultFuzzSelector(address(handler), actions);
    }

    function _noViolation(uint8 property) internal view {
        string memory reason = handler.violation(property);
        require(bytes(reason).length == 0, reason);
    }

    /// All vault properties, checked after every handler call. Each check
    /// names the property it enforces in its failure message.
    function invariant_vaultSecurityProperties() public view {
        _custodyConservation();
        _burnReleasedAtMostOnce();
        _releaseLimits();
        _acceptanceMatchesSpecification();
        _onlyCurrentQuorumAuthorizes();
        _noCrossDomainReplay();
        _pausedMeansNoMovement();
        _rescueNeverMovesXtc();
        _onlyApprovedRecipientsPaid();
    }

    /// Vault balance == initial + deposits + donations - releases. No other
    /// path (control action, rescue, failed call) moves canonical XTC.
    function _custodyConservation() internal view {
        require(
            token.balanceOf(address(vault)) ==
                handler.initialBalance() + handler.ghostDeposited() + handler.ghostDonated() - handler.ghostReleased(),
            "custody: vault balance != initial + deposits + donations - releases"
        );
        require(vault.depositNonce() == handler.ghostDepositCount(), "custody: deposit nonce");
    }

    /// Each burn ID is released at most once, and processedBurns records
    /// exactly the burns that were paid.
    function _burnReleasedAtMostOnce() internal view {
        _noViolation(VaultProperty.REPLAY);
        uint256 size = handler.burnPoolSize();
        for (uint256 i; i < size; ++i) {
            bytes32 burn = handler.burnId(i);
            uint256 count = handler.releaseCount(burn);
            require(count <= 1, "replay: burn paid more than once");
            require(vault.processedBurns(burn) == (count == 1), "replay: processed flag differs from payouts");
        }
    }

    /// Every accepted release respected the per-transfer and daily limits in
    /// force; releasedToday is the sum of the day's releases and stays within
    /// the daily limit unless the quorum lowered the limit below that usage.
    function _releaseLimits() internal view {
        _noViolation(VaultProperty.LIMITS);
        uint256 day = vault.releaseDay();
        require(vault.releasedToday() == handler.releasedOnDay(day), "limits: daily release accounting");
        if (day == handler.currentTime() / 1 days) {
            require(
                vault.releasedToday() <= vault.dailyReleaseLimit() || handler.loweredBelowUsageDay() == day,
                "limits: released today above the daily limit"
            );
        }
        require(vault.maxReleaseAmount() <= vault.dailyReleaseLimit(), "limits: per-transfer above daily");
    }

    /// Acceptance matches the specification exactly, and a rejected call
    /// changes no state.
    function _acceptanceMatchesSpecification() internal view {
        _noViolation(VaultProperty.SPEC);
        _noViolation(VaultProperty.ATOMIC);
    }

    /// Only 2 of the current 3 signers, with the current nonce and signer-set
    /// version, can release or run a control action. Old, outsider, duplicate,
    /// malleated, compact and malformed signatures never count.
    function _onlyCurrentQuorumAuthorizes() internal view {
        _noViolation(VaultProperty.AUTH);
        require(vault.governanceNonce() == handler.ghostControlCount(), "authorization: governance nonce");
        require(vault.signerSetVersion() == 1 + handler.ghostRotations(), "authorization: signer-set version");
        uint256[3] memory keys = handler.currentKeys();
        address[3] memory configured = vault.signers();
        for (uint256 i; i < 3; ++i) {
            require(configured[i] == handler.keyAddress(keys[i]), "authorization: signer set");
        }
        for (uint256 key = 1; key <= 7; ++key) {
            require(
                vault.isSigner(handler.keyAddress(key)) == handler.isCurrentKey(key),
                "authorization: isSigner differs from the current set"
            );
        }
        for (uint256 key = 901; key <= 903; ++key) {
            require(!vault.isSigner(handler.keyAddress(key)), "authorization: attacker key configured");
        }
    }

    /// Signatures made for another chain ID, another vault or another
    /// EIP-712 domain never count, on this vault or on the other vault.
    function _noCrossDomainReplay() internal view {
        _noViolation(VaultProperty.CROSS);
        require(token.balanceOf(address(otherVault)) == OTHER_VAULT_BALANCE, "cross-domain: other vault balance changed");
        require(
            otherVault.governanceNonce() == 0 && otherVault.signerSetVersion() == 1,
            "cross-domain: other vault governance changed"
        );
        require(otherVault.releasedToday() == 0 && !otherVault.paused(), "cross-domain: other vault state changed");
        uint256 size = handler.burnPoolSize();
        for (uint256 i; i < size; ++i) {
            require(!otherVault.processedBurns(handler.burnId(i)), "cross-domain: other vault processed a burn");
        }
    }

    /// While paused, no XTC enters or leaves through deposit or release; only
    /// the guardian can pause; only a quorum can resume.
    function _pausedMeansNoMovement() internal view {
        _noViolation(VaultProperty.PAUSE);
        require(vault.paused() == handler.ghostPaused(), "pause: state differs from the model");
        require(vault.guardian() == handler.guardianNow(), "pause: guardian differs from the model");
    }

    /// Rescue never moves canonical XTC; foreign tokens move only by quorum.
    function _rescueNeverMovesXtc() internal view {
        _noViolation(VaultProperty.RESCUE);
        require(
            foreign.balanceOf(address(vault)) == handler.ghostForeignDonated() - handler.ghostForeignRescued(),
            "rescue: foreign token accounting"
        );
        require(token.balanceOf(address(0x5E5C)) == 0, "rescue: XTC reached the rescue recipient");
    }

    /// XTC leaves the vault only to approved recipients, in the approved
    /// amounts. Relayers and front-runners never receive any.
    function _onlyApprovedRecipientsPaid() internal view {
        _noViolation(VaultProperty.RECIPIENT);
        uint256 count = handler.actorCount();
        uint256 paid;
        for (uint256 i; i < count; ++i) {
            require(token.balanceOf(handler.actor(i)) == 0, "recipients: relayer or attacker holds XTC");
            address to = handler.recipient(i);
            require(token.balanceOf(to) == handler.paidTo(to), "recipients: balance differs from approvals");
            paid += handler.paidTo(to);
        }
        require(paid == handler.ghostReleased(), "recipients: released total differs from payouts");
    }
}

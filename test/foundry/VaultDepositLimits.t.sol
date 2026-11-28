// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {CronosBridgeVault} from "../../contracts/cronos/bridge/CronosBridgeVault.sol";
import {MockERC20} from "../../contracts/test/MockERC20.sol";

// Local EVM simulations only. Signing keys 1, 2 and 3 are public synthetic
// test keys; no RPC, network or deployed contract is involved.

interface Vm {
    function addr(uint256) external returns (address);
    function sign(uint256, bytes32) external returns (uint8, bytes32, bytes32);
    function warp(uint256) external;
}

abstract contract VaultSigning {
    Vm internal constant vm =
        Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 internal constant SIGNATURE_DEADLINE = 4_000_000_000;

    function _bound(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        return min + (x % (max - min + 1));
    }

    function _domain(CronosBridgeVault vault) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(vault.EIP712_NAME())),
                keccak256(bytes(vault.EIP712_VERSION())),
                block.chainid,
                address(vault)
            )
        );
    }

    function _signDigest(bytes32 digest) internal returns (bytes[] memory sigs) {
        sigs = new bytes[](2);
        for (uint256 i; i < 2; ++i) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(i + 1, digest);
            sigs[i] = abi.encodePacked(r, s, v);
        }
    }

    function _signControl(
        CronosBridgeVault vault,
        bytes32 action,
        bytes32 payloadHash,
        uint256 nonce
    ) internal returns (bytes[] memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                vault.CONTROL_TYPEHASH(),
                action,
                payloadHash,
                nonce,
                vault.signerSetVersion(),
                SIGNATURE_DEADLINE
            )
        );
        return _signDigest(keccak256(abi.encodePacked("\x19\x01", _domain(vault), structHash)));
    }

    function _signRelease(
        CronosBridgeVault vault,
        bytes32 burn,
        address to,
        uint256 amount
    ) internal returns (bytes[] memory) {
        bytes32 structHash = keccak256(
            abi.encode(vault.RELEASE_TYPEHASH(), burn, to, amount, uint64(1), SIGNATURE_DEADLINE)
        );
        return _signDigest(keccak256(abi.encodePacked("\x19\x01", _domain(vault), structHash)));
    }

    function _depositLimitsPayload(uint256 maximum, uint256 daily, uint256 locked)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(maximum, daily, locked));
    }

    function _newVault(MockERC20 token, uint256 maximum, uint256 daily, uint256 locked)
        internal
        returns (CronosBridgeVault)
    {
        address[3] memory signers = [vm.addr(1), vm.addr(2), vm.addr(3)];
        return new CronosBridgeVault(
            token,
            keccak256("synthetic-route"),
            signers,
            address(0x4444),
            1_000,
            5_000,
            maximum,
            daily,
            locked,
            false
        );
    }
}

/// Stateless fuzz tests for the deposit limits and their control action.
contract VaultDepositLimitsFuzzTest is VaultSigning {
    uint256 internal constant MAX_DEPOSIT = 1_000;
    uint256 internal constant DAILY_DEPOSIT = 5_000;
    uint256 internal constant MAX_LOCKED = 50_000;
    uint256 internal constant START = 1_700_000_000;
    address internal constant RECIPIENT = address(0xBEEF);

    MockERC20 internal token;
    CronosBridgeVault internal vault;

    function setUp() public {
        vm.warp(START);
        token = new MockERC20("Synthetic", "TEST");
        vault = _newVault(token, MAX_DEPOSIT, DAILY_DEPOSIT, MAX_LOCKED);
        token.mint(address(this), type(uint128).max);
        token.approve(address(vault), type(uint256).max);
    }

    function _tryDeposit(uint256 amount) internal returns (bool ok) {
        (ok, ) = address(vault).call(abi.encodeCall(vault.deposit, (amount, RECIPIENT)));
    }

    /// A deposit succeeds exactly when it satisfies all three limits, and a
    /// rejected deposit changes no accounting.
    function testFuzz_depositAcceptedIffWithinLimits(
        uint256 priorSeed,
        uint256 donationSeed,
        uint256 amountSeed
    ) public {
        uint256 prior = _bound(priorSeed, 0, MAX_DEPOSIT);
        if (prior > 0) require(_tryDeposit(prior), "prior deposit");
        uint256 donation = _bound(donationSeed, 0, MAX_LOCKED + MAX_DEPOSIT);
        token.mint(address(vault), donation);
        uint256 amount = _bound(amountSeed, 1, 2 * MAX_DEPOSIT);

        uint256 balanceBefore = token.balanceOf(address(vault));
        uint256 usedBefore = vault.depositedToday();
        uint256 nonceBefore = vault.depositNonce();
        bool expected = amount <= MAX_DEPOSIT &&
            usedBefore + amount <= DAILY_DEPOSIT &&
            balanceBefore + amount <= MAX_LOCKED;

        bool ok = _tryDeposit(amount);
        require(ok == expected, "acceptance must match limits");
        if (ok) {
            require(token.balanceOf(address(vault)) == balanceBefore + amount, "exact lock");
            require(token.balanceOf(address(vault)) <= vault.maxLockedAmount(), "cap");
            require(vault.depositedToday() == usedBefore + amount, "day total");
            require(vault.depositNonce() == nonceBefore + 1, "nonce");
        } else {
            require(token.balanceOf(address(vault)) == balanceBefore, "balance changed");
            require(vault.depositedToday() == usedBefore, "day total changed");
            require(vault.depositNonce() == nonceBefore, "nonce changed");
        }
    }

    /// After using the whole daily limit, a further deposit succeeds exactly
    /// when the next one falls in a later UTC day (block.timestamp / 1 days).
    function testFuzz_dailyBucketFollowsUtcDay(uint256 startSeed, uint256 deltaSeed) public {
        uint256 start = _bound(startSeed, START, START + 3650 days);
        uint256 delta = _bound(deltaSeed, 0, 3 days);
        vm.warp(start);
        for (uint256 i; i < DAILY_DEPOSIT / MAX_DEPOSIT; ++i) {
            require(_tryDeposit(MAX_DEPOSIT), "fill day");
        }
        require(vault.depositedToday() == DAILY_DEPOSIT, "day full");
        require(!_tryDeposit(1), "same instant over limit");

        vm.warp(start + delta);
        bool newDay = (start + delta) / 1 days != start / 1 days;
        require(_tryDeposit(1) == newDay, "bucket boundary");
        if (newDay) {
            require(vault.depositDay() == (start + delta) / 1 days, "day index");
            require(vault.depositedToday() == 1, "reset");
        }
    }

    /// Constructor validation: non-zero values, per-deposit <= daily and
    /// per-deposit <= locked cap.
    function testFuzz_constructorValidatesDepositLimits(
        uint256 maximum,
        uint256 daily,
        uint256 locked
    ) public {
        maximum = maximum % 4;
        daily = daily % 4;
        locked = locked % 4;
        bool valid = maximum != 0 && daily != 0 && locked != 0 &&
            maximum <= daily && maximum <= locked;
        bool deployed;
        try this.deployForTest(maximum, daily, locked) {
            deployed = true;
        } catch (bytes memory reason) {
            require(bytes4(reason) == CronosBridgeVault.InvalidDepositLimits.selector, "error");
        }
        require(deployed == valid, "constructor validation");
    }

    function deployForTest(uint256 maximum, uint256 daily, uint256 locked) external {
        _newVault(token, maximum, daily, locked);
    }

    /// The control action binds all three values, consumes exactly one nonce
    /// on success and cannot be replayed.
    function testFuzz_depositLimitUpdateBindsPayloadAndNonce(
        uint256 maximumSeed,
        uint256 dailySeed,
        uint256 lockedSeed,
        uint8 mutation
    ) public {
        uint256 maximum = _bound(maximumSeed, 1, 10_000);
        uint256 daily = _bound(dailySeed, maximum, 100_000);
        uint256 locked = _bound(lockedSeed, maximum, 1_000_000);
        bytes32 action = vault.ACTION_UPDATE_DEPOSIT_LIMITS();
        bytes[] memory sigs = _signControl(
            vault,
            action,
            _depositLimitsPayload(maximum, daily, locked),
            0
        );

        uint256 m = maximum;
        uint256 d = daily;
        uint256 l = locked;
        uint256 which = mutation % 3;
        if (which == 0) d = daily + 1;
        else if (which == 1) l = locked + 1;
        else if (maximum < daily && maximum < locked) m = maximum + 1;
        else d = daily + 1;
        (bool ok, bytes memory reason) = address(vault).call(
            abi.encodeCall(vault.updateDepositLimits, (m, d, l, 0, SIGNATURE_DEADLINE, sigs))
        );
        require(!ok && vault.governanceNonce() == 0, "mutated payload accepted");
        require(bytes4(reason) == CronosBridgeVault.UnauthorizedSigner.selector, "signature binding");
        require(vault.maxDepositAmount() == MAX_DEPOSIT, "limits changed");

        vault.updateDepositLimits(maximum, daily, locked, 0, SIGNATURE_DEADLINE, sigs);
        require(vault.governanceNonce() == 1, "nonce consumed once");
        require(
            vault.maxDepositAmount() == maximum &&
                vault.dailyDepositLimit() == daily &&
                vault.maxLockedAmount() == locked,
            "limits stored"
        );

        (ok, ) = address(vault).call(
            abi.encodeCall(vault.updateDepositLimits, (maximum, daily, locked, 0, SIGNATURE_DEADLINE, sigs))
        );
        require(!ok && vault.governanceNonce() == 1, "replay accepted");
    }

    /// Lowering the daily limit below the current day's usage is accepted and
    /// stops further deposits until the next UTC day.
    function testFuzz_loweringDailyLimitBelowUsageBlocksRestOfDay(uint256 usedSeed) public {
        uint256 used = _bound(usedSeed, 2, MAX_DEPOSIT);
        require(_tryDeposit(used), "initial deposit");
        uint256 lowered = used - 1;
        bytes[] memory sigs = _signControl(
            vault,
            vault.ACTION_UPDATE_DEPOSIT_LIMITS(),
            _depositLimitsPayload(1, lowered, MAX_LOCKED),
            0
        );
        vault.updateDepositLimits(1, lowered, MAX_LOCKED, 0, SIGNATURE_DEADLINE, sigs);
        require(vault.depositedToday() == used, "usage kept");
        require(!_tryDeposit(1), "deposit after lowering");

        vm.warp((block.timestamp / 1 days + 1) * 1 days);
        require(_tryDeposit(1), "next day deposit");
    }
}

/// Handler driven by the invariant fuzzer: deposits (some over the limits),
/// donations, releases, quorum limit updates and time warps.
contract VaultDepositHandler is VaultSigning {
    address internal constant RECIPIENT = address(0xBEEF);
    address internal constant RELEASE_RECIPIENT = address(0xCAFE);

    CronosBridgeVault public immutable vault;
    MockERC20 public immutable token;

    uint256 public currentTime;
    uint256 public initialBalance;
    uint256 public ghostDeposited;
    uint256 public ghostDonated;
    uint256 public ghostReleased;
    uint256 public ghostDepositCount;
    uint256 public ghostControlCount;
    uint256 public releaseCount;
    uint256 public loweredBelowUsageDay = type(uint256).max;

    bool public acceptedOverPerDepositMaximum;
    bool public acceptedOverDailyLimit;
    bool public acceptedOverLockedCap;
    bool public acceptedOutsideLimits;
    bool public rejectedWithinLimits;

    constructor(CronosBridgeVault targetVault, MockERC20 targetToken, uint256 startTime) {
        vault = targetVault;
        token = targetToken;
        currentTime = startTime;
        initialBalance = targetToken.balanceOf(address(targetVault));
    }

    function currentDay() public view returns (uint256) {
        return currentTime / 1 days;
    }

    function deposit(uint256 amountSeed) external {
        vm.warp(currentTime);
        uint256 maximum = vault.maxDepositAmount();
        uint256 amount = _bound(amountSeed, 1, 2 * maximum);
        uint256 balanceBefore = token.balanceOf(address(vault));
        uint256 usedBefore = vault.depositDay() == currentDay() ? vault.depositedToday() : 0;
        bool withinLimits = amount <= maximum &&
            usedBefore + amount <= vault.dailyDepositLimit() &&
            balanceBefore + amount <= vault.maxLockedAmount();

        token.mint(address(this), amount);
        token.approve(address(vault), amount);
        try vault.deposit(amount, RECIPIENT) {
            ghostDeposited += amount;
            ++ghostDepositCount;
            if (amount > maximum) acceptedOverPerDepositMaximum = true;
            if (vault.depositedToday() > vault.dailyDepositLimit()) acceptedOverDailyLimit = true;
            if (token.balanceOf(address(vault)) > vault.maxLockedAmount()) acceptedOverLockedCap = true;
            if (!withinLimits) acceptedOutsideLimits = true;
        } catch {
            if (withinLimits) rejectedWithinLimits = true;
        }
    }

    function donate(uint256 amountSeed) external {
        vm.warp(currentTime);
        uint256 amount = _bound(amountSeed, 1, 3_000);
        token.mint(address(vault), amount);
        ghostDonated += amount;
    }

    function release(uint256 amountSeed) external {
        vm.warp(currentTime);
        uint256 balance = token.balanceOf(address(vault));
        uint256 maximum = vault.maxReleaseAmount();
        uint256 ceiling = balance < maximum ? balance : maximum;
        if (ceiling == 0) return;
        uint256 amount = _bound(amountSeed, 1, ceiling);
        bytes32 burn = keccak256(abi.encode("handler-burn", ++releaseCount));
        bytes[] memory sigs = _signRelease(vault, burn, RELEASE_RECIPIENT, amount);
        try vault.release(burn, RELEASE_RECIPIENT, amount, 1, SIGNATURE_DEADLINE, sigs) {
            ghostReleased += amount;
        } catch {}
    }

    function updateDepositLimits(uint256 maximumSeed, uint256 dailySeed, uint256 lockedSeed) external {
        vm.warp(currentTime);
        uint256 maximum = _bound(maximumSeed, 1, 3_000);
        uint256 daily = _bound(dailySeed, maximum, 20_000);
        uint256 locked = _bound(lockedSeed, maximum, 100_000);
        uint256 nonce = vault.governanceNonce();
        bytes[] memory sigs = _signControl(
            vault,
            vault.ACTION_UPDATE_DEPOSIT_LIMITS(),
            _depositLimitsPayload(maximum, daily, locked),
            nonce
        );
        vault.updateDepositLimits(maximum, daily, locked, nonce, SIGNATURE_DEADLINE, sigs);
        ++ghostControlCount;
        if (vault.depositDay() == currentDay() && vault.depositedToday() > daily) {
            loweredBelowUsageDay = currentDay();
        }
    }

    function warp(uint256 secondsSeed) external {
        currentTime += _bound(secondsSeed, 0, 2 days);
        vm.warp(currentTime);
    }
}

struct FuzzSelector {
    address addr;
    bytes4[] selectors;
}

/// Handler-based invariants for the deposit limits (Hardhat 3 / EDR and
/// Foundry both discover `invariant_*` functions with these target hooks).
contract VaultDepositInvariantTest is VaultSigning {
    uint256 internal constant START = 1_700_000_000;

    MockERC20 internal token;
    CronosBridgeVault internal vault;
    VaultDepositHandler internal handler;

    function setUp() public {
        vm.warp(START);
        token = new MockERC20("Synthetic", "TEST");
        vault = _newVault(token, 1_000, 5_000, 50_000);
        token.mint(address(vault), 10_000);
        handler = new VaultDepositHandler(vault, token, START);
    }

    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory selectors) {
        bytes4[] memory actions = new bytes4[](5);
        actions[0] = VaultDepositHandler.deposit.selector;
        actions[1] = VaultDepositHandler.donate.selector;
        actions[2] = VaultDepositHandler.release.selector;
        actions[3] = VaultDepositHandler.updateDepositLimits.selector;
        actions[4] = VaultDepositHandler.warp.selector;
        selectors = new FuzzSelector[](1);
        selectors[0] = FuzzSelector(address(handler), actions);
    }

    /// The current day's deposit total never exceeds the daily limit, unless
    /// governance lowered the limit below that day's usage (then deposits are
    /// blocked for the rest of the day; see the fuzz test above).
    function invariant_dailyDepositedWithinLimit() public view {
        if (vault.depositDay() != handler.currentDay()) return;
        require(
            vault.depositedToday() <= vault.dailyDepositLimit() ||
                handler.loweredBelowUsageDay() == vault.depositDay(),
            "daily deposit total above limit"
        );
    }

    /// No successful deposit ever exceeded the per-deposit maximum, the daily
    /// limit, or left the vault balance above maxLockedAmount.
    function invariant_depositsNeverExceedLimitsInForce() public view {
        require(!handler.acceptedOverPerDepositMaximum(), "per-deposit maximum bypassed");
        require(!handler.acceptedOverDailyLimit(), "daily deposit limit bypassed");
        require(!handler.acceptedOverLockedCap(), "balance above cap via deposit");
    }

    /// Acceptance matches the specification exactly: a deposit is accepted if
    /// and only if it satisfies all three limits in force.
    function invariant_depositAcceptanceMatchesLimits() public view {
        require(!handler.acceptedOutsideLimits(), "deposit outside limits accepted");
        require(!handler.rejectedWithinLimits(), "deposit within limits rejected");
    }

    /// Custody conservation and nonce accounting across the whole sequence.
    function invariant_custodyAndNonceAccounting() public view {
        require(
            token.balanceOf(address(vault)) ==
                handler.initialBalance() +
                    handler.ghostDeposited() +
                    handler.ghostDonated() -
                    handler.ghostReleased(),
            "custody conservation"
        );
        require(vault.depositNonce() == handler.ghostDepositCount(), "deposit nonce");
        require(vault.governanceNonce() == handler.ghostControlCount(), "governance nonce");
    }
}

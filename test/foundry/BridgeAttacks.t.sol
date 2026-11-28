// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {CronosBridgeVault} from "../../contracts/cronos/bridge/CronosBridgeVault.sol";
import {CronosBootstrapEscrow} from "../../contracts/cronos/bridge/CronosBootstrapEscrow.sol";
import {MockERC20} from "../../contracts/test/MockERC20.sol";
import {AdversarialERC20} from "../../contracts/test/AdversarialERC20.sol";
import {DoubleEntryERC20} from "../../contracts/test/DoubleEntryERC20.sol";
import {BridgeTestBase} from "./utils/BridgeTestBase.sol";

/// Shared vault fixture for the stateless attack tests.
abstract contract VaultAttackFixture is BridgeTestBase {
    uint256 internal constant START = 1_700_000_000;
    uint256 internal constant LIQUIDITY = 1_000_000;
    address internal constant GUARDIAN = address(0x6A00);
    address internal constant RECIPIENT = address(0xE0);
    bytes32 internal constant ROUTE = keccak256("synthetic-route");

    function _deployVault(IERC20 asset) internal returns (CronosBridgeVault) {
        return new CronosBridgeVault(
            asset, ROUTE, [vm.addr(1), vm.addr(2), vm.addr(3)], GUARDIAN,
            10_000, 100_000, 10_000, 100_000, 2_000_000, false
        );
    }

    function _releaseDigest(CronosBridgeVault vault, bytes32 burn, address to, uint256 amount)
        internal
        view
        returns (bytes32)
    {
        return _typedDigest(
            _vaultDomain(vault),
            _releaseStruct(burn, to, amount, vault.signerSetVersion(), FAR_DEADLINE)
        );
    }

    function _releaseCall(CronosBridgeVault vault, bytes32 burn, address to, uint256 amount, bytes[] memory sigs)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodeCall(vault.release, (burn, to, amount, vault.signerSetVersion(), FAR_DEADLINE, sigs));
    }

    function _controlDigest(CronosBridgeVault vault, bytes32 action, bytes32 payloadHash, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        return _typedDigest(
            _vaultDomain(vault),
            _controlStruct(action, payloadHash, nonce, vault.signerSetVersion(), FAR_DEADLINE)
        );
    }

    function _burn(uint256 seed) internal pure returns (bytes32 burn) {
        burn = keccak256(abi.encode("attack-burn", seed));
    }

    function _amount(uint256 seed) internal pure returns (uint256) {
        return _bound(seed, 1, 10_000);
    }

    function _requireUntouched(CronosBridgeVault vault, IERC20 asset, bytes32 burn, uint256 balance) internal view {
        require(!vault.processedBurns(burn), "burn marked");
        require(vault.releasedToday() == 0, "daily accounting changed");
        require(asset.balanceOf(address(vault)) == balance, "vault balance changed");
        require(asset.balanceOf(RECIPIENT) == 0, "recipient paid");
    }
}

/// Signature forgery and replay attempts against the vault.
contract VaultSignatureAttackTest is VaultAttackFixture {
    MockERC20 internal token;
    CronosBridgeVault internal vault;

    function setUp() public {
        vm.warp(START);
        token = new MockERC20("Synthetic", "TEST");
        vault = _deployVault(token);
        token.mint(address(vault), LIQUIDITY);
    }

    /// A high-s (malleated) signature never counts, alone or next to a valid
    /// one, although ecrecover returns the same signer for it.
    function testFuzz_highSSignatureNeverCounts(uint256 burnSeed, uint256 amountSeed, uint8 which) public {
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        uint256 first = which % 2;
        uint256 second = 1 - first;
        bytes32 digest = _releaseDigest(vault, burn, RECIPIENT, amount);
        bytes[] memory sigs = _sign2(1, 2, digest);
        bytes memory malleated = _malleate(sigs[first]);
        require(_rawRecover(digest, malleated) == vm.addr(1 + first), "malleated form recovers the signer");

        bytes[] memory attack = new bytes[](2);
        attack[first] = malleated;
        attack[second] = sigs[second];
        (bool ok, bytes4 err) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, attack));
        require(!ok && err == ECDSA.ECDSAInvalidSignatureS.selector, "high-s accepted");

        attack[second] = _malleate(sigs[second]);
        (ok, err) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, attack));
        require(!ok && err == ECDSA.ECDSAInvalidSignatureS.selector, "two high-s accepted");
        _requireUntouched(vault, token, burn, LIQUIDITY);

        // The canonical form of the same approval succeeds: the rejection is not vacuous.
        vault.release(burn, RECIPIENT, amount, 1, FAR_DEADLINE, sigs);
        require(token.balanceOf(RECIPIENT) == amount, "canonical approval");
    }

    function _rawRecover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        return ecrecover(digest, v, r, s);
    }

    /// The same signer twice, directly or through its malleated twin, never
    /// makes a quorum.
    function testFuzz_duplicateSignerNeverCounts(uint256 burnSeed, uint256 amountSeed, uint256 keySeed) public {
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        uint256 key = 1 + (keySeed % 3);
        bytes memory one = _sign(key, _releaseDigest(vault, burn, RECIPIENT, amount));
        bytes[] memory sigs = new bytes[](3);
        sigs[0] = one;
        sigs[1] = one;
        sigs[2] = one;
        (bool ok, bytes4 err) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, sigs));
        require(!ok && err == CronosBridgeVault.DuplicateSignature.selector, "duplicate accepted");

        bytes[] memory two = new bytes[](2);
        two[0] = one;
        two[1] = one;
        (ok, err) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, two));
        require(!ok && err == CronosBridgeVault.DuplicateSignature.selector, "pair of duplicates accepted");
        _requireUntouched(vault, token, burn, LIQUIDITY);
    }

    /// A key that is not configured never counts, whatever else is supplied.
    function testFuzz_unconfiguredSignerNeverCounts(uint256 keySeed, uint256 burnSeed, uint256 amountSeed) public {
        uint256 outsider = _outsiderKey(keySeed);
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        bytes32 digest = _releaseDigest(vault, burn, RECIPIENT, amount);

        bytes[] memory sigs = _sign2(1, outsider, digest);
        (bool ok, bytes4 err) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, sigs));
        require(!ok && err == CronosBridgeVault.UnauthorizedSigner.selector, "outsider counted");

        // Two valid approvals plus an outsider: the outsider still rejects the call.
        sigs = _sign3(1, 2, outsider, digest);
        (ok, err) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, sigs));
        require(!ok && err == CronosBridgeVault.UnauthorizedSigner.selector, "outsider tolerated");
        _requireUntouched(vault, token, burn, LIQUIDITY);
    }

    /// Malformed encodings never count: 64-byte compact form, v outside
    /// {27, 28}, wrong lengths and random bytes.
    function testFuzz_malformedSignaturesNeverCount(uint256 burnSeed, uint256 amountSeed, uint8 v, bytes32 junk) public {
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        bytes[] memory sigs = _sign2(1, 2, _releaseDigest(vault, burn, RECIPIENT, amount));
        bytes[] memory attack = new bytes[](2);

        attack[0] = _compact(sigs[0]);
        attack[1] = _compact(sigs[1]);
        (bool ok, ) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, attack));
        require(!ok, "compact signatures accepted");

        if (v != 27 && v != 28) {
            attack[0] = _withV(sigs[0], v);
            attack[1] = sigs[1];
            (ok, ) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, attack));
            require(!ok, "invalid v accepted");
        }

        attack[0] = abi.encodePacked(sigs[0], junk);
        attack[1] = sigs[1];
        (ok, ) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, attack));
        require(!ok, "overlong signature accepted");

        attack[0] = abi.encodePacked(junk, keccak256(abi.encode(junk)), uint8(27));
        attack[1] = abi.encodePacked(keccak256(abi.encode(junk, 1)), junk, uint8(28));
        (ok, ) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, attack));
        require(!ok, "random signatures accepted");
        _requireUntouched(vault, token, burn, LIQUIDITY);
    }

    /// A release signed for any other EIP-712 domain (chain ID, verifying
    /// contract, name or version) never counts here.
    function testFuzz_releaseForAnotherDomainNeverCounts(
        uint256 burnSeed,
        uint256 amountSeed,
        uint256 chainId,
        address verifyingContract,
        uint8 field
    ) public {
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        string memory name = vault.EIP712_NAME();
        string memory version = vault.EIP712_VERSION();
        uint256 domainChain = block.chainid;
        address domainContract = address(vault);
        uint256 which = field % 4;
        if (which == 0) domainChain = chainId == block.chainid ? chainId + 1 : chainId;
        else if (which == 1) domainContract = verifyingContract == address(vault) ? address(0xBAD) : verifyingContract;
        else if (which == 2) name = "Xitcoin Cronos Bootstrap Escrow";
        else version = "2";

        bytes32 digest = _typedDigest(
            _domain(name, version, domainChain, domainContract),
            _releaseStruct(burn, RECIPIENT, amount, 1, FAR_DEADLINE)
        );
        bytes[] memory sigs = _sign3(1, 2, 3, digest);
        (bool ok, bytes4 err) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, sigs));
        require(!ok && err == CronosBridgeVault.UnauthorizedSigner.selector, "foreign-domain release accepted");
        _requireUntouched(vault, token, burn, LIQUIDITY);
    }

    /// Changing block.chainid after signing (a fork that keeps the vault
    /// address) invalidates the approval: the domain is recomputed.
    function testFuzz_releaseDoesNotSurviveAChainIdChange(uint256 burnSeed, uint256 amountSeed, uint64 newChain) public {
        uint256 originalChain = block.chainid;
        if (newChain == originalChain || newChain == 0) newChain = uint64(originalChain + 1);
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        bytes[] memory sigs = _sign2(2, 3, _releaseDigest(vault, burn, RECIPIENT, amount));
        vm.chainId(newChain);
        (bool ok, ) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, sigs));
        require(!ok, "approval survived a chain ID change");
        vm.chainId(originalChain);
        _requireUntouched(vault, token, burn, LIQUIDITY);
        vault.release(burn, RECIPIENT, amount, 1, FAR_DEADLINE, sigs);
    }

    /// Anyone may submit a copied approval first. The approved recipient is
    /// paid exactly once; the front-runner receives nothing; the original
    /// submission and a recipient substitution both fail.
    function testFuzz_frontRunningPaysOnlyTheApprovedRecipient(
        uint256 burnSeed,
        uint256 amountSeed,
        uint160 attackerSeed
    ) public {
        address attacker = address(uint160(_bound(attackerSeed, 0x1000, type(uint160).max)));
        if (attacker == RECIPIENT || attacker == address(vault)) attacker = address(0xBAD);
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        bytes[] memory sigs = _sign2(1, 3, _releaseDigest(vault, burn, RECIPIENT, amount));

        (bool ok, bytes4 err) = _tryAs(attacker, address(vault), _releaseCall(vault, burn, attacker, amount, sigs));
        require(!ok && err == CronosBridgeVault.UnauthorizedSigner.selector, "recipient substitution accepted");

        (ok, ) = _tryAs(attacker, address(vault), _releaseCall(vault, burn, RECIPIENT, amount, sigs));
        require(ok, "copied approval should execute for the approved recipient");
        require(token.balanceOf(RECIPIENT) == amount && token.balanceOf(attacker) == 0, "front-run payout");

        (ok, err) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, sigs));
        require(!ok && err == CronosBridgeVault.BurnAlreadyProcessed.selector, "double payment");
        require(token.balanceOf(RECIPIENT) == amount, "recipient paid twice");
        require(token.balanceOf(address(vault)) == LIQUIDITY - amount, "vault debit");
    }

    /// After a rotation that keeps two of the three signers, approvals signed
    /// before the rotation (control or release) never execute, even for the
    /// next nonce; fresh approvals from the same keys do.
    function testFuzz_noReplayAcrossSignerRotation(uint256 keptSeed, uint256 burnSeed, uint256 limitSeed) public {
        uint256 dropped = 1 + (keptSeed % 3);
        uint256 keptA = dropped == 1 ? 2 : 1;
        uint256 keptB = dropped == 3 ? 2 : 3;
        uint256 newcomer = 4 + (keptSeed % 3);
        address[3] memory rotated = [vm.addr(keptA), vm.addr(keptB), vm.addr(newcomer)];
        uint256 maximum = _bound(limitSeed, 1, 10_000);
        bytes32 limitsPayload = keccak256(abi.encode(maximum, uint256(100_000)));

        // Pre-signed under signer set 1: a limit change for nonce 1 and a release.
        bytes[] memory staleControl = _sign2(keptA, keptB, _controlDigest(vault, vault.ACTION_UPDATE_LIMITS(), limitsPayload, 1));
        bytes32 burn = _burn(burnSeed);
        bytes[] memory staleRelease = _sign2(keptA, keptB, _releaseDigest(vault, burn, RECIPIENT, 10));

        bytes[] memory rotation = _sign2(1, 2, _controlDigest(
            vault, vault.ACTION_ROTATE_SIGNERS(), keccak256(abi.encode(rotated)), 0
        ));
        vault.rotateSigners(rotated, 0, FAR_DEADLINE, rotation);
        require(vault.signerSetVersion() == 2 && vault.governanceNonce() == 1, "rotation applied");
        require(!vault.isSigner(vm.addr(dropped)) && vault.isSigner(vm.addr(newcomer)), "signer flags");

        (bool ok, bytes4 err) = _try(
            address(vault),
            abi.encodeCall(vault.updateLimits, (maximum, 100_000, 1, FAR_DEADLINE, staleControl))
        );
        require(!ok && err == CronosBridgeVault.UnauthorizedSigner.selector, "pre-rotation control replayed");
        (ok, err) = _try(address(vault), abi.encodeCall(vault.release, (burn, RECIPIENT, 10, 1, FAR_DEADLINE, staleRelease)));
        require(!ok && err == CronosBridgeVault.InvalidSignerSetVersion.selector, "pre-rotation release with old version");
        (ok, err) = _try(address(vault), abi.encodeCall(vault.release, (burn, RECIPIENT, 10, 2, FAR_DEADLINE, staleRelease)));
        require(!ok && err == CronosBridgeVault.UnauthorizedSigner.selector, "pre-rotation release with new version");

        // The dropped signer, even with a kept signer, no longer counts.
        bytes[] memory withDropped = _sign2(keptA, dropped, _controlDigest(vault, vault.ACTION_UPDATE_LIMITS(), limitsPayload, 1));
        (ok, err) = _try(
            address(vault),
            abi.encodeCall(vault.updateLimits, (maximum, 100_000, 1, FAR_DEADLINE, withDropped))
        );
        require(!ok && err == CronosBridgeVault.UnauthorizedSigner.selector, "retired signer counted");
        require(vault.governanceNonce() == 1 && vault.maxReleaseAmount() == 10_000, "state after rejections");

        // Fresh approvals from the new set work.
        bytes[] memory fresh = _sign2(keptB, newcomer, _controlDigest(vault, vault.ACTION_UPDATE_LIMITS(), limitsPayload, 1));
        vault.updateLimits(maximum, 100_000, 1, FAR_DEADLINE, fresh);
        require(vault.maxReleaseAmount() == maximum && vault.governanceNonce() == 2, "fresh control");
    }

    /// Two vaults with the same signers, nonce and parameters: an approval for
    /// one never executes on the other. The same holds after a chain ID change.
    function testFuzz_controlNeverCrossesVaultsOrChains(address newGuardianSeed, uint64 otherChain) public {
        address newGuardian = newGuardianSeed;
        if (newGuardian == address(0) || newGuardian == vault.DEAD_ADDRESS()) newGuardian = address(0x6A01);
        CronosBridgeVault twin = _deployVault(token);
        bytes32 payload = keccak256(abi.encode(newGuardian));
        bytes[] memory forTwin = _sign2(1, 2, _controlDigest(twin, twin.ACTION_CHANGE_GUARDIAN(), payload, 0));

        (bool ok, bytes4 err) = _try(address(vault), abi.encodeCall(vault.changeGuardian, (newGuardian, 0, FAR_DEADLINE, forTwin)));
        require(!ok && err == CronosBridgeVault.UnauthorizedSigner.selector, "cross-vault control accepted");

        bytes[] memory forVault = _sign2(1, 2, _controlDigest(vault, vault.ACTION_CHANGE_GUARDIAN(), payload, 0));
        uint256 originalChain = block.chainid;
        if (otherChain == originalChain || otherChain == 0) otherChain = uint64(originalChain + 1);
        vm.chainId(otherChain);
        (ok, err) = _try(address(vault), abi.encodeCall(vault.changeGuardian, (newGuardian, 0, FAR_DEADLINE, forVault)));
        require(!ok && err == CronosBridgeVault.UnauthorizedSigner.selector, "cross-chain control accepted");
        vm.chainId(originalChain);
        require(vault.guardian() == GUARDIAN && vault.governanceNonce() == 0, "state changed");

        twin.changeGuardian(newGuardian, 0, FAR_DEADLINE, forTwin);
        vault.changeGuardian(newGuardian, 0, FAR_DEADLINE, forVault);
        (ok, err) = _try(address(vault), abi.encodeCall(vault.changeGuardian, (newGuardian, 0, FAR_DEADLINE, forVault)));
        require(!ok && err == CronosBridgeVault.InvalidNonce.selector, "control replayed");
    }

    /// While paused, no deposit or release moves XTC, whatever the approval.
    function testFuzz_pausedMeansNoMovement(uint256 burnSeed, uint256 amountSeed) public {
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        bytes[] memory sigs = _sign3(1, 2, 3, _releaseDigest(vault, burn, RECIPIENT, amount));
        vm.prank(GUARDIAN);
        vault.pause();
        (bool ok, ) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, sigs));
        require(!ok, "release while paused");
        token.mint(address(this), amount);
        token.approve(address(vault), amount);
        (ok, ) = _try(address(vault), abi.encodeCall(vault.deposit, (amount, RECIPIENT)));
        require(!ok, "deposit while paused");
        require(token.balanceOf(address(this)) == amount && vault.depositNonce() == 0, "deposit state");
        _requireUntouched(vault, token, burn, LIQUIDITY);
    }
}

/// Non-standard token behavior: no partial state, no reentry, no XTC rescue.
contract AdversarialTokenAttackTest is VaultAttackFixture {
    AdversarialERC20 internal token;
    CronosBridgeVault internal vault;

    function setUp() public {
        vm.warp(START);
        token = new AdversarialERC20();
        vault = _deployVault(token);
        token.mint(address(vault), LIQUIDITY);
    }

    function _mode(uint8 seed) internal pure returns (uint8) {
        uint8[4] memory modes = [uint8(1), 2, 4, 5]; // no-op success, burn fee, false, fee to collector
        return modes[seed % 4];
    }

    /// A deposit through a token that under-delivers, lies or returns false
    /// reverts completely: no nonce, no daily usage, no balance change.
    function testFuzz_depositWithNonStandardTokenLeavesNoPartialState(uint8 modeSeed, uint256 amountSeed) public {
        uint8 mode = _mode(modeSeed);
        uint256 amount = _bound(amountSeed, 1, 10_000);
        token.mint(address(this), amount);
        token.approve(address(vault), amount);
        token.configureTransferFrom(mode, address(0), "");
        (bool ok, ) = _try(address(vault), abi.encodeCall(vault.deposit, (amount, RECIPIENT)));
        require(!ok, "non-standard deposit accepted");
        require(vault.depositNonce() == 0 && vault.depositedToday() == 0 && vault.depositDay() == 0, "deposit accounting");
        require(token.balanceOf(address(vault)) == LIQUIDITY && token.balanceOf(address(this)) == amount, "balances");
        require(token.balanceOf(token.FEE_COLLECTOR()) == 0, "fee collected");
    }

    /// A release through such a token reverts completely: the burn stays
    /// unprocessed, the daily accounting and both balances are unchanged.
    function testFuzz_releaseWithNonStandardTokenLeavesNoPartialState(
        uint8 modeSeed,
        uint256 burnSeed,
        uint256 amountSeed
    ) public {
        uint8 mode = _mode(modeSeed);
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        if (mode == 2 || mode == 5) amount = _bound(amountSeed, 2, 10_000);
        bytes[] memory sigs = _sign2(1, 2, _releaseDigest(vault, burn, RECIPIENT, amount));
        token.configure(mode, address(0), "");
        (bool ok, ) = _try(address(vault), _releaseCall(vault, burn, RECIPIENT, amount, sigs));
        require(!ok, "non-standard release accepted");
        _requireUntouched(vault, token, burn, LIQUIDITY);
        require(vault.releaseDay() == 0, "day index changed");
        require(token.balanceOf(token.FEE_COLLECTOR()) == 0, "fee collected");

        token.configure(0, address(0), "");
        vault.release(burn, RECIPIENT, amount, 1, FAR_DEADLINE, sigs);
        require(token.balanceOf(RECIPIENT) == amount, "same approval once the token behaves");
    }

    /// A token callback cannot re-enter deposit or release, and cannot reach
    /// rescue during a release; the outer call completes exactly.
    function testFuzz_reentrantTokenCannotReenter(uint256 burnSeed, uint256 amountSeed, uint8 targetSeed) public {
        bytes32 burn = _burn(burnSeed);
        uint256 amount = _amount(amountSeed);
        bytes32 otherBurn = keccak256(abi.encode(burn));
        bytes[] memory otherSigs = _sign2(2, 3, _releaseDigest(vault, otherBurn, RECIPIENT, amount));
        bytes memory reenter;
        uint256 which = targetSeed % 3;
        if (which == 0) {
            reenter = _releaseCall(vault, otherBurn, RECIPIENT, amount, otherSigs);
        } else if (which == 1) {
            token.mint(address(token), amount);
            reenter = abi.encodeCall(vault.deposit, (amount, RECIPIENT));
        } else {
            MockERC20 stray = new MockERC20("Stray", "STRAY");
            stray.mint(address(vault), 5);
            bytes32 payload = keccak256(abi.encode(address(stray), RECIPIENT, uint256(5)));
            bytes[] memory rescueSigs = _sign2(1, 3, _controlDigest(vault, vault.ACTION_RESCUE_FOREIGN_TOKEN(), payload, 0));
            reenter = abi.encodeCall(vault.rescueForeignToken, (stray, RECIPIENT, 5, 0, FAR_DEADLINE, rescueSigs));
        }

        // Release path: the callback runs inside the vault's transfer.
        bytes[] memory sigs = _sign2(1, 2, _releaseDigest(vault, burn, RECIPIENT, amount));
        token.configure(3, address(vault), reenter);
        vault.release(burn, RECIPIENT, amount, 1, FAR_DEADLINE, sigs);
        require(!token.callbackSucceeded(), "reentered during release");
        require(!vault.processedBurns(otherBurn) && vault.governanceNonce() == 0, "reentrant effect");
        require(vault.releasedToday() == amount && token.balanceOf(RECIPIENT) == amount, "outer release exact");

        // Deposit path: the callback runs inside transferFrom.
        token.configure(0, address(0), "");
        token.mint(address(this), amount);
        token.approve(address(vault), amount);
        token.configureTransferFrom(3, address(vault), reenter);
        vault.deposit(amount, RECIPIENT);
        require(!token.fromCallbackSucceeded(), "reentered during deposit");
        require(vault.depositNonce() == 1 && vault.depositedToday() == amount, "outer deposit exact");
        require(token.balanceOf(address(vault)) == LIQUIDITY - amount + amount, "vault balance");
    }

    /// A foreign token that returns false makes the rescue revert without
    /// consuming the nonce; a foreign token whose transfer calls back into
    /// release cannot re-enter.
    function test_nonStandardForeignTokenRescue() public {
        AdversarialERC20 stray = new AdversarialERC20();
        stray.mint(address(vault), 100);
        bytes32 payload = keccak256(abi.encode(address(stray), RECIPIENT, uint256(100)));
        bytes[] memory sigs = _sign2(1, 2, _controlDigest(vault, vault.ACTION_RESCUE_FOREIGN_TOKEN(), payload, 0));

        stray.configure(4, address(0), "");
        (bool ok, ) = _try(address(vault), abi.encodeCall(vault.rescueForeignToken, (stray, RECIPIENT, 100, 0, FAR_DEADLINE, sigs)));
        require(!ok && vault.governanceNonce() == 0, "false-returning rescue consumed the nonce");

        bytes32 burn = _burn(7);
        bytes[] memory releaseSigs = _sign2(2, 3, _releaseDigest(vault, burn, RECIPIENT, 10));
        stray.configure(3, address(vault), _releaseCall(vault, burn, RECIPIENT, 10, releaseSigs));
        vault.rescueForeignToken(stray, RECIPIENT, 100, 0, FAR_DEADLINE, sigs);
        require(!stray.callbackSucceeded() && !vault.processedBurns(burn), "release reentered during rescue");
        require(stray.balanceOf(RECIPIENT) == 100 && token.balanceOf(address(vault)) == LIQUIDITY, "rescue effects");
    }
}

/// Rescue must never move the canonical asset, including through a second
/// address that shares the asset's balance ledger.
contract RescueDoubleEntryTest is VaultAttackFixture {
    DoubleEntryERC20 internal token;
    CronosBridgeVault internal vault;

    function setUp() public {
        vm.warp(START);
        token = new DoubleEntryERC20();
        vault = _deployVault(IERC20(address(token)));
        token.mint(address(vault), LIQUIDITY);
    }

    function testFuzz_rescueNeverMovesTheCanonicalAsset(uint256 amountSeed) public {
        uint256 amount = _bound(amountSeed, 1, LIQUIDITY);
        IERC20 secondary = IERC20(token.secondaryEntry());
        bytes32 payload = keccak256(abi.encode(address(secondary), RECIPIENT, amount));
        bytes[] memory sigs = _sign2(1, 2, _controlDigest(vault, vault.ACTION_RESCUE_FOREIGN_TOKEN(), payload, 0));
        (bool ok, ) = _try(
            address(vault),
            abi.encodeCall(vault.rescueForeignToken, (secondary, RECIPIENT, amount, 0, FAR_DEADLINE, sigs))
        );
        require(!ok, "rescue moved the canonical asset through a second entry point");
        require(token.balanceOf(address(vault)) == LIQUIDITY && token.balanceOf(RECIPIENT) == 0, "canonical balance");
        require(vault.governanceNonce() == 0, "nonce consumed");
    }
}

/// Escrow behavior with non-standard tokens.
contract EscrowTokenAttackTest is BridgeTestBase {
    uint256 internal constant START = 1_700_000_000;
    uint256 internal constant AMOUNT = 1_000 ether;
    address internal constant VAULT = address(0xA11CE);
    address internal constant REFUND = address(0xB0B);
    bytes32 internal constant GENESIS = keccak256("synthetic-genesis");

    AdversarialERC20 internal token;
    CronosBootstrapEscrow internal escrow;

    function setUp() public {
        vm.warp(START);
        token = new AdversarialERC20();
        escrow = new CronosBootstrapEscrow(
            token, VAULT, REFUND, address(this), GENESIS, AMOUNT, [vm.addr(1), vm.addr(2), vm.addr(3)]
        );
        token.mint(address(this), AMOUNT);
        token.approve(address(escrow), AMOUNT);
    }

    function _decision(bool activate) internal returns (bytes memory) {
        bytes32 action = activate ? escrow.ACTION_ACTIVATE() : escrow.ACTION_CANCEL();
        bytes[] memory sigs = _sign2(1, 2, _typedDigest(
            _escrowDomain(escrow),
            _decisionStruct(action, GENESIS, AMOUNT, escrow.decisionNonce(), FAR_DEADLINE)
        ));
        return activate
            ? abi.encodeCall(escrow.activate, (escrow.decisionNonce(), FAR_DEADLINE, sigs))
            : abi.encodeCall(escrow.cancel, (escrow.decisionNonce(), FAR_DEADLINE, sigs));
    }

    /// Funding with a token that under-delivers, lies or returns false
    /// reverts: the escrow stays unfunded with no funding time.
    function testFuzz_fundRejectsNonStandardTokens(uint8 modeSeed) public {
        uint8[4] memory modes = [uint8(1), 2, 4, 5];
        token.configureTransferFrom(modes[modeSeed % 4], address(0), "");
        (bool ok, ) = _try(address(escrow), abi.encodeCall(escrow.fund, ()));
        require(!ok, "non-standard funding accepted");
        require(uint8(escrow.state()) == 0 && escrow.fundedAt() == 0, "escrow state");
        require(token.balanceOf(address(escrow)) == 0 && token.balanceOf(address(this)) == AMOUNT, "balances");
    }

    /// A failing transfer rolls a decision or the timeout refund back
    /// completely; a callback cannot re-enter any exit.
    function testFuzz_failingOrReentrantTokenLeavesNoPartialState(uint8 exitSeed, uint8 reentrySeed) public {
        escrow.fund();
        uint256 exit = exitSeed % 3;
        if (exit == 2) vm.warp(START + escrow.REFUND_TIMEOUT());
        bytes memory exitCall = exit == 0
            ? _decision(true)
            : exit == 1 ? _decision(false) : abi.encodeCall(escrow.refundAfterTimeout, ());

        token.configure(4, address(0), "");
        (bool ok, ) = _try(address(escrow), exitCall);
        require(!ok, "false-returning exit accepted");
        require(uint8(escrow.state()) == 1 && escrow.decisionNonce() == 0, "state after failed exit");
        require(token.balanceOf(address(escrow)) == AMOUNT, "balance after failed exit");

        bytes memory reenter;
        uint256 r = reentrySeed % 4;
        if (r == 0) reenter = abi.encodeCall(escrow.refundAfterTimeout, ());
        else if (r == 1) reenter = abi.encodeCall(escrow.forwardTerminalBalance, ());
        else if (r == 2) reenter = exit == 2 ? _decision(true) : _decision(exit == 0 ? false : true);
        else reenter = exitCall;
        token.configure(3, address(escrow), reenter);
        (ok, ) = _try(address(escrow), exitCall);
        require(ok, "exit with a reentrant token");
        require(!token.callbackSucceeded(), "callback re-entered the escrow");
        address fixedRecipient = exit == 0 ? VAULT : REFUND;
        address other = exit == 0 ? REFUND : VAULT;
        require(token.balanceOf(fixedRecipient) == AMOUNT && token.balanceOf(other) == 0, "single fixed payout");
        require(token.balanceOf(address(escrow)) == 0, "escrow emptied");
    }

    /// If the token starts charging a fee after funding, an exit still sends
    /// the escrow's whole balance to the fixed recipient address and to no
    /// address the caller chooses; the fee is taken by the token itself.
    /// The escrow, unlike the vault, does not check how much the recipient
    /// received (see the pull request notes).
    function testFuzz_feeAfterFundingNeverRedirectsTheExit(uint8 exitSeed, uint160 callerSeed) public {
        escrow.fund();
        uint256 exit = exitSeed % 3;
        if (exit == 2) vm.warp(START + escrow.REFUND_TIMEOUT());
        bytes memory exitCall = exit == 0
            ? _decision(true)
            : exit == 1 ? _decision(false) : abi.encodeCall(escrow.refundAfterTimeout, ());
        address caller = address(uint160(_bound(callerSeed, 0x1000, type(uint160).max)));
        token.configure(5, address(0), "");
        (bool ok, ) = _tryAs(caller, address(escrow), exitCall);
        require(ok, "exit");
        address fixedRecipient = exit == 0 ? VAULT : REFUND;
        require(token.balanceOf(address(escrow)) == 0, "escrow emptied");
        require(token.balanceOf(fixedRecipient) == AMOUNT - 1, "fixed recipient received the balance minus the token fee");
        require(token.balanceOf(token.FEE_COLLECTOR()) == 1 && token.balanceOf(caller) == 0, "no other recipient");
    }
}

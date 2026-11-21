// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title XitcoinV4
/// @notice Upgrade-only implementation for the Cronos XTC proxy. Replaces V3,
///         the version live before this upgrade (XitcoinV3_cyberscope.sol,
///         SHA-256 b5de4f5c4f13334bf644ec8fa97f8b0cda836ddc76935dc14c7bfcda2a73ff14).
///
/// Addresses the Cyberscope findings of Corrected Phase 5 (draft SHA-256
/// 3465cfce51d8dddce4796772eb9192ce163e3e6b70afec35df924ccd0fbc237c) and the
/// minor points of Corrected Phase 6 (draft SHA-256
/// 4eeb05a5cb4bff30168704d0dd0ed112e3abb60f5f3d71c0977e984a5d3b4ced):
///
/// IUB  The legacy 3-of-3 vote installs this implementation with empty call
///      data and never checks the owner. This implementation refuses to be
///      installed while the proxy owner has no contract code: during the
///      upgrade the proxy calls `proxiableUUID()`, which reads the current
///      owner from the proxy and reverts for a plain or delegated (EIP-7702)
///      wallet, so the legacy vote fails atomically and ownership must be
///      moved to a contract (intended: the governance timelock, IGV) first
///      (RVLD). Governance operations
///      (upgrade, rescue, metadata, ownership transfer) stay locked until the
///      governance contract confirms (`governanceMigrated`):
///        (a) intended order: the governance contract owns the proxy at
///            upgrade time and calls `confirmGovernance()`, which also cancels
///            any recovery nomination;
///        (b) recovery (fallback only): the owner is a contract that cannot
///            act. The three historical V3 voters unanimously nominate a
///            governance contract through `voteRecoveryGovernance()`, each
///            vote counting only for
///            `RECOVERY_VOTE_WINDOW`; the nominee may call `acceptOwnership()`
///            between `recoveryReadyAt` (`RECOVERY_DELAY` after the unanimous
///            nomination) and `RECOVERY_ACCEPT_WINDOW` later (NERN).
///      A live contract owner always has precedence over the historical
///      voters: its `confirmGovernance()` cancels any nomination at any time
///      during the delay and closes recovery for good. The delay must exceed
///      the governance contract's own execution latency (for a 48-hour
///      timelock this is checked off-chain before migration). Path (b) needs
///      all three historical voters; path (a) installs whichever contract owns
///      the proxy when the 3-of-3 upgrade vote executes, so that owner is
///      verified off-chain immediately before the third vote (IGV). After
///      migration, recovery is the governance contract's own responsibility
///      (signer redundancy).
///
/// TMSD The hard-coded `symbol()` override is removed. `symbol()` again reads
///      ERC-20 storage, and `reinitializeMetadata()` (reinitializer 2,
///      governance only, once) rewrites the stored symbol to the canonical
///      value so stored and reported metadata never diverge. Future
///      reinitializers must use version 3 or higher.
///
/// IGV  Code existence is a sanity check only. Safe type, signer threshold
///      and timelock delay are an off-chain trust assumption that must be
///      verified on the deployed configuration before and after migration.
///      EIP-7702 delegation designators are not accepted as contract code.
///
/// CO   The duplicated zero-address test is removed from
///      `_checkGovernanceCandidate`. The only explicit zero-address check is
///      the input validation in `transferOwnership`, the setter of
///      `pendingGovernance`; `voteRecoveryGovernance` treats a zero
///      nomination as a withdrawal and never passes it to the helper.
///
/// MEE  Every recovery nomination that is cleared (broken or lapsed
///      agreement, migration) emits `RecoveryVoteCleared`.
contract XitcoinV4 is
    Initializable,
    ERC20Upgradeable,
    OwnableUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;

    // ------------------------------------------------------------------
    // V3 storage (slots 0-8). Slot positions, labels and types retained
    // verbatim. Confers no authority except `voters`, which is read by
    // the pre-migration recovery vote. Never reorder, insert or remove
    // anything in this block.
    // ------------------------------------------------------------------
    address[3] public voters;

    // Upgrade Voting
    mapping(address => bool) public upgradeVotes;
    uint8 public upgradeVoteCount;
    address public pendingUpgrade;
    bool private _upgradeInProgress;

    // Owner Change Voting
    mapping(address => bool) public ownerChangeVotes;
    uint8 public ownerChangeVoteCount;
    // Inert legacy slot. No getter, so Ownable2Step-aware tooling does not
    // read it as the live value; the live value is `pendingGovernance`.
    address internal pendingOwner;

    // Proposal Cooldown
    uint256 public constant PROPOSAL_COOLDOWN_BLOCKS = 1000;
    uint256 public lastUpgradeProposalBlock;
    uint256 public lastOwnerProposalBlock;

    // ------------------------------------------------------------------
    // Storage added in V4 (absent from V3), appended after slot 8:
    // pendingGovernance is slot 9 offset 0; governanceMigrated (offset 20)
    // and recoveryReadyAt (offset 21) pack into the rest of slot 9;
    // recoveryVotes is slot 10, recoveryVotedAt slot 11.
    // Next free slot: 12 (slot 9 offsets 29-31 are also free).
    // ------------------------------------------------------------------

    /// @notice Pending governance hand-off. Separate from the V3
    ///         pendingOwner slot, which is inert.
    address public pendingGovernance;

    /// @notice True once a governance contract has taken ownership.
    ///         Unlocks every governance operation (IUB). One-way.
    bool public governanceMigrated;

    /// @notice Earliest timestamp at which the recovery nominee may accept.
    ///         Zero when no recovery nomination is scheduled. Acceptance is
    ///         possible only until recoveryReadyAt + RECOVERY_ACCEPT_WINDOW; a
    ///         lapsed nomination stays stored (here and in pendingGovernance)
    ///         until the next recovery vote or confirmGovernance(). Timestamps
    ///         fit in 64 bits for the foreseeable future.
    uint64 public recoveryReadyAt;

    /// @notice Pre-migration recovery nominations, one per historical voter.
    mapping(address => address) public recoveryVotes;

    /// @notice Time at which each historical voter last cast its nomination.
    ///         A nomination counts toward unanimity for `RECOVERY_VOTE_WINDOW`.
    mapping(address => uint64) public recoveryVotedAt;

    /// @notice Public notice period between a unanimous recovery nomination
    ///         and its acceptance. Must exceed the governance contract's own
    ///         execution latency so that a live owner can always confirm first.
    uint64 public constant RECOVERY_DELAY = 7 days;

    /// @notice Validity of a single recovery nomination: the three agreeing
    ///         nominations must all have been cast within this period.
    uint64 public constant RECOVERY_VOTE_WINDOW = 7 days;

    /// @notice Period after `recoveryReadyAt` during which the recovery
    ///         nominee may accept; afterwards the nomination lapses.
    uint64 public constant RECOVERY_ACCEPT_WINDOW = 7 days;

    string public constant CANONICAL_NAME = "Xitcoin";
    string public constant CANONICAL_SYMBOL = "XTC";

    error LegacyGovernanceDisabled();
    error InvalidGovernance();
    error NotPendingGovernance();
    error ForbiddenDestination();
    error GovernanceNotMigrated();
    error GovernanceAlreadyMigrated();
    error NotRecoveryVoter();
    error RecoveryNotReady(uint64 readyAt);
    error RecoveryExpired(uint64 deadline);
    error UpgradeRequiresGovernanceOwner(address owner);

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferCancelled(address indexed owner, address indexed cancelledOwner);
    event RecoveryVoteCast(address indexed voter, address indexed governance);
    event RecoveryScheduled(address indexed governance, uint64 readyAt);
    event RecoveryVoteCleared(address indexed voter, address indexed governance);
    event GovernanceMigrated(address indexed governance);
    event MetadataReinitialized(string name, string symbol);
    event ERC20Rescued(address indexed token, address indexed to, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    // Upgrade-only implementation: never initialize or mint a fresh supply.
    /// @custom:oz-upgrades-unsafe-allow missing-initializer-call
    function initialize(address[3] memory, uint256) public pure {
        revert LegacyGovernanceDisabled();
    }

    // Legacy voting surface is permanently disabled. `isVoter` keeps its
    // legacy meaning (no legacy vote is possible); use `isRecoveryVoter`.
    // `voteToRotateVoters` never existed on V3; it is kept disabled for ABI
    // parity with the Corrected Phase 5 draft.
    function isVoter(address) public pure returns (bool) { return false; }
    function voteToUpgrade(address) public pure { revert LegacyGovernanceDisabled(); }
    function voteToChangeOwner(address) public pure { revert LegacyGovernanceDisabled(); }
    function voteToRotateVoters(address[3] calldata) external pure { revert LegacyGovernanceDisabled(); }

    /// @notice Whether `account` may currently cast a recovery nomination.
    function isRecoveryVoter(address account) external view returns (bool) {
        return !governanceMigrated && _isHistoricalVoter(account);
    }

    // ------------------------------------------------------------------
    // Authority
    // ------------------------------------------------------------------

    /// @dev Governance authority: only after migration, only the governance
    ///      contract that owns the proxy. Code existence is a sanity check,
    ///      not a proof of threshold or delay.
    modifier onlyGovernance() {
        _checkOwner();
        if (!governanceMigrated) revert GovernanceNotMigrated();
        if (!_hasContractCode(msg.sender)) revert InvalidGovernance();
        _;
    }

    /// @dev Contract code, excluding an EIP-7702 delegation designator
    ///      (0xef0100 ++ 20-byte address), which is still a single key.
    function _hasContractCode(address account) internal view returns (bool) {
        uint256 size = account.code.length;
        if (size == 0) return false;
        if (size == 23 && bytes3(account.code) == 0xef0100) return false;
        return true;
    }

    /// @dev A governance candidate must be a distinct contract. The zero
    ///      address has no code, so the code check rejects it; the public
    ///      entry points check it explicitly before calling this helper.
    function _checkGovernanceCandidate(address candidate) internal view {
        if (
            !_hasContractCode(candidate) ||
            candidate == address(this) ||
            candidate == owner()
        ) revert InvalidGovernance();
    }

    function _isHistoricalVoter(address account) internal view returns (bool) {
        return account != address(0) &&
            (account == voters[0] || account == voters[1] || account == voters[2]);
    }

    // ------------------------------------------------------------------
    // Ownership hand-off (two-step, cancellable), governance only.
    // ------------------------------------------------------------------

    /// @notice Nominates the next governance contract. Replaces, and
    ///         explicitly cancels, any nomination still pending.
    function transferOwnership(address newOwner) public override onlyGovernance {
        if (newOwner == address(0)) revert InvalidGovernance();
        _checkGovernanceCandidate(newOwner);
        _cancelPendingGovernance();
        pendingGovernance = newOwner;
        emit OwnershipTransferStarted(owner(), newOwner);
    }

    function cancelOwnershipTransfer() external onlyGovernance {
        _cancelPendingGovernance();
    }

    function _cancelPendingGovernance() internal {
        address cancelled = pendingGovernance;
        if (cancelled == address(0)) return;
        delete pendingGovernance;
        delete recoveryReadyAt;
        emit OwnershipTransferCancelled(owner(), cancelled);
    }

    /// @notice Pre-migration recovery (IUB, path b; fallback for a contract
    ///         owner that cannot act). Each historical voter nominates a
    ///         governance contract; when all three nominations agree and were
    ///         cast within `RECOVERY_VOTE_WINDOW`, that contract becomes
    ///         `pendingGovernance` and may accept between `recoveryReadyAt`
    ///         and `RECOVERY_ACCEPT_WINDOW` later. While a nomination is
    ///         pending, a changed nomination, or any nomination cast after its
    ///         acceptance period lapsed, cancels it and clears the other
    ///         nominations (each with `RecoveryVoteCleared`), so a new agreement
    ///         needs three fresh nominations. Unavailable once the proxy has
    ///         migrated; a live contract owner can pre-empt it at any time
    ///         with `confirmGovernance()`.
    function voteRecoveryGovernance(address governance) external {
        if (governanceMigrated) revert GovernanceAlreadyMigrated();
        if (!_isHistoricalVoter(msg.sender)) revert NotRecoveryVoter();
        if (governance != address(0)) _checkGovernanceCandidate(governance);

        address pending = pendingGovernance;
        if (pending != address(0) && (governance != pending || _recoveryAcceptanceLapsed())) {
            // Agreement broken or lapsed: cancel, and require three fresh
            // nominations before any nominee can be scheduled again.
            _cancelPendingGovernance();
            _clearRecoveryVotes(msg.sender);
            pending = address(0);
        }

        recoveryVotes[msg.sender] = governance;
        recoveryVotedAt[msg.sender] = uint64(block.timestamp);
        emit RecoveryVoteCast(msg.sender, governance);

        if (pending == address(0) && _hasRecentRecoveryAgreement(governance)) {
            uint64 readyAt = uint64(block.timestamp) + RECOVERY_DELAY;
            pendingGovernance = governance;
            recoveryReadyAt = readyAt;
            emit OwnershipTransferStarted(owner(), governance);
            emit RecoveryScheduled(governance, readyAt);
        }
    }

    /// @dev True when all three historical voters nominated `governance`
    ///      within `RECOVERY_VOTE_WINDOW`.
    function _hasRecentRecoveryAgreement(address governance) internal view returns (bool) {
        if (governance == address(0)) return false;
        for (uint256 i = 0; i < 3; ++i) {
            address voter = voters[i];
            if (recoveryVotes[voter] != governance) return false;
            if (block.timestamp > uint256(recoveryVotedAt[voter]) + RECOVERY_VOTE_WINDOW) return false;
        }
        return true;
    }

    /// @dev True when a scheduled recovery nomination was not accepted within
    ///      `RECOVERY_ACCEPT_WINDOW` after `recoveryReadyAt`.
    function _recoveryAcceptanceLapsed() internal view returns (bool) {
        uint64 readyAt = recoveryReadyAt;
        return readyAt != 0 && block.timestamp > uint256(readyAt) + RECOVERY_ACCEPT_WINDOW;
    }

    /// @dev Clears the nominations of the historical voters other than
    ///      `keep`, emitting `RecoveryVoteCleared` for each non-empty one.
    function _clearRecoveryVotes(address keep) internal {
        for (uint256 i = 0; i < 3; ++i) {
            address voter = voters[i];
            if (voter == keep) continue;
            address previous = recoveryVotes[voter];
            delete recoveryVotedAt[voter];
            if (previous != address(0)) {
                delete recoveryVotes[voter];
                emit RecoveryVoteCleared(voter, previous);
            }
        }
    }

    /// @notice Completes a governance hand-off. A recovery nominee may accept
    ///         only between `recoveryReadyAt` and `RECOVERY_ACCEPT_WINDOW`
    ///         later; a nominee chosen by the governance contract after
    ///         migration may accept immediately. The timestamp comparisons are
    ///         the TimelockController pattern; validator clock skew of seconds
    ///         is immaterial against multi-day periods.
    function acceptOwnership() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        if (!_hasContractCode(msg.sender)) revert InvalidGovernance();
        uint64 readyAt = recoveryReadyAt;
        if (readyAt != 0) {
            if (block.timestamp < readyAt) revert RecoveryNotReady(readyAt);
            uint64 deadline = readyAt + RECOVERY_ACCEPT_WINDOW;
            if (block.timestamp > deadline) revert RecoveryExpired(deadline);
        }
        delete pendingGovernance;
        delete recoveryReadyAt;
        _transferOwnership(msg.sender);
        _completeMigration(msg.sender);
    }

    /// @notice Completes the migration when a governance contract already owns
    ///         the proxy at upgrade time (ownership moved to it under V3 before
    ///         the upgrade),
    ///         so there is no pending hand-off to accept. Any nomination
    ///         pre-positioned through the recovery vote is cancelled, so the
    ///         historical voters retain no influence after migration.
    ///         One-way, owner only, rejected for an owner without contract code.
    ///         Installs whatever contract owns the proxy at that moment,
    ///         permanently: the owner's identity is verified off-chain before
    ///         ownership is moved.
    function confirmGovernance() external onlyOwner {
        if (!_hasContractCode(msg.sender)) revert InvalidGovernance();
        if (governanceMigrated) revert GovernanceAlreadyMigrated();
        _cancelPendingGovernance();
        _completeMigration(msg.sender);
    }

    function _completeMigration(address governance) internal {
        if (!governanceMigrated) {
            governanceMigrated = true;
            // The historical voters have no role from here on; clear their
            // nominations so no stale agreement survives in storage.
            _clearRecoveryVotes(address(0));
            emit GovernanceMigrated(governance);
        }
    }

    function renounceOwnership() public view override onlyOwner {
        revert("Renouncing ownership is disabled");
    }

    // ------------------------------------------------------------------
    // Governance-only operations (locked until migration)
    // ------------------------------------------------------------------

    function _authorizeUpgrade(address) internal override onlyGovernance {}

    /// @notice ERC-1822. The proxy calls this during an upgrade to this
    ///         implementation. The upgrade is refused while the proxy owner has
    ///         no contract code (a plain or EIP-7702 delegated wallet), so the
    ///         legacy 3-of-3 vote cannot install this implementation before
    ///         ownership has moved to a contract (intended: the governance
    ///         timelock, whose identity is verified off-chain, IGV); the legacy
    ///         vote then reverts atomically, reported by the proxy as
    ///         ERC1967InvalidImplementation (IUB, RVLD).
    /// @dev    A caller without code gets the standard answer. For a contract
    ///         caller the check fails closed: this call reverts if owner()
    ///         reverts, runs out of gas or does not return an address, and is
    ///         refused with UpgradeRequiresGovernanceOwner if the owner has no
    ///         contract code.
    function proxiableUUID() external view override notDelegated returns (bytes32) {
        if (msg.sender.code.length != 0) {
            address currentOwner = OwnableUpgradeable(msg.sender).owner();
            if (!_hasContractCode(currentOwner)) revert UpgradeRequiresGovernanceOwner(currentOwner);
        }
        return ERC1967Utils.IMPLEMENTATION_SLOT;
    }

    /// @notice Aligns stored ERC-20 metadata with the canonical symbol (TMSD).
    ///         Runs once; the proxy is at initializer version 1 before this
    ///         upgrade.
    function reinitializeMetadata() external onlyGovernance reinitializer(2) {
        __ERC20_init(CANONICAL_NAME, CANONICAL_SYMBOL);
        emit MetadataReinitialized(CANONICAL_NAME, CANONICAL_SYMBOL);
    }

    /// @notice Moves tokens held by the proxy itself, including XTC that was
    ///         sent to it before self-transfers were rejected. Cannot debit
    ///         any holder.
    function rescueERC20(address token, address to, uint256 amount) external onlyGovernance {
        require(token != address(0), "Invalid token");
        _checkDestination(to);
        IERC20(token).safeTransfer(to, amount);
        emit ERC20Rescued(token, to, amount);
    }

    // ------------------------------------------------------------------
    // Token surface
    // ------------------------------------------------------------------

    function burn(uint256 amount) external { _burn(msg.sender, amount); }

    // Check ordinary destinations before allowance spending. _burn bypasses this
    // entry point and keeps the standard ERC20 zero-address Transfer event.
    function transfer(address to, uint256 amount) public override returns (bool) {
        _checkDestination(to);
        return super.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        _checkDestination(to);
        return super.transferFrom(from, to, amount);
    }

    function _checkDestination(address to) internal view {
        if (to == address(0) || to == 0x000000000000000000000000000000000000dEaD || to == address(this))
            revert ForbiddenDestination();
    }
}

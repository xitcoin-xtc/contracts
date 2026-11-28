# Bridge properties enforced by tests

Every property below is checked by a Solidity test in this directory. Hardhat
3 runs them with `npm test` on every pull request (fuzz tests: 256 runs;
invariant suites: 64 runs of 64 calls) and nightly with a fresh seed and
larger campaigns (`.github/workflows/nightly-fuzz.yml`). They are local EVM
simulations with public synthetic keys. They test the contracts; they are not
an audit or a formal proof.

## Stateful attack simulations

`VaultSecurityInvariants.t.sol` drives `CronosBridgeVault` with random
sequences of deposits, donations, honest releases, copied and mutated
releases, forged releases, honest and forged control actions (signer
rotation included), approvals pre-signed before a rotation, guardian and
outsider pauses, rescues and time jumps. A second vault with the same signers
on the same chain receives cross-vault replays. After every call:

| Property | Check |
|---|---|
| Vault balance == initial + deposits + donations − releases | `_custodyConservation` |
| Each burn ID is released at most once; `processedBurns` marks exactly the paid burns | `_burnReleasedAtMostOnce` |
| Every release respected `maxReleaseAmount` and `dailyReleaseLimit` in force; `releasedToday` is the sum of the day's releases | `_releaseLimits` |
| A call is accepted exactly when the specification allows it; a rejected call changes no state | `_acceptanceMatchesSpecification` |
| Releases and control actions need 2 of the current 3 signers, the current nonce and the current signer-set version; rotated-out, outsider, duplicate, high-s, compact, malformed and expired signatures never count | `_onlyCurrentQuorumAuthorizes` |
| Signatures for another chain ID, another vault or another EIP-712 domain never count | `_noCrossDomainReplay` |
| While paused, no deposit or release moves XTC; only the guardian pauses; only a quorum resumes | `_pausedMeansNoMovement` |
| Rescue never moves XTC, even with a valid quorum | `_rescueNeverMovesXtc` |
| XTC leaves only to the approved recipient, in the approved amount; a front-runner submitting copied calldata pays the approved recipient once and receives nothing | `_onlyApprovedRecipientsPaid` |

`EscrowSecurityInvariants.t.sol` drives `CronosBootstrapEscrow` with funding
attempts, honest and forged decisions, approvals kept and submitted later,
permissionless refunds and forwarding, donations and time jumps (including to
the exact timeout second). A second escrow with identical parameters receives
cross-escrow replays.

| Property | Check |
|---|---|
| Escrowed tokens only reach the permanent vault or the refund recipient | `_fundsOnlyToFixedRecipients` |
| At most one terminal outcome; the other recipient receives nothing | `_terminalStatesExclusive` |
| Decisions only before `fundedAt + 180 days`; the refund only from that second | `_timeoutHolds` |
| Only 2 of the 3 configured signers decide; other escrows, chains and domains never count | `_onlyQuorumDecides` |
| Acceptance matches the specification; a rejected call changes no state | `_acceptanceMatchesSpecification` |

`VaultDepositLimits.t.sol` keeps the deposit-limit invariants (per-deposit,
daily and locked caps).

## Targeted fuzz tests

`BridgeAttacks.t.sol`, `VaultInvariants.t.sol`, `VaultDepositLimits.t.sol`
and `EscrowTimeout.t.sol` cover single attacks with fuzzed inputs: high-s and
duplicate signatures, unconfigured signers, malformed encodings, foreign
domains and chain ID changes, replay across a rotation that keeps two
signers, cross-vault control replay, front-running, pause, payload binding,
day rollover, and tokens that return false, under-deliver, charge a fee or
call back into the vault or escrow. `RescueDoubleEntryTest` checks that a
token address sharing XTC's balance ledger cannot be rescued.

## Outside what these tests can show

- Whether the signer service only signs real, final Xitcoin burns, and the
  security of the signer keys. A compromised 2-of-3 quorum can raise limits,
  replace the guardian and release funds; the tests treat the quorum as the
  authority it is.
- The XTC token itself. The adversarial token models show what the vault and
  escrow do if the token misbehaves; the escrow does not check how much a
  recipient received (see `testFuzz_feeAfterFundingNeverRedirectsTheExit`).
- The Xitcoin chain and its bridge module.

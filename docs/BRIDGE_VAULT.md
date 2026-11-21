# Cronos bridge vault

## Purpose

`CronosBridgeVault` is the Cronos custody component of the canonical XTC route between Cronos and Xitcoin.

- Cronos to Xitcoin: a holder deposits canonical Cronos XTC into the vault. The corresponding native XTC settlement is performed by the Xitcoin bridge after its independent attestation checks.
- Xitcoin to Cronos: native XTC is burned on Xitcoin. The vault releases the corresponding locked Cronos XTC after two current bridge signers approve the burn record.

The vault does not mint or burn the Cronos token. Sending XTC to a dead address is not a bridge operation and does not reduce ERC-20 `totalSupply`.

## Canonical asset

Production construction must use the XTC proxy, not its implementation address:

```text
0xE45FE733BC8617FA6DAC8437FC44B5FFFA949991
```

The implementation address may change through the independently governed UUPS upgrade process. The proxy is the stable integration address.

## Security model

- every release and control approval is bound by EIP-712 to the Cronos chain ID and the deployed vault address;
- every release identifies one native Xitcoin burn and that identifier can be processed only once;
- two distinct approvals from the current three-member signer set are required;
- signer-set versions prevent approvals from silently crossing a signer rotation;
- signatures expire;
- per-release and daily release limits cap release exposure;
- per-deposit, daily deposit and total locked limits cap what can be locked;
- releases cannot exceed the vault's actual XTC balance;
- deposits and releases reject the zero and conventional dead addresses;
- the emergency guardian can pause immediately but cannot resume the vault;
- resumption, signer rotation, release and deposit limit changes, guardian changes and foreign-token rescue require signer quorum and a monotonic governance nonce;
- no owner or administrative withdrawal of canonical XTC exists;
- a quorum-controlled rescue is restricted to unrelated ERC-20 assets.

The signer service must approve a release only after independently confirming finality, the native burn amount, the recipient, the route, the signer-set version and the absence of an earlier approval for the same burn identifier.

### Who can do what

| Actor | Can | Cannot |
|---|---|---|
| Anyone | `deposit` while not paused and within the deposit limits; submit a `release` or control action that carries valid quorum signatures (the submitter is not part of what is signed) | Move canonical XTC out of the vault without a valid release approval |
| Guardian | `pause` (stops `deposit` and `release` immediately) | Resume, change limits, rotate signers, replace itself, rescue tokens or move funds |
| 2 of the 3 current signers | Approve `release`, `resume`, `rotateSigners`, `updateLimits` (release limits), `updateDepositLimits`, `changeGuardian`, `rescueForeignToken` | Rescue canonical XTC; reuse an approval after its nonce, signer-set version or deadline has passed |

Control actions other than `resume` are accepted whether or not the vault is paused; `resume` requires the paused state. All of them take effect in the transaction that executes them; there is no delay. The guardian therefore cannot veto a compromised quorum: the same quorum can replace the guardian, raise limits and resume. Options for changing this are described, but not implemented, in [`GOVERNANCE_PROPOSAL.md`](GOVERNANCE_PROPOSAL.md).

### What each signature binds

All signatures use the EIP-712 domain `name = "Xitcoin Cronos Bridge Vault"`, `version = "1"`, the Cronos chain ID and the vault address. Nothing else about the route is signed: the canonical asset and `routeId` are immutable per vault and are bound only through the vault address.

- `Release(bytes32 sourceBurnId,address recipient,uint256 amount,uint64 signerSetVersion,uint256 deadline)`. Replay is prevented by `processedBurns[sourceBurnId]`, not by a nonce. The approval does not bind the caller.
- `Control(bytes32 action,bytes32 payloadHash,uint256 nonce,uint64 signerSetVersion,uint256 deadline)`, where `nonce` must equal the single shared `governanceNonce` (incremented by every successful control action) and `payloadHash` is:

| Action (`keccak256` of) | Function | `payloadHash` |
|---|---|---|
| `RESUME` | `resume` | `bytes32(0)` |
| `ROTATE_SIGNERS` | `rotateSigners` | `keccak256(abi.encode(address[3] newSigners))` |
| `UPDATE_LIMITS` | `updateLimits` | `keccak256(abi.encode(maxReleaseAmount, dailyReleaseLimit))` |
| `UPDATE_DEPOSIT_LIMITS` | `updateDepositLimits` | `keccak256(abi.encode(maxDepositAmount, dailyDepositLimit, maxLockedAmount))` |
| `CHANGE_GUARDIAN` | `changeGuardian` | `keccak256(abi.encode(newGuardian))` |
| `RESCUE_FOREIGN_TOKEN` | `rescueForeignToken` | `keccak256(abi.encode(token, recipient, amount))` |

Because all control actions share one nonce, approvals are strictly ordered: two approvals signed for the same nonce can never both execute, and an approval left unused is invalidated by any other control action.

Deposits are not signed. Each `Deposited` event carries `depositId = keccak256(abi.encode(block.chainid, vault, routeId, depositor, recipient, amount, depositNonce))`.

## Limits

All amounts are in the canonical token's base units (18 decimals). Day buckets are UTC days computed as `block.timestamp / 1 days`, so a new bucket starts at 00:00:00 UTC by block time. A failed transaction leaves every counter unchanged.

### Vault release limits

- `maxReleaseAmount`: a release above it reverts with `ReleaseLimitExceeded`;
- `dailyReleaseLimit`: `releasedToday` resets when the UTC day changes; a release that would take it above the limit reverts with `DailyLimitExceeded`;
- a release above the vault's current XTC balance reverts with `InsufficientLiquidity`.

### Vault deposit limits

- `maxDepositAmount`: a deposit above it reverts with `DepositLimitExceeded`;
- `dailyDepositLimit`: `depositedToday` resets when the UTC day changes (`depositDay` holds the day index); a deposit that would take it above the limit reverts with `DailyDepositLimitExceeded`;
- `maxLockedAmount`: a deposit reverts with `LockedAmountCapExceeded` if `asset.balanceOf(vault) + amount` would exceed it. The check uses the vault's real token balance, so direct transfers to the vault (donations) and the bootstrap reserve moved in by `CronosBootstrapEscrow` count toward the cap, although neither goes through `deposit` and neither is limited by it.

All three are set in the constructor and can be changed only by a quorum `updateDepositLimits` action. The constructor and the action require every value to be non-zero, `maxDepositAmount <= dailyDepositLimit` and `maxDepositAmount <= maxLockedAmount`; otherwise they revert with `InvalidDepositLimits`. A change applies immediately and does not reset the current day's total. Lowering `dailyDepositLimit` below the day's total blocks deposits until the next UTC day; lowering `maxLockedAmount` below the current balance blocks deposits until releases bring the balance back under it. Deposit limits never affect releases.

Anyone can fill the locked cap with a direct transfer and so block deposits. Such a transfer cannot be withdrawn by its sender, so it is costly; the quorum can respond by raising the cap within the Xitcoin route limit, and the guardian can pause.

### Xitcoin route limits

The Xitcoin bridge module enforces its own route configuration, independently of this vault. As implemented in the chain's `x/bridge` module at the time of writing (that repository is authoritative):

- `max_transfer_amount`: maximum amount of one inbound settlement or outbound burn;
- `daily_limit`: one bucket per route and UTC day of block time, shared by inbound settlements and outbound burns;
- `max_outstanding_amount`: an inbound settlement is rejected if the bridge's outstanding amount (the genesis value plus bridge mints minus bridge burns) would exceed it; an outbound burn cannot exceed the outstanding amount.

### Configuring the vault against the route

The deposit limits exist so that a deposit the chain could not mint is rejected on Cronos instead of being locked:

- set `maxDepositAmount` no higher than the route's `max_transfer_amount`; a larger deposit could never be settled on Xitcoin;
- set `maxLockedAmount` no higher than the route's `max_outstanding_amount`. Every outstanding native unit is backed by locked XTC, and locked XTC also includes deposits not yet settled and donations, so the vault balance is at least the chain's outstanding amount; capping the balance keeps every accepted deposit within the outstanding limit. This assumes the route's genesis outstanding amount matches the bootstrap reserve and that releases follow burns;
- size `maxLockedAmount` to include the bootstrap reserve, which counts toward the balance from activation onward;
- `dailyDepositLimit` cannot guarantee same-day settlement, because the chain's daily bucket is shared with outbound burns; an accepted deposit can be delayed until that bucket has room;
- compare the values on both sides in the same base units, and re-check the vault whenever the route configuration changes.

The contract cannot read the chain's configuration; keeping these values consistent is an operational responsibility of whoever approves the configuration on both sides.

## Build and tests

The project deliberately uses two Solidity compilers:

- `0.8.4` for the exact historical V1 source;
- `0.8.30` with EVM target `paris` for V2 and the vault.

```bash
npm ci
npm run audit:production
npm run compile
npm run test:vault
```

The package lock is authoritative. Do not apply an automated breaking dependency rewrite to deployment tooling.

## Deployment controls

Deployment is a separate reviewed operation. Before any Cronos transaction:

1. confirm the canonical XTC proxy from `deployments/cronos.json` and the Cronos Explorer;
2. define three distinct bridge signer addresses and a separate guardian;
3. define conservative initial release limits and deposit limits consistent with the Xitcoin route (see [Limits](#limits));
4. derive and record the route identifier;
5. reproduce the build from `package-lock.json`;
6. test construction on Cronos testnet;
7. verify the exact source and constructor arguments in Cronos Explorer;
8. perform deposits and releases with low-value test assets before considering a production route.

No private key, mnemonic, API key or RPC credential belongs in this repository.

## Isolated Cronos testnet deployment

The repository provides a fail-closed testnet deployment command. It accepts
only Cronos EVM Testnet chain ID `338`, deploys the fixed-supply `tXTC` test
asset and the vault for route
`XTC:CRONOS-TESTNET:338:XITCOIN-TESTNET-V2-1`, and writes a new local deployment
record with mode `0600`. The vault starts paused and requires a later 2-of-3
signer approval to resume. It refuses Cronos mainnet chain ID `25`, duplicate
signers, a signer used as guardian, unsafe release or deposit limits, an unfunded
tCRO deployer and overwriting an earlier record. Deposit limits default to
`BRIDGE_TESTNET_MAX_DEPOSIT=100`, `BRIDGE_TESTNET_DAILY_DEPOSIT_LIMIT=500` and
`BRIDGE_TESTNET_MAX_LOCKED=10000` tXTC.

The vault recorded in `deployments/cronos-testnet.json` was deployed from the
earlier bytecode and predates deposit limits: it has no deposit limits and its
constructor takes seven arguments. Testing deposit limits on Cronos testnet
needs a new, separately reviewed deployment.

Use `.env.example` as a variable checklist, inject the values from a private
secret store, provide distinct test-only identities, and run only after an
independently reviewed transaction authorization:

```bash
npm ci
npm run test:testnet-deployment
npm run deploy:cronos-testnet
```

The generated record under `deployments/generated/` is intentionally ignored.
After explorer verification and review, publish a sanitized registry entry in a
separate pull request. A testnet deployment does not authorize route activation
or any mainnet operation.

## Explorer verification

Current Cronos Explorer endpoints are tracked separately from compilation because explorer APIs can change independently of contract source:

```text
Mainnet explorer: https://explorer.cronos.com
Mainnet API:      https://explorer-api.cronos.org/mainnet/api/v2
Testnet explorer: https://explorer.cronos.com/testnet
Testnet API:      https://explorer-api.cronos.org/testnet/api/v2
```

At deployment time, use the current supported Hardhat verification configuration and keep the explorer API key in an environment variable. If automated multi-source verification is rejected by the Explorer API, submit the identical standard compiler input through the Explorer interface and record the verified address and source hash in `deployments/cronos.json`.

No deployment address is canonical until it appears in the deployment registry on the default branch.

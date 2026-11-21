# Cronos bootstrap escrow

`CronosBootstrapEscrow` is a one-time safety boundary for the initial native
XTC reserve. It does not replace `CronosBridgeVault` and it does not add an
administrator withdrawal to that permanent vault.

## Required sequence

1. Deploy the permanent bridge vault and the bootstrap escrow with reviewed,
   immutable addresses, the canonical genesis SHA-256, the exact bootstrap
   amount and three independent decision signers.
2. The fixed funding account approves and funds the escrow once. The funding
   timestamp is recorded as `fundedAt`.
3. Build and start the Xitcoin network privately. Public RPC, public P2P entry,
   deposits and user transfers remain closed.
4. If the private launch fails, two of three signers authorize `cancel`. Every
   canonical `$XTC` unit held by the escrow returns to the immutable refund
   recipient and that escrow can never be activated.
5. If the private launch passes its acceptance checks, two of three signers
   authorize `activate`. Every canonical `$XTC` unit held by the escrow moves
   to the immutable permanent vault and that escrow can never be cancelled.
6. Only after activation is confirmed on Cronos may the Xitcoin mainnet become
   public.

Steps 3 and 6 are an operational procedure. No contract and no chain rule
enforces that the network stays private until activation: the escrow cannot
observe the Xitcoin network, and nothing on the chain checks the escrow's
state. The procedure matters because the escrow can still return the reserve
to the refund recipient (by `cancel` or by the timeout refund below) at any
time before activation. If the network were opened before activation, native
XTC could circulate while the reserve meant to back it is refunded.

## Timeout refund

The decision signers are immutable and cannot be rotated. To keep the reserve
from being locked forever if a quorum of them becomes unavailable, the escrow
has a permissionless timeout:

- `REFUND_TIMEOUT` is 180 days, counted from `fundedAt` (not from deployment);
  `refundAvailableAt()` returns `fundedAt + REFUND_TIMEOUT`, or zero before
  funding;
- from `refundAvailableAt()` onward, while the escrow is still `Funded`, anyone
  may call `refundAfterTimeout()`. It moves the escrow to `Cancelled`, transfers
  the escrow's entire canonical balance to the immutable refund recipient and
  emits `BootstrapRefundedAfterTimeout(refundRecipient, amount, genesisHash,
  caller)`. Unlike `cancel`, it does not require the balance to cover
  `expectedAmount`, so the reserve can always leave;
- `activate` and `cancel` are accepted only while `block.timestamp <
  refundAvailableAt()`. From that instant both revert with
  `RefundTimeoutElapsed`, even with approvals signed earlier whose deadline is
  later. This is deliberate: once the timeout has passed, holders and the
  funder can rely on the refund, and a stale or late quorum cannot activate
  instead. Cancellation after the timeout would have the same recipient as the
  timeout refund, so only the permissionless path remains;
- before `refundAvailableAt()`, `refundAfterTimeout()` reverts with
  `RefundTimeoutNotReached`; after `activate` or `cancel` it reverts with
  `InvalidState`.

Operators must therefore complete activation well before the timeout. A launch
that cannot be activated within 180 days of funding ends in a refund, and a
new escrow would be needed.

## Who can do what

| Actor | Can |
|---|---|
| Fixed funding account | `fund` once, pulling exactly `expectedAmount` |
| 2 of the 3 decision signers | Approve `activate` or `cancel` while `Funded` and before the timeout |
| Anyone | Submit a quorum-approved `activate` or `cancel`; call `refundAfterTimeout` after the timeout; call `forwardTerminalBalance` after a terminal outcome |

No actor can choose a recipient: the permanent vault and the refund recipient
are fixed at deployment.

## What a decision signature binds

`Decision(bytes32 action,bytes32 genesisHash,uint256 expectedAmount,uint256 nonce,uint256 deadline)`
under the EIP-712 domain `name = "Xitcoin Cronos Bootstrap Escrow"`,
`version = "1"`, the Cronos chain ID and the escrow address. `action` is
`keccak256("ACTIVATE")` or `keccak256("CANCEL")` and `nonce` must equal
`decisionNonce`. The recipients and the signer set are not signed; they are
immutable and bound through the escrow address.

## Safety properties

- Activation, cancellation and the timeout refund are mutually exclusive
  terminal outcomes; the timeout refund ends in the `Cancelled` state.
- Both quorum decisions require two distinct authorized EIP-712 signatures and
  are only possible before the timeout.
- Funding, refund and permanent-vault addresses are immutable, and so are the
  decision signers.
- There is no arbitrary canonical-token recipient and no owner withdrawal.
- Directly transferred canonical dust follows the full reserve to the same
  fixed terminal recipient; it cannot be redirected.
- Canonical tokens sent directly after closure are not trapped: anyone may
  trigger `forwardTerminalBalance`, but it can forward only to the permanent
  vault after activation or the immutable refund recipient after cancellation
  or a timeout refund.
- When the reserve reaches the permanent vault it counts toward the vault's
  `maxLockedAmount`; see [`BRIDGE_VAULT.md`](BRIDGE_VAULT.md#vault-deposit-limits).

## Deployment rule

Do not deploy or fund from placeholders. Record and independently verify the
canonical `$XTC` proxy, implementation, escrow, permanent vault, refund
recipient, funding account, signer addresses, genesis hash, expected amount,
transaction hashes and bytecode verification before moving real value. Record
`fundedAt` and `refundAvailableAt()` after funding and plan activation against
that date.

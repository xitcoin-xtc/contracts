# Bridge governance options

> **Proposal: not implemented, requires owner decision.**
> Nothing in this document describes current contract behavior. The contracts
> in this repository do not contain any of these mechanisms. Current behavior
> is documented in [`BRIDGE_VAULT.md`](BRIDGE_VAULT.md) and
> [`BOOTSTRAP_ESCROW.md`](BOOTSTRAP_ESCROW.md).

## Current state

In `CronosBridgeVault`, the guardian can only pause. The same 2-of-3 signer
quorum that approves releases also approves every control action (resume,
signer rotation, release limits, deposit limits, guardian change and
foreign-token rescue), and each action takes effect in the transaction that
executes it. A compromised quorum can therefore replace the guardian, raise
limits, resume and release in a short sequence of transactions. The limits
bound the rate of loss only as long as that quorum does not raise them.

In `CronosBootstrapEscrow`, the three decision signers are immutable. The
180-day timeout refund guarantees that the reserve can leave, but only to the
fixed refund recipient.

The vault is not upgradeable, so any of the options below applies only to a
new deployment and changes its constructor and control interface. The
off-chain relayer depends on the release signature, the `Deposited` event and
the existing control encodings; options should add new actions rather than
change existing ones.

## Options

### 1. Delay before limit increases take effect

Increases to release or deposit limits are queued for a fixed delay (for
example 48 hours, matching the XTC timelock) and executed by anyone after it;
decreases and `pause` stay immediate.

- For: a compromised quorum cannot raise limits and drain faster within the
  delay; the guardian and watchers have time to pause.
- For: decreases, the defensive direction, keep working instantly.
- Against: legitimate increases (for example after higher demand) are slower;
  queued actions need cancellation rules and monitoring.
- Against: only useful if someone watches the queue and the guardian is
  independent of the quorum; the quorum can still change the guardian unless
  that change is delayed too.

### 2. Separate key or role for raising limits

Raising limits requires approval from a key or role distinct from the release
signers (for example the existing XTC Safe or timelock), while the signers
keep the ability to lower limits.

- For: compromise of the release signers alone no longer raises the exposure
  ceiling.
- For: combines well with option 1 (the separate role acts through a delay).
- Against: one more key set to secure, rotate and keep available; if it is
  lost, limits can never be raised again in that deployment.
- Against: adds a cross-system dependency (Safe or timelock availability)
  to routine operations.

### 3. Signer rotation

Today a vault rotation needs approval from the current quorum and is
immediate; escrow signers cannot be rotated at all.

- Delay rotations in the vault: protects against a quorum handing control to
  new keys instantly, but slows the response when one key is known to be
  compromised (the two honest signers would want to rotate at once).
- Require an independent role (option 2) to co-approve rotations: limits a
  compromised quorum, but makes recovery depend on that role.
- Escrow rotation: adding a quorum-approved rotation to a future escrow would
  help if one signer is lost, but not if two are lost, and it widens the
  escrow's attack surface during the private launch window. The 180-day
  timeout refund already covers loss of the quorum; a shorter timeout, or a
  rotation path controlled by the funding account, are alternatives with
  their own trust trade-offs.

### 4. Resume after pause

Today `resume` needs the same quorum and is immediate.

- Delay `resume` (for example 24 to 48 hours): a compromised quorum cannot
  unpause and release at once after the guardian has paused; the guardian
  could also be allowed to cancel a pending resume.
- Against: lengthens every legitimate outage, including false alarms.
- Require an independent role to co-approve `resume`: stronger, with the same
  availability cost as option 2.
- Keep releases paused but allow deposits (or the reverse) after a partial
  resume: finer control, more states to test and to explain to users.

## Decision needed

The owner should decide which, if any, of these options a future deployment
should include, the delay values, and which existing key set (if any) holds a
separate role. Each choice needs its own design review, tests and relayer
changes before implementation.

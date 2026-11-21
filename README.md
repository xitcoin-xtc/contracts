# Xitcoin Contracts

Canonical source, deployment, security and ecosystem references for Xitcoin smart contracts.

## Cronos deployments

| Component | Address | Decimals | Purpose |
|---|---|---:|---|
| Old Xitcoin (V1) | `0xDD646291D2fff52c75F27CCDAdD0D4C2A24f37Dd` | 8 | Legacy fixed-supply token |
| XTC proxy | `0xE45FE733BC8617FA6DAC8437FC44B5FFFA949991` | 18 | The XTC token: the address to use |
| XTC implementation V4 | `0x3F4e9e3b1B4317674AF9C87d69ECA25c76E4a8B5` | 18 | Current implementation, live since 1 October 2026 |
| Governance timelock | `0x33221850aDC263Ea61cF64662CDa2E7D654eD409` | — | Owner of the XTC proxy, 48-hour minimum delay |
| Xitcoin Safe | `0xA18A28A79c2B0b67c8cF37FfF863EbaD75B02945` | — | 2-of-3 multisig that runs the timelock |
| Migration | `0x5A570197e4835d0c2F2F956026981E0cff50A8c9` | — | Converts Old Xitcoin units to XTC |

Earlier implementations: V3 `0x6c171952999421F0DA00E14F97B9C2DfBE71D8A0` (18 February to 1 October 2026), V2 `0xDBCd79A3651C2E0d9ae8736F4652516FAecd5bc7` (July 2025 to February 2026).

Use the proxy address for every integration. The machine-readable deployment registry is [`deployments/cronos.json`](deployments/cronos.json).

Since V4 the token returns `XTC` from `symbol()` (it returned `$XTC` before 1 October 2026). The native Xitcoin blockchain uses the same symbol `XTC`; its atomic denomination is `axtc`. See [`ecosystem/README.md`](ecosystem/README.md) for the integration distinction.

## Repository layout

- `contracts/cronos/v1/`: verified V1 source;
- `contracts/cronos/v2/`: verified V3 implementation source (historical folder name);
- `contracts/cronos/migration/`: verified migration source;
- `contracts/cronos/bridge/`: reviewed bridge custody candidates;
- `deployments/`: canonical network and contract registry;
- `audits/`: independent smart-contract audit records and exact source scope;
- `verification/`: external project verification and KYC references;
- `ecosystem/`: explorer verification, listings, markets and official community channels;
- `docs/MIGRATION.md`: migration accounting and verification;
- `docs/UPGRADE_POLICY.md`: how the token is governed and upgraded.

The native XTC asset on Xitcoin EVM is implemented by the chain. It is not an ERC-20 deployment in this repository.

`contracts/cronos/bridge/CronosBridgeVault.sol` contains the Cronos custody side of the canonical XTC route. It accepts voluntary XTC deposits within a per-deposit maximum, a daily deposit limit and a cap on the total locked balance, and releases locked XTC only after a two-of-three EIP-712 approval representing a native Xitcoin burn, within per-release and daily release limits. A guardian can pause; every other control action needs the same two-of-three signer quorum. Source publication does not identify a deployment; canonical addresses are added to `deployments/` only after deployment and verification. No bridge vault or escrow is deployed on Cronos mainnet; the testnet vault recorded in `deployments/cronos-testnet.json` predates the deposit limits.

`contracts/cronos/bridge/CronosBootstrapEscrow.sol` holds the one-time bootstrap reserve until a two-of-three quorum activates (moves it to the permanent vault) or cancels (refunds it to a fixed recipient). If neither happens within 180 days of funding, anyone can refund it to that fixed recipient. Keeping the Xitcoin network private until activation is an operational procedure that no contract enforces.

The vault security model, roles, limits and verification procedure are documented in [`docs/BRIDGE_VAULT.md`](docs/BRIDGE_VAULT.md), the escrow in [`docs/BOOTSTRAP_ESCROW.md`](docs/BOOTSTRAP_ESCROW.md). Governance changes under consideration (not implemented) are listed in [`docs/GOVERNANCE_PROPOSAL.md`](docs/GOVERNANCE_PROPOSAL.md).

## Audit and external verification

The V4 implementation source (SHA-256 `48de6f7b…`, [verified on Cronos Explorer](https://explorer.cronos.com/address/0x3F4e9e3b1B4317674AF9C87d69ECA25c76E4a8B5#code)) was audited by Cyberscope (Corrected Phase 5, 29 September 2026) before it went live; the V3 source was audited in February 2026. See [`audits/README.md`](audits/README.md).

Cyberscope's project profile and KYC record are indexed separately in [`verification/README.md`](verification/README.md). KYC confirms an identity-verification result; it does not expand smart-contract audit scope.

No audit coverage is claimed here for V1, the migration contract, Xitcoin EVM or a future bridge unless an explicit report is added with a matching source hash.

## Verification, listings and community

Cronos Explorer verification, CoinGecko, CoinMarketCap, current market-discovery references and official community channels are maintained in [`ecosystem/README.md`](ecosystem/README.md). Third-party markets are not designated as official pools. Always verify the Cronos chain and the XTC proxy address before signing.

## Verification commands

```bash
sha256sum contracts/cronos/v1/XitcoinV1.sol
sha256sum contracts/cronos/v2/XTCV2.sol
sha256sum contracts/cronos/migration/Migration.sol
npm ci
npm run compile
npm run test:vault
npm run audit:production
jq . deployments/cronos.json
jq . ecosystem/cronos.json
```

Expected source hashes are recorded in `deployments/cronos.json`.

## Development dependency compatibility

The lockfile uses Zod 4.6.6 to fix GHSA-mrhx-c7xc-m3w5. Hardhat's
`hardhat-zod-utils` 3.0.6 still expects two Zod 3 error APIs. The installation
script applies a checksum-checked compatibility patch: use `error.issues` and
the `error` customization option. It rejects unexpected helper versions or
source changes and does not run against a production-only install.

Run `npm run test:tooling` to check early rejection of oversized collections,
configuration schemas and actual CLI rejection of invalid configurations.
The full audit and Solidity tests remain blocking in CI. Remove this temporary
patch when a supported upstream release provides equivalent compatibility;
do not replace Zod 4 with the vulnerable `zod/v3` compatibility entry.

## Security

Verify the chain, address and intended function before signing. Report vulnerabilities privately according to [`SECURITY.md`](SECURITY.md).

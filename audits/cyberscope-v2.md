# Cyberscope audit — XTC implementation V3 (replaced on 1 October 2026)

V3 was the live implementation from 18 February to 1 October 2026. The current implementation is V4: see [`cyberscope-v4.md`](cyberscope-v4.md).

## Official record

| Field | Value |
|---|---|
| Auditor | Cyberscope |
| Report | https://www.cyberscope.io/audits/1-xtc |
| Network | Cronos Mainnet |
| Proxy | `0xE45FE733BC8617FA6DAC8437FC44B5FFFA949991` |
| Implementation | `0x6c171952999421F0DA00E14F97B9C2DfBE71D8A0` |
| Audited source label | `XitcoinV3_cyberscope.sol` |
| Canonical repository source | `contracts/cronos/v2/XTCV2.sol` |
| SHA-256 | `b5de4f5c4f13334bf644ec8fa97f8b0cda836ddc76935dc14c7bfcda2a73ff14` |

The auditor's historical filename and the canonical repository filename differ. The source hash identifies the reviewed code; the deployed implementation contract is named `XitcoinImplementation`.

## Published iterations

Cyberscope lists four iterations for this audit record:

- 2 July 2025;
- 16 July 2025;
- 16 February 2026;
- 17 February 2026.

The official record publishes its current findings and status. Live scores, rankings and project statistics are not duplicated in this repository because Cyberscope updates them independently.

## Scope

This audit record covers only the source identified by the SHA-256 above. It does not cover:

- Xitcoin V1;
- the V1-to-V2 migration contract;
- the Xitcoin Proof-of-Stake chain;
- validator or explorer infrastructure;
- a bridge implementation;
- later implementations (V4 has its own record).

After any proxy upgrade, verify the active implementation address and source hash before relying on this audit record.

## Reproducible verification

```bash
sha256sum contracts/cronos/v2/XTCV2.sol
jq -r '.contracts.xtc.previous_implementations[0] | .address, .source_sha256' deployments/cronos.json
```

Expected source hash:

```text
b5de4f5c4f13334bf644ec8fa97f8b0cda836ddc76935dc14c7bfcda2a73ff14
```

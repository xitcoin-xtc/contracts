# Cyberscope audit — XTC implementation V4

| Field | Value |
|---|---|
| Auditor | Cyberscope |
| Record | https://www.cyberscope.io/audits/1-xtc |
| Report | Corrected Phase 5, 29 September 2026 |
| Network | Cronos Mainnet |
| Proxy | `0xE45FE733BC8617FA6DAC8437FC44B5FFFA949991` |
| Implementation | `0x3F4e9e3b1B4317674AF9C87d69ECA25c76E4a8B5` (live since 1 October 2026) |
| Source | [Verified on Cronos Explorer](https://explorer.cronos.com/address/0x3F4e9e3b1B4317674AF9C87d69ECA25c76E4a8B5#code) (`XitcoinV4.sol`) |
| SHA-256 | `48de6f7b619b949027a0377adf1f4780f37a0bca283da124d4abb2cc04ab700d` |

The report found no critical and no medium-severity issue; the three minor findings were acknowledged by the team. The deployed source was verified on Cronos Explorer on 2 October 2026 and matches the audited file.

Scope: this source only. It does not cover Old Xitcoin (V1), the migration contract, the governance timelock or Safe (official, unmodified contracts), the Xitchain blockchain, or a bridge.

To check: download the verified `XitcoinV4.sol` from Cronos Explorer and compare its SHA-256 with the value above, or read it from the registry:

```bash
jq -r '.contracts.xtc.implementation | .address, .source_sha256' deployments/cronos.json
```

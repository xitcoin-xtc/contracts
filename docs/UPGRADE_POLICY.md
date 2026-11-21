# XTC governance and upgrades

XTC is accessed through the ERC-1967 proxy at `0xE45FE733BC8617FA6DAC8437FC44B5FFFA949991` (Cronos Mainnet). The implementation is V4 (`0x3F4e9e3b1B4317674AF9C87d69ECA25c76E4a8B5`), live since 1 October 2026.

## Since V4 (1 October 2026)

- The owner of the proxy is the governance timelock `0x33221850aDC263Ea61cF64662CDa2E7D654eD409` (OpenZeppelin TimelockController 5.4.0), with a 48-hour minimum delay.
- Only the Xitcoin Safe `0xA18A28A79c2B0b67c8cF37FfF863EbaD75B02945` (Safe 1.4.1, 2 of 3 signers) can propose, execute or cancel timelock operations.
- So no single key can change XTC: any upgrade or owner action needs the Safe's approval, then stays public for 48 hours before it can execute.
- The previous owner address and the three V3 voters have no role since V4.

## Before V4

Under V3 (18 February to 1 October 2026), an implementation upgrade needed the unanimous approval of three voter addresses. The inherited `transferOwnership` also let the owner change ownership directly. Both paths ended when ownership moved to the timelock.

## Read-only verification

```bash
export CRONOS_RPC='https://evm.cronos.org'
export PROXY='0xE45FE733BC8617FA6DAC8437FC44B5FFFA949991'

# implementation (last 20 bytes of the ERC-1967 slot)
cast storage "$PROXY" 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url "$CRONOS_RPC"
# owner: the timelock
cast call "$PROXY" 'owner()(address)' --rpc-url "$CRONOS_RPC"
# timelock delay in seconds: 172800
cast call 0x33221850aDC263Ea61cF64662CDa2E7D654eD409 'getMinDelay()(uint256)' --rpc-url "$CRONOS_RPC"
# Safe threshold: 2
cast call 0xA18A28A79c2B0b67c8cF37FfF863EbaD75B02945 'getThreshold()(uint256)' --rpc-url "$CRONOS_RPC"
```

The deployed implementation can change after a valid upgrade; integrations must keep using the proxy address. The machine-readable registry is [`deployments/cronos.json`](../deployments/cronos.json).

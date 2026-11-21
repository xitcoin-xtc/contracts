# Xitcoin on Cronos

This directory records stable public discovery, verification and community references for the XTC token on Cronos Mainnet.

## Canonical identity

| Field | Value |
|---|---|
| Network | Cronos Mainnet |
| Chain ID | `25` |
| Asset | Xitcoin |
| On-chain `symbol()` | `XTC` (since V4, 1 October 2026; `$XTC` before) |
| Public asset notation | `XTC` |
| XTC proxy | `0xE45FE733BC8617FA6DAC8437FC44B5FFFA949991` |
| Decimals | `18` |

Wallets that saved the token before 1 October 2026 may still show the old label `$XTC`; the balance is the same. The native Xitcoin blockchain uses the same symbol `XTC`; its atomic denomination is `axtc`.

Applications integrating the Cronos token must use the proxy address. The source and deployment registry remain authoritative for contract integration.

## Verification and listings

- [Cronos Explorer token profile](https://explorer.cronos.com/token/0xe45fe733bc8617fa6dac8437fc44b5fffa949991)
- [Cronos Explorer contract](https://explorer.cronos.com/address/0xe45fe733bc8617fa6dac8437fc44b5fffa949991)
- [Cyberscope project profile](https://www.cyberscope.io/audits/1-xtc)
- [CoinGecko](https://www.coingecko.com/en/coins/xitcoin) — API identifier: `xitcoin`
- [CoinMarketCap](https://coinmarketcap.com/currencies/xitcoin/) — asset identifier: `39608`

The smart-contract audit scope and the external KYC record are documented separately in [`audits/`](../audits/) and [`verification/`](../verification/). Third-party pages are discovery references; contract identity must always be confirmed against the proxy address above.

## Official community channels

- [Website](https://xitcoin.com)
- [X / Twitter](https://x.com/xitcoin_xtc)
- [Telegram](https://t.me/official_xitcoin)
- [Discord](https://discord.gg/kcalbapp)
- [GitHub](https://github.com/xitcoin-xtc)

Only stable, verified channel URLs are recorded. Follower counts, member counts, scores and rankings are intentionally excluded because they change independently of this repository.

## Markets

CoinGecko indexes XTC markets on VVS V3 (Cronos), Obsidian Finance and Ebisu's Bay. Market availability, liquidity, volume and routing are dynamic third-party data.

The repository therefore does not designate a trading pair as an official pool and does not publish mutable market statistics. Use the [CoinGecko markets table](https://www.coingecko.com/en/coins/xitcoin#markets) for current discovery, then verify that the route uses the XTC proxy address before signing.

## Machine-readable reference

`cronos.json` contains stable identifiers and URLs. It intentionally excludes prices, volumes, liquidity balances, audience statistics and unverified pool addresses.

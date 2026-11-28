import { configVariable, defineConfig } from 'hardhat/config';
import hardhatEthers from '@nomicfoundation/hardhat-ethers';
import hardhatEthersChaiMatchers from '@nomicfoundation/hardhat-ethers-chai-matchers';
import hardhatMocha from '@nomicfoundation/hardhat-mocha';

// Fuzz and invariant campaign sizes for the Solidity tests in test/foundry.
// Pull requests use the defaults below. The nightly workflow raises them
// through these variables and uses a fresh seed for each run.
function positiveInteger(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  if (!/^[1-9][0-9]*$/.test(raw)) {
    throw new Error(`${name} must be a positive integer`);
  }
  return Number(raw);
}

const fuzzSeed = process.env.SOLIDITY_FUZZ_SEED || '0x5eed20261128';
if (!/^0x[0-9a-fA-F]{1,64}$/.test(fuzzSeed)) {
  throw new Error('SOLIDITY_FUZZ_SEED must be a 0x-prefixed hexadecimal value');
}

export default defineConfig({
  plugins: [hardhatEthers, hardhatEthersChaiMatchers, hardhatMocha],
  solidity: {
    compilers: [
      {
        version: '0.8.4',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      },
      {
        version: '0.8.30',
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          },
          evmVersion: 'paris',
          metadata: {
            bytecodeHash: 'none'
          }
        }
      }
    ]
  },
  networks: {
    cronosTestnet: {
      type: 'http',
      chainType: 'l1',
      chainId: 338,
      url: configVariable('CRONOS_TESTNET_RPC_URL'),
      accounts: [configVariable('CRONOS_TESTNET_DEPLOYER_KEY')]
    }
  },
  paths: {
    sources: './contracts',
    tests: './test',
    cache: './cache',
    artifacts: './artifacts'
  },
  test: {
    mocha: {
      timeout: 120000
    },
    solidity: {
      fuzz: {
        runs: positiveInteger('SOLIDITY_FUZZ_RUNS', 256),
        seed: fuzzSeed
      },
      invariant: {
        runs: positiveInteger('SOLIDITY_INVARIANT_RUNS', 64),
        depth: positiveInteger('SOLIDITY_INVARIANT_DEPTH', 64),
        failOnRevert: false
      }
    }
  }
});

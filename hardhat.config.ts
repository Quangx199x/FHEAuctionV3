import "@nomicfoundation/hardhat-toolbox";
import "@fhevm/hardhat-plugin";
import "@nomicfoundation/hardhat-chai-matchers";
import "@nomicfoundation/hardhat-ethers";
import "@nomicfoundation/hardhat-verify";
import "@typechain/hardhat";
import "hardhat-deploy";
import "hardhat-gas-reporter";
import type { HardhatUserConfig } from "hardhat/config";
import { vars } from "hardhat/config";
import "solidity-coverage";

// THÊM: Load .env để dùng PRIVATE_KEY, SEPOLIA_RPC_URL, ETHERSCAN_API_KEY
import * as dotenv from "dotenv";
dotenv.config();

import "./tasks/accounts";

const MNEMONIC: string = vars.get("MNEMONIC", "");
const INFURA_API_KEY: string = vars.get("INFURA_API_KEY", "");

// Define FHEVM_REPO_ROOT (từ .env hoặc vars)
const FHEVM_REPO_ROOT: string = process.env.FHEVM_REPO_ROOT || vars.get("FHEVM_REPO_ROOT", "../fhevm");

const config: HardhatUserConfig = {
  defaultNetwork: "hardhat",
  namedAccounts: {
    deployer: 0,
  },
  etherscan: {
  apiKey: process.env.ETHERSCAN_API_KEY || "",
  sourcify: {
    enabled: true,
  },
},
  gasReporter: {
    currency: "USD",
    enabled: process.env.REPORT_GAS ? true : false,
    excludeContracts: [],
  },
  networks: {
    hardhat: {
      accounts: {
        mnemonic: MNEMONIC,
      },
      chainId: 31337,
      fhevm: true,
    },
    anvil: {
      accounts: {
        mnemonic: MNEMONIC,
        path: "m/44'/60'/0'/0/",
        count: 10,
      },
      chainId: 31337,
      url: "http://localhost:8545",
    },
    sepolia: {
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : {
        mnemonic: MNEMONIC,
        path: "m/44'/60'/0'/0/",
        count: 10,
      },
      chainId: 11155111,
      url: process.env.SEPOLIA_RPC_URL || `https://sepolia.infura.io/v3/${INFURA_API_KEY}`,
      fhevm: true,
    },
  },
  paths: {
    artifacts: "./artifacts",
    cache: "./cache",
    sources: "./contracts",
    tests: "./test",
    deploy: "deploy",
  },
  solidity: {
    version: "0.8.24",
    settings: {
      metadata: {
        bytecodeHash: "none",
      },
      optimizer: {
        enabled: true,
        runs: 800,
      },
      evmVersion: "cancun",
    },
    remappings: [
      `@fhevm/solidity=${FHEVM_REPO_ROOT}/library-solidity/contracts/`,
      `fhevm=${FHEVM_REPO_ROOT}/library-solidity/contracts/`,
      `@openzeppelin/contracts/=node_modules/@openzeppelin/contracts/`,
    ],
  },
  typechain: {
    outDir: "types",
    target: "ethers-v6",
  },
};

export default config;
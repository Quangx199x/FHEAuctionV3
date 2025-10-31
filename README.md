# FHEAuctionV3: Blind Auction with Full Security

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Powered by FHEVM](https://img.shields.io/badge/Powered%20by-FHEVM-blue.svg)](https://www.zama.ai/fhevm)
[![Solidity Version](https://img.shields.io/badge/Solidity-%5E0.8.24-lightgrey.svg)](https://soliditylang.org/)

> A decentralized, secure blind auction contract on Ethereum, using **Fully Homomorphic Encryption (FHE)** to ensure absolute privacy of bids.



This project implements an auction where participants can bid without revealing their value to anyone—including the contract administrator—until the auction ends. All bid comparisons (to find the highest bid) are performed **on encrypted data** using `FHE.gt()` and `FHE.select()` from Zama's FHEVM library.

---

## 📚 Table of Contents

* [Architecture & Features](#-architecture--features)
* [Workflow](#-workflow-workflow)
* [Guide for dApp Users (Client-Side)](#-guide-for-dapp-client-side-users)
* [Developer Guide (Solidity)](#-solidity-developer-guide)
    * [System Requirements](#system-requirements)
    * [Install & Run Local](#install--run-local)
    * [Deployment](#deployment-deployment)
* [Contract API (Main Function)](#-api-contract-main-function)
* [Safety & Security](#-safety--security)
* [License](#-license)

---

## ✨ Architecture & Features

* **Security by FHE:** Bids are encrypted client-side (to `euint64`) and never decrypted on-chain during the auction.
* **True Blind Auction:** No one can see anyone else's bids until the auction ends, preventing "front-running" and "bid sniping".
* **Homomorphic Comparison:** The contract uses `FHE.gt()` (greater than) and `FHE.select()` (select) to find the new highest bid (`encryptedMaxBid`) entirely on the encrypted data.
* **Post-Decryption Validation:** To maintain privacy, rules (like `MIN_BID_INCREMENT`) are only checked *after* the auction ends and KMS has decrypted the bids. Invalid bids will be refunded 100%.
* **Anti-Snipe Mechanism:** Automatically extend the auction duration (`EXTENSION_DURATION_BLOCKS`) if a bid is placed near the end.
* **Advanced Security:** Integrated `ReentrancyGuard`, EIP-712, `onlyGateway` authentication for KMS callback, and "Pull-over-Push" refund mechanism.
* **State Machine:** Manage the auction lifecycle through 5 clear states (`Active`, `Ended`, `Finalizing`, `Finalized`, `Emergency`).

---

## 🔄 Workflow

1. **Phase 1: Bidding (Active)**
    * User (Bob) decides to bid `10 ETH`.
    * Bob's client-side dApp uses `@fhevm/sdk` to encode `10` into `encryptedBid`.
    * Bob calls the function `bid(encryptedBid, ...)` and sends along `msg.value` (the deposit amount, must be >= `minBidDeposit`).
    * Contract updates `encryptedMaxBid` using FHE operation.

2. **Phase 2: Ended**
    * `block.number` passes `auctionEndBlock`. Bidding phase ends.

3. **Phase 3: Finalizing Request**
    * The owner/user calls `requestFinalize()`, ( Everyone can call `requestFinalize()`).
    * The contract collects all `encryptedBid`s and sends a decryption request to the Zama KMS Gateway.

4. **Phase 4: Callback & Authentication**
    * KMS Gateway decrypts the bids and calls the `onDecryptionCallback()` function with the plaintext values.
    * KMS signature authentication contract.

5. **Phase 5: Finalized**
    * The contract *now* iterates through the plaintext bids, checks `MIN_BID_INCREMENT`, and determines a valid winner.
    * Transfer money to the beneficiary (`beneficiary`) and collect fees (`feeCollector`).
    * Losers and invalid bidders receive `pendingRefunds`.
    * A new auction round (`currentRound + 1`) starts automatically.

---

## 🛠️ Developer Guide (Solidity)

This section is for developers who want to fork, test, or deploy the `FHEAuctionV3` contract. This project is built using Hardhat.

### System requirements

* [Node.js](https://nodejs.org/) (v18+)
* [Yarn](https://yarnpkg.com/) (recommended) or `npm`
* [Git](https://git-scm.com/)

### Install & Run Local

1.  **Clone repo:**
    ```bash
    git clone [https://github.com/](https://github.com/)[username-github]/[tên-repo].git
    cd [repo-name]
    ```

2. **Install dependencies:**
    ```bash
    yarn install
    # or
    npm install
    ```

3. **Contract translation:**
    ```bash
    npx hardhat compile
    ```

### Deployment

You must deploy this contract on a network that supports FHEVM (e.g. Zama Sepolia Testnet).

1. **Configure `.env`:**
    Create `.env` file and add Private Key of deploy wallet:
    ```
    PRIVATE_KEY="0x..."
    SEPOLIA_RPC_URL="https://[your - rpc-url]"
    ```

2. **Configuring `hardhat.config.ts`:**
    Make sure you have added the Zama Sepolia network:
    ```typescript
    const config: HardhatUserConfig = {
      // ...
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
    };
    ```

3. **Prepare Deployment Script (`deploy.ts`):**
    You need to provide parameters to the `constructor`:
    * `_minDeposit`: Minimum deposit amount (e.g. `0.1 ETH`).
    * `_pauserSet`: The address of the `IPauserSet` contract (or `address(0)` if not used).
    * `_beneficiary`: Address to receive winnings.
    * `_gatewayContract`: **IMPORTANT:** Zama's Gateway address.
        * *Sepolia Testnet: `0xa02Cda4Ca3a71D7C46997716F4283aa851C28812`*
    * `_feeCollector`: Address to receive platform fees.

4. **Run the Deploy command:**
    ```bash
    npx hardhat deploy --network sepolia     
    ```

---

## 📜 Contract API (Main Function)

The most important functions for users and administrators.

### Functions for Users (Bidders)

* **`bid(externalEuint64 encryptedBid, bytes calldata inputProof, bytes32 publicKey, bytes calldata signature)`**
    * `payable` function to place bid. Send encoded bid (from FHE-SDK) and deposit (`msg.value`).
* **`cancelBid()`**
    * Allows bid cancellation and 100% deposit refund *before* the auction ends.
* **`withdrawRefund()`**
    * *(Assuming this function exists based on `pendingRefunds`)*: Withdraw the refund (if you lose or the bid is invalid) after the auction ends.

### Functions for Owner

* **`requestFinalize()`**
    * Trigger the termination and decryption process. Only the owner can call if there is a bid.
* **`cancelDecryption()`**
    * Emergency function to cancel decryption request if KMS gets stuck (after `DECRYPTION_TIMEOUT_BLOCKS` time).
* **`setBeneficiary(address _newBeneficiary)`**
    * Update the winnings receiving address.
* **`setFeeCollector(address _newCollector)`**
    * Update the fee receiving address.
* **`pause()` / `unpause()`**
    * Suspend/resume contract (local).

---

## 🛡️ Safe & Secure

This contract incorporates many standard and advanced security features:

* **ReentrancyGuard:** `nonReentrant` modifier on functions that change the main state.
* **EIP-712:** Signature verification to associate FHE public key with Ethereum address.
* **Gateway Authentication:** The `onlyGateway` modifier ensures that only Zama KMS can send decryption results.
* **Pull-over-Push:** Use `pendingRefunds` mapping to allow users to withdraw funds safely.
* **Custom Errors:** Save gas and provide clear error messages.
* **State Machine:** Prevent invalid actions (e.g. can't `bid` while `Finalizing`).

---

## ⚖️ License

This project is licensed under the **MIT License**. See the `LICENSE` file for details.

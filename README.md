# Vault-UUPS: Upgradeable ERC4626 Vault with On-Chain Governance

A secure, upgradeable ERC4626 vault implementation with comprehensive on-chain governance, enabling decentralized management and upgrade paths for the vault's functionality.

## Overview

This project implements a tokenized vault following the ERC4626 standard with a secure upgrade mechanism using OpenZeppelin's UUPS (Universal Upgradeable Proxy Standard) pattern. The system includes a complete governance layer to ensure that upgrades and significant vault actions are executed through democratic processes.

## 🛠 Architecture

Core Components:

1. GovToken: ERC20 token with voting capabilities (ERC20Votes)
2. Vault: UUPS-compatible ERC4626 vault implementation
3. VaultV2: Upgraded implementation adding pause/unpause functionality
4. VaultGovernor: Governance contract enabling token-based voting
5. TimelockController: Delay mechanism for governance actions

Security Design:

- Role-Based Access Control:
  - GOVERNANCE_ROLE: For governance operations
  - UPGRADER_ROLE: For executing upgrades (assigned to timelock)
- Upgrade Security:
  - Upgrades must pass through governance voting
  - Implementation through timelock controller for transparency
  - Authorization checks prevent unauthorized upgrades

## 🚀 Getting Started

Prerequisites

- Foundry
- Node.js (v14+)

Installation

```
# Clone the repository
git clone https://github.com/yourusername/vault-uups.git
cd vault-uups

# Install dependencies
forge install

# Build
forge build
```

Environment Setup
Create a `.env` file with:

```
PRIVATE_KEY=your_private_key
SEPOLIA_RPC_URL=your_sepolia_rpc_url
MAINNET_RPC_URL=your_mainnet_rpc_url
```

Usage
Deployment

```
# Deploy the full governance system (Vault, Token, Governor, Timelock)
forge script script/DeployGovernance.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --verify
```

Upgrading the Vault

1. Deploy VaultV2 implementation:

```
forge script script/DeployVaultV2.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --verify
```

2. Propose the upgrade through governance:

```
export PROXY_ADDRESS=<vault_proxy_address>
export VAULTV2_ADDRESS=<vaultv2_implementation_address>
export GOVERNOR_ADDRESS=<governor_contract_address>
export PROPOSER_KEY=<proposer_private_key>

forge script script/ProposeUpgrade.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast
```

3. Vote, queue, and execute the proposal through the governance UI or direct contract interaction.
   Interacting with the Vault

```
// Deposit tokens to the vault
uint256 depositAmount = 100 * 10**18; // 100 tokens
govToken.approve(vaultAddress, depositAmount);
vault.deposit(depositAmount, receiverAddress);

// Withdraw tokens from the vault
uint256 withdrawAmount = 50 * 10**18; // 50 tokens
vault.withdraw(withdrawAmount, receiverAddress, ownerAddress);
```

## Security Considerations
The system implements several security best practices:

1. Timelock-enforced upgrades: All upgrades must pass through the timelock delay
2. Role-based access: Specific roles for different permission levels
3. State preservation: All user balances and vault state preserved during upgrades
4. Reentrancy protection: Built-in protection through ERC4626 standard implementations
5. Comprehensive testing: Including malicious implementation tests

Attack Vectors Addressed

- Front-running attacks: Mitigated by timelock delays
- Governance attacks: Requires significant voting power
- Implementation corruption: Prevented by access controls
- Function selector clashes: Avoided in upgrades
- Storage layout corruption: Protected through proper inheritance order

## Testing

```
# Run all tests
forge test

# Run specific test file
forge test --match-path test/Vault.t.sol -vvv

# Run with gas reporting
forge test --gas-report

# Run fork tests (requires RPC URL in .env)
forge test --match-path test/GovernanceTest.t.sol --fork-url $SEPOLIA_RPC_URL
```

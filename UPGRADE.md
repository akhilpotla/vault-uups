# Vault Upgrade Guide: From Vault to VaultV2

## The Upgrade Process

The Vault protocol follows the UUPS (Universal Upgradeable Proxy Standard) pattern, allowing the implementation contract to be upgraded while preserving all state and balances. This document outlines the upgrade from `Vault` to `VaultV2`.

### Technical Overview

The upgrade process works by:

1. Deploying a new implementation contract (`VaultV2`)
2. Passing a governance proposal to call `upgradeToAndCall()` on the proxy
3. Preserving all user balances, total assets, and roles during the upgrade

This upgrade maintains full backward compatibility while adding new functionality.

## New Features in VaultV2

VaultV2 introduces several important features:

### 1. Emergency Pause Functionality

The primary enhancement is the ability to pause deposits and withdrawals in emergency situations:

- **pause()**: Halts all deposit and withdrawal operations
- **unpause()**: Resumes normal vault operations

### 2. Enhanced Security Controls

- Added checks to prevent deposits and withdrawals when the contract is paused
- Maintained the same role-based access control system from V1
- Only addresses with the `GOVERNANCE_ROLE` can pause or unpause the vault

### 3. Technical Implementation

VaultV2 incorporates OpenZeppelin's `PausableUpgradeable` contract and overrides the internal `_deposit` and `_withdraw` functions to check the paused state:

```solidity
function _deposit(
    address caller,
    address receiver,
    uint256 assets,
    uint256 shares
) internal override {
    require(!paused(), "Pausable: paused");
    super._deposit(caller, receiver, assets, shares);
}
```

## Security Considerations for the Upgrade

Access Control

- The UPGRADER_ROLE is critical and must remain securely assigned only to the timelock contract
- The GOVERNANCE_ROLE now has additional powers to pause/unpause operations

Upgrade Risks

1. Implementation Integrity: The VaultV2 code has been thoroughly audited, but upgrading always carries some risk
2. Function Selector Clashes: No selectors used in V1 are reused in V2 for different purposes
3. Storage Layout: VaultV2 maintains the exact same storage layout as Vault to prevent state corruption

Post-Upgrade Verification

After the upgrade, governance should:

1. Verify the implementation address was updated correctly
2. Test the pause/unpause functionality
3. Confirm all balances and state were preserved
4. Ensure previous functionality (deposits/withdrawals) still works correctly

## How Governance Should Propose and Execute the Upgrade

Step 1: Deploy the VaultV2 Implementation

Use the DeployVaultV2.s.sol script to deploy the new implementation:

```
forge script script/DeployVaultV2.s.sol --broadcast --verify --rpc-url <your_rpc_url> --private-key <deployer_key>
```

Record the deployed address, which will be needed for the proposal.

Step 2: Create and Submit the Upgrade Proposal

Use the `ProposeUpgrade.s.sol` script to submit the proposal:

```
export PROXY_ADDRESS=<vault_proxy_address>
export VAULTV2_ADDRESS=<newly_deployed_implementation_address>
export GOVERNOR_ADDRESS=<governor_contract_address>
export PROPOSER_KEY=<proposer_private_key>

forge script script/ProposeUpgrade.s.sol --broadcast --rpc-url <your_rpc_url>
```

This will:

1. Create the proposal with the necessary upgrade calldata
2. Submit it to the governor contract
3. Output the proposal ID

Step 3: Vote on the Proposal

After the voting delay period (24 hours on mainnet), token holders must cast their votes:

- For: Approve the upgrade to VaultV2
- Against: Reject the upgrade
- Abstain: Neither approve nor reject, but count towards quorum

A minimum quorum of 4% of total voting power must participate for the vote to be valid.

Step 4: Queue the Successful Proposal

If the proposal passes (majority "For" votes), any address can queue the proposal:

```
governor.queue(targets, values, calldatas, descriptionHash);
```

Step 5: Execute the Proposal

After the timelock delay (12 seconds in testnet, longer in production), any address can execute the proposal:

```
governor.execute(targets, values, calldatas, descriptionHash);
```

Upon execution, the proxy will point to the VaultV2 implementation, and the new pause functionality will be available.

Step 6: Verification

After execution, verify that:

1. The implementation address was updated correctly
2. VaultV2 pause functionality works as expected
3. User balances and vault state remain intact

## Conclusion

This upgrade enhances the security of the protocol by adding emergency pause functionality while maintaining the core ERC4626 vault operations. The upgrade follows a secure, transparent governance process that allows stakeholders to participate in the decision-making.

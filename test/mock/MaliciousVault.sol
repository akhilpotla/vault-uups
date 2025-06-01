// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Vault} from "../../src/Vault.sol";

contract MaliciousVault is Vault {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }

    // Add this function to MaliciousVault
    function tryToStealFunds(address attacker) external {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender));
        // Try to grant the attacker the GOVERNANCE_ROLE which would let them control the vault
        _grantRole(GOVERNANCE_ROLE, attacker);
        // Also try to grant UPGRADER_ROLE which would let them replace the implementation
        _grantRole(UPGRADER_ROLE, attacker);

        // As a bonus attack, try to steal all funds
        // This should fail because we don't have permission, even though we're the implementation
        IERC20(asset()).transfer(attacker, totalAssets());
    }
}

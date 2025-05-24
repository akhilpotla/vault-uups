// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Vault} from "./Vault.sol";

contract MaliciousVault is Vault {
    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}

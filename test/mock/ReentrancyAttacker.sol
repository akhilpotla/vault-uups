// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Vault} from "../../src/Vault.sol";

contract ReentrancyAttacker {
    Vault private immutable vault;
    IERC20 private immutable token;
    bool private attacking;
    uint256 public attackCount;
    uint8 private attackMethod; // 0=withdraw, 1=redeem, 2=mint

    constructor(address _vault, address _token) {
        vault = Vault(_vault);
        token = IERC20(_token);
    }

    function setAttackMethod(uint8 _method) external {
        require(_method <= 2, "Invalid method");
        attackMethod = _method;
    }

    function receiveTokens() internal {
        if (attacking) {
            attackCount++;
            if (attackMethod == 0) {
                vault.withdraw(1, address(this), address(this));
            } else if (attackMethod == 1) {
                vault.redeem(1, address(this), address(this));
            } else {
                token.approve(address(vault), 1);
                vault.mint(1, address(this));
            }
        }
    }

    function performAttack(uint256 amount) external {
        attacking = true;
        token.approve(address(vault), amount);
        vault.deposit(amount, address(this));
        attacking = false;
    }

    function withdrawWithoutAttack(uint256 amount) external {
        vault.withdraw(amount, address(this), address(this));
    }

    // Required to receive ETH
    receive() external payable {
        if (attacking) receiveTokens();
    }

    // Required for safeTransfer callbacks
    function onERC20Received(address, uint256) external returns (bool) {
        if (attacking) receiveTokens();
        return true;
    }
}

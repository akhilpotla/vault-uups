// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC4626Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

contract VaultV2 is
    Initializable,
    ERC4626Upgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // Initializer deliberately not implemented as we're upgrading into this contract

    function _authorizeUpgrade(address newImplementation) internal override {
        require(
            hasRole(UPGRADER_ROLE, msg.sender),
            "Vault: must have upgrader role to upgrade"
        );
    }

    // New function added in V2
    function pause() external {
        require(
            hasRole(GOVERNANCE_ROLE, msg.sender),
            "Vault: must have governance role to pause"
        );
        _pause();
    }

    // New function added in V2
    function unpause() external {
        require(
            hasRole(GOVERNANCE_ROLE, msg.sender),
            "Vault: must have governance role to unpause"
        );
        _unpause();
    }

    // Override _beforeTokenTransfer to check for paused state
    function _deposit(
        address caller,
        address receiver,
        uint256 assets,
        uint256 shares
    ) internal override {
        require(!paused(), "Pausable: paused");
        super._deposit(caller, receiver, assets, shares);
    }

    function _withdraw(
        address caller,
        address receiver,
        address owner,
        uint256 assets,
        uint256 shares
    ) internal override {
        require(!paused(), "Pausable: paused");
        super._withdraw(caller, receiver, owner, assets, shares);
    }
}

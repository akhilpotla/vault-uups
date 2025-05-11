// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC4626Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC4626Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract Vault is
    Initializable,
    ERC4626Upgradeable,
    AccessControlUpgradeable,
    UUPSUpgradeable
{
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    function initialize(
        IERC20 asset_,
        address timelock,
        address admin
    ) public initializer {
        __ERC4626_init(asset_);
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GOVERNANCE_ROLE, timelock);
        _grantRole(UPGRADER_ROLE, timelock);
    }

    function _authorizeUpgrade(address newImplementation) internal override {
        require(
            hasRole(UPGRADER_ROLE, msg.sender),
            "Vault: must have upgrader role to upgrade"
        );
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {GovToken} from "./GovToken.sol";

contract Vault is ERC4626 {
    mapping(address => uint256) public shareHolder;

    constructor(
        address _underlyingToken
    ) ERC4626(IERC20(_underlyingToken)) ERC20("Vault Token", "VT") {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/Test.sol";
import {VaultV2} from "../src/VaultV2.sol";

contract DeployVaultV2 is Script {
    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy new implementation
        VaultV2 vaultV2 = new VaultV2();

        // Note: The actual upgrade happens through governance
        vm.stopBroadcast();

        console.log("VaultV2 implementation deployed at:", address(vaultV2));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/Test.sol";
import {VaultV2} from "../src/VaultV2.sol";
import {VaultGovernor} from "../src/VaultGovernor.sol";
import {Vault} from "../src/Vault.sol";

contract ProposeUpgrade is Script {
    function run() public {
        uint256 proposerPrivateKey = vm.envUint("PROPOSER_KEY");
        vm.startBroadcast(proposerPrivateKey);

        address proxyAddress = vm.envAddress("PROXY_ADDRESS");
        address vaultV2Impl = vm.envAddress("VAULTV2_ADDRESS");
        address governorAddress = vm.envAddress("GOVERNOR_ADDRESS");

        // Prepare proposal data
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);

        targets[0] = proxyAddress;
        values[0] = 0;
        calldatas[0] = abi.encodeWithSelector(
            Vault(proxyAddress).upgradeToAndCall.selector,
            vaultV2Impl,
            ""
        );

        string
            memory description = "Upgrade Vault to VaultV2 with pause functionality";

        // Submit proposal
        VaultGovernor governor = VaultGovernor(payable(governorAddress));
        uint256 proposalId = governor.propose(
            targets,
            values,
            calldatas,
            description
        );

        vm.stopBroadcast();

        console.log("Proposal submitted with ID:", proposalId);
    }
}

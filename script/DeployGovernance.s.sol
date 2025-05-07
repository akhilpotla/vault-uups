// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {GovToken} from "../src/GovToken.sol";
import {Vault} from "../src/Vault.sol";
import {VaultGovernor} from "../src/VaultGovernor.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {console2} from "forge-std/console2.sol";

contract DeployGovernance is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        GovToken token = new GovToken(100_000 * 10 ** 18, 1_000_000 * 10 ** 18);
        address deployer = vm.addr(deployerPrivateKey);

        address[] memory proposers = new address[](1);
        proposers[0] = deployer;

        address[] memory executors = new address[](1);
        executors[0] = address(0);

        uint256 minDelay = 12 hours;
        TimelockController timelock = new TimelockController(
            minDelay,
            proposers,
            executors,
            deployer
        );

        Vault vaultImpl = new Vault();

        bytes memory initData = abi.encodeWithSelector(
            Vault.initialize.selector,
            address(token),
            address(timelock),
            deployer
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(vaultImpl), initData);
        Vault vault = Vault(address(proxy));

        VaultGovernor vaultGovernor = new VaultGovernor(token, timelock);

        bytes32 PROPOSER_ROLE = timelock.PROPOSER_ROLE();
        bytes32 EXECUTOR_ROLE = timelock.EXECUTOR_ROLE();
        bytes32 CANCELLER_ROLE = timelock.CANCELLER_ROLE();
        bytes32 TIMELOCK_ADMIN_ROLE = timelock.DEFAULT_ADMIN_ROLE();

        timelock.grantRole(PROPOSER_ROLE, address(vaultGovernor));
        timelock.grantRole(CANCELLER_ROLE, address(vaultGovernor));
        timelock.grantRole(PROPOSER_ROLE, deployer);

        console2.log("GovToken deployed at:", address(token));
        console2.log("Timelock deployed at:", address(timelock));
        console2.log("Vault implementation deployed at:", address(vaultImpl));
        console2.log("Vault proxy deployed at:", address(vault));
        console2.log("VaultGovernor deployed at:", address(vaultGovernor));

        vm.stopBroadcast();
    }
}

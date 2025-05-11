// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {GovToken} from "../src/GovToken.sol";
import {Vault} from "../src/Vault.sol";
import {console2} from "forge-std/console2.sol";

contract VaultTest is Test {
    GovToken public token;
    Vault public vaultImpl;
    Vault public vault;
    address public USER = makeAddr("USER");
    address public TOKEN_DEPLOYER;
    uint256 public constant INITIAL_SUPPLY = 1_000;
    uint256 public constant SUPPLY_CAP = 100_000;
    uint256 public constant MIN_DELAY = 12 seconds;
    address[] public proposers = new address[](1);
    address[] public executors = new address[](1);

    function setUp() public {
        token = new GovToken(INITIAL_SUPPLY * 10 ** 18, SUPPLY_CAP * 10 ** 18);
        TOKEN_DEPLOYER = address(this);
        proposers[0] = TOKEN_DEPLOYER;
        executors[0] = address(0);
        vaultImpl = new Vault();
    }

    // Initialization Tests
    function testCorrectInitialization() public {
        TimelockController timelock = new TimelockController(
            MIN_DELAY,
            proposers,
            executors,
            TOKEN_DEPLOYER
        );

        bytes memory initData = abi.encodeWithSelector(
            Vault.initialize.selector,
            address(token),
            address(timelock),
            TOKEN_DEPLOYER
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(vaultImpl), initData);
        vault = Vault(address(proxy));

        // Verify the roles were set correctly
        bytes32 DEFAULT_ADMIN_ROLE = 0x00;
        bytes32 GOVERNANCE_ROLE = vault.GOVERNANCE_ROLE();
        bytes32 UPGRADER_ROLE = vault.UPGRADER_ROLE();

        assertTrue(
            vault.hasRole(DEFAULT_ADMIN_ROLE, TOKEN_DEPLOYER),
            "Admin role not set correctly"
        );
        assertTrue(
            vault.hasRole(GOVERNANCE_ROLE, address(timelock)),
            "Governance role not set correctly"
        );
        assertTrue(
            vault.hasRole(UPGRADER_ROLE, address(timelock)),
            "Upgrader role not set correctly"
        );

        // Also verify the asset was set correctly
        assertEq(
            address(vault.asset()),
            address(token),
            "Asset not set correctly"
        );
    }

    function testDoubleInitializationFails() public {
        TimelockController timelock = new TimelockController(
            MIN_DELAY,
            proposers,
            executors,
            TOKEN_DEPLOYER
        );

        bytes memory initData = abi.encodeWithSelector(
            Vault.initialize.selector,
            address(token),
            address(timelock),
            TOKEN_DEPLOYER
        );
        new ERC1967Proxy(address(vaultImpl), initData);
        vm.expectRevert();
        vault.initialize(token, address(timelock), TOKEN_DEPLOYER);
    }

    function testZeroAddressRejection() public {}

    // Access Control Tests
    function testOnlyTimelockedUpgraderCanUpgrade() public {}
    function testUpgradeWithoutRoleFails() public {}
    function testAdminCanGrantRoles() public {}
    function testNonAdminCannotGrantRoles() public {}

    // ERC4626 Functionality Tests
    function testDeposit() public {}
    function testWithdraw() public {}
    function testMaxDeposit() public {}
    function testPreviewDeposit() public {}
    function testPreviewWithdraw() public {}

    // Upgradeability Tests
    function testUpgradeToNewImplementation() public {}
    function testStorageLayoutPreservation() public {}
    function testSelfdestruct() public {}

    // Integration Tests
    function testTimelockDelayedUpgrade() public {}
    function testProposalExecution() public {}
    function testDepositAndUpgrade() public {}

    // Edge Cases and Security
    function testReentrancyProtection() public {}
    function testFuzzDeposits() public {}
    function testFuzzWithdraws() public {}
    function testTransferOwnershipDoesNotAffectFunds() public {}
}

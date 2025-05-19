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

    function testZeroAddressRejection() public {
        address admin = address(0);
        TimelockController timelock = new TimelockController(
            MIN_DELAY,
            proposers,
            executors,
            admin
        );

        bytes memory initData = abi.encodeWithSelector(
            Vault.initialize.selector,
            address(token),
            address(timelock),
            admin
        );
        vm.expectRevert("Admin cannot be the zero address.");
        new ERC1967Proxy(address(vaultImpl), initData);
    }

    // Access Control Tests
    function testOnlyTimelockedUpgraderCanUpgrade() public {
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

        Vault newImplementation = new Vault();

        // Test that USER cannot upgrade
        vm.prank(USER);
        vm.expectRevert("Vault: must have upgrader role to upgrade");
        vault.upgradeToAndCall(address(newImplementation), "");

        // Test that timelock CAN upgrade
        vm.prank(address(timelock));
        vault.upgradeToAndCall(address(newImplementation), "");
    }
    function testUpgradeWithoutRoleFails() public {}

    function testAdminCanGrantRoles() public {
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

        bytes32 DEFAULT_ADMIN_ROLE = 0x00;
        bytes32 GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

        assertFalse(vault.hasRole(DEFAULT_ADMIN_ROLE, USER));

        vm.prank(TOKEN_DEPLOYER);
        vault.grantRole(DEFAULT_ADMIN_ROLE, USER);
        assertTrue(vault.hasRole(DEFAULT_ADMIN_ROLE, USER));

        vm.prank(USER);
        vault.grantRole(GOVERNANCE_ROLE, makeAddr("USER2"));
    }

    function testNonAdminCannotGrantRoles() public {
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

        bytes32 DEFAULT_ADMIN_ROLE = 0x00;

        assertFalse(vault.hasRole(DEFAULT_ADMIN_ROLE, USER));

        vm.prank(USER);
        vm.expectRevert();
        vault.grantRole(DEFAULT_ADMIN_ROLE, makeAddr("USER2"));
    }

    // ERC4626 Functionality Tests
    function testDeposit() public {
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

        uint256 depositAmount = 100 * 10 ** 18;
        address receiver = USER;

        uint256 initialTokenBalance = token.balanceOf(TOKEN_DEPLOYER);
        uint256 initialShareBalance = vault.balanceOf(receiver);

        token.approve(address(vault), depositAmount);

        uint256 expectedShares = vault.previewDeposit(depositAmount);

        uint256 sharesReceived = vault.deposit(depositAmount, receiver);

        assertEq(
            sharesReceived,
            expectedShares,
            "Shares received should match the expected shares"
        );
        assertEq(
            token.balanceOf(TOKEN_DEPLOYER),
            initialTokenBalance - depositAmount,
            "Tokens should be deducted from depositor"
        );
        assertEq(
            vault.balanceOf(USER),
            initialShareBalance + sharesReceived,
            "Shares should be added to receiver"
        );
        assertEq(
            vault.totalAssets(),
            depositAmount,
            "Total assets should match deposit"
        );
    }

    function testWithdraw() public {
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

        uint256 depositAmount = 100 * 10 ** 18;
        address receiver = USER;

        token.approve(address(vault), depositAmount);
        vault.deposit(depositAmount, receiver);

        uint256 userInitialTokenBalance = token.balanceOf(USER);
        uint256 userInitialShareBalance = vault.balanceOf(USER);
        uint256 vaultInitialAssets = vault.totalAssets();

        uint256 withdrawAmount = 50 * 10 ** 18;
        uint256 expectedBurnedShares = vault.previewWithdraw(withdrawAmount);

        vm.prank(USER);
        vault.approve(address(this), expectedBurnedShares);

        uint256 burnedShares = vault.withdraw(withdrawAmount, USER, USER);

        assertEq(
            burnedShares,
            expectedBurnedShares,
            "Burned shares should match expected burned shares"
        );
        assertEq(
            token.balanceOf(USER),
            userInitialTokenBalance + withdrawAmount
        );
        assertEq(vault.balanceOf(USER), userInitialShareBalance - burnedShares);
        assertEq(vault.totalAssets(), vaultInitialAssets - withdrawAmount);
    }

    function testMaxDeposit() public {
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

        address receiver = USER;
        uint256 maxShares = vault.maxDeposit(receiver);

        assertEq(
            maxShares,
            type(uint256).max,
            "Max deposit should be unlimited"
        );
    }

    function testPreviewDeposit() public {
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

        uint256 depositAmount = 100 * 10 ** 18;
        uint256 expectedShares = vault.previewDeposit(depositAmount);

        assertEq(
            expectedShares,
            depositAmount,
            "Expected shares should match the deposit amount"
        );

        // Test preview after deposits exist
        token.approve(address(vault), depositAmount);
        vault.deposit(depositAmount, TOKEN_DEPLOYER);

        // Now preview another deposit
        uint256 secondDepositAmount = 50 * 10 ** 18;
        uint256 expectedSharesForSecondDeposit = vault.previewDeposit(
            secondDepositAmount
        );

        // For a standard vault without fees, this should still be 1:1
        assertEq(expectedSharesForSecondDeposit, secondDepositAmount);
    }

    function testPreviewWithdraw() public {
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

        uint256 depositAmount = 100 * 10 ** 18;
        address receiver = USER;

        token.approve(address(vault), depositAmount);
        vault.deposit(depositAmount, receiver);

        uint256 withdrawAmount = 50 * 10 ** 18;
        uint256 expectedBurnedShares = vault.previewWithdraw(withdrawAmount);

        assertEq(
            expectedBurnedShares,
            withdrawAmount,
            "Expected burned shares should equal withdraw amount"
        );

        vm.prank(USER);
        vault.approve(address(this), expectedBurnedShares);
        vault.withdraw(withdrawAmount, USER, USER);

        uint256 secondWithdrawAmount = 20 * 10 ** 18;
        uint256 secondExpectedBurnedShares = vault.previewWithdraw(
            secondWithdrawAmount
        );
        assertEq(secondExpectedBurnedShares, secondWithdrawAmount);

        // Donate tokens to change the exchange rate
        token.transfer(address(vault), 10 * 10 ** 18);
        uint256 thirdWithdrawAmount = 10 * 10 ** 18;
        // Now shares needed should be less than assets withdrawn
        uint256 thirdExpectedBurnedShares = vault.previewWithdraw(
            thirdWithdrawAmount
        );
        assertTrue(thirdExpectedBurnedShares < thirdWithdrawAmount);
    }

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

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {GovToken} from "../src/GovToken.sol";
import {MaliciousVault} from "../src/MaliciousVault.sol";
import {Vault} from "../src/Vault.sol";
import {VaultV2} from "../src/VaultV2.sol";
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

    function _setupVaultAndProxy()
        internal
        returns (TimelockController, ERC1967Proxy)
    {
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
        return (timelock, proxy);
    }

    // Initialization Tests
    function testCorrectInitialization() public {
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
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
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
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
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
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

    // TODO: testUpgradeWithoutRoleFails
    function testUpgradeWithoutRoleFails() public {}

    function testAdminCanGrantRoles() public {
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
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
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
        vault = Vault(address(proxy));

        bytes32 DEFAULT_ADMIN_ROLE = 0x00;

        assertFalse(vault.hasRole(DEFAULT_ADMIN_ROLE, USER));

        vm.prank(USER);
        vm.expectRevert();
        vault.grantRole(DEFAULT_ADMIN_ROLE, makeAddr("USER2"));
    }

    // ERC4626 Functionality Tests
    function testDeposit() public {
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
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
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
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
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
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
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
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
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
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
    function testUpgradeToNewImplementation() public {
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
        vault = Vault(address(proxy));

        uint256 depositAmount = 100 * 10 ** 18;
        token.approve(address(vault), depositAmount);
        vault.deposit(depositAmount, USER);

        assertEq(vault.totalAssets(), depositAmount);
        assertEq(vault.balanceOf(USER), depositAmount);

        VaultV2 newImplementation = new VaultV2();

        // Upgrade to the new implementation
        vm.prank(address(timelock));
        vault.upgradeToAndCall(address(newImplementation), "");

        // Convert the proxy to VaultV2 to access new functions
        VaultV2 upgradedVault = VaultV2(address(proxy));

        // Verify state is preserved after upgrade
        assertEq(
            upgradedVault.totalAssets(),
            depositAmount,
            "Assets not preserved after upgrade"
        );
        assertEq(
            upgradedVault.balanceOf(USER),
            depositAmount,
            "Shares not preserved after upgrade"
        );
        assertEq(
            address(upgradedVault.asset()),
            address(token),
            "Asset reference not preserved"
        );

        // Verify new functionality works
        assertFalse(
            upgradedVault.paused(),
            "Vault should not be paused after upgrade"
        );

        // Test new pause functionality (from the new implementation)
        vm.prank(address(timelock));
        upgradedVault.pause();
        assertTrue(upgradedVault.paused(), "Vault should be paused");

        // Verify that paused vault doesn't allow deposits
        token.approve(address(upgradedVault), depositAmount);
        vm.expectRevert("Pausable: paused");
        upgradedVault.deposit(depositAmount, USER);

        // Test unpause
        vm.prank(address(timelock));
        upgradedVault.unpause();
        assertFalse(upgradedVault.paused(), "Vault should be unpaused");

        // Verify deposits work again
        upgradedVault.deposit(depositAmount, USER);
        assertEq(
            upgradedVault.totalAssets(),
            depositAmount * 2,
            "Deposit after unpause failed"
        );
    }

    function testStorageLayoutPreservation() public {
        // 1. Setup initial contract and proxy
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
        vault = Vault(address(proxy));

        // 2. Create test addresses
        address user1 = makeAddr("USER1");
        address user2 = makeAddr("USER2");
        address user3 = makeAddr("USER3");

        // 3. Setup complex state before upgrade
        // Deposit different amounts for different users
        uint256 amount1 = 100 * 10 ** 18;
        uint256 amount2 = 250 * 10 ** 18;
        uint256 amount3 = 75 * 10 ** 18;

        // Transfer tokens to users
        token.transfer(user1, amount1);
        token.transfer(user2, amount2);
        token.transfer(user3, amount3);

        // Perform deposits
        vm.startPrank(user1);
        token.approve(address(vault), amount1);
        vault.deposit(amount1, user1);
        vm.stopPrank();

        vm.startPrank(user2);
        token.approve(address(vault), amount2);
        vault.deposit(amount2, user2);
        vm.stopPrank();

        vm.startPrank(user3);
        token.approve(address(vault), amount3);
        vault.deposit(amount3, user3);
        vm.stopPrank();

        // Grant some custom roles
        bytes32 CUSTOM_ROLE = keccak256("CUSTOM_ROLE");
        vm.prank(TOKEN_DEPLOYER);
        vault.grantRole(CUSTOM_ROLE, user1);

        // 4. Capture state before upgrade
        uint256 totalAssetsBefore = vault.totalAssets();
        uint256 user1SharesBefore = vault.balanceOf(user1);
        uint256 user2SharesBefore = vault.balanceOf(user2);
        uint256 user3SharesBefore = vault.balanceOf(user3);
        address assetBefore = address(vault.asset());
        bool user1HasCustomRole = vault.hasRole(CUSTOM_ROLE, user1);
        bool timelockHasUpgraderRole = vault.hasRole(
            vault.UPGRADER_ROLE(),
            address(timelock)
        );
        bool timelockHasGovernanceRole = vault.hasRole(
            vault.GOVERNANCE_ROLE(),
            address(timelock)
        );

        // 5. Deploy and upgrade to VaultV2
        VaultV2 newImplementation = new VaultV2();
        vm.prank(address(timelock));
        vault.upgradeToAndCall(address(newImplementation), "");

        // 6. Access the upgraded contract
        VaultV2 upgradedVault = VaultV2(address(proxy));

        // 7. Verify all state has been preserved
        assertEq(
            upgradedVault.totalAssets(),
            totalAssetsBefore,
            "Total assets not preserved"
        );
        assertEq(
            upgradedVault.balanceOf(user1),
            user1SharesBefore,
            "User1 shares not preserved"
        );
        assertEq(
            upgradedVault.balanceOf(user2),
            user2SharesBefore,
            "User2 shares not preserved"
        );
        assertEq(
            upgradedVault.balanceOf(user3),
            user3SharesBefore,
            "User3 shares not preserved"
        );
        assertEq(
            address(upgradedVault.asset()),
            assetBefore,
            "Asset reference not preserved"
        );
        assertEq(
            upgradedVault.hasRole(CUSTOM_ROLE, user1),
            user1HasCustomRole,
            "Custom role not preserved"
        );
        assertEq(
            upgradedVault.hasRole(
                upgradedVault.UPGRADER_ROLE(),
                address(timelock)
            ),
            timelockHasUpgraderRole,
            "Upgrader role not preserved"
        );
        assertEq(
            upgradedVault.hasRole(
                upgradedVault.GOVERNANCE_ROLE(),
                address(timelock)
            ),
            timelockHasGovernanceRole,
            "Governance role not preserved"
        );

        // 8. Test new VaultV2 functionality still works with preserved state
        vm.prank(address(timelock));
        upgradedVault.pause();
        assertTrue(
            upgradedVault.paused(),
            "New functionality should work after upgrade"
        );

        // 9. Verify state integrity through operations
        vm.prank(address(timelock));
        upgradedVault.unpause();

        // User1 should be able to withdraw their original deposit
        vm.startPrank(user1);
        upgradedVault.withdraw(amount1, user1, user1);
        vm.stopPrank();

        assertEq(
            token.balanceOf(user1),
            amount1,
            "User1 should recover their full deposit"
        );
        assertEq(
            upgradedVault.balanceOf(user1),
            0,
            "User1 should have 0 shares after withdrawal"
        );
    }

    function testSelfdestruct() public {
        // 1. Setup the initial vault and proxy using your standard procedure
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
        vault = Vault(address(proxy));

        uint256 amount = 100 * 10 ** 18;
        token.transfer(USER, amount);

        vm.startPrank(USER);
        uint256 depositAmount = 50 * 10 ** 18;
        token.approve(address(vault), depositAmount);
        vault.deposit(depositAmount, USER);
        vm.stopPrank();

        uint256 initialTokenAmount = token.balanceOf(USER);
        uint256 initialShares = vault.balanceOf(USER);

        // 2. Deploy the malicious implementation contract
        MaliciousVault maliciousVaultImpl = new MaliciousVault();

        // 3. Perform an upgrade to the malicious implementation
        vm.prank(address(timelock));
        vault.upgradeToAndCall(address(maliciousVaultImpl), "");

        // 4. Call the destroy function to selfdestruct the implementation
        MaliciousVault(address(proxy)).destroy();

        // 5. Verify the proxy still works by calling functions and checking state
        assertEq(initialTokenAmount, token.balanceOf(USER));
        assertEq(initialShares, vault.balanceOf(USER));

        uint256 withdrawAmount = 10 * 10 ** 18;
        vm.prank(USER);
        vault.withdraw(withdrawAmount, USER, USER);
        assertEq(initialTokenAmount + withdrawAmount, token.balanceOf(USER));
    }

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

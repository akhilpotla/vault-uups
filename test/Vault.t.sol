// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IVotes} from "@openzeppelin/contracts/governance/utils/IVotes.sol";
import {IGovernor} from "@openzeppelin/contracts/governance/IGovernor.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {GovToken} from "../src/GovToken.sol";
import {MaliciousVault} from "./mock/MaliciousVault.sol";
import {Vault} from "../src/Vault.sol";
import {VaultV2} from "../src/VaultV2.sol";
import {VaultGovernor} from "../src/VaultGovernor.sol";
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
        assertEq(initialShares - withdrawAmount, vault.balanceOf(USER));
    }

    // Integration Tests
    function testTimelockDelayedUpgrade() public {
        // 1. Setup Phase
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
        vault = Vault(address(proxy));

        // Add before upgrade
        uint256 depositAmount = 100 * 10 ** 18;
        token.approve(address(vault), depositAmount);
        vault.deposit(depositAmount, USER);
        uint256 initialBalance = vault.balanceOf(USER);

        // 2. Prepare the upgrade
        VaultV2 newImplementation = new VaultV2();

        // 3. Schedule the upgrade
        bytes memory upgradeCallData = abi.encodeWithSelector(
            vault.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );
        bytes32 salt = keccak256(
            abi.encodePacked(block.timestamp, address(newImplementation))
        );
        timelock.schedule(
            address(proxy),
            0,
            upgradeCallData,
            bytes32(0),
            salt,
            1000 * MIN_DELAY
        );

        // 4. Test premature execution
        vm.expectRevert();
        vault.upgradeToAndCall(address(newImplementation), "");

        // 5. Advance time
        vm.warp(block.timestamp + 1000 * MIN_DELAY);

        // 6. Execute the upgrade
        timelock.execute(address(proxy), 0, upgradeCallData, bytes32(0), salt);

        // 7. Verify success
        VaultV2 upgradedVault = VaultV2(address(proxy));
        vm.prank(address(timelock));
        upgradedVault.pause();
        assertTrue(upgradedVault.paused());

        // 8. Additional verification
        assertEq(
            upgradedVault.balanceOf(USER),
            initialBalance,
            "User balance should be preserved"
        );
        assertEq(
            upgradedVault.totalAssets(),
            depositAmount,
            "Total assets should be preserved"
        );
    }

    function testProposalExecution() public {
        // 1. Setup the governance system
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
        vault = Vault(address(proxy));

        VaultGovernor governor = new VaultGovernor(
            IVotes(address(token)),
            timelock
        );

        bytes32 PROPOSER_ROLE = timelock.PROPOSER_ROLE();
        bytes32 EXECUTOR_ROLE = timelock.EXECUTOR_ROLE();
        bytes32 CANCELLER_ROLE = timelock.CANCELLER_ROLE();

        timelock.grantRole(PROPOSER_ROLE, address(governor));
        timelock.grantRole(EXECUTOR_ROLE, address(governor));
        timelock.grantRole(CANCELLER_ROLE, address(governor));

        // 2. Distribute tokens and setup voting power
        // Setup users with tokens
        address user1 = makeAddr("USER1");
        address user2 = makeAddr("USER2");
        address user3 = makeAddr("USER3");

        uint256 amount1 = 100 * 10 ** 18;
        uint256 amount2 = 250 * 10 ** 18;
        uint256 amount3 = 75 * 10 ** 18;

        token.transfer(user1, amount1);
        token.transfer(user2, amount2);
        token.transfer(user3, amount3);

        // Users must delegate voting power to themselves
        vm.prank(user1);
        token.delegate(user1);

        vm.prank(user2);
        token.delegate(user2);

        vm.prank(user3);
        token.delegate(user3);

        // 3. Create a proposal
        VaultV2 vaultV2Impl = new VaultV2();
        vm.prank(address(timelock));
        vault.upgradeToAndCall(address(vaultV2Impl), "");
        VaultV2 upgradedVault = VaultV2(address(proxy));

        // Create calldata for pausing the vault
        bytes memory pauseCalldata = abi.encodeWithSelector(
            VaultV2.pause.selector
        );

        // Create proposal
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        string memory description = "Proposal #1: Pause the vault";

        targets[0] = address(proxy);
        values[0] = 0;
        calldatas[0] = pauseCalldata;

        vm.prank(user1);
        uint256 proposalId = governor.propose(
            targets,
            values,
            calldatas,
            description
        );

        // 4. Vote on the proposal
        // Advance time past voting delay
        vm.roll(block.number + governor.votingDelay() + 1);

        // Cast votes
        vm.prank(user1);
        governor.castVote(proposalId, 1);

        vm.prank(user2);
        governor.castVote(proposalId, 1);

        vm.prank(user3);
        governor.castVote(proposalId, 1);

        // Advance time past voting period
        vm.roll(block.number + governor.votingPeriod() + 1);

        // 5. Queue and execute
        // Check proposal secceeded
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Succeeded)
        );

        // Queue proposal
        bytes32 descriptionHash = keccak256(bytes(description));
        governor.queue(targets, values, calldatas, descriptionHash);

        // Advance time past timelock delay
        vm.warp(block.timestamp + timelock.getMinDelay() + 1);

        // Execute proposal
        governor.execute(targets, values, calldatas, descriptionHash);

        // Verify the vault is now paused
        assertTrue(
            upgradedVault.paused(),
            "Vault should be paused after proposal execution"
        );

        // Try to deposit - should fail
        token.approve(address(upgradedVault), 10 * 10 ** 18);
        vm.expectRevert("Pausable: paused");
        upgradedVault.deposit(10 * 10 ** 18, user1);
    }
    function testDepositAndUpgrade() public {
        // 1. Setup initial environment
        (
            TimelockController timelock,
            ERC1967Proxy proxy
        ) = _setupVaultAndProxy();
        vault = Vault(address(proxy));

        // 2. Initial state testing
        uint256 initialAssets = vault.totalAssets();
        uint256 maxDeposit = vault.maxDeposit(USER);

        // 3. Pre-upgrade deposits
        address user1 = makeAddr("USER1");
        address user2 = makeAddr("USER2");
        address user3 = makeAddr("USER3");
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

        uint256 totalAssetsBefore = vault.totalAssets();
        uint256 user1SharesBefore = vault.balanceOf(user1);
        uint256 user2SharesBefore = vault.balanceOf(user2);
        uint256 user3SharesBefore = vault.balanceOf(user3);
        uint256 user1BalanceBefore = token.balanceOf(user1);
        uint256 user2BalanceBefore = token.balanceOf(user2);
        uint256 user3BalanceBefore = token.balanceOf(user3);

        // 4. Prepare for upgrade
        VaultV2 newImplementation = new VaultV2();

        // 5. Perform upgrade
        vm.prank(address(timelock));
        vault.upgradeToAndCall(address(newImplementation), "");
        VaultV2 upgradedVault = VaultV2(address(proxy));

        // 6. Verify state preservation
        assertEq(user1SharesBefore, upgradedVault.balanceOf(user1));
        assertEq(user2SharesBefore, upgradedVault.balanceOf(user2));
        assertEq(user3SharesBefore, upgradedVault.balanceOf(user3));
        assertEq(user1BalanceBefore, token.balanceOf(user1));
        assertEq(user2BalanceBefore, token.balanceOf(user2));
        assertEq(user3BalanceBefore, token.balanceOf(user3));

        // 7. Post-upgrade deposits
        uint256 amount1_2 = 20 * 10 ** 18;
        uint256 amount2_2 = 25 * 10 ** 18;
        uint256 amount3_2 = 30 * 10 ** 18;
        token.transfer(user1, amount1_2);
        token.transfer(user2, amount2_2);
        token.transfer(user3, amount3_2);
        // Perform deposits
        vm.startPrank(user1);
        token.approve(address(upgradedVault), amount1_2);
        vault.deposit(amount1_2, user1);
        vm.stopPrank();

        vm.startPrank(user2);
        token.approve(address(upgradedVault), amount2_2);
        vault.deposit(amount2_2, user2);
        vm.stopPrank();

        vm.startPrank(user3);
        token.approve(address(upgradedVault), amount3_2);
        vault.deposit(amount3_2, user3);
        vm.stopPrank();

        assertEq(upgradedVault.balanceOf(user1), amount1 + amount1_2);
        assertEq(upgradedVault.balanceOf(user2), amount2 + amount2_2);
        assertEq(upgradedVault.balanceOf(user3), amount3 + amount3_2);

        // 8. Test new functionality with deposits
        vm.prank(address(timelock));
        upgradedVault.pause();
        assertTrue(upgradedVault.paused());

        token.transfer(user1, amount1_2);
        vm.startPrank(user1);
        token.approve(address(upgradedVault), amount1_2);
        vm.expectRevert();
        vault.deposit(amount1_2, user1);
        vm.stopPrank();

        vm.prank(address(timelock));
        upgradedVault.unpause();
        assertFalse(upgradedVault.paused());
        vm.startPrank(user1);
        token.approve(address(upgradedVault), amount1_2);
        vault.deposit(amount1_2, user1);
        vm.stopPrank();

        assertEq(upgradedVault.balanceOf(user1), amount1 + 2 * amount1_2);

        // 9. Withdrawal testing
        uint256 withdrawAmount = 50 * 10 ** 18;
        uint256 expectedBurnedShares = vault.previewWithdraw(withdrawAmount);

        vm.prank(user1);
        vault.approve(address(this), expectedBurnedShares);

        uint256 burnedShares = vault.withdraw(withdrawAmount, user1, user1);
        assertEq(expectedBurnedShares, burnedShares);

        // 10. Edge cases
        // Test deposit of zero amount
        vm.startPrank(user1);
        token.approve(address(upgradedVault), 0);
        uint256 sharesBefore = upgradedVault.balanceOf(user1);
        upgradedVault.deposit(0, user1);
        assertEq(
            upgradedVault.balanceOf(user1),
            sharesBefore,
            "Zero deposit should not change shares"
        );
        vm.stopPrank();

        // Test very small deposit (1 wei)
        vm.startPrank(user1);
        token.approve(address(upgradedVault), 1);
        sharesBefore = upgradedVault.balanceOf(user1);
        uint256 sharesReceived = upgradedVault.deposit(1, user1);
        assertEq(
            upgradedVault.balanceOf(user1),
            sharesBefore + sharesReceived,
            "Tiny deposit should work correctly"
        );
        vm.stopPrank();

        // Test exchange rate changes by direct token transfer
        uint256 directDonation = 100 * 10 ** 18;
        token.transfer(address(upgradedVault), directDonation);
        assertEq(
            upgradedVault.totalAssets(),
            totalAssetsBefore +
                2 *
                amount1_2 +
                amount2_2 +
                amount3_2 +
                1 +
                directDonation -
                withdrawAmount,
            "Total assets incorrect after donation"
        );

        // Test deposit after exchange rate change
        uint256 depositAmountAfterDonation = 10 * 10 ** 18;
        token.transfer(user2, depositAmountAfterDonation);
        vm.startPrank(user2);
        token.approve(address(upgradedVault), depositAmountAfterDonation);
        uint256 previewedShares = upgradedVault.previewDeposit(
            depositAmountAfterDonation
        );
        sharesReceived = upgradedVault.deposit(
            depositAmountAfterDonation,
            user2
        );
        assertEq(
            sharesReceived,
            previewedShares,
            "Shares received should match preview"
        );
        assertTrue(
            sharesReceived < depositAmountAfterDonation,
            "Shares should be less than assets after donation"
        );
        vm.stopPrank();

        // Test max withdrawal
        vm.prank(user3);
        uint256 maxWithdraw = upgradedVault.maxWithdraw(user3);
        assertTrue(maxWithdraw > 0, "Max withdraw should be non-zero");
        assertEq(
            maxWithdraw,
            upgradedVault.convertToAssets(upgradedVault.balanceOf(user3)),
            "Max withdraw should equal converted shares"
        );

        // Test rounding consistency across multiple operations
        address roundingTester = makeAddr("ROUNDING_TESTER");
        uint256 smallAmount = 5; // Odd number to check rounding
        token.transfer(roundingTester, smallAmount * 10);
        vm.startPrank(roundingTester);
        token.approve(address(upgradedVault), smallAmount * 10);

        uint256 shareSum = 0;
        for (uint i = 0; i < 10; i++) {
            shareSum += upgradedVault.deposit(smallAmount, roundingTester);
        }

        uint256 bulkShares = upgradedVault.previewDeposit(smallAmount * 10);
        assertApproxEqRel(
            shareSum,
            bulkShares,
            0.05e18,
            "Bulk deposit should not be more than 5% more efficient"
        );
        vm.stopPrank();
    }

    // Edge Cases and Security
    function testReentrancyProtection() public {}
    function testFuzzDeposits() public {}
    function testFuzzWithdraws() public {}
    function testTransferOwnershipDoesNotAffectFunds() public {}
}

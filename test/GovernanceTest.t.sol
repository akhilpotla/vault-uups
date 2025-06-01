// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IGovernor} from "@openzeppelin/contracts/governance/IGovernor.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {GovToken} from "../src/GovToken.sol";
import {MaliciousVault} from "./mock/MaliciousVault.sol";
import {Vault} from "../src/Vault.sol";
import {VaultV2} from "../src/VaultV2.sol";
import {VaultGovernor} from "../src/VaultGovernor.sol";

contract GovernanceTest is Test {
    ERC1967Proxy public proxy;
    GovToken public token;
    Vault public vaultImpl;
    Vault public vault;
    VaultGovernor public governor;
    TimelockController timelock;
    address public USER = makeAddr("USER");
    address public TOKEN_DEPLOYER;
    uint256 public constant INITIAL_SUPPLY = 1_000;
    uint256 public constant SUPPLY_CAP = 100_000;
    uint256 public constant MIN_DELAY = 12 seconds;
    address[] public proposers = new address[](1);
    address[] public executors = new address[](1);
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE");

    function setUp() public {
        token = new GovToken(INITIAL_SUPPLY * 10 ** 18, SUPPLY_CAP * 10 ** 18);
        TOKEN_DEPLOYER = address(this);

        proposers[0] = TOKEN_DEPLOYER;
        executors[0] = address(0);
        vaultImpl = new Vault();

        timelock = new TimelockController(
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
        proxy = new ERC1967Proxy(address(vaultImpl), initData);
        vault = Vault(address(proxy));
        governor = new VaultGovernor(token, timelock);
    }

    function _setupGovernanceSystemRoles() internal {
        timelock.grantRole(PROPOSER_ROLE, address(governor));
        timelock.grantRole(EXECUTOR_ROLE, address(governor));
        vault.grantRole(UPGRADER_ROLE, address(timelock));
    }

    function _setupVotingAccounts(
        address user1,
        address user2,
        address user3,
        uint256 amount1,
        uint256 amount2,
        uint256 amount3
    ) internal {
        token.transfer(user1, amount1);
        token.transfer(user2, amount2);
        token.transfer(user3, amount3);

        vm.startPrank(user1);
        token.delegate(user1);
        token.approve(address(vault), amount1 / 2);
        vault.deposit(amount1 / 2, user1);
        vm.stopPrank();

        vm.startPrank(user2);
        token.delegate(user2);
        token.approve(address(vault), amount2 / 2);
        vault.deposit(amount2 / 2, user2);
        vm.stopPrank();

        vm.startPrank(user3);
        token.delegate(user3);
        token.approve(address(vault), amount3 / 2);
        vault.deposit(amount3 / 2, user3);
        vm.stopPrank();
    }

    function testProposalLifecycle() public {
        // 1. Setup governance roles
        _setupGovernanceSystemRoles();
        assertTrue(timelock.hasRole(PROPOSER_ROLE, address(governor)));
        assertTrue(timelock.hasRole(EXECUTOR_ROLE, address(governor)));
        assertTrue(vault.hasRole(UPGRADER_ROLE, address(timelock)));

        // 2. Setup voting accounts
        address user1 = makeAddr("USER1");
        address user2 = makeAddr("USER2");
        address user3 = makeAddr("USER3");
        uint256 amount1 = 100 * 10 ** 18;
        uint256 amount2 = 250 * 10 ** 18;
        uint256 amount3 = 75 * 10 ** 18;
        _setupVotingAccounts(user1, user2, user3, amount1, amount2, amount3);

        assertEq(token.getVotes(user1), amount1 / 2);
        assertEq(token.getVotes(user2), amount2 / 2);
        assertEq(token.getVotes(user3), amount3 / 2);

        uint256 preUpgradeTotalAssets = vault.totalAssets();

        // 4. Create an upgrade proposal
        VaultV2 newImplementation = new VaultV2();
        bytes memory upgradeCallData = abi.encodeWithSelector(
            vault.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );
        // Create proposal
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        string memory description = "Proposal #1: Upgrade the vault";

        targets[0] = address(proxy);
        values[0] = 0;
        calldatas[0] = upgradeCallData;

        // 5. Submit proposal
        uint256 proposalId = governor.propose(
            targets,
            values,
            calldatas,
            description
        );
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Pending),
            "Proposal should be in pending state"
        );

        // 6. Progress through voting period
        vm.roll(block.number + governor.votingDelay() + 1);
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Active),
            "Proposal should be in active state"
        );

        governor.castVote(proposalId, 1);
        vm.prank(user1);
        governor.castVote(proposalId, 1);
        vm.prank(user2);
        governor.castVote(proposalId, 1);
        vm.prank(user3);
        governor.castVote(proposalId, 1);

        vm.roll(block.number + governor.votingPeriod() + 1);
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Succeeded),
            "Proposal should be in succeeded state"
        );

        // 7. Queue and execute
        bytes32 descriptionHash = keccak256(bytes(description));
        governor.queue(targets, values, calldatas, descriptionHash);
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Queued),
            "Proposal should be in queued state"
        );
        vm.warp(block.timestamp + timelock.getMinDelay() + 1);
        governor.execute(targets, values, calldatas, descriptionHash);
        assertEq(
            uint256(governor.state(proposalId)),
            uint256(IGovernor.ProposalState.Executed),
            "Proposal should be in executed state"
        );

        // 8. Verification
        VaultV2 upgradedVault = VaultV2(address(proxy));
        vm.prank(address(timelock));
        upgradedVault.pause();
        assertTrue(upgradedVault.paused());

        assertEq(
            upgradedVault.balanceOf(user1),
            amount1 / 2,
            "User1 balance should be preserved"
        );
        assertEq(
            upgradedVault.balanceOf(user2),
            amount2 / 2,
            "User2 balance should be preserved"
        );
        assertEq(
            upgradedVault.balanceOf(user3),
            amount3 / 2,
            "User3 balance should be preserved"
        );
        assertEq(
            upgradedVault.totalAssets(),
            preUpgradeTotalAssets,
            "Total assets should be preserved"
        );
        assertTrue(
            upgradedVault.hasRole(GOVERNANCE_ROLE, address(timelock)),
            "Governance role not maintained"
        );
        assertTrue(
            upgradedVault.hasRole(UPGRADER_ROLE, address(timelock)),
            "Upgrader role not maintained"
        );

        vm.prank(USER);
        vm.expectRevert();
        upgradedVault.pause();

        vm.prank(address(timelock));
        upgradedVault.unpause();

        uint256 postUpgradeDeposit = 25 * 10 ** 18;
        token.approve(address(upgradedVault), postUpgradeDeposit);
        uint256 preDepositBalance = upgradedVault.balanceOf(TOKEN_DEPLOYER);
        upgradedVault.deposit(postUpgradeDeposit, TOKEN_DEPLOYER);
        assertEq(
            upgradedVault.balanceOf(TOKEN_DEPLOYER),
            postUpgradeDeposit,
            "Deposit should work after upgrade"
        );

        uint256 withdrawAmount = 10 * 10 ** 18;
        uint256 preWithdrawBalance = token.balanceOf(TOKEN_DEPLOYER);
        upgradedVault.withdraw(withdrawAmount, TOKEN_DEPLOYER, TOKEN_DEPLOYER);
        assertEq(
            token.balanceOf(TOKEN_DEPLOYER),
            preWithdrawBalance + withdrawAmount,
            "Withdrawal should work after upgrade"
        );
    }

    function testUpgradeToSecurity() public {
        // 1. Setup the test environment
        _setupGovernanceSystemRoles();

        // 2. Test unauthorized direct upgrade attempts
        VaultV2 newImplementation = new VaultV2();
        vm.expectRevert();
        vault.upgradeToAndCall(address(newImplementation), "");

        vm.startPrank(address(governor));
        vm.expectRevert("Vault: must have upgrader role to upgrade");
        vault.upgradeToAndCall(address(newImplementation), "");
        vm.stopPrank();

        // 3. Test bypassing governance
        VaultV2 upgradedVaultImpl = new VaultV2();
        bytes memory upgradeCallData = abi.encodeWithSelector(
            vault.upgradeToAndCall.selector,
            address(upgradedVaultImpl),
            ""
        );
        bytes32 salt = keccak256(
            abi.encodePacked(block.timestamp, address(upgradedVaultImpl))
        );

        vm.prank(TOKEN_DEPLOYER);
        timelock.schedule(
            address(proxy),
            0,
            upgradeCallData,
            bytes32(0),
            salt,
            MIN_DELAY
        );

        vm.expectRevert();
        timelock.execute(address(proxy), 0, upgradeCallData, bytes32(0), salt);

        vm.warp(block.timestamp + MIN_DELAY + 1);
        timelock.execute(address(proxy), 0, upgradeCallData, bytes32(0), salt);

        VaultV2 upgradedVault = VaultV2(address(proxy));
        vm.startPrank(address(timelock));
        upgradedVault.pause(); // Test new functionality
        assertTrue(upgradedVault.paused());
        upgradedVault.unpause();
        vm.stopPrank();

        // 4. Test role management security
        address randomUser = makeAddr("RANDOM_USER");

        // Attempt to grant UPGRADER_ROLE without admin permissions
        vm.prank(randomUser);
        vm.expectRevert();
        vault.grantRole(UPGRADER_ROLE, randomUser);

        // Test revoking UPGRADER_ROLE from timelock and verify upgrade fails
        vm.prank(TOKEN_DEPLOYER);
        vault.revokeRole(UPGRADER_ROLE, address(timelock));
        VaultV2 anotherImplementation = new VaultV2();
        vm.prank(address(timelock));
        vm.expectRevert("Vault: must have upgrader role to upgrade");
        vault.upgradeToAndCall(address(anotherImplementation), "");

        // Grant back the role for further tests
        vm.prank(TOKEN_DEPLOYER);
        vault.grantRole(UPGRADER_ROLE, address(timelock));

        // 5. Test with malicious implementation
        MaliciousVault maliciousImpl = new MaliciousVault();

        // Try to upgrade to malicious implementation
        vm.prank(address(timelock));
        vault.upgradeToAndCall(address(maliciousImpl), "");

        // Verify malicious implementation can't self-grant roles
        MaliciousVault maliciousVault = MaliciousVault(address(proxy));
        address attacker = makeAddr("ATTACKER");
        assertFalse(
            maliciousVault.hasRole(GOVERNANCE_ROLE, attacker),
            "Attacker shouldn't have GOVERNANCE_ROLE before attack"
        );
        assertFalse(
            maliciousVault.hasRole(UPGRADER_ROLE, attacker),
            "Attacker shouldn't have UPGRADER_ROLE before attack"
        );
        vm.prank(attacker);
        vm.expectRevert();
        maliciousVault.tryToStealFunds(attacker);

        assertFalse(
            maliciousVault.hasRole(GOVERNANCE_ROLE, attacker),
            "Attacker shouldn't have GOVERNANCE_ROLE after attack"
        );
        assertFalse(
            maliciousVault.hasRole(UPGRADER_ROLE, attacker),
            "Attacker shouldn't have UPGRADER_ROLE after attack"
        );

        // 6. Test upgrade security through valid governance flow
        VaultV2 validV2Implementation = new VaultV2();
        // VaultGovernor governor2 = new VaultGovernor(token, timelock);
        timelock.grantRole(PROPOSER_ROLE, address(governor));
        timelock.grantRole(EXECUTOR_ROLE, address(governor));

        // Create proposal data
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        string memory description = "Upgrade to VaultV2 via governance";

        upgradeCallData = abi.encodeWithSelector(
            vault.upgradeToAndCall.selector,
            address(validV2Implementation),
            ""
        );

        targets[0] = address(proxy);
        values[0] = 0;
        calldatas[0] = upgradeCallData;

        // Self-delegate to get voting power
        token.delegate(TOKEN_DEPLOYER);

        // Submit proposal
        uint256 proposalId = governor.propose(
            targets,
            values,
            calldatas,
            description
        );
        vm.roll(block.number + governor.votingDelay() + 1);

        // Vote on proposal
        governor.castVote(proposalId, 1); // Vote in favor

        // Advance blocks
        vm.roll(block.number + governor.votingPeriod() + 1);

        // Queue and execute
        bytes32 descriptionHash = keccak256(bytes(description));
        governor.queue(targets, values, calldatas, descriptionHash);
        vm.warp(block.timestamp + timelock.getMinDelay() + 1);
        governor.execute(targets, values, calldatas, descriptionHash);

        // Verify upgrade worked via governance
        VaultV2 govUpgradedVault = VaultV2(address(proxy));
        vm.prank(address(timelock));
        govUpgradedVault.pause();
        assertTrue(govUpgradedVault.paused());

        // Define the implementation slot directly as bytes32
        bytes32 IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

        // Load implementation address using the correct slot
        address currentImpl = address(
            uint160(uint256(vm.load(address(proxy), IMPLEMENTATION_SLOT)))
        );

        assertEq(
            currentImpl,
            address(validV2Implementation),
            "Implementation address not properly stored"
        );

        // Try to call initialize again (should fail - already initialized)
        vm.expectRevert();
        Vault(address(govUpgradedVault)).initialize(
            IERC20(address(token)),
            address(timelock),
            TOKEN_DEPLOYER
        );
    }

    function testGovernanceOnFork() public {
        // 1. Setup the fork environment
        // 2. Contract deployment options
        // 3. Setup governance structure
        // 4. Create an upgrade proposal
        // 5. Use real block data
        // 6. Execute the governance flow
        // 7. Verify seccessful execution
        // 8. Test on different network states
    }
}

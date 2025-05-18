// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test, console} from "forge-std/Test.sol";
import {GovToken} from "../src/GovToken.sol";

contract GovTokenTest is Test {
    GovToken public token;
    address public USER = makeAddr("USER");
    address public TOKEN_DEPLOYER;
    uint256 public constant INITIAL_SUPPLY = 1_000;
    uint256 public constant SUPPLY_CAP = 100_000;

    function setUp() public {
        token = new GovToken(INITIAL_SUPPLY, SUPPLY_CAP);
        TOKEN_DEPLOYER = address(this);
        token.transfer(USER, 500);
    }

    function testInitialSupply() public view {
        assertEq(
            token.totalSupply(),
            INITIAL_SUPPLY,
            "The total supply should be 1000"
        );
        assertEq(
            token.balanceOf(TOKEN_DEPLOYER),
            500,
            "TOKEN_DEPLOYER balance should 500 after transfering token to the USER"
        );
    }

    function testMintingToCapSucceeds() public {
        // Mint up to the cap
        token.mint(USER, SUPPLY_CAP - INITIAL_SUPPLY);
        assertEq(token.totalSupply(), SUPPLY_CAP);
    }

    function testMintingBeyondCapFails() public {
        // Try to mint beyond the cap
        vm.expectRevert();
        token.mint(USER, SUPPLY_CAP - INITIAL_SUPPLY + 1);
    }

    function testDelegation() public {
        // Check initial voting power
        assertEq(token.getVotes(USER), 0, "USER should have 0 votes initially");
        assertEq(
            token.getVotes(TOKEN_DEPLOYER),
            500,
            "TOKEN_DEPLOYER should have 500 votes initially"
        );

        // USER delegates votes to themselves
        vm.startPrank(USER);
        token.delegate(USER);
        vm.stopPrank();

        // Check voting power after delegation
        assertEq(
            token.getVotes(USER),
            500,
            "USER should have 500 votes after self-delegation"
        );
        assertEq(
            token.getVotes(TOKEN_DEPLOYER),
            500,
            "TOKEN_DEPLOYER should have 500 votes after USER self-delegates"
        );

        // USER delegates votes to TOKEN_DEPLOYER
        vm.startPrank(USER);
        token.delegate(TOKEN_DEPLOYER);
        vm.stopPrank();

        // Check voting power after delegation to TOKEN_DEPLOYER
        assertEq(
            token.balanceOf(USER),
            500,
            "USER should still have 500 tokens after delegating voting rights"
        );
        assertEq(
            token.getVotes(USER),
            0,
            "USER should have 0 votes after delegating to TOKEN_DEPLOYER"
        );
        assertEq(
            token.getVotes(TOKEN_DEPLOYER),
            INITIAL_SUPPLY,
            "TOKEN_DEPLOYER should have 1000 votes after USER transfers delegation"
        );
    }

    function testTransferUpdatesVotingPower() public {
        // First delegate to themselves so transfers affect voting power
        vm.startPrank(USER);
        token.delegate(USER);
        vm.stopPrank();

        // Transfer more tokens to USER
        token.transfer(USER, 200);

        // Check voting power updates automatically through _update
        assertEq(
            token.getVotes(USER),
            700,
            "USER should have 700 votes after additional transfer of 200 tokens"
        );
        assertEq(
            token.getVotes(TOKEN_DEPLOYER),
            300,
            "TOKEN_DEPLOYER should have 300 votes"
        );
    }

    function testNewMintedTokensIncreaseVotingPower() public {
        vm.startPrank(USER);
        token.delegate(USER);
        vm.stopPrank();

        token.mint(USER, 100);
        assertEq(
            token.balanceOf(USER),
            600,
            "USER should have 600 tokens after mint"
        );
        assertEq(
            token.getVotes(USER),
            600,
            "USER should have 600 votes after self-delegation and token mint"
        );
        assertEq(
            token.balanceOf(TOKEN_DEPLOYER),
            500,
            "TOKEN_DEPLOYER should still have 500 tokens after token mint for USER"
        );
        assertEq(
            token.getVotes(TOKEN_DEPLOYER),
            500,
            "TOKEN_DEPLOYER should still have 500 votes after token mint for USER"
        );
    }

    function testUSERShouldNotBeAbleToMintTokens() public {
        vm.startPrank(USER);
        vm.expectRevert();
        token.mint(USER, 100);
        vm.stopPrank();

        assertEq(
            token.balanceOf(USER),
            500,
            "USER should have 500 tokens after minting with incorrect role"
        );
    }

    // Role Management Tests
    function testAdminCanGrantMinterRole() public {
        token.grantRole(token.MINTER_ROLE(), USER);

        vm.prank(USER);
        token.mint(USER, 100);
        assertEq(
            token.balanceOf(USER),
            600,
            "USER should have 600 after minting"
        );
    }

    function testRevokeRole() public {
        token.grantRole(token.MINTER_ROLE(), USER);
        token.revokeRole(token.MINTER_ROLE(), USER);

        vm.prank(USER);
        vm.expectRevert();
        token.mint(USER, 100);
    }

    // Permit Functionality Tests
    function testPermit() public {
        uint256 privateKey = 1;
        address owner = vm.addr(privateKey);

        token.transfer(owner, 100);

        uint256 deadline = block.timestamp + 1 hours;
        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(
                    abi.encode(
                        keccak256(
                            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                        ),
                        owner,
                        USER,
                        100,
                        0,
                        deadline
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        token.permit(owner, USER, 100, deadline, v, r, s);
        assertEq(token.allowance(owner, USER), 100);
    }

    // Historical Voting Power Tests
    function testGetPastVotes() public {
        vm.prank(USER);
        token.delegate(USER);

        uint256 blockNumber = block.number;
        vm.roll(blockNumber + 1);

        token.transfer(USER, 200);
        vm.roll(blockNumber + 2);

        assertEq(token.getPastVotes(USER, blockNumber), 500);
        assertEq(token.getPastVotes(USER, blockNumber + 1), 700);
    }

    // Additional Edge Cases
    function testBurnTokensAffectsVotingPower() public {
        vm.prank(USER);
        token.delegate(USER);

        vm.prank(USER);
        token.burn(100);

        assertEq(token.getVotes(USER), 400);
    }
    function testDelegateChangeDuringTransfer() public {}
}

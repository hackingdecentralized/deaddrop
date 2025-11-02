// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../bug_report.sol";

interface DAO {
    function totalSupply() external view returns (uint256);
}

contract DAOTest is Test, BugReport {
    string  rpcUrl;
    address targetAddr;
    uint256 forkId;
    uint256 preDaoBalance;

    function setUp() public {
        rpcUrl = vm.envString("MAINNET_RPC_URL");
        targetAddr = vm.envAddress("TARGET");
        forkId = vm.createFork(rpcUrl, vm.envUint("block_num"));
    }

    // This sets up the initial state before the bug is triggered.
    function pre_inv() internal {
        vm.selectFork(forkId);
        preDaoBalance = address(targetAddr).balance;
    }

    // If the bug doesn't work, it will remain the same as the pre-invocation balance.
    // If the bug works, the balance will be drained.
    // This is the post-invocation check.
    function post_inv() internal {
        uint256 postBalance = address(targetAddr).balance;
        assertEq(
            postBalance,
            preDaoBalance,
            "DAO balance was drained!"
        );
    }

    // The underlying tool relies on the bug implementing a test interface. 
    // This is the test that will be run by the tool for a submitted bug report.
    function testConstraint() public {
        pre_inv();
        bug(forkId, targetAddr);
        post_inv();
    }

    // Additional test to check if the total supply of the DAO is non-zero to
    // begin with and remains so after the bug is triggered.
    function testTotalSupplyIsNonzero() public {
        bug(forkId, targetAddr);
        uint256 supply = DAO(targetAddr).totalSupply();
        assertGt(supply, 0);
    }
}
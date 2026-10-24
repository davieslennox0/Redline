// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Staking.sol";
import "../src/MockToken.sol";

contract StakingTest is Test {
    MockToken stk;
    MockToken rwd;
    StakeRewards s;
    address alice = address(0xA11CE);

    function setUp() public {
        stk = new MockToken();
        rwd = new MockToken();
        s = new StakeRewards(IERC20(address(stk)), IERC20(address(rwd)), 1e18);
        rwd.mint(address(s), 1_000_000e18);
        stk.mint(alice, 100e18);
        vm.prank(alice);
        stk.approve(address(s), type(uint256).max);
    }

    function test_StakeAndWithdraw() public {
        vm.startPrank(alice);
        s.stake(100e18);
        s.withdraw(100e18);
        assertEq(stk.balanceOf(alice), 100e18);
        vm.stopPrank();
    }

    function test_SoleStakerEarns() public {
        vm.prank(alice);
        s.stake(100e18);
        skip(100);
        vm.prank(alice);
        s.claim();
        assertEq(rwd.balanceOf(alice), 100e18);
    }
}

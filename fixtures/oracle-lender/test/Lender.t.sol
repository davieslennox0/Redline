// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Lender.sol";

contract LenderTest is Test {
    Token a;
    Token b;
    AMM amm;
    Lender lender;
    address alice = address(0xA11CE);

    function setUp() public {
        a = new Token("COL");
        b = new Token("USD");
        amm = new AMM(a, b);
        lender = new Lender(a, b, amm);
        a.mint(address(this), 1_000e18);
        b.mint(address(this), 1_000e18);
        a.approve(address(amm), type(uint256).max);
        b.approve(address(amm), type(uint256).max);
        amm.addLiquidity(1_000e18, 1_000e18);
        b.mint(address(lender), 10_000e18);
        a.mint(alice, 100e18);
    }

    function test_BorrowWithinLtv() public {
        vm.startPrank(alice);
        a.approve(address(lender), 100e18);
        lender.depositCollateral(100e18);
        lender.borrow(70e18);
        assertEq(b.balanceOf(alice), 70e18);
        vm.stopPrank();
    }

    function test_CannotOverBorrow() public {
        vm.startPrank(alice);
        a.approve(address(lender), 100e18);
        lender.depositCollateral(100e18);
        vm.expectRevert("undercollateralized");
        lender.borrow(80e18);
        vm.stopPrank();
    }
}

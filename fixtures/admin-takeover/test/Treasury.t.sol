// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Treasury.sol";

contract TreasuryTest is Test {
    Treasury t;
    address owner = address(0x0A11);
    address stranger = address(0xBAD);

    function setUp() public {
        t = new Treasury();
        t.initialize(owner, 100);
        vm.deal(address(t), 5 ether);
    }

    function test_OwnerCanSweep() public {
        vm.prank(owner);
        t.sweep(payable(owner), 1 ether);
        assertEq(owner.balance, 1 ether);
    }

    function test_StrangerCannotSweep() public {
        vm.prank(stranger);
        vm.expectRevert("not owner");
        t.sweep(payable(stranger), 1 ether);
    }

    function test_FeeCap() public {
        vm.prank(owner);
        vm.expectRevert("fee too high");
        t.setFee(5000);
    }
}

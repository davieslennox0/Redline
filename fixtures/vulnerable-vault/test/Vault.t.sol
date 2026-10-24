// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract VaultTest is Test {
    Vault vault;
    address alice = address(0xA11CE);

    function setUp() public {
        vault = new Vault();
        vm.deal(alice, 10 ether);
    }

    function test_DepositWithdraw() public {
        vm.startPrank(alice);
        vault.deposit{value: 1 ether}();
        assertEq(vault.balances(alice), 1 ether);
        vault.withdraw(1 ether);
        assertEq(vault.balances(alice), 0);
        vm.stopPrank();
        assertEq(alice.balance, 10 ether);
    }

    function test_CannotOverdraw() public {
        vm.prank(alice);
        vault.deposit{value: 1 ether}();
        vm.prank(alice);
        vm.expectRevert("insufficient");
        vault.withdraw(2 ether);
    }
}

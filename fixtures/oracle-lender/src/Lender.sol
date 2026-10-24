// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Token.sol";
import "./AMM.sol";

/// @notice Borrow stable (B) against collateral (A) at 75% LTV.
contract Lender {
    Token public immutable collateral;
    Token public immutable stable;
    AMM public immutable amm;

    mapping(address => uint256) public collateralOf;
    mapping(address => uint256) public debtOf;

    constructor(Token _c, Token _s, AMM _amm) {
        collateral = _c;
        stable = _s;
        amm = _amm;
    }

    function depositCollateral(uint256 amt) external {
        collateral.transferFrom(msg.sender, address(this), amt);
        collateralOf[msg.sender] += amt;
    }

    function maxBorrow(address user) public view returns (uint256) {
        return (collateralOf[user] * amm.spotPrice() / 1e18) * 75 / 100;
    }

    function borrow(uint256 amt) external {
        require(debtOf[msg.sender] + amt <= maxBorrow(msg.sender), "undercollateralized");
        debtOf[msg.sender] += amt;
        stable.transfer(msg.sender, amt);
    }

    function repay(uint256 amt) external {
        stable.transferFrom(msg.sender, address(this), amt);
        debtOf[msg.sender] -= amt;
    }

    function withdrawCollateral(uint256 amt) external {
        collateralOf[msg.sender] -= amt;
        require(debtOf[msg.sender] <= maxBorrow(msg.sender), "undercollateralized");
        collateral.transfer(msg.sender, amt);
    }
}

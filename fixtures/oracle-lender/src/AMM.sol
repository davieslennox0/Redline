// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Token.sol";

/// @notice Constant-product pool between collateral token (A) and stable token (B).
contract AMM {
    Token public immutable a;
    Token public immutable b;
    uint256 public reserveA;
    uint256 public reserveB;

    constructor(Token _a, Token _b) {
        a = _a;
        b = _b;
    }

    function addLiquidity(uint256 amtA, uint256 amtB) external {
        a.transferFrom(msg.sender, address(this), amtA);
        b.transferFrom(msg.sender, address(this), amtB);
        reserveA += amtA;
        reserveB += amtB;
    }

    function swapAForB(uint256 amtIn) external returns (uint256 out) {
        out = (reserveB * amtIn) / (reserveA + amtIn);
        a.transferFrom(msg.sender, address(this), amtIn);
        b.transfer(msg.sender, out);
        reserveA += amtIn;
        reserveB -= out;
    }

    function swapBForA(uint256 amtIn) external returns (uint256 out) {
        out = (reserveA * amtIn) / (reserveB + amtIn);
        b.transferFrom(msg.sender, address(this), amtIn);
        a.transfer(msg.sender, out);
        reserveB += amtIn;
        reserveA -= out;
    }

    /// @return price of 1e18 A in units of B
    function spotPrice() external view returns (uint256) {
        return (reserveB * 1e18) / reserveA;
    }
}

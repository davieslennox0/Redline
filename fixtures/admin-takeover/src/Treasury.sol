// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Proxy-style treasury; `initialize` is called by the deployer after deployment.
contract Treasury {
    address public owner;
    uint256 public feeBps;
    bool public paused;

    function initialize(address _owner, uint256 _feeBps) external {
        owner = _owner;
        feeBps = _feeBps;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    receive() external payable {}

    function setPaused(bool p) external onlyOwner {
        paused = p;
    }

    function setFee(uint256 bps) external onlyOwner {
        require(bps <= 1000, "fee too high");
        feeBps = bps;
    }

    function sweep(address payable to, uint256 amount) external onlyOwner {
        require(!paused, "paused");
        to.transfer(amount);
    }
}

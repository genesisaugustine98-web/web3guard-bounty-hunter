// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

/// @title VulnerableLending - Oracle manipulation (DO NOT USE)
/// @notice INTENTIONALLY VULNERABLE for scanner testing.
/// VULN: spot price from a single (manipulable) pair, no TWAP, no staleness check.
contract VulnerableLending {
    address public priceOracle;     // supposed to be a DEX pair
    IERC20 public collateralToken;
    IERC20 public borrowToken;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) borrowed;
    uint256 public collateralFactorBps = 7500; // 75%

    constructor(address _oracle, address _col, address _borrow) {
        priceOracle = _oracle;
        collateralToken = IERC20(_col);
        borrowToken = IERC20(_borrow);
    }

    // VULN: spot price from a single pool — flash-loan manipulable
    function getPrice() public view returns (uint256) {
        (uint112 r0, uint112 r1,) = IUniswapV2Pair(priceOracle).getReserves();
        return uint256(r1) * 1e18 / uint256(r0);
    }

    function depositCollateral(uint256 amount) external {
        collateralToken.transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        uint256 price = getPrice();
        uint256 maxBorrow = collateral[msg.sender] * price * collateralFactorBps / 1e18 / 10000;
        require(borrowed[msg.sender] + amount <= maxBorrow, "over");
        borrowed[msg.sender] += amount;
        borrowToken.transfer(msg.sender, amount);
    }
}

interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

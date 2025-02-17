// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.25;

import { IUniswapV3Factory } from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol";
import { MockPool } from "./MockPool.t.sol";

contract MockUniswapV3Factory is IUniswapV3Factory {
    mapping(address => mapping(address => mapping(uint24 => address))) internal pools;

    function createPool(address tokenA, address tokenB, uint24 fee) external override returns (address pool) {
        pool = address(new MockPool{ salt: keccak256(abi.encodePacked(tokenA, tokenB, fee)) }());
        pools[tokenA][tokenB][fee] = pool;
        pools[tokenB][tokenA][fee] = pool;
    }

    function getPool(address tokenA, address tokenB, uint24 fee) external view override returns (address) {
        return pools[tokenA][tokenB][fee];
    }

    function setOwner(address) external { }
    function enableFeeAmount(uint24, int24) external { }

    function feeAmountTickSpacing(uint24 fee) external pure returns (int24) {
        if (fee == type(uint24).max) return 0;
        return 100;
    }

    function owner() external view returns (address) { }
}

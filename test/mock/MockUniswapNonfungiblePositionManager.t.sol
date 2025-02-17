// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.25;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { INonfungiblePositionManager } from "@uniswap/v3-periphery/contracts/interfaces/INonfungiblePositionManager.sol";
import { MockUniswapV3Factory } from "./MockUniswapV3Factory.t.sol";
import { IMulticall } from "@uniswap/v3-periphery/contracts/interfaces/IMulticall.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { WETH9 } from "./WETH.t.sol";
import { Test } from "forge-std/src/Test.sol";
import { MockPool } from "./MockPool.t.sol";

contract MockUniswapNonfungiblePositionManager is ERC721, IMulticall, Test {
    WETH9 public immutable WETH;
    MockUniswapV3Factory public immutable FACTORY;

    uint256 public lastTokenId;

    struct PositionInfo {
        IERC20 token0;
        IERC20 token1;
    }

    mapping(uint256 => PositionInfo) private _token;

    constructor(address weth, address factory) ERC721("Uniswap V3 LP", "UNI-V3-LP") {
        WETH = WETH9(payable(weth));
        FACTORY = MockUniswapV3Factory(factory);
    }

    function mint(INonfungiblePositionManager.MintParams calldata params)
        external
        payable
        returns (uint256 tokenId, uint128, uint256, uint256)
    {
        tokenId = ++lastTokenId;

        address pool = FACTORY.getPool(params.token0, params.token1, params.fee);

        _token[tokenId] = PositionInfo({ token0: IERC20(params.token0), token1: IERC20(params.token1) });

        if (params.token0 != address(WETH) || msg.value == 0) {
            _token[tokenId].token0.transferFrom(msg.sender, pool, params.amount0Desired);
        } else {
            WETH.deposit{ value: params.amount0Desired }();
            WETH.transfer(pool, params.amount0Desired);
        }

        if (params.token1 != address(WETH) || msg.value == 0) {
            _token[tokenId].token1.transferFrom(msg.sender, pool, params.amount1Desired);
        } else {
            WETH.deposit{ value: params.amount1Desired }();
            WETH.transfer(pool, params.amount1Desired);
        }

        _mint(params.recipient, tokenId);
    }

    function refundETH() external payable { }

    function multicall(bytes[] calldata calls) external payable returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(calls[i]);
            require(success);
            results[i] = result;
        }
    }

    struct CollectParams {
        uint256 tokenId;
        address recipient;
        uint128 amount0Max;
        uint128 amount1Max;
    }

    /// @notice Transfers 10% of the pool's liquidity to the recipient
    function collect(CollectParams calldata params) external payable returns (uint256 amount0, uint256 amount1) {
        require(params.tokenId <= lastTokenId, "Nonexistent");
        IERC20 token0 = _token[params.tokenId].token0;
        IERC20 token1 = _token[params.tokenId].token1;

        address pool = FACTORY.getPool(address(token0), address(token1), 10_000);

        amount0 = token0.balanceOf(pool) * 1000 / 10_000;
        amount1 = token1.balanceOf(pool) * 1000 / 10_000;

        MockPool(pool).transferToken(token0, params.recipient, amount0);
        MockPool(pool).transferToken(token1, params.recipient, amount1);
    }

    function positions(uint256 tokenId)
        external
        view
        returns (
            uint96,
            address,
            address token0,
            address token1,
            uint24,
            int24,
            int24,
            uint128,
            uint256,
            uint256,
            uint128,
            uint128
        )
    {
        require(tokenId <= lastTokenId, "Nonexistent");
        token0 = address(_token[tokenId].token0);
        token1 = address(_token[tokenId].token1);
    }
}

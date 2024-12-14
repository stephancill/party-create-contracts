// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import { Clones } from "@openzeppelin/contracts/proxy/Clones.sol";
import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import { PartyERC20 } from "./PartyERC20.sol";
import { PartyTokenAdminERC721 } from "./PartyTokenAdminERC721.sol";
import { PartyLPLocker } from "./PartyLPLocker.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import { IUniswapV3Factory } from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Factory.sol";
import { IUniswapV3Pool } from "@uniswap/v3-core/contracts/interfaces/IUniswapV3Pool.sol";
import { INonfungiblePositionManager } from "@uniswap/v3-periphery/contracts/interfaces/INonfungiblePositionManager.sol";
import { ILocker } from "./interfaces/ILocker.sol";
import { Implementation } from "./utils/Implementation.sol";

contract PartyTokenLauncher is IERC721Receiver, Implementation {
    using MerkleProof for bytes32[];
    using SafeCast for uint256;
    using Clones for address;

    event LaunchCreated(
        address indexed creator,
        IERC20 indexed token,
        address tokenLiquidityPool,
        ERC20Args erc20Args,
        LaunchArgs launchArgs
    );
    event Contribute(
        address indexed contributor,
        string comment,
        uint96 ethContributed,
        uint96 tokensReceived
    );
    event Withdraw(
        address indexed contributor,
        uint96 tokensReceived,
        uint96 ethContributed,
        uint96 withdrawalFee
    );
    event Finalized(
        IERC20 indexed token, uint256 liquidityPoolTokenId, uint96 ethAmountForPool
    );
    event RecipientTransfer(IERC20 indexed token, address indexed recipient, uint96 numTokens);
    event AllowlistUpdated(bytes32 oldMerkleRoot, bytes32 newMerkleRoot);

    error OnlyAdmin(address admin);
    error InvalidUniswapPoolFee();
    error LaunchInvalid();
    error InvalidRecipient();
    error TargetContributionTooLow();
    error NoLockerFeeRecipients();
    error TotalSupplyMismatch();
    error TotalSupplyExceedsLimit();
    error InvalidMerkleProof();
    error InvalidBps();
    error ContributionZero();
    error ContributionsExceedsMaxPerAddress(
        uint96 newContribution, uint96 existingContributionsByAddress, uint96 maxContributionPerAddress
    );
    error InvalidLifecycleState(LaunchLifecycle actual, LaunchLifecycle expected);
    error ETHTransferFailed(address recipient, uint96 amount);
    error InvalidFee();

    enum LaunchLifecycle {
        Active,
        Finalized
    }

    struct LockerFeeRecipient {
        address recipient;
        uint16 bps;
    }

    struct ERC20Args {
        string name;
        string symbol;
        string image;
        string description;
        uint96 totalSupply;
    }

    struct LaunchArgs {
        uint96 numTokensForLP;
        uint96 numTokensForDistribution;
        uint96 numTokensForRecipient;
        uint96 targetContribution;
        uint96 maxContributionPerAddress;
        bytes32 merkleRoot;
        address recipient;
        uint16 finalizationFeeBps;
        uint16 withdrawalFeeBps;
        LockerFeeRecipient[] lockerFeeRecipients;
    }

    PartyTokenAdminERC721 public immutable TOKEN_ADMIN_ERC721;
    PartyERC20 public immutable PARTY_ERC20_LOGIC;
    INonfungiblePositionManager public immutable POSITION_MANAGER;
    IUniswapV3Factory public immutable UNISWAP_FACTORY;
    uint24 public immutable POOL_FEE;
    int24 public immutable MIN_TICK;
    int24 public immutable MAX_TICK;
    address public immutable WETH;
    ILocker public immutable POSITION_LOCKER;
    address public immutable owner;

    uint32 public numOfLaunches;

    PartyERC20 public token;
    bytes32 public merkleRoot;
    uint96 public totalContributions;
    uint96 public targetContribution;
    uint96 public maxContributionPerAddress;
    uint96 public numTokensForLP;
    uint96 public numTokensForDistribution;
    uint96 public numTokensForRecipient;
    address public recipient;
    uint16 public finalizationFeeBps;
    uint16 public withdrawalFeeBps;
    PartyLPLocker.LPInfo public lpInfo;

    constructor(
        address payable partyDAO,
        PartyTokenAdminERC721 tokenAdminERC721,
        PartyERC20 partyERC20Logic,
        INonfungiblePositionManager positionManager,
        IUniswapV3Factory uniswapFactory,
        address weth,
        uint24 poolFee,
        ILocker positionLocker
    )
    {
        owner = partyDAO;
        TOKEN_ADMIN_ERC721 = tokenAdminERC721;
        PARTY_ERC20_LOGIC = partyERC20Logic;
        POSITION_MANAGER = positionManager;
        UNISWAP_FACTORY = uniswapFactory;
        WETH = weth;
        POOL_FEE = poolFee;
        POSITION_LOCKER = positionLocker;

        int24 tickSpacing = uniswapFactory.feeAmountTickSpacing(poolFee);
        if (tickSpacing == 0) revert InvalidUniswapPoolFee();

        MIN_TICK = (-887_272 / tickSpacing) * tickSpacing;
        MAX_TICK = (887_272 / tickSpacing) * tickSpacing;
    }

    /// @notice Initializer to be called prior to using the contract.
    function initialize(
        ERC20Args memory erc20Args,
        LaunchArgs memory launchArgs
    ) public payable onlyInitialize {
        if (launchArgs.finalizationFeeBps > 250 || launchArgs.withdrawalFeeBps > 250) {
            revert InvalidFee();
        }
        uint96 flatLockFee = POSITION_LOCKER.getFlatLockFee();
        uint96 finalizationFee = (launchArgs.targetContribution * launchArgs.finalizationFeeBps) / 1e4;
        if (launchArgs.targetContribution - finalizationFee <= flatLockFee) revert TargetContributionTooLow();
        if (
            erc20Args.totalSupply
                != launchArgs.numTokensForLP + launchArgs.numTokensForDistribution + launchArgs.numTokensForRecipient
        ) {
            revert TotalSupplyMismatch();
        }
        if (erc20Args.totalSupply > type(uint96).max) revert TotalSupplyExceedsLimit();
        if (launchArgs.lockerFeeRecipients.length == 0) {
            revert NoLockerFeeRecipients();
        }
        if (launchArgs.numTokensForRecipient > 0 && launchArgs.recipient == address(0)) revert LaunchInvalid();

        bytes32 tokenSalt = keccak256(abi.encodePacked(address(this), block.chainid, block.timestamp));

        uint256 tokenAdminId = TOKEN_ADMIN_ERC721.mint(
            erc20Args.name,
            erc20Args.image,
            msg.sender,
            Clones.predictDeterministicAddress(
                address(PARTY_ERC20_LOGIC), tokenSalt)
            );

        // Deploy new ERC20 token. Mints the total supply upfront to this contract.
        token = PartyERC20(
            address(PARTY_ERC20_LOGIC).cloneDeterministic(tokenSalt)
        );
        token.initialize(
            erc20Args.name,
            erc20Args.symbol,
            erc20Args.description,
            erc20Args.totalSupply,
            address(this),
            address(this),
            tokenAdminId
        );
        token.setPaused(true);

        // Initialize new launch.
        _initializeLaunch(token, tokenAdminId, launchArgs);

        // Initialize empty Uniswap pool. Will be liquid after launch is successful and finalized.
        address pool = _initializeUniswapPool(launchArgs.targetContribution - finalizationFee - flatLockFee);

        emit LaunchCreated(msg.sender, token, pool, erc20Args, launchArgs);
    }

    function _initializeLaunch(
        PartyERC20 _token,
        uint256 tokenAdminId,
        LaunchArgs memory launchArgs
    )
        private
    {
        token = _token;
        targetContribution = launchArgs.targetContribution;
        totalContributions = 0;
        maxContributionPerAddress = launchArgs.maxContributionPerAddress;
        numTokensForLP = launchArgs.numTokensForLP;
        numTokensForDistribution = launchArgs.numTokensForDistribution;
        numTokensForRecipient = launchArgs.numTokensForRecipient;
        merkleRoot = launchArgs.merkleRoot;
        recipient = launchArgs.recipient;
        finalizationFeeBps = launchArgs.finalizationFeeBps;
        withdrawalFeeBps = launchArgs.withdrawalFeeBps;
        lpInfo.partyTokenAdminId = tokenAdminId;

        uint16 totalAdditionalFeeRecipientsBps = 0;
        for (uint256 i = 0; i < launchArgs.lockerFeeRecipients.length; i++) {
            if (launchArgs.lockerFeeRecipients[i].recipient == address(0)) revert InvalidRecipient();
            lpInfo.additionalFeeRecipients.push(
                PartyLPLocker.AdditionalFeeRecipient({
                    recipient: launchArgs.lockerFeeRecipients[i].recipient,
                    percentageBps: launchArgs.lockerFeeRecipients[i].bps,
                    feeType: WETH < address(token) ? PartyLPLocker.FeeType.Token0 : PartyLPLocker.FeeType.Token1
                })
            );
            totalAdditionalFeeRecipientsBps += launchArgs.lockerFeeRecipients[i].bps;
        }
        if (totalAdditionalFeeRecipientsBps > 10_000) revert InvalidBps();
    }

    function updateAllowlist(bytes32 newMerkleRoot) external {
        // Check the launch is active
        if (_getLaunchLifecycle() != LaunchLifecycle.Active) {
            revert InvalidLifecycleState(_getLaunchLifecycle(), LaunchLifecycle.Active);
        }

        // Check the caller is the token admin
        uint256 tokenAdminId = lpInfo.partyTokenAdminId;
        address tokenAdmin = TOKEN_ADMIN_ERC721.ownerOf(tokenAdminId);
        if (msg.sender != tokenAdmin) revert OnlyAdmin(tokenAdmin);

        emit AllowlistUpdated(merkleRoot, newMerkleRoot);

        merkleRoot = newMerkleRoot;
    }

    function getLaunchLifecycle() public view returns (LaunchLifecycle) {
        return _getLaunchLifecycle();
    }

    function _getLaunchLifecycle() private view returns (LaunchLifecycle) {
        if (targetContribution == 0) {
            revert LaunchInvalid();
        } else if (totalContributions >= targetContribution) {
            return LaunchLifecycle.Finalized;
        } else {
            return LaunchLifecycle.Active;
        }
    }

    /**
     * @notice Contribute ETH to a launch and receive tokens.
     * @param tokenAddress Address of the token expected to be received.
     * @param comment Comment for the contribution.
     * @param merkleProof Merkle proof for the contribution.
     * @return tokensReceived Number of tokens received for the contribution.
     */
    function contribute(
        address tokenAddress,
        string calldata comment,
        bytes32[] calldata merkleProof
    )
        public
        payable
        returns (uint96 tokensReceived)
    {
        if (address(token) != tokenAddress) revert LaunchInvalid();

        // Verify merkle proof if merkle root is set
        if (merkleRoot != bytes32(0)) {
            bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
            if (!MerkleProof.verifyCalldata(merkleProof, merkleRoot, leaf)) revert InvalidMerkleProof();
        }

        tokensReceived = _contribute(msg.sender, msg.value.toUint96(), comment);
    }

    function _contribute(
        address contributor,
        uint96 amount,
        string memory comment
    )
        private
        returns (uint96)
    {
        LaunchLifecycle launchLifecycle = _getLaunchLifecycle();
        if (launchLifecycle != LaunchLifecycle.Active) {
            revert InvalidLifecycleState(launchLifecycle, LaunchLifecycle.Active);
        }
        if (amount == 0) revert ContributionZero();
        uint96 ethContributed = _convertTokensReceivedToETHContributed(
            uint96(token.balanceOf(contributor))
        );

        uint96 newTotalContributions = totalContributions + amount;
        uint96 excessContribution;
        if (newTotalContributions > targetContribution) {
            excessContribution = newTotalContributions - targetContribution;
            amount -= excessContribution;

            newTotalContributions = targetContribution;
        }

        if (ethContributed + amount > maxContributionPerAddress) {
            revert ContributionsExceedsMaxPerAddress(amount, ethContributed, maxContributionPerAddress);
        }

        // Update state
        totalContributions = newTotalContributions;

        uint96 tokensReceived =
            _convertETHContributedToTokensReceived(amount);

        emit Contribute(contributor, comment, amount, tokensReceived);

        // Check if the crowdfund has reached its target and finalize if necessary
        if (_getLaunchLifecycle() == LaunchLifecycle.Finalized) {
            _finalize();
        }

        // Transfer the tokens to the contributor
        token.transfer(contributor, tokensReceived);

        if (excessContribution > 0) {
            // Refund excess contribution
            (bool success,) = payable(contributor).call{ value: excessContribution, gas: 1e5 }("");
            if (!success) revert ETHTransferFailed(contributor, excessContribution);
        }

        return tokensReceived;
    }

    /**
     * @notice Convert ETH contributed to tokens received.
     * @param ethContributed Number of ETH contributed.
     * @return tokensReceived Number of tokens received for the contribution.
     */
    function convertETHContributedToTokensReceived(
        uint96 ethContributed
    )
        external
        view
        returns (uint96 tokensReceived)
    {
        tokensReceived = _convertETHContributedToTokensReceived(
            ethContributed
        );
    }

    /**
     * @notice Convert tokens received to ETH contributed.
     * @param tokensReceived Number of tokens received for the contribution.
     * @return ethContributed Number of ETH contributed.
     */
    function convertTokensReceivedToETHContributed(
        uint96 tokensReceived
    )
        external
        view
        returns (uint96 ethContributed)
    {
        ethContributed = _convertTokensReceivedToETHContributed(
            tokensReceived
        );
    }

    function _convertETHContributedToTokensReceived(
        uint96 ethContributed
    )
        private
        view
        returns (uint96 tokensReceived)
    {
        // tokensReceived = ethContributed * numTokensForDistribution / targetContribution
        // Use Math.mulDiv to avoid overflow doing math with uint96s, then safe cast uint256 result to uint96.
        tokensReceived = Math.mulDiv(ethContributed, numTokensForDistribution, targetContribution).toUint96();
    }

    function _convertTokensReceivedToETHContributed(
        uint96 tokensReceived
    )
        private
        view
        returns (uint96 ethContributed)
    {
        // tokensReceived = ethContributed * numTokensForDistribution / targetContribution
        // Use Math.mulDiv to avoid overflow doing math with uint96s, then safe cast uint256 result to uint96.
        ethContributed = Math.mulDiv(tokensReceived, targetContribution, numTokensForDistribution).toUint96();
    }

    function _finalize() private {
        uint96 finalizationFee = (targetContribution * finalizationFeeBps) / 1e4;
        uint96 flatLockFee = POSITION_LOCKER.getFlatLockFee();
        uint96 amountForPool = targetContribution - finalizationFee - flatLockFee;

        (address token0, address token1) =
            WETH < address(token) ? (WETH, address(token)) : (address(token), WETH);
        (uint256 amount0, uint256 amount1) = WETH < address(token)
            ? (amountForPool, numTokensForLP)
            : (numTokensForLP, amountForPool);

        // Add liquidity to the pool
        token.approve(address(POSITION_MANAGER), numTokensForLP);

        (uint256 tokenId,,,) = POSITION_MANAGER.mint{ value: amountForPool }(
            INonfungiblePositionManager.MintParams({
                token0: token0,
                token1: token1,
                fee: POOL_FEE,
                tickLower: MIN_TICK,
                tickUpper: MAX_TICK,
                amount0Desired: amount0,
                amount1Desired: amount1,
                amount0Min: amount0 * 9999 / 10_000,
                amount1Min: amount1 * 9999 / 10_000,
                recipient: address(this),
                deadline: block.timestamp
            })
        );

        // Transfer finalization fee to PartyDAO
        owner.call{ value: finalizationFee, gas: 1e5 }("");

        // Transfer tokens to recipient
        if (numTokensForRecipient > 0) {
            token.transfer(recipient, numTokensForRecipient);

            emit RecipientTransfer(token, recipient, numTokensForRecipient);
        }

        // Indicate launch succeeded
        TOKEN_ADMIN_ERC721.setLaunchSucceeded(lpInfo.partyTokenAdminId);

        // Unpause token
        token.setPaused(false);

        // Renounce ownership
        token.renounceOwnership();

        // Transfer flat fee to locker contract
        if (flatLockFee > 0) {
            payable(address(POSITION_LOCKER)).call{ value: flatLockFee, gas: 1e5 }("");
        }

        // Transfer LP to fee locker contract
        POSITION_MANAGER.safeTransferFrom(
            address(this), address(POSITION_LOCKER), tokenId, abi.encode(lpInfo, flatLockFee, token)
        );

        emit Finalized(token, tokenId, amountForPool);
    }

    function _initializeUniswapPool(uint96 amountForPool) private returns (address pool) {
        (uint256 amount0, uint256 amount1) = WETH < address(token)
            ? (amountForPool, numTokensForLP)
            : (numTokensForLP, amountForPool);

        pool = UNISWAP_FACTORY.createPool(address(token), WETH, POOL_FEE);
        IUniswapV3Pool(pool).initialize(_calculateSqrtPriceX96(amount0, amount1));
    }

    function _calculateSqrtPriceX96(uint256 amount0, uint256 amount1) private pure returns (uint160) {
        uint256 numerator = amount1 * 1e18;
        uint256 denominator = amount0;
        return uint160(Math.sqrt(numerator / denominator) * (2 ** 96) / 1e9);
    }

    /**
     * @notice Withdraw ETH contributed to a launch by `msg.sender`.
     * @param receiver Address to receive the ETH.
     * @return ethReceived Number of ETH received for the withdrawal.
     */
    function withdraw(address receiver) external returns (uint96 ethReceived) {
        LaunchLifecycle launchLifecycle = _getLaunchLifecycle();
        if (launchLifecycle != LaunchLifecycle.Active) {
            revert InvalidLifecycleState(launchLifecycle, LaunchLifecycle.Active);
        }

        uint96 tokensReceived = uint96(token.balanceOf(msg.sender));
        uint96 ethContributed = _convertTokensReceivedToETHContributed(tokensReceived);
        uint96 withdrawalFee = (ethContributed * withdrawalFeeBps) / 1e4;
        ethReceived = ethContributed - withdrawalFee;

        // Pull tokens from sender
        token.transferFrom(msg.sender, address(this), tokensReceived);

        // Update launch state
        totalContributions -= ethContributed;

        // Transfer withdrawal fee to PartyDAO
        owner.call{ value: withdrawalFee, gas: 1e5 }("");

        // Transfer ETH to sender
        (bool success,) = receiver.call{ value: ethReceived, gas: 1e5 }("");
        if (!success) revert ETHTransferFailed(receiver, ethReceived);

        emit Withdraw(msg.sender, tokensReceived, ethContributed, withdrawalFee);
    }

    /// @notice Handle ERC721 tokens received.
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    /**
     * @dev Returns the version of the contract. Decimal versions indicate change in logic. Number change indicates
     *      change in ABI.
     */
    function VERSION() external pure returns (string memory) {
        return "1.0.0";
    }
}

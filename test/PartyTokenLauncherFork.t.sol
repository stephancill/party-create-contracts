// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import "forge-std/src/Test.sol";

import "../src/PartyTokenLauncher.sol";
import "../src/PartyLPLocker.sol";
import {PartyLaunchFactory} from "../src/PartyLaunchFactory.sol";

contract PartyTokenLauncherForkTest is Test {
    PartyLaunchFactory launchFactory;
    PartyTokenLauncher launchImpl;
    PartyERC20 partyERC20Logic;
    PartyLPLocker lpLocker;
    IUNCX uncx;
    address payable partyDAO;
    INonfungiblePositionManager public positionManager;
    IUniswapV3Factory public uniswapFactory;
    address payable public weth;
    uint24 public poolFee;

    function setUp() public {
        positionManager = INonfungiblePositionManager(0x03a520b32C04BF3bEEf7BEb72E919cf822Ed34f1);
        uniswapFactory = IUniswapV3Factory(0x33128a8fC17869897dcE68Ed026d694621f6FDfD);
        weth = payable(positionManager.WETH9());
        poolFee = 3000;

        partyDAO = payable(vm.createWallet("Party DAO").addr);
        uncx = IUNCX(0x231278eDd38B00B07fBd52120CEf685B9BaEBCC1);
        lpLocker = new PartyLPLocker(address(this), positionManager, uncx);
        partyERC20Logic = new PartyERC20();
        launchImpl = new PartyTokenLauncher(
            partyDAO, partyERC20Logic, positionManager, uniswapFactory, weth, poolFee, lpLocker
        );
        launchFactory = new PartyLaunchFactory();
    }

    function testIntegration_launchLifecycle() public {
        address creator = vm.createWallet("Creator").addr;
        PartyTokenLauncher.LockerFeeRecipient[] memory lockerFeeRecipients =
            new PartyTokenLauncher.LockerFeeRecipient[](1);
        lockerFeeRecipients[0] = PartyTokenLauncher.LockerFeeRecipient({
            recipient: vm.createWallet("AdditionalLPFeeRecipient").addr,
            bps: 1e4
        });
        address contributor1 = vm.createWallet("Contributor1").addr;
        address contributor2 = vm.createWallet("Contributor2").addr;

        vm.deal(creator, 1 ether);
        vm.deal(contributor1, 1 ether);
        vm.deal(contributor2, 1 ether);

        // Step 1: Create a new launch
        PartyTokenLauncher.ERC20Args memory erc20Args = PartyTokenLauncher.ERC20Args({
            name: "TestToken",
            symbol: "TT",
            image: "test_image_url",
            description: "Test Description",
            totalSupply: 1_000_000_000e18
        });

        PartyTokenLauncher.LaunchArgs memory launchArgs = PartyTokenLauncher.LaunchArgs({
            numTokensForLP: 500_000_000e18,
            numTokensForDistribution: 300_000_000e18,
            numTokensForRecipient: 200_000_000e18,
            targetContribution: 10 ether,
            maxContributionPerAddress: 9 ether,
            merkleRoot: bytes32(0),
            recipient: vm.createWallet("Recipient").addr,
            finalizationFeeBps: 200, // 2%
            withdrawalFeeBps: 100, // 1%
            lockerFeeRecipients: lockerFeeRecipients
        });

        vm.prank(creator);
        PartyTokenLauncher launch = launchFactory.createLauncher(creator, launchImpl, erc20Args, launchArgs);
        
        vm.prank(creator);
        launch.contribute{value: 1 ether}("Test contribution", new bytes32[](0));

        uint96 expectedTotalContributions;
        uint96 expectedPartyDAOBalance;
        {
            uint96 expectedTokensReceived = launch.convertETHContributedToTokensReceived(1 ether);
            expectedTotalContributions += 1 ether;
            assertEq(launch.totalContributions(), expectedTotalContributions);
            assertEq(partyDAO.balance, expectedPartyDAOBalance);
            assertEq(launch.token().totalSupply(), erc20Args.totalSupply);
            assertEq(launch.token().balanceOf(creator), expectedTokensReceived);
            assertEq(launch.token().balanceOf(address(launch)), erc20Args.totalSupply - expectedTokensReceived);
        }

        // Step 2: Contribute to the launch
        vm.deal(contributor1, 5 ether);
        vm.prank(contributor1);
        launch.contribute{ value: 5 ether }("Contribution", new bytes32[](0));

        expectedTotalContributions += 5 ether;
        {
            uint96 expectedTokensReceived = launch.convertETHContributedToTokensReceived(5 ether);
            assertEq(launch.totalContributions(), expectedTotalContributions);
            assertEq(launch.token().balanceOf(contributor1), expectedTokensReceived);
            assertEq(partyDAO.balance, expectedPartyDAOBalance);
        }

        // Step 3: Withdraw from the launch
        {
            uint96 tokenBalance = uint96(launch.token().balanceOf(contributor1));
            vm.startPrank(contributor1);
            launch.token().approve(address(launch), tokenBalance);
            launch.withdraw(contributor1);
            vm.stopPrank();

            uint96 expectedETHReceived = launch.convertTokensReceivedToETHContributed(tokenBalance);
            expectedTotalContributions -= expectedETHReceived;
            uint96 withdrawalFee = expectedETHReceived * launchArgs.withdrawalFeeBps / 1e4;
            expectedPartyDAOBalance += withdrawalFee;
            assertEq(launch.token().balanceOf(contributor1), 0);
            assertEq(contributor1.balance, expectedETHReceived - withdrawalFee);
            assertEq(partyDAO.balance, expectedPartyDAOBalance);
        }

        // Step 4: Finalize the launch
        uint96 remainingContribution = launchArgs.targetContribution - expectedTotalContributions;
        vm.deal(contributor2, remainingContribution);
        vm.prank(contributor2);
        launch.contribute{ value: remainingContribution }("Final Contribution", new bytes32[](0));

        expectedTotalContributions += remainingContribution;
        {
            PartyTokenLauncher.LaunchLifecycle lifecycle = launch.getLaunchLifecycle();
            assertTrue(lifecycle == PartyTokenLauncher.LaunchLifecycle.Finalized);
        }
        {
            uint96 finalizationFee = launchArgs.finalizationFeeBps * launchArgs.targetContribution / 1e4;
            uint256 tokenUncxFee = uncx.getFee("LVP").lpFee * launchArgs.numTokensForLP / 1e4;
            uint256 wethUncxFee = uncx.getFee("LVP").lpFee * launchArgs.targetContribution / 1e4;
            expectedPartyDAOBalance += finalizationFee;
            address pool = uniswapFactory.getPool(address(launch.token()), weth, poolFee);
            assertApproxEqRel(launch.token().balanceOf(pool), launchArgs.numTokensForLP - tokenUncxFee, 0.001e18); // 0.01%
                // tolerance
            assertApproxEqRel(
                IERC20(weth).balanceOf(pool),
                launchArgs.targetContribution - finalizationFee - wethUncxFee - uncx.getFee("LVP").flatFee,
                0.001e18
            ); // 0.01% tolerance
        }
        {
            uint96 expectedTokensReceived = launch.convertETHContributedToTokensReceived(remainingContribution);
            assertEq(launch.totalContributions(), expectedTotalContributions);
            assertEq(launch.token().balanceOf(contributor2), expectedTokensReceived);
            assertEq(partyDAO.balance, expectedPartyDAOBalance);
            assertEq(launch.token().balanceOf(launchArgs.recipient), launchArgs.numTokensForRecipient);
            assertApproxEqAbs(launch.token().balanceOf(address(launch)), 0, 0.0001e18);
            assertEq(launch.launchSuccessful(), true);
        }
    }
}

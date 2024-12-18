// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import "forge-std/src/Test.sol";
import { WETH9 } from "./mock/WETH.t.sol";
import { MockUniswapV3Factory } from "./mock/MockUniswapV3Factory.t.sol";
import { MockUniswapNonfungiblePositionManager } from "./mock/MockUniswapNonfungiblePositionManager.t.sol";
import { MockUniswapV3Deployer } from "./mock/MockUniswapV3Deployer.t.sol";
import { MockUNCX, IUNCX } from "./mock/MockUNCX.t.sol";

import {PartyLaunchFactory} from "../src/PartyLaunchFactory.sol";
import "../src/PartyTokenLauncher.sol";

contract PartyTokenLauncherTest is Test, MockUniswapV3Deployer {
    event AllowlistUpdated(bytes32 oldMerkleRoot, bytes32 newMerkleRoot);

    PartyLaunchFactory launchFactory;
    PartyTokenLauncher launchImpl;
    PartyERC20 partyERC20Logic;
    address payable partyDAO;
    PartyLPLocker positionLocker;
    INonfungiblePositionManager public positionManager;
    IUniswapV3Factory public uniswapFactory;
    IUNCX public uncx;
    address payable public weth;
    address public launchToken;
    uint24 public poolFee;

    uint16 finalizationFeeBps = 100; // 1%
    uint16 partyDAOPoolFeeBps = 50; // 0.5%
    uint16 withdrawalFeeBps = 200; // 2%

    function setUp() public {
        MockUniswapV3Deployer.UniswapV3Deployment memory deploy = _deployUniswapV3();

        weth = deploy.WETH;
        uniswapFactory = IUniswapV3Factory(deploy.FACTORY);
        positionManager = INonfungiblePositionManager(deploy.POSITION_MANAGER);
        uncx = new MockUNCX();
        poolFee = 3000;

        partyDAO = payable(vm.createWallet("Party DAO").addr);
        positionLocker = new PartyLPLocker(address(this), positionManager, uncx);
        partyERC20Logic = new PartyERC20();
        launchImpl = new PartyTokenLauncher(
            partyDAO, partyERC20Logic, positionManager, uniswapFactory, weth, poolFee, positionLocker
        );
        launchFactory = new PartyLaunchFactory();
    }

    function test_constructor_works() public view {
        assertEq(address(launchImpl.owner()), partyDAO);
        assertEq(address(launchImpl.POSITION_MANAGER()), address(positionManager));
        assertEq(address(launchImpl.UNISWAP_FACTORY()), address(uniswapFactory));
        assertEq(address(launchImpl.WETH()), weth);
        assertEq(launchImpl.POOL_FEE(), poolFee);
        assertEq(address(launchImpl.POSITION_LOCKER()), address(positionLocker));
    }

    function test_createLaunch_works() public returns (PartyTokenLauncher launch, PartyERC20 token) {
        address creator = vm.createWallet("Creator").addr;
        address recipient = vm.createWallet("Recipient").addr;
        vm.deal(creator, 1 ether);

        PartyTokenLauncher.LockerFeeRecipient[] memory lockerFeeRecipients =
            new PartyTokenLauncher.LockerFeeRecipient[](1);
        lockerFeeRecipients[0] = PartyTokenLauncher.LockerFeeRecipient({
            recipient: vm.createWallet("AdditionalLPFeeRecipient").addr,
            bps: 1e4
        });

        PartyTokenLauncher.ERC20Args memory erc20Args = PartyTokenLauncher.ERC20Args({
            name: "NewToken",
            symbol: "NT",
            image: "image_url",
            description: "New Token Description",
            totalSupply: 1_000_000 ether
        });

        PartyTokenLauncher.LaunchArgs memory launchArgs = PartyTokenLauncher.LaunchArgs({
            numTokensForLP: 500_000 ether,
            numTokensForDistribution: 300_000 ether,
            numTokensForRecipient: 200_000 ether,
            targetContribution: 10 ether,
            maxContributionPerAddress: 8 ether,
            merkleRoot: bytes32(0),
            recipient: recipient,
            finalizationFeeBps: finalizationFeeBps,
            withdrawalFeeBps: withdrawalFeeBps,
            lockerFeeRecipients: lockerFeeRecipients
        });

        vm.prank(creator);
        launch = launchFactory.createLauncher(creator, launchImpl, erc20Args, launchArgs);
        token = launch.token();

        vm.prank(creator);
        launch.contribute{ value: 1 ether }("", new bytes32[](0));

        assertEq(launch.WETH(), weth);
        assertEq(launch.owner(), partyDAO);

        assertTrue(launch.getLaunchLifecycle() == PartyTokenLauncher.LaunchLifecycle.Active);

        uint96 expectedTokensReceived = launch.convertETHContributedToTokensReceived(1 ether);
        assertEq(launch.token().balanceOf(creator), expectedTokensReceived);
        assertEq(launch.token().totalSupply(), erc20Args.totalSupply);
        assertEq(creator.balance, 0);
    }

    function test_createLaunch_withFullContribution() public {
        address creator = vm.createWallet("Creator").addr;
        address recipient = vm.createWallet("Recipient").addr;
        vm.deal(creator, 10 ether);

        PartyTokenLauncher.LockerFeeRecipient[] memory lockerFeeRecipients =
            new PartyTokenLauncher.LockerFeeRecipient[](1);
        lockerFeeRecipients[0] = PartyTokenLauncher.LockerFeeRecipient({
            recipient: vm.createWallet("AdditionalLPFeeRecipient").addr,
            bps: 1e4
        });

        PartyTokenLauncher.ERC20Args memory erc20Args = PartyTokenLauncher.ERC20Args({
            name: "NewToken",
            symbol: "NT",
            image: "image_url",
            description: "New Token Description",
            totalSupply: 1_000_000 ether
        });

        PartyTokenLauncher.LaunchArgs memory launchArgs = PartyTokenLauncher.LaunchArgs({
            numTokensForLP: 500_000 ether,
            numTokensForDistribution: 300_000 ether,
            numTokensForRecipient: 200_000 ether,
            targetContribution: 10 ether,
            maxContributionPerAddress: 10 ether,
            merkleRoot: bytes32(0),
            recipient: recipient,
            finalizationFeeBps: finalizationFeeBps,
            withdrawalFeeBps: withdrawalFeeBps,
            lockerFeeRecipients: lockerFeeRecipients
        });

        vm.prank(creator);
        PartyTokenLauncher launch = launchFactory.createLauncher(creator, launchImpl, erc20Args, launchArgs);
        launch.contribute{ value: 10 ether }("", new bytes32[](0));

        assertTrue(launch.getLaunchLifecycle() == PartyTokenLauncher.LaunchLifecycle.Finalized);
    }

    function test_createLaunch_invalidFee() external {
        address creator = vm.createWallet("Creator").addr;
        address recipient = vm.createWallet("Recipient").addr;
        vm.deal(creator, 1 ether);

        PartyTokenLauncher.LockerFeeRecipient[] memory lockerFeeRecipients =
            new PartyTokenLauncher.LockerFeeRecipient[](1);
        lockerFeeRecipients[0] = PartyTokenLauncher.LockerFeeRecipient({
            recipient: vm.createWallet("AdditionalLPFeeRecipient").addr,
            bps: 1e4
        });

        PartyTokenLauncher.ERC20Args memory erc20Args = PartyTokenLauncher.ERC20Args({
            name: "NewToken",
            symbol: "NT",
            image: "image_url",
            description: "New Token Description",
            totalSupply: 1_000_000 ether
        });

        PartyTokenLauncher.LaunchArgs memory launchArgs = PartyTokenLauncher.LaunchArgs({
            numTokensForLP: 500_000 ether,
            numTokensForDistribution: 300_000 ether,
            numTokensForRecipient: 200_000 ether,
            targetContribution: 10 ether,
            maxContributionPerAddress: 8 ether,
            merkleRoot: bytes32(0),
            recipient: recipient,
            finalizationFeeBps: 251,
            withdrawalFeeBps: withdrawalFeeBps,
            lockerFeeRecipients: lockerFeeRecipients
        });

        vm.prank(creator);
        vm.expectRevert(PartyTokenLauncher.InvalidFee.selector);
        launchFactory.createLauncher(creator, launchImpl, erc20Args, launchArgs);

        launchArgs.finalizationFeeBps = 0;
        launchArgs.withdrawalFeeBps = 251;

        vm.prank(creator);
        vm.expectRevert(PartyTokenLauncher.InvalidFee.selector);
        launchFactory.createLauncher(creator, launchImpl, erc20Args, launchArgs);
    }

    function test_updateAllowlist_works() public {
        (PartyTokenLauncher launch,) = test_createLaunch_works();
        bytes32 newMerkleRoot = keccak256(abi.encodePacked("newMerkleRoot"));

        address tokenAdmin = launch.ownerOf(1);

        vm.expectEmit(true, true, true, true);
        emit AllowlistUpdated(bytes32(0), newMerkleRoot);

        vm.prank(tokenAdmin);
        launch.updateAllowlist(newMerkleRoot);

        assertEq(launch.merkleRoot(), newMerkleRoot);
    }

    function test_updateAllowlist_invalidLifecycle() public {
        (PartyTokenLauncher launch,) = test_finalize_works();
        bytes32 newMerkleRoot = keccak256(abi.encodePacked("newMerkleRoot"));

        address tokenAdmin = launch.ownerOf(1);

        vm.prank(tokenAdmin);
        vm.expectRevert(
            abi.encodeWithSelector(
                PartyTokenLauncher.InvalidLifecycleState.selector,
                PartyTokenLauncher.LaunchLifecycle.Finalized,
                PartyTokenLauncher.LaunchLifecycle.Active
            )
        );
        launch.updateAllowlist(newMerkleRoot);
    }

    function test_updateAllowlist_onlyAdmin() public {
        (PartyTokenLauncher launch,) = test_createLaunch_works();
        bytes32 newMerkleRoot = keccak256(abi.encodePacked("newMerkleRoot"));

        address nonAdmin = vm.createWallet("NonAdmin").addr;

        vm.prank(nonAdmin);
        vm.expectRevert(abi.encodeWithSelector(PartyTokenLauncher.OnlyAdmin.selector, vm.createWallet("Creator").addr));
        launch.updateAllowlist(newMerkleRoot);
    }

    function test_contribute_works() public {
        (PartyTokenLauncher launch, PartyERC20 token) = test_createLaunch_works();
        address contributor = vm.createWallet("Contributor").addr;
        vm.deal(contributor, 5 ether);

        vm.prank(contributor);
        launch.contribute{ value: 5 ether }("Adding funds", new bytes32[](0));

        uint96 expectedTokensReceived = launch.convertETHContributedToTokensReceived(5 ether);
        assertEq(token.balanceOf(contributor), expectedTokensReceived);
        assertEq(launch.totalContributions(), 6 ether);
        assertEq(contributor.balance, 0);
        assertEq(address(launch).balance, 6 ether);
    }

    function test_contribute_refundExcessContribution() public {
        (PartyTokenLauncher launch, PartyERC20 token) = test_createLaunch_works();
        // Total contribution: 1 ether

        address contributor = vm.createWallet("Contributor").addr;
        vm.deal(contributor, 2 ether);

        vm.prank(contributor);
        launch.contribute{ value: 2 ether }("", new bytes32[](0));
        // Total contribution: 3 ether

        address finalContributor = vm.createWallet("Final Contributor").addr;
        vm.deal(finalContributor, 8 ether);

        vm.prank(finalContributor);
        launch.contribute{ value: 8 ether }("", new bytes32[](0));
        // Total contribution: 10 ether (expect 1 ether refund)


        assertTrue(launch.getLaunchLifecycle() == PartyTokenLauncher.LaunchLifecycle.Finalized);
        assertEq(token.balanceOf(finalContributor), launch.convertETHContributedToTokensReceived(7 ether));
        assertEq(launch.totalContributions(), launch.targetContribution());
        assertEq(finalContributor.balance, 1 ether);
    }

    function test_contribute_maxContributionCheckAfterExcessDeduction() public {
        (PartyTokenLauncher launch, PartyERC20 token) = test_createLaunch_works();
        address creator = vm.createWallet("Creator").addr;
        vm.deal(creator, 1 ether);
        address contributor = vm.createWallet("Contributor").addr;
        vm.deal(contributor, 9 ether);

        // Contribute 1 ether so that 8 ether is required to finalize
        vm.prank(creator);
        launch.contribute{ value: 1 ether }("", new bytes32[](0));

        // Contribute 9 ether, which exceeds max contribution per address, but
        // should be accepted because 1 ether was refunded
        vm.prank(contributor);
        launch.contribute{ value: 9 ether }("", new bytes32[](0));

        assertEq(contributor.balance, 1 ether); // 1 ether should be refunded
    }

    function test_contribute_cannotExceedMaxContributionPerAddress() public {
        (PartyTokenLauncher launch, PartyERC20 token) = test_createLaunch_works();
        address contributor = vm.createWallet("Contributor").addr;
        vm.deal(contributor, 8 ether + 1);

        vm.prank(contributor);
        launch.contribute{ value: 8 ether }("", new bytes32[](0));

        vm.prank(contributor);
        vm.expectRevert(
            abi.encodeWithSelector(PartyTokenLauncher.ContributionsExceedsMaxPerAddress.selector, 1, 8 ether, 8 ether)
        );
        launch.contribute{ value: 1 }("", new bytes32[](0));
    }

    function test_withdraw_works() public {
        (PartyTokenLauncher launch, PartyERC20 token) = test_createLaunch_works();
        address creator = vm.createWallet("Creator").addr;

        uint96 tokenBalance = uint96(token.balanceOf(creator));

        vm.prank(creator);
        uint96 ethReceived = launch.withdraw(creator);

        uint96 expectedETHReturned = launch.convertTokensReceivedToETHContributed(tokenBalance);
        uint96 withdrawalFee = (expectedETHReturned * withdrawalFeeBps) / 10_000;
        assertEq(creator.balance, expectedETHReturned - withdrawalFee);
        assertEq(ethReceived, expectedETHReturned - withdrawalFee);
        assertEq(token.balanceOf(creator), 0);
        assertEq(partyDAO.balance, withdrawalFee);
        assertEq(launch.totalContributions(), 0);
    }

    function test_withdraw_differentReceiver() public {
        (PartyTokenLauncher launch, PartyERC20 token) = test_createLaunch_works();
        address creator = vm.createWallet("Creator").addr;
        address receiver = vm.createWallet("Receiver").addr;

        uint96 tokenBalance = uint96(token.balanceOf(creator));

        vm.prank(creator);
        uint96 ethReceived = launch.withdraw(receiver);

        uint96 expectedETHReturned = launch.convertTokensReceivedToETHContributed(tokenBalance);
        uint96 withdrawalFee = (expectedETHReturned * withdrawalFeeBps) / 10_000;
        assertEq(receiver.balance, expectedETHReturned - withdrawalFee);
        assertEq(ethReceived, expectedETHReturned - withdrawalFee);
        assertEq(creator.balance, 0);
    }

    function test_finalize_works() public returns (PartyTokenLauncher launch, PartyERC20 token) {
        (launch, token) = test_createLaunch_works();

        address contributor = vm.createWallet("Contributor").addr;
        vm.deal(contributor, 2 ether);
        vm.prank(contributor);
        launch.contribute{ value: 2 ether }("", new bytes32[](0));

        address contributor2 = vm.createWallet("Final Contributor").addr;

        uint96 remainingContribution = launch.targetContribution() - launch.totalContributions();
        vm.deal(contributor2, remainingContribution);

        vm.prank(contributor2);
        launch.contribute{ value: remainingContribution }("Finalize", new bytes32[](0));

        assertTrue(launch.getLaunchLifecycle() == PartyTokenLauncher.LaunchLifecycle.Finalized);

        uint96 expectedTokensReceived = launch.convertETHContributedToTokensReceived(remainingContribution);
        assertEq(token.balanceOf(contributor2), expectedTokensReceived);
        assertEq(launch.totalContributions(), launch.targetContribution());
        assertEq(contributor2.balance, 0);
        assertEq(token.balanceOf(address(launch)), 0);
        assertEq(address(launch).balance, 0);
        assertEq(launch.launchSuccessful(), true);
    }

    function test_createLaunch_tooMuchToAdditionalRecipients_invalidBps() external {
        address creator = vm.createWallet("Creator").addr;
        address recipient = vm.createWallet("Recipient").addr;
        vm.deal(creator, 1 ether);

        PartyTokenLauncher.LockerFeeRecipient[] memory lockerFeeRecipients =
            new PartyTokenLauncher.LockerFeeRecipient[](2);
        lockerFeeRecipients[0] = PartyTokenLauncher.LockerFeeRecipient({
            recipient: vm.createWallet("AdditionalLPFeeRecipient").addr,
            bps: 1e4
        });
        lockerFeeRecipients[1] = PartyTokenLauncher.LockerFeeRecipient({
            recipient: vm.createWallet("AdditionalLPFeeRecipient2").addr,
            bps: 9100
        });

        PartyTokenLauncher.ERC20Args memory erc20Args = PartyTokenLauncher.ERC20Args({
            name: "NewToken",
            symbol: "NT",
            image: "image_url",
            description: "New Token Description",
            totalSupply: 1_000_000 ether
        });

        PartyTokenLauncher.LaunchArgs memory launchArgs = PartyTokenLauncher.LaunchArgs({
            numTokensForLP: 500_000 ether,
            numTokensForDistribution: 300_000 ether,
            numTokensForRecipient: 200_000 ether,
            targetContribution: 10 ether,
            maxContributionPerAddress: 8 ether,
            merkleRoot: bytes32(0),
            recipient: recipient,
            finalizationFeeBps: finalizationFeeBps,
            withdrawalFeeBps: withdrawalFeeBps,
            lockerFeeRecipients: lockerFeeRecipients
        });

        vm.prank(creator);
        vm.expectRevert(PartyTokenLauncher.InvalidBps.selector);
        launchFactory.createLauncher(creator, launchImpl, erc20Args, launchArgs);
    }

    function test_constructor_invalidUniswapPoolFee() external {
        vm.expectRevert(PartyTokenLauncher.InvalidUniswapPoolFee.selector);
        new PartyTokenLauncher(
            partyDAO,
            partyERC20Logic,
            positionManager,
            uniswapFactory,
            weth,
            type(uint24).max,
            positionLocker
        );
    }

    function test_VERSION_works() public view {
        assertEq(launchImpl.VERSION(), "1.0.0");
    }

    function test_createLaunch_invalidRecipient() public {
        address creator = vm.createWallet("Creator").addr;
        address recipient = vm.createWallet("Recipient").addr;
        vm.deal(creator, 1 ether);

        PartyTokenLauncher.LockerFeeRecipient[] memory lockerFeeRecipients =
            new PartyTokenLauncher.LockerFeeRecipient[](1);
        lockerFeeRecipients[0] = PartyTokenLauncher.LockerFeeRecipient({ recipient: address(0), bps: 1e4 });

        PartyTokenLauncher.ERC20Args memory erc20Args = PartyTokenLauncher.ERC20Args({
            name: "NewToken",
            symbol: "NT",
            image: "image_url",
            description: "New Token Description",
            totalSupply: 1_000_000 ether
        });

        PartyTokenLauncher.LaunchArgs memory launchArgs = PartyTokenLauncher.LaunchArgs({
            numTokensForLP: 500_000 ether,
            numTokensForDistribution: 300_000 ether,
            numTokensForRecipient: 200_000 ether,
            targetContribution: 10 ether,
            maxContributionPerAddress: 8 ether,
            merkleRoot: bytes32(0),
            recipient: recipient,
            finalizationFeeBps: finalizationFeeBps,
            withdrawalFeeBps: withdrawalFeeBps,
            lockerFeeRecipients: lockerFeeRecipients
        });

        vm.prank(creator);
        vm.expectRevert(PartyTokenLauncher.InvalidRecipient.selector);
        launchFactory.createLauncher(creator, launchImpl, erc20Args, launchArgs);
    }
}

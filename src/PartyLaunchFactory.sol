// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.25;

import { Clones } from "@openzeppelin/contracts/proxy/Clones.sol";
import { PartyTokenLauncher } from "./PartyTokenLauncher.sol";

contract PartyLaunchFactory is Ownable, IERC721Receiver {
  using Clones for address;

  function createLauncher(
        PartyTokenLauncher launcherImpl,
        PartyTokenLauncher.ERC20Args memory erc20Args,
        PartyTokenLauncher.LaunchArgs memory launchArgs
    ) public payable returns (PartyTokenLauncher inst) {
        inst = PartyTokenLauncher(address(launcherImpl).clone());
        inst.initialize{ value: msg.value }(
            erc20Args, 
            launchArgs
        );
    }
}
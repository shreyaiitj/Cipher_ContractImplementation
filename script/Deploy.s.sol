// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/Contract.sol";

contract DeployCipher is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        CipherContract broker = new CipherContract(vm.addr(deployerPrivateKey));
        console.log("CipherContract deployed to:", address(broker));

        vm.stopBroadcast();
    }
}
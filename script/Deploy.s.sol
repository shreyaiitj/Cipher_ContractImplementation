// SPDX-License-Identifier: MIT 
// warning hatane ke liye use kiya hai good practice
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/ProviderRegistration.sol";
import "../src/ChannelManager.sol";
import "../src/ClaimTicket.sol";

contract DeployCipher is Script {
    
    // standard Foundry runner function
    function run() external { 
        // private key strictly env variables se hi load karni hai
        // Local storage me hardcode mat krna Varna directly fund gayab
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        // Broadcast start krte hi transactions live chain pr execute hone lagegi
        vm.startBroadcast(deployerPrivateKey);

        // Subse pehle registry banegi kyuki iska address baaki logo ko chahiye hoga
        ProviderRegistration registry = new ProviderRegistration();
        console.log("ProviderRegistration deployed to:", address(registry));

        // Registry pass krdi manager me mapping internally track krne ke liye
        ChannelManager channelManager = new ChannelManager(address(registry));
        console.log("ChannelManager deployed to:", address(channelManager));

        // Complex dynamic multi-contract dependency initialization boundary
        ClaimTicket lottery = new ClaimTicket(address(channelManager), address(registry));
        console.log("ClaimTicket deployed to:", address(lottery));

        // Cross-linking logic link krne ke baad state update check hoga
        // Yeh line bhool gye toh channel manager access nahi dega ticket claimer ko
        channelManager.setClaimTicket(address(lottery));

        // Broadcast stop krne ke baad logs me transactions bhejne ke liye ready hai
        vm.stopBroadcast();
    }
}
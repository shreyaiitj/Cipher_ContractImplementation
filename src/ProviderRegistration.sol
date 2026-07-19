// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ProviderRegistration{
    error AlreadyRegistered();
    error NotRegistered();
    // Custom errors are cheaper than require strings
    error InvalidStake();
    error ZeroAmount();
    error TransferFailed();

    // compilation time pe pata hai toh strictly constant hi use krna ex hardcoded values constant cheaper than immutable
    uint256 public constant minStake = 10 ether;

    // constructor me assign hogi value aur change nahi kr skte baadme uske liye use immutable
    address public immutable owner;

    struct ProviderCred{
        uint128 stake;
        bool registered;
    }

    mapping(address => ProviderCred) public providers;

    event ProviderRegistered(address indexed provider, uint256 stake);
    event StakeAdded(address indexed provider, uint256 amount);
    event ProviderUnregistered(address indexed provider, uint256 stake);
    event Slashed(address indexed provider, uint256 amount, address indexed to);

    constructor(){
        owner = msg.sender; // Deployer automatically becomes owner
    }

    modifier onlyOwner(){
        require(msg.sender == owner, "Not owner");
        _;
    }

    function registerProvider() external payable {
        // Double entry block condition
        if (providers[msg.sender].registered) revert AlreadyRegistered();
        if (msg.value < minStake) revert InvalidStake();

        providers[msg.sender] = ProviderCred({
            stake: uint128(msg.value),
            registered: true
        });
        emit ProviderRegistered(msg.sender, msg.value);
    }

    function unregisterProvider() external{
        ProviderCred storage p = providers[msg.sender];
        if (!p.registered) revert NotRegistered();
        uint256 amount = p.stake;
        // reset krne ke baad log me bhejne ke liye state instantly wiped out
        delete providers[msg.sender];
        // FAMOUS ETH TRANSFER PATTERN
        // Low- level call forwarded with modern error catch handles
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit ProviderUnregistered(msg.sender, amount);
    }

    function slash(address provider, uint256 amount, address to) external onlyOwner {
        // Zero address check strictly mandatory taaki fund dead wallet me na jaye
        require(provider != address(0) && to != address(0), "Invalid address");
        ProviderCred storage p = providers[provider];
        if (!p.registered) revert NotRegistered();
        // Ternary check logic applied to prevent subtraction underflow crashes
        uint256 slashAmount = amount > p.stake ? p.stake : amount;
        require(slashAmount > 0, "Nothing to slash");
        // Bookkeeping balance updates calculated safely
        p.stake = uint128(p.stake - slashAmount);
        (bool ok, ) = to.call{value: slashAmount}("");
        require(ok, "Slash transfer failed");
        emit Slashed(provider, slashAmount, to);
    }

    // View Helpers
    // Zero processing logic just returns storage states for off chain readers
    function isRegistered(address provider) external view returns (bool) {
        return providers[provider].registered;
    }

    function stakeOf(address provider) external view returns (uint256) {
        return providers[provider].stake;
    }
}
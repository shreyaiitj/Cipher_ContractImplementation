// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./ProviderRegistration.sol";

contract ChannelManager is ReentrancyGuard {

    // Custom errors
    error ChannelNotFound();
    error NotChannelParty();
    error InvalidProvider();
    error InvalidAmount();
    error ChannelClosed();
    error InsufficientFunds();
    error NotTicketLottery();

    // Registry me changes nahi krne honge deploy hone ke baad, immutable optimized
    ProviderRegistration public immutable registry;
    address public ticketLottery;
    address public immutable deployer;

    // Direct channel registration index pointer variable
    uint256 public nextChannelId = 1;

    struct Channel{
        address client;
        address provider;
        uint128 deposit;
        uint128 spent;
        uint64 openedAt;
        bool closed;
    }

    mapping(uint256 => Channel) public channels;

    event ChannelOpened(uint256 indexed channelId, address indexed client, address indexed provider, uint256 deposit);
    event ChannelFunded(uint256 indexed channelId, uint256 amount);
    event ChannelClosedEvt(uint256 indexed channelId, address indexed client, uint256 refunded);
    event ChannelSpent(uint256 indexed channelId, uint256 amount);
    event ChannelPaid(uint256 indexed channelId, address indexed provider, uint256 amount);

    constructor(address registryAddr){
        registry = ProviderRegistration(registryAddr);
        deployer = msg.sender;
    }

    modifier onlyTicketLottery(){
        if (msg.sender != ticketLottery) revert NotTicketLottery();
        _;
    }

    // Called by deployer to set the lottery contract
    function setTicketLottery(address _ticketLottery) external {
        require(msg.sender == deployer, "Only deployer");
        // Ek baar register hone ke baad, koi overwrite nahi kar sakta
        require(ticketLottery == address(0), "Already set");
        ticketLottery = _ticketLottery;
    }

    function openChannel(address provider) external payable nonReentrant returns (uint256 channelId) {

        // Validation patterns to check provider status first
        if (!registry.isRegistered(provider)) revert InvalidProvider();
        require(msg.value > 0, "Deposit required");

        channelId = nextChannelId++;

        // Gas optimizing strict casting applied to time bounds and value arrays
        channels[channelId] = Channel({
            client: msg.sender,
            provider: provider,
            deposit: uint128(msg.value),
            spent: 0,
            openedAt: uint64(block.timestamp),
            closed: false
        });

        emit ChannelOpened(channelId, msg.sender, provider, msg.value);
    }

    function topUpChannel(uint256 channelId) external payable nonReentrant {
        Channel storage c = channels[channelId];

        // Zero address tracking block pattern applied to catch those dead structs
        if (c.client == address(0)) revert ChannelNotFound();
        if (c.closed) revert ChannelClosed();

        require(msg.sender == c.client, "Only client can top up");
        require(msg.value > 0, "Amount required");

        // storage variable manipulation logic execution
        c.deposit += uint128(msg.value);
        emit ChannelFunded(channelId, msg.value);
    }

    function closeChannel(uint256 channelId) external nonReentrant {
        Channel storage c = channels[channelId];
        if (c.client == address(0)) revert ChannelNotFound();
        if (c.closed) revert ChannelClosed();
        require(msg.sender == c.client || msg.sender == c.provider, "Not a party");
        // Lock condition applied before state transfers to prevent potential reentrancy overlaps
        c.closed = true;
        uint256 remaining = c.deposit - c.spent;
        if (remaining > 0) {
            (bool ok, ) = c.client.call{value: remaining}("");
            require(ok, "Refund failed");
        }
        // reset krne ke baad log me bhejne ke liye data packaging complete
        emit ChannelClosedEvt(channelId, c.client, remaining);
    }

    // Called only by TicketLottery to deduct spent funds
    function markSpent(uint256 channelId, uint256 amount) external onlyTicketLottery {
        Channel storage c = channels[channelId];
        if (c.client == address(0)) revert ChannelNotFound();
        if (c.closed) revert ChannelClosed();

        // Overflow safety assertion constraint matrix:
        if (c.spent + amount > c.deposit) revert InsufficientFunds();

        c.spent += uint128(amount);
        emit ChannelSpent(channelId, amount);
    }

    // Called only by TicketLottery to pay the provider from the channel
    function payProvider(uint256 channelId, uint256 amount) external onlyTicketLottery nonReentrant {
        Channel storage c = channels[channelId];
        if (c.client == address(0)) revert ChannelNotFound();
        if (c.closed) revert ChannelClosed();

        if (c.spent + amount > c.deposit) revert InsufficientFunds();

        c.spent += uint128(amount);

        (bool ok, ) = c.provider.call{value: amount}("");
        require(ok, "Payout failed");

        emit ChannelPaid(channelId, c.provider, amount);
    }

    // View Helpers
    function spendable(uint256 channelId) external view returns (uint256) {
        Channel storage c = channels[channelId];
        if (c.client == address(0)) return 0;
        return uint256(c.deposit - c.spent);
    }

    function getChannel(uint256 channelId)
        external
        view
        returns (
            address client,
            address provider,
            uint256 deposit,
            uint256 spent,
            uint256 openedAt,
            bool closed
        )
    {
        Channel storage c = channels[channelId];
        return (c.client, c.provider, c.deposit, c.spent, c.openedAt, c.closed);
    }
}
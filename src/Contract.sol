// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract CipherContract is ReentrancyGuard {

    // --- State Variables ---
    uint256 public constant minStake = 1 ether; // Kam se kam 1 ETH stake required hai
    uint256 public constant probabDenom = 100; // Probability base range check ke liye
    uint256 public constant blockLookback = 256; // EVM limit of blockhash lookup
    uint256 public constant maxTicketPct = 25; // Single ticket payout limit (25% of balance)
    uint64 public constant unbondingPeriod = 7200; // Unstake lock time (~1 day)
    uint64 public constant disputePeriod = 3600; // Channel closure dispute timer (12 hours)

    // --- Custom Errors (Gas saver exceptions) ---
    error AlreadyRegistered();      // Provider already registered error
    error NotRegistered();          // Provider not registered error
    error InvalidStake();           // Stake deposit 1 ETH se kam hone par
    error ZeroAmount();             // Zero value transaction request par
    error TransferFailed();         // ETH transfer fail custom exception
    error ChannelNotFound();        // Invalid channel lookup
    error ChannelLocked();          // Claims locked after exit timer
    error NotChannelParty();        // Unauthorised access request
    error InsufficientBalance();    // Channel limits exceeded
    error TicketUsed();             // Ticket replay protection
    error BadSigner();              // Invalid client signature
    error SaltNotRevealed();        // Salt commitment reveal verification fail
    error InvalidBlock();           // Blockhash range out of limits (lookback)
    error SaltCommittedTooLate();   // Salt commit post target block mining
    error TicketExceedsLimit();     // Max 25% claim exceeded
    error WinProbabTooHigh();       // Probab parameters incorrect
    error NoPendingWithdrawal();    // Pull payout wallet empty

    struct Provider {
        uint256 stake;              // Locked stake amount
        uint64 unstakeBlock;        // Block number jab stake unlock hoga
        bool registered;            // Actively registered flag
    }

    struct Channel {
        uint256 deposit;            // Total client deposit
        uint256 spent;              // Total approved spent
        uint64 unlockBlock;         // Unlock block height timer
        uint64 closureRequestedAt;  // Block close request blockheight
        bool closureInitiated;      // Close process active
    }

    struct Ticket {
        uint256 channelId;          // Active payment channel ID
        address client;             // Signer client address
        address provider;           // Recipient provider address
        uint256 amount;             // Payout payout value
        uint256 nonce;              // Replay check serial
        uint256 futureBlock;        // Entropy target block
        uint256 winProbab;          // Probability boundary (win threshold)
        bytes32 saltCommit;         // Salt commit hash
    }

    mapping(address => Provider) public providers; // Address to Provider record map
    uint256 public nextChannelId = 1; // Counter for next channel ID
    mapping(uint256 => Channel) public channels; // ID to Channel record map
    mapping(uint256 => address) public channelClient; // Channel client mapping
    mapping(uint256 => address) public channelProvider; // Channel provider mapping
    mapping(bytes32 => bool) public usedNullifiers; // Replay prevention tracking index
    mapping(bytes32 => address) public saltOwner; // Salt commit address tracker
    mapping(bytes32 => bytes32) public saltRevealed; // Salt pre-image reveal record
    mapping(bytes32 => uint256) public saltCommitBlock; // Block height of salt commitment
    mapping(address => uint256) public pendingWithdrawals; // Pull-payment mapping for providers
    address public owner; // Owner address for admin operations
    address public treasury; // Treasury wallet to receive slashed funds

    event ProviderRegistered(address indexed provider, uint256 stake);
    event UnstakeRequested(address indexed provider, uint256 stake);
    event ProviderWithdrawn(address indexed provider, uint256 stake);
    event ProviderSlashed(address indexed provider, uint256 amount, address indexed to);
    event ChannelOpened(uint256 indexed channelId, address indexed client, address indexed provider, uint256 deposit);
    event ChannelClosed(uint256 indexed channelId, address indexed client, uint256 refunded);
    event ChannelPaid(uint256 indexed channelId, address indexed provider, uint256 amount);
    event SaltCommitted(bytes32 indexed saltCommit, address indexed provider);
    event SaltRevealed(bytes32 indexed saltCommit, bytes32 salt);
    event TicketClaimed(bytes32 indexed nullifier, uint256 indexed channelId, address indexed provider, uint256 amount, bool won);
    event TicketLost(bytes32 indexed nullifier, uint256 indexed channelId, address indexed provider, uint256 amount);
    event WithdrawalPending(address indexed recipient, uint256 amount);

    constructor(address _treasury) {
        owner = msg.sender;
        treasury = _treasury;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner"); // Admin control verification
        _;
    }

    // --- Provider Registration Functions ---
    function registerProvider() external payable { // Stake deposit lock to register
        Provider storage p = providers[msg.sender];
        if (p.registered) revert AlreadyRegistered();
        if (msg.value < minStake) revert InvalidStake();
        p.stake = msg.value;
        p.registered = true;
        p.unstakeBlock = 0;
        emit ProviderRegistered(msg.sender, msg.value);
    }

    function requestUnstake() external { // Request unstake to initiate waiting lock
        Provider storage p = providers[msg.sender];
        if (!p.registered) revert NotRegistered();
        if (p.unstakeBlock != 0) revert("Already unbonding");
        p.unstakeBlock = uint64(block.number + unbondingPeriod);
        emit UnstakeRequested(msg.sender, p.stake);
    }

    function withdrawStake() external nonReentrant { // Retrieve stake post wait duration
        Provider storage p = providers[msg.sender];
        if (p.unstakeBlock == 0) revert("Not unbonding");
        if (block.number < p.unstakeBlock) revert("Unbonding not complete");
        uint256 amount = p.stake;
        p.stake = 0;
        p.unstakeBlock = 0;
        p.registered = false;
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit ProviderWithdrawn(msg.sender, amount);
    }

    function slashProvider(address provider, uint256 amount) external onlyOwner { // Slash stake for misbehaviour
        Provider storage p = providers[provider];
        if (!p.registered) revert NotRegistered();
        uint256 slashAmount = amount > p.stake ? p.stake : amount;
        p.stake -= slashAmount;
        if (p.stake == 0) {
            p.registered = false;
        }
        (bool ok, ) = treasury.call{value: slashAmount}("");
        if (!ok) revert TransferFailed();
        emit ProviderSlashed(provider, slashAmount, treasury);
    }

    function isProvider(address provider) external view returns (bool) {
        return providers[provider].registered;
    }

    function stakeOf(address provider) external view returns (uint256) {
        return providers[provider].stake;
    }

    // --- Channel Management Functions ---
    function openChannel(address provider) external payable nonReentrant { // Open channel and deposit collateral
        if (!providers[provider].registered) revert NotRegistered();
        if (msg.value == 0) revert ZeroAmount();
        uint256 id = nextChannelId++;
        channelClient[id] = msg.sender;
        channelProvider[id] = provider;
        channels[id] = Channel({
            deposit: msg.value,
            spent: 0,
            unlockBlock: 0,
            closureRequestedAt: 0,
            closureInitiated: false
        });
        emit ChannelOpened(id, msg.sender, provider, msg.value);
    }

    function closeChannel(uint256 channelId) external nonReentrant { // Request channel closure with safety locks
        Channel storage c = channels[channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.closureInitiated) revert ChannelLocked();
        if (msg.sender != channelClient[channelId] && msg.sender != channelProvider[channelId]) {
            revert NotChannelParty();
        }
        c.closureInitiated = true;
        c.closureRequestedAt = uint64(block.number);
        c.unlockBlock = uint64(block.number + unbondingPeriod + disputePeriod);
    }

    function withdrawChannel(uint256 channelId) external nonReentrant { // Reclaim remaining funds after unlock
        Channel storage c = channels[channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (!c.closureInitiated) revert("Channel not closing");
        if (block.number < c.unlockBlock) revert("Unbonding not complete");
        if (msg.sender != channelClient[channelId]) revert NotChannelParty();
        uint256 remaining = c.deposit - c.spent;
        c.deposit = 0;
        c.closureInitiated = false;
        (bool ok, ) = msg.sender.call{value: remaining}("");
        if (!ok) revert TransferFailed();
        emit ChannelClosed(channelId, msg.sender, remaining);
    }

    function _payProvider(uint256 channelId, uint256 amount) internal { // Record payout balance internally
        Channel storage c = channels[channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.closureInitiated && block.number >= c.unlockBlock) revert ChannelLocked();
        if (c.spent + amount > c.deposit) revert InsufficientBalance();
        c.spent += amount;
        address provider = channelProvider[channelId];
        pendingWithdrawals[provider] += amount;
        emit ChannelPaid(channelId, provider, amount);
        emit WithdrawalPending(provider, amount);
    }

    function withdrawPending() external nonReentrant { // Provider withdraws accumulated payouts
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert NoPendingWithdrawal();
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    // --- Randomness Commit-Reveal Logic ---
    function commitSalt(bytes32 commit) external { // Register salt commit before target block
        if (saltOwner[commit] != address(0)) revert("Already committed");
        saltOwner[commit] = msg.sender;
        saltCommitBlock[commit] = block.number;
        emit SaltCommitted(commit, msg.sender);
    }

    function revealSalt(bytes32 commit, bytes32 salt) external { // Reveal salt pre-image after target block
        if (saltOwner[commit] != msg.sender) revert("Not the committer");
        if (saltRevealed[commit] != bytes32(0)) revert("Already revealed");
        if (keccak256(abi.encodePacked(salt)) != commit) {
            revert("Hash mismatch");
        }
        saltRevealed[commit] = salt;
        emit SaltRevealed(commit, salt);
    }

    function getHash(Ticket calldata ticket) public view returns (bytes32) { // Hashing EIP-191 payload structure
        bytes32 h = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                ticket.channelId,
                ticket.client,
                ticket.provider,
                ticket.amount,
                ticket.nonce,
                ticket.futureBlock,
                ticket.winProbab,
                ticket.saltCommit
            )
        );
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    function _getNullifier(Ticket calldata ticket) internal view returns (bytes32) { // Generate ticket uniqueness key
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                ticket.channelId,
                ticket.client,
                ticket.provider,
                ticket.amount,
                ticket.nonce,
                ticket.futureBlock
            )
        );
    }

    function _recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) { // Parse signature to extract client
        if (sig.length != 65) revert BadSigner();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert BadSigner();
        }
        if (v != 27 && v != 28) revert BadSigner();
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert BadSigner();
        return signer;
    }

    // --- claimTicket: Main Settlement Logic ---
    function claimTicket(Ticket calldata ticket, bytes calldata sig) external nonReentrant { // Verify and settle wins
        bytes32 nullifier = _getNullifier(ticket); // Retrieve ticket uniqueness nullifier
        if (usedNullifiers[nullifier]) revert TicketUsed();
        if (ticket.amount == 0) revert ZeroAmount();
        if (ticket.winProbab == 0 || ticket.winProbab > probabDenom) revert WinProbabTooHigh();

        Channel storage c = channels[ticket.channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.closureInitiated && block.number >= c.unlockBlock) revert ChannelLocked();

        address client = channelClient[ticket.channelId];
        address provider = channelProvider[ticket.channelId];
        if (client != ticket.client) revert("Client mismatch");
        if (provider != ticket.provider) revert("Provider mismatch");
        if (!providers[ticket.provider].registered) revert NotRegistered();

        bytes32 hash = getHash(ticket); // Validate off-chain client signature
        address signer = _recoverSigner(hash, sig);
        if (signer != ticket.client) revert BadSigner();

        if (block.number <= ticket.futureBlock) revert("Block not mined yet"); // Check block height parameters
        if (block.number > ticket.futureBlock + blockLookback) {
            revert InvalidBlock();
        }
        bytes32 bh = blockhash(ticket.futureBlock);
        if (bh == bytes32(0)) revert("Missing blockhash");

        bytes32 salt = saltRevealed[ticket.saltCommit]; // Verify salt commitment
        if (salt == bytes32(0)) revert SaltNotRevealed();
        if (saltCommitBlock[ticket.saltCommit] >= ticket.futureBlock) {
            revert SaltCommittedTooLate();
        }
        if (saltOwner[ticket.saltCommit] != ticket.provider) {
            revert("Salt not from provider");
        }

        uint256 available = c.deposit - c.spent; // Verification payout limits (max 25%)
        uint256 maxAllowed = (available * maxTicketPct) / 100;
        if (ticket.amount > maxAllowed) revert TicketExceedsLimit();

        bytes32 entropy = keccak256(abi.encodePacked(bh, salt, nullifier)); // Generate secure unpredictability outcome
        bool won = (uint256(entropy) % probabDenom) < ticket.winProbab;
        usedNullifiers[nullifier] = true; // Consume ticket (Jeete ya Haare double claim block hoga)

        if (won) {
            _payProvider(ticket.channelId, ticket.amount);
        } else {
            emit TicketLost(nullifier, ticket.channelId, ticket.provider, ticket.amount);
        }

        emit TicketClaimed(nullifier, ticket.channelId, ticket.provider, ticket.amount, won);
    }

    function getChannel(uint256 channelId) external view returns (address client, address provider, uint256 deposit, uint256 spent, uint256 unlockBlock, bool closureInitiated) {
        Channel storage c = channels[channelId];
        return (channelClient[channelId], channelProvider[channelId], c.deposit, c.spent, c.unlockBlock, c.closureInitiated);
    }

    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    function getSalt(bytes32 commit) external view returns (bytes32) {
        return saltRevealed[commit];
    }

    function getSaltCommitBlock(bytes32 commit) external view returns (uint256) {
        return saltCommitBlock[commit];
    }

    function channelBalance(uint256 channelId) external view returns (uint256) {
        Channel storage c = channels[channelId];
        return c.deposit - c.spent;
    }

    function getPendingWithdrawal(address provider) external view returns (uint256) {
        return pendingWithdrawals[provider];
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CipherContract {

    // Constants

    // Minimum stake required to register as a provider.
    uint256 public constant minStake = 1 ether;

    // Denominator for probability calculations (1% granularity).
    uint256 public constant probabDenom = 100;

    // Maximum number of blocks Ethereum stores blockhash for.
    uint256 public constant blockLookback = 256;

    // Maximum percentage of channel balance a single ticket can claim.
    uint256 public constant maxTicketPct = 25;

    // Unbonding period for provider stakes and channel closures (~1 day).
    uint64 public constant unbondingPeriod = 7200;

    // Custom Errors

    error AlreadyRegistered();
    error NotRegistered();
    error InvalidStake();
    error ZeroAmount();
    error TransferFailed();
    error ChannelNotFound();
    error ChannelLocked();
    error NotChannelParty();
    error InsufficientBalance();
    error TicketUsed();
    error BadSigner();
    error SaltNotRevealed();
    error InvalidBlock();
    error SaltCommittedTooLate();
    error TicketExceedsLimit();
    error WinProbabTooHigh();
    error ReentrancyGuardReentrantCall();

    // Transient Storage Reentrancy Guard (EIP-1153)

    // We use transient storage for the reentrancy guard because it's
    // cheaper than persistent storage. The guard is set at the start
    // of a guarded function and cleared at the end.
    bytes32 private constant reentrancyGuardSlot =
        keccak256("cipher.reentrancy.guard");

    modifier nonReentrant() {
        bytes32 slot = reentrancyGuardSlot;
        assembly {
            if tload(slot) {
                mstore(0x00, 0x37ed32e8)
                revert(0x1c, 0x04)
            }
            tstore(slot, 1)
        }
        _;
        assembly {
            tstore(slot, 0)
        }
    }

    // Structs

    // Provider state tracking stake amount, unstake release window, and registration flag.
    struct Provider {
        uint256 stake;
        uint64 unstakeBlock;
        bool registered;
    }

    // Payment channel state tracking client deposits, claims paid, and exit timelock.
    struct Channel {
        uint256 deposit;
        uint256 spent;
        uint64 unlockBlock;
    }

    // Ticket payload signed by the client for probabilistic payments.
    struct Ticket {
        uint256 channelId;
        address client;
        address provider;
        uint256 amount;
        uint256 nonce;
        uint256 futureBlock;
        uint256 winProbab;
        bytes32 saltCommit;
    }

    // Storage

    // Provider registry map
    mapping(address => Provider) public providers;

    // Payment channel storage
    uint256 public nextChannelId = 1;
    mapping(uint256 => Channel) public channels;
    mapping(uint256 => address) public channelClient;
    mapping(uint256 => address) public channelProvider;

    // Nullifier map prevents the same ticket from being claimed twice
    mapping(bytes32 => bool) public usedNullifiers;

    // Commit-reveal state for entropy generation
    mapping(bytes32 => address) public saltOwner;
    mapping(bytes32 => bytes32) public saltRevealed;
    mapping(bytes32 => uint256) public saltCommitBlock;

    // Events

    event ProviderRegistered(address indexed provider, uint256 stake);
    event ProviderUnregistered(address indexed provider, uint256 stake);
    event ProviderSlashed(address indexed provider, uint256 amount);
    event ChannelOpened(
        uint256 indexed channelId,
        address indexed client,
        address indexed provider,
        uint256 deposit
    );
    event ChannelClosed(
        uint256 indexed channelId,
        address indexed client,
        uint256 refunded
    );
    event ChannelPaid(
        uint256 indexed channelId,
        address indexed provider,
        uint256 amount
    );
    event SaltCommitted(bytes32 indexed saltCommit, address indexed provider);
    event SaltRevealed(bytes32 indexed saltCommit, bytes32 salt);
    event TicketClaimed(
        bytes32 indexed nullifier,
        uint256 indexed channelId,
        address indexed provider,
        uint256 amount,
        bool won
    );

    // Provider Registration Logic

    // Register as a provider by staking ETH.
    // The stake acts as a security bond that can be slashed for misbehaviour.
    function registerProvider() external payable {
        Provider storage p = providers[msg.sender];
        if (p.registered) revert AlreadyRegistered();
        if (msg.value < minStake) revert InvalidStake();

        p.stake = msg.value;
        p.registered = true;
        p.unstakeBlock = 0;

        emit ProviderRegistered(msg.sender, msg.value);
    }

    // Request to unregister as a provider.
    // The stake enters an unbonding period before it can be withdrawn.
    function requestUnstake() external {
        Provider storage p = providers[msg.sender];
        if (!p.registered) revert NotRegistered();
        if (p.unstakeBlock != 0) revert("Already unbonding");

        p.unstakeBlock = uint64(block.number + unbondingPeriod);
        p.registered = false;

        emit ProviderUnregistered(msg.sender, p.stake);
    }

    // Withdraw the stake after the unbonding period has completed.
    function withdrawStake() external nonReentrant {
        Provider storage p = providers[msg.sender];
        if (p.unstakeBlock == 0) revert("Not unbonding");
        if (block.number < p.unstakeBlock) revert("Unbonding not complete");

        uint256 amount = p.stake;
        p.stake = 0;
        p.unstakeBlock = 0;

        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit ProviderUnregistered(msg.sender, amount);
    }

    // Slash a provider's stake for misbehaviour.
    function slashProvider(address provider, uint256 amount) external {
        Provider storage p = providers[provider];
        if (!p.registered) revert NotRegistered();

        uint256 slashAmount = amount > p.stake ? p.stake : amount;
        p.stake -= slashAmount;

        if (p.stake == 0) {
            p.registered = false;
        }

        (bool ok, ) = msg.sender.call{value: slashAmount}("");
        if (!ok) revert TransferFailed();

        emit ProviderSlashed(provider, slashAmount);
    }

    // Check if an address is a registered provider.
    function isProvider(address provider) external view returns (bool) {
        return providers[provider].registered;
    }

    // Get a provider's current stake.
    function stakeOf(address provider) external view returns (uint256) {
        return providers[provider].stake;
    }

    // Channel Management Logic

    // Open a payment channel with a registered provider.
    function openChannel(address provider) external payable nonReentrant {
        if (!providers[provider].registered) revert NotRegistered();
        if (msg.value == 0) revert ZeroAmount();

        uint256 id = nextChannelId++;
        channelClient[id] = msg.sender;
        channelProvider[id] = provider;

        channels[id] = Channel({
            deposit: msg.value,
            spent: 0,
            unlockBlock: 0
        });

        emit ChannelOpened(id, msg.sender, provider, msg.value);
    }

    // Top up an existing channel with more funds.
    function topUpChannel(uint256 channelId) external payable nonReentrant {
        Channel storage c = channels[channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.unlockBlock != 0) revert ChannelLocked();
        if (msg.sender != channelClient[channelId]) revert NotChannelParty();
        if (msg.value == 0) revert ZeroAmount();

        c.deposit += msg.value;
    }

    // Initiate closure of a payment channel.
    function closeChannel(uint256 channelId) external nonReentrant {
        Channel storage c = channels[channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.unlockBlock != 0) revert ChannelLocked();
        if (
            msg.sender != channelClient[channelId] &&
            msg.sender != channelProvider[channelId]
        ) {
            revert NotChannelParty();
        }

        c.unlockBlock = uint64(block.number + unbondingPeriod);
    }

    // Withdraw remaining funds from a closed channel after unbonding.
    function withdrawChannel(uint256 channelId) external nonReentrant {
        Channel storage c = channels[channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.unlockBlock == 0) revert("Channel not closing");
        if (block.number < c.unlockBlock) revert("Unbonding not complete");
        if (msg.sender != channelClient[channelId]) revert NotChannelParty();

        uint256 remaining = c.deposit - c.spent;
        c.deposit = 0;

        (bool ok, ) = msg.sender.call{value: remaining}("");
        if (!ok) revert TransferFailed();

        emit ChannelClosed(channelId, msg.sender, remaining);
    }

    // Internal function to pay a provider from a channel.
    function _payProvider(uint256 channelId, uint256 amount) internal {
        Channel storage c = channels[channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.spent + amount > c.deposit) revert InsufficientBalance();

        c.spent += amount;

        (bool ok, ) = channelProvider[channelId].call{value: amount}("");
        if (!ok) revert TransferFailed();

        emit ChannelPaid(channelId, channelProvider[channelId], amount);
    }

    // Commit and Reveal Logic

    // Commit a salt hash before the target block is mined.
    function commitSalt(bytes32 commit) external {
        if (saltOwner[commit] != address(0)) revert("Already committed");
        saltOwner[commit] = msg.sender;
        saltCommitBlock[commit] = block.number;
        emit SaltCommitted(commit, msg.sender);
    }

    // Reveal the salt after the target block is mined.
    function revealSalt(bytes32 commit, bytes32 salt) external {
        if (saltOwner[commit] != msg.sender) revert("Not the committer");
        if (saltRevealed[commit] != bytes32(0)) revert("Already revealed");
        if (keccak256(abi.encodePacked(salt)) != commit) {
            revert("Hash mismatch");
        }

        saltRevealed[commit] = salt;
        emit SaltRevealed(commit, salt);
    }

    // Ticket Hashing Functions

    // Compute the full EIP-191 signed hash that the client signs.
    function getHash(Ticket calldata ticket) public view returns (bytes32) {
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

    // Derive the unique nullifier for a ticket to prevent replay attacks.
    function _getNullifier(Ticket calldata ticket) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                ticket.channelId,
                ticket.client,
                ticket.nonce
            )
        );
    }

    // Signature Recovery

    // Recover the signer from a ticket hash and signature with malleability checks.
    function _recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert BadSigner();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }

        // Check signature malleability (s > n/2)
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E735E5AFAED1537A57D8F045F3B) {
            revert BadSigner();
        }

        if (v != 27 && v != 28) revert BadSigner();

        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert BadSigner();

        return signer;
    }

    // Ticket Claiming Logic

    // Claim a probabilistic ticket by verifying signature, timing, and winning threshold.
    function claimTicket(Ticket calldata ticket, bytes calldata sig) external nonReentrant {
        bytes32 nullifier = _getNullifier(ticket);
        if (usedNullifiers[nullifier]) revert TicketUsed();

        // Validate channel parameters
        Channel storage c = channels[ticket.channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.unlockBlock != 0) revert ChannelLocked();

        address client = channelClient[ticket.channelId];
        address provider = channelProvider[ticket.channelId];

        if (client != ticket.client) revert("Client mismatch");
        if (provider != ticket.provider) revert("Provider mismatch");
        if (!providers[ticket.provider].registered) revert NotRegistered();

        // Verify the client's signature
        bytes32 hash = getHash(ticket);
        address signer = _recoverSigner(hash, sig);
        if (signer != ticket.client) revert BadSigner();

        // Validate block entropy window
        if (block.number <= ticket.futureBlock) revert("Block not mined yet");
        if (block.number > ticket.futureBlock + blockLookback) {
            revert InvalidBlock();
        }

        bytes32 bh = blockhash(ticket.futureBlock);
        if (bh == bytes32(0)) revert("Missing blockhash");

        // Validate salt and ensure it was committed before the target block
        bytes32 salt = saltRevealed[ticket.saltCommit];
        if (salt == bytes32(0)) revert SaltNotRevealed();

        if (saltCommitBlock[ticket.saltCommit] >= ticket.futureBlock) {
            revert SaltCommittedTooLate();
        }

        if (saltOwner[ticket.saltCommit] != ticket.provider) {
            revert("Salt not from provider");
        }

        // Cap individual ticket payouts to 25% of channel capacity
        uint256 available = c.deposit - c.spent;
        uint256 maxAllowed = (available * maxTicketPct) / 100;
        if (ticket.amount > maxAllowed) revert TicketExceedsLimit();

        // Calculate lottery outcome
        bytes32 entropy = keccak256(abi.encodePacked(bh, salt, nullifier));
        uint256 winProbab = ticket.winProbab;
        if (winProbab > probabDenom) revert WinProbabTooHigh();

        bool won = (uint256(entropy) % probabDenom) < winProbab;

        // Consume nullifier before triggering payout
        usedNullifiers[nullifier] = true;

        if (won) {
            _payProvider(ticket.channelId, ticket.amount);
        }

        emit TicketClaimed(
            nullifier,
            ticket.channelId,
            ticket.provider,
            ticket.amount,
            won
        );
    }

    // View Helpers

    // Get channel details.
    function getChannel(uint256 channelId)
        external
        view
        returns (
            address client,
            address provider,
            uint256 deposit,
            uint256 spent,
            uint256 unlockBlock
        )
    {
        Channel storage c = channels[channelId];
        return (
            channelClient[channelId],
            channelProvider[channelId],
            c.deposit,
            c.spent,
            c.unlockBlock
        );
    }

    // Check if a nullifier has been used.
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    // Get the revealed salt for a commit.
    function getSalt(bytes32 commit) external view returns (bytes32) {
        return saltRevealed[commit];
    }

    // Get the block number when a salt was committed.
    function getSaltCommitBlock(bytes32 commit) external view returns (uint256) {
        return saltCommitBlock[commit];
    }

    // Get the spendable balance of a channel.
    function channelBalance(uint256 channelId) external view returns (uint256) {
        Channel storage c = channels[channelId];
        return c.deposit - c.spent;
    }
}
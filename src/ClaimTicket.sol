// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "./ChannelManager.sol";
import "./ProviderRegistration.sol";

contract TicketLottery is ReentrancyGuard {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // constants
    uint256 public constant ProbabDenom = 100;
    // EVM limit: 256 blocks ke baad purana blockhash zero ho jata hai
    uint256 public constant BlockL = 256;
    uint256 public constant MaxTicket = 25; // 25% of channel balance

    ChannelManager public immutable channelManager;
    ProviderRegistration public immutable registry;

    mapping(bytes32 => bool) public usedNullifiers;
    mapping(bytes32 => address) public saltOwner;
    mapping(bytes32 => bytes32) public saltRevealed;
    mapping(bytes32 => uint256) public saltCommitBlock; // track when salt was committed

    // TODO: consider packing these structs tighter for gas uint128 combinations might optimize slot usage but what if dont fit
    struct Ticket{
        uint256 channelId;
        address client;
        address provider;
        uint256 amount;
        uint256 nonce;
        uint256 futureBlock;
        uint256 winProbab;
        bytes32 saltCommit;
    }

    event SaltCommitted(bytes32 indexed saltCommit);
    event SaltRevealed(bytes32 indexed saltCommit, bytes32 salt);
    event TicketClaimed(bytes32 indexed nullifier, uint256 indexed channelId, address indexed provider, uint256 amount, bool won);

    // Custom errors
    error BadSigner();
    error TicketUsed();
    error SaltNotRevealed();
    error InvalidBlock();
    error SaltCommittedTooLate();

    constructor(address channelManagerAddr, address registryAddr) {
        channelManager = ChannelManager(channelManagerAddr);
        registry = ProviderRegistration(registryAddr);
    }

    // Commit / Reveal for provider entropy
    function commitSalt(bytes32 commit) external {
        require(saltOwner[commit] == address(0), "Already committed");
        saltOwner[commit] = msg.sender;
        saltCommitBlock[commit] = block.number; // record commit block
        emit SaltCommitted(commit);
    }

    function revealSalt(bytes32 commit, bytes32 salt) external {
        require(saltOwner[commit] == msg.sender, "Not the committer");
        require(saltRevealed[commit] == bytes32(0), "Already revealed");
        // verifying hash equivalence before storing
        require(keccak256(abi.encodePacked(salt)) == commit, "Hash mismatch");
        saltRevealed[commit] = salt;
        emit SaltRevealed(commit, salt);
    }

    // Ticket hashing & verification
    // Off- chain signing metadata mapping utility assembly
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
        return h.toEthSignedMessageHash();
    }

    function _verifySig(Ticket calldata ticket, bytes calldata sig) internal view {
        address signer = getHash(ticket).recover(sig);
        if (signer != ticket.client) revert BadSigner();
    }

    function _getNullifier(Ticket calldata ticket) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), ticket.channelId, ticket.client, ticket.nonce));
    }

    // Main claim function
    function claimTicket(Ticket calldata ticket, bytes calldata sig) external nonReentrant {
        bytes32 nullifier = _getNullifier(ticket);
        if (usedNullifiers[nullifier]) revert TicketUsed();

        // Validate channel
        (address client, address provider, uint256 deposit, uint256 spent, , bool closed) = channelManager.getChannel(ticket.channelId);

        require(!closed, "Channel closed");
        require(client == ticket.client && provider == ticket.provider, "Channel mismatch");
        require(registry.isRegistered(ticket.provider), "Provider not registered");

        //Validate signature
        _verifySig(ticket, sig);

        // Validate block entropy
        require(block.number > ticket.futureBlock, "Block not mined yet");
        if (block.number > ticket.futureBlock + BlockL) revert InvalidBlock();

        bytes32 bh = blockhash(ticket.futureBlock);
        require(bh != bytes32(0), "Missing blockhash");

        //  Validate salt
        bytes32 salt = saltRevealed[ticket.saltCommit];
        if (salt == bytes32(0)) revert SaltNotRevealed();

        // Ensure salt was committed BEFORE the future block
        // This prevents the provider from grinding salts after seeing the blockhash
        require(saltCommitBlock[ticket.saltCommit] < ticket.futureBlock, "Salt committed too late");

        //Ensure salt was committed by this provider
        require(saltOwner[ticket.saltCommit] == ticket.provider, "Salt not committed by this provider");

        //Anti- drain
        // check that individual ticket does not sweep out whole channels
        uint256 available = deposit - spent;
        uint256 maxAllowed = (available * MaxTicket) / 100;
        require(ticket.amount <= maxAllowed, "Ticket exceeds limit");

        // Determine win
        // Include nullifier in entropy for stronger randomness
        bytes32 entropy = keccak256(abi.encodePacked(bh, salt, nullifier));
        uint256 winProbab = ticket.winProbab;
        require(winProbab > 0 && winProbab <= ProbabDenom, "Win probab must be 1-100");

        bool won = (uint256(entropy) % ProbabDenom) < winProbab;

        // Effects
        // State mutation done right before external calls to lock state space
        usedNullifiers[nullifier] = true;

        //Payment
        if (won) {
            channelManager.payProvider(ticket.channelId, ticket.amount);
        }
        // reset krne ke baad log me bhejne ke liye data structure packed
        emit TicketClaimed(nullifier, ticket.channelId, ticket.provider, ticket.amount, won);
    }

    // View helpers
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return usedNullifiers[nullifier];
    }

    function getSalt(bytes32 commit) external view returns (bytes32) {
        return saltRevealed[commit];
    }

    function getSaltCommitBlock(bytes32 commit) external view returns (uint256) {
        return saltCommitBlock[commit];
    }
}
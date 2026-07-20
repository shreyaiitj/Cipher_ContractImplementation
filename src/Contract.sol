// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract CipherContract is ReentrancyGuard {
    uint256 public constant minStake = 1 ether;
    uint256 public constant probabDenom = 100; // To check probability base chosen 
    uint256 public constant blockLookback = 256; // EVM sirf last 256 blocks ka hi blockhash read kar sakta hai so uski limit set ke liye
    uint256 public constant maxTicketPct = 25; // anti drain saftey limit 
    uint64 public constant unbondingPeriod = 7200; // Provider unstake request krne ke baad defined time for it to stay locked
    uint64 public constant disputePeriod = 3600; // Channel close request karne ke baad provider ko pending ticket claims submit karne ke liye time

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
    error NoPendingWithdrawal();    

    struct Provider {
        uint256 stake;         
        uint64 unstakeBlock; // Block number jab unbonding complete hogi aur fund withdraw kar payenge.
        bool registered;        
    }

    struct Channel {
        uint256 deposit;            
        uint256 spent;              
        uint64 unlockBlock; // Unlock block timestamp (is block ke baad client fund nikal sakta hai).
        uint64 closureRequestedAt;  
        bool closureInitiated;      
    }

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

    mapping(address => Provider) public providers; // Wallet address to Provider struct storage.
    uint256 public nextChannelId = 1;                       
    mapping(uint256 => Channel) public channels;            
    mapping(uint256 => address) public channelClient;       
    mapping(uint256 => address) public channelProvider;     
    mapping(bytes32 => bool) public usedNullifiers; // Nullifier registry
    mapping(bytes32 => address) public saltOwner;          
    mapping(bytes32 => bytes32) public saltRevealed;       
    mapping(bytes32 => uint256) public saltCommitBlock;    
    mapping(address => uint256) public pendingWithdrawals; // For Safe Pull-Payment

    address public owner;
    address public treasury;

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
        require(msg.sender == owner, "Not owner"); //Safety check
        _;
    }

    function registerProvider() external payable {
        Provider storage p = providers[msg.sender];
        if (p.registered) revert AlreadyRegistered();
        if (msg.value < minStake) revert InvalidStake();
        p.stake = msg.value;
        p.registered = true;
        p.unstakeBlock = 0; // Lock resets
        emit ProviderRegistered(msg.sender, msg.value);
    }

    function requestUnstake() external { // Unstake start karne ke liye request as Direct withdraw allowed nahi hai 
        Provider storage p = providers[msg.sender];
        if (!p.registered) revert NotRegistered();
        if (p.unstakeBlock != 0) revert("Already unbonding");
        p.unstakeBlock = uint64(block.number + unbondingPeriod);
        emit UnstakeRequested(msg.sender, p.stake);
    }

    function withdrawStake() external nonReentrant {
        Provider storage p = providers[msg.sender];
        if (p.unstakeBlock == 0) revert("Not unbonding");
        if (block.number < p.unstakeBlock) revert("Unbonding not complete");
        uint256 amount = p.stake;
        p.stake = 0;
        p.unstakeBlock = 0;
        p.registered = false; // Registration permanently cancel.
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit ProviderWithdrawn(msg.sender, amount);
    }

    function slashProvider(address provider, uint256 amount) external onlyOwner {
        Provider storage p = providers[provider];
        if (!p.registered) revert NotRegistered();
        uint256 slashAmount = amount > p.stake ? p.stake : amount;
        p.stake -= slashAmount;
        if (p.stake == 0) {
            p.registered = false; // Agar provider ka sara stake chala jaye, to automatic deregister kardo.
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

    function openChannel(address provider) external payable nonReentrant { // Client cash (deposit) lock karta hai provider ke against.
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

    function closeChannel(uint256 channelId) external nonReentrant { // Provider ko safe rakhne ke liye, ek unbonding delay aur dispute window is added. Is lock window ke andr provider outstanding claims submit kar sakta hai.
        Channel storage c = channels[channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.closureInitiated) revert ChannelLocked();
        if (msg.sender != channelClient[channelId] && msg.sender != channelProvider[channelId]) {
            revert NotChannelParty();
        }
        c.closureInitiated = true;
        c.closureRequestedAt = uint64(block.number);
        c.unlockBlock = uint64(block.number + unbondingPeriod + disputePeriod); // Pura exit timing = unbonding timer + 12-hour dispute delay.
    }

    function withdrawChannel(uint256 channelId) external nonReentrant { // Unlock period complete hone ke baad client remaining balances (deposit - spent) nikal sakta hai.
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

    function _payProvider(uint256 channelId, uint256 amount) internal { // Micropayment internal handler: Balance deduct karta hai aur provider ke pending claim account me update karta hai. Agar channel close timing block cross ho chuka ho, tab balance freeze ho jata hai.
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

    function withdrawPending() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert NoPendingWithdrawal();
        pendingWithdrawals[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    // Provider blockhash prediction attack prevent karne ke liye
    function commitSalt(bytes32 commit) external {
        if (saltOwner[commit] != address(0)) revert("Already committed");
        saltOwner[commit] = msg.sender;
        saltCommitBlock[commit] = block.number;
        emit SaltCommitted(commit, msg.sender);
    }

    // Aane wale target block ke mine ho jane par provider original secret reveal kara
    function revealSalt(bytes32 commit, bytes32 salt) external {
        if (saltOwner[commit] != msg.sender) revert("Not the committer");
        if (saltRevealed[commit] != bytes32(0)) revert("Already revealed");
        if (keccak256(abi.encodePacked(salt)) != commit) {
            revert("Hash mismatch");
        }
        saltRevealed[commit] = salt;
        emit SaltRevealed(commit, salt);
    }

    // EIP-191 signatures verify karne ke liye structured ticket message generate kar rha
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

    // Replay attack block karne ke liye ticket properties hash 
    function _getNullifier(Ticket calldata ticket) internal view returns (bytes32) {
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

    // ECDSA signature se payload sign karne wale client ka wallet address extraction
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
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert BadSigner();
        }
        if (v != 27 && v != 28) revert BadSigner();
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert BadSigner();
        return signer;
    }

    // block hash entropy check, signature parsing, and payout transfer sequence handling
    function claimTicket(Ticket calldata ticket, bytes calldata sig) external nonReentrant {
        bytes32 nullifier = _getNullifier(ticket);
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
        bytes32 hash = getHash(ticket);
        address signer = _recoverSigner(hash, sig);
        if (signer != ticket.client) revert BadSigner();
        if (block.number <= ticket.futureBlock) revert("Block not mined yet"); // lock has been mined aur lookback historical limits me hai to ensure
        if (block.number > ticket.futureBlock + blockLookback) {
            revert InvalidBlock();
        }
        bytes32 bh = blockhash(ticket.futureBlock);
        if (bh == bytes32(0)) revert("Missing blockhash");
        bytes32 salt = saltRevealed[ticket.saltCommit]; // Salt reveal verification
        if (salt == bytes32(0)) revert SaltNotRevealed();
        if (saltCommitBlock[ticket.saltCommit] >= ticket.futureBlock) {
            revert SaltCommittedTooLate();
        }
        if (saltOwner[ticket.saltCommit] != ticket.provider) {
            revert("Salt not from provider");
        }
        uint256 available = c.deposit - c.spent;
        uint256 maxAllowed = (available * maxTicketPct) / 100; // 25% total cap check.
        if (ticket.amount > maxAllowed) revert TicketExceedsLimit();
        bytes32 entropy = keccak256(abi.encodePacked(bh, salt, nullifier)); //Target blockhash + Provider revealed salt + Nullifier unique variables.
        bool won = (uint256(entropy) % probabDenom) < ticket.winProbab;
        usedNullifiers[nullifier] = true;
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
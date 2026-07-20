// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// OpenZeppelin ka standard guard import kiya hai taaki safe transfers ho sakein aur reentrancy attack na ho.
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract CipherContract is ReentrancyGuard {

    // --- State Variables (Contract ki settings aur parameters) ---

    // Provider ko register karne ke liye kam se kam 1 ETH security deposit (stake) lock karna padega.
    uint256 public constant minStake = 1 ether;

    // Probability (percentage) check karne ke liye base number 100 set kiya hai.
    uint256 public constant probabDenom = 100;

    // EVM sirf last 256 blocks ka hi blockhash read kar sakta hai, so uski limit set ki hai.
    uint256 public constant blockLookback = 256;

    // Koi single ticket channel ke remaining balance ka 25% se zyada drain nahi kar sakti (anti-drain safety limit).
    uint256 public constant maxTicketPct = 25;

    // Provider unstake request karne ke baad lagbhag 1 day (7200 blocks) tak lock rehta hai.
    uint64 public constant unbondingPeriod = 7200;

    // Channel close request karne ke baad provider ko pending ticket claims submit karne ke liye 12 hours (3600 blocks) milte hain.
    uint64 public constant disputePeriod = 3600;

    // --- Custom Errors (Kuch galat hone par gas bacha ke tx revert karne ke liye) ---
    error AlreadyRegistered();      // Jab provider pehle se register ho aur firse apply kare.
    error NotRegistered();          // Jab unregistered address provider functions call kare.
    error InvalidStake();           // Stake amount 1 ETH se kam hone par error.
    error ZeroAmount();             // Zero payment ya zero value transaction try karne par error.
    error TransferFailed();         // ETH transfer fail hone par error.
    error ChannelNotFound();        // Invalid channel ID use karne par error.
    error ChannelLocked();          // Channel lock state me hone par claims block karne ke liye.
    error NotChannelParty();        // Koi teesra banda channel functions access karne ki koshish kare tab.
    error InsufficientBalance();    // Channel me claim amount se kam deposit hone par error.
    error TicketUsed();             // Replay attack prevent karne ke liye (agar ticket pehle hi use ho chuki ho).
    error BadSigner();              // Client ka signature verify na hone par custom error.
    error SaltNotRevealed();        // Provider ne abhi tak salt value open (reveal) na ki ho.
    error InvalidBlock();           // Blockhash history window (256 blocks) se purani block target karne par.
    error SaltCommittedTooLate();   // Target block mine hone ke baad salt commit karne ki koshish par error.
    error TicketExceedsLimit();     // Ticket value 25% safety limit cross karne par error.
    error WinProbabTooHigh();       // Winning probability range (1-100) se bahar hone par.
    error NoPendingWithdrawal();    // Provider ka balance account me zero hone par withdrawal request reject karne ke liye.

    // --- Structs (Data formats jo state store karne ke liye use hote hain) ---

    // Provider ki info track karne ke liye struct
    struct Provider {
        uint256 stake;          // Lock kiya hua total deposit.
        uint64 unstakeBlock;    // Block number jab unbonding complete hogi aur fund withdraw kar payenge.
        bool registered;        // Provider actively registered hai ya nahi.
    }

    // Client aur Provider ke beech active payment channel track karne ke liye struct
    struct Channel {
        uint256 deposit;            // Total paisa jo client ne lock kiya.
        uint256 spent;              // Total payment jo provider ko approve ho chuki hai.
        uint64 unlockBlock;         // Unlock block timestamp (is block ke baad client fund nikal sakta hai).
        uint64 closureRequestedAt;  // Block jab channel close ki request aayi.
        bool closureInitiated;      // Close process start ho chuka hai ya nahi.
    }

    // Off-chain client jo payment ticket sign karke provider ko deta hai uski format
    struct Ticket {
        uint256 channelId;      // Kis channel se paise niklenge.
        address client;         // Client ka public wallet address.
        address provider;       // Provider ka public wallet address.
        uint256 amount;         // Is ticket ki payment value.
        uint256 nonce;          // Serial number taaki unique ticket generate ho.
        uint256 futureBlock;    // Randomness generate karne ke liye aane wala target block.
        uint256 winProbab;      // Ticket jeetne ke probability chance (out of 100).
        bytes32 saltCommit;     // Salt hash commitment jo provider ne register kiya hai.
    }

    // --- Mappings (Database variables) ---
    mapping(address => Provider) public providers;          // Wallet address to Provider struct storage.
    uint256 public nextChannelId = 1;                       // Naye channels ke liye counter.
    mapping(uint256 => Channel) public channels;            // Channel ID to Channel state map.
    mapping(uint256 => address) public channelClient;       // Channel client links.
    mapping(uint256 => address) public channelProvider;     // Channel provider links.

    // Ticket replay protect karne ke liye tracking map (Nullifier registry)
    mapping(bytes32 => bool) public usedNullifiers;

    // Randomness verify karne ke liye Provider ke pre-committed values ki mappings
    mapping(bytes32 => address) public saltOwner;           // Salt hash kis provider ka hai.
    mapping(bytes32 => bytes32) public saltRevealed;        // Commit hash ka original value kya tha.
    mapping(bytes32 => uint256) public saltCommitBlock;     // Salt kis block me commit kiya gaya tha.

    // Safe Pull-Payment: Provider ka claim kiya hua balance yahan store hota hai jise wo baad me withdraw karte hain
    mapping(address => uint256) public pendingWithdrawals;

    // Governance aur admin functions manage karne ke liye variables
    address public owner;
    address public treasury;

    // --- Events (Log statements taaki tools track kar sakein on-chain events) ---
    event ProviderRegistered(address indexed provider, uint256 stake);
    event UnstakeRequested(address indexed provider, uint256 stake);
    event ProviderWithdrawn(address indexed provider, uint256 stake);
    event ProviderSlashed(address indexed provider, uint256 amount, address indexed to);
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
    event TicketLost(
        bytes32 indexed nullifier,
        uint256 indexed channelId,
        address indexed provider,
        uint256 amount
    );
    event WithdrawalPending(
        address indexed recipient,
        uint256 amount
    );

    // Constructor: Contract deploy karte time run hoga. Admin (owner) and treasury wallet assign karega.
    constructor(address _treasury) {
        owner = msg.sender;
        treasury = _treasury;
    }

    // Owner check karne ke liye modifier
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // --- Provider Registration Functions (Provider management logic) ---

    // Provider register karne ke liye function. Call karte time ETH (deposit) lagana zaroori hai.
    function registerProvider() external payable {
        Provider storage p = providers[msg.sender];
        if (p.registered) revert AlreadyRegistered();
        if (msg.value < minStake) revert InvalidStake();

        p.stake = msg.value;
        p.registered = true;
        p.unstakeBlock = 0; // Lock resets.

        emit ProviderRegistered(msg.sender, msg.value);
    }

    // Unstake start karne ke liye request. Direct withdraw allowed nahi hai (unbonding period lag jata hai).
    // Provider register hi rahega taaki unbonding time me bhi old payments settle kar sake.
    function requestUnstake() external {
        Provider storage p = providers[msg.sender];
        if (!p.registered) revert NotRegistered();
        if (p.unstakeBlock != 0) revert("Already unbonding");

        // Release window block update kar rahe hain. Is block number ke baad withdraw stake allowed hoga.
        p.unstakeBlock = uint64(block.number + unbondingPeriod);

        emit UnstakeRequested(msg.sender, p.stake);
    }

    // Unbonding/waiting duration end hone ke baad, provider apna security deposit wapas lene ke liye ise call karega.
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

    // Slasher logic (Strictly onlyOwner): Agar provider bad activity kare, to admin unka stake cut (slash) karke treasury me bhej dega.
    function slashProvider(address provider, uint256 amount) external onlyOwner {
        Provider storage p = providers[provider];
        if (!p.registered) revert NotRegistered();

        uint256 slashAmount = amount > p.stake ? p.stake : amount;
        p.stake -= slashAmount;

        // Agar provider ka sara stake chala jaye, to automatic deregister kardo.
        if (p.stake == 0) {
            p.registered = false;
        }

        (bool ok, ) = treasury.call{value: slashAmount}("");
        if (!ok) revert TransferFailed();

        emit ProviderSlashed(provider, slashAmount, treasury);
    }

    // View helper functions: Active registration aur current stake check karne ke liye.
    function isProvider(address provider) external view returns (bool) {
        return providers[provider].registered;
    }

    function stakeOf(address provider) external view returns (uint256) {
        return providers[provider].stake;
    }

    // --- Channel Management Functions (Channel lifecycle management) ---

    // Naya micropayment channel kholne ke liye function. Client cash (deposit) lock karta hai provider ke against.
    function openChannel(address provider) external payable nonReentrant {
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


    // Client/Provider channel close karne ki request trigger karte hain.
    // Provider ko safe rakhne ke liye, ek unbonding delay aur dispute windows (lock window) add ho jata hai.
    // Is lock window ke andr provider outstanding claims submit kar sakta hai.
    function closeChannel(uint256 channelId) external nonReentrant {
        Channel storage c = channels[channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.closureInitiated) revert ChannelLocked();
        if (
            msg.sender != channelClient[channelId] &&
            msg.sender != channelProvider[channelId]
        ) {
            revert NotChannelParty();
        }

        c.closureInitiated = true;
        c.closureRequestedAt = uint64(block.number);
        
        // Pura exit timing = unbonding timer + 12-hour dispute delay.
        c.unlockBlock = uint64(block.number + unbondingPeriod + disputePeriod);
    }

    // Unlock period complete hone ke baad client remaining balances (deposit - spent) nikal sakta hai.
    function withdrawChannel(uint256 channelId) external nonReentrant {
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

    // Micropayment internal handler: Balance deduct karta hai aur provider ke pending claim account me update karta hai.
    // Agar channel close timing block cross ho chuka ho, tab balance freeze ho jata hai.
    function _payProvider(uint256 channelId, uint256 amount) internal {
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

    // Pull-Payment: Provider is function se apne pure accumulated settlement payments nikal sakte hain (no reentrancy risk).
    function withdrawPending() external nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert NoPendingWithdrawal();

        pendingWithdrawals[msg.sender] = 0;

        (bool ok, ) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    // --- Randomness Commit-Reveal Logic (Micropayment security design) ---

    // Commit Step: Provider blockhash prediction attack prevent karne ke liye aane wale target block se pehle salt commit karta hai.
    function commitSalt(bytes32 commit) external {
        if (saltOwner[commit] != address(0)) revert("Already committed");
        saltOwner[commit] = msg.sender;
        saltCommitBlock[commit] = block.number;
        emit SaltCommitted(commit, msg.sender);
    }

    // Reveal Step: Aane wale target block ke mine ho jane par provider original secret reveal karta hai.
    function revealSalt(bytes32 commit, bytes32 salt) external {
        if (saltOwner[commit] != msg.sender) revert("Not the committer");
        if (saltRevealed[commit] != bytes32(0)) revert("Already revealed");
        if (keccak256(abi.encodePacked(salt)) != commit) {
            revert("Hash mismatch");
        }

        saltRevealed[commit] = salt;
        emit SaltRevealed(commit, salt);
    }

    // Hashing: EIP-191 signatures verify karne ke liye structured ticket message generate karta hai.
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

    // Nullifier Generator: Replay attack block karne ke liye ticket properties hash karta hai (including futureBlock and amount).
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

    // Recover Signer: ECDSA signature se payload sign karne wale client ka wallet address extract karta hai.
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

        // secp256k1 standard limit check taaki signature structure bypass na ho sake.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert BadSigner();
        }

        if (v != 27 && v != 28) revert BadSigner();

        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert BadSigner();

        return signer;
    }

    // --- claimTicket: Main Settlement Logic ---

    // Micropayment claim submit karne ka core execution path.
    // Isme block hash entropy check, signature parsing, aur payout transfer sequence handle hote hain.
    function claimTicket(Ticket calldata ticket, bytes calldata sig) external nonReentrant {
        // Replay validation: Nullifier checks.
        bytes32 nullifier = _getNullifier(ticket);
        if (usedNullifiers[nullifier]) revert TicketUsed();

        // Parameters limits verification.
        if (ticket.amount == 0) revert ZeroAmount();
        if (ticket.winProbab == 0 || ticket.winProbab > probabDenom) revert WinProbabTooHigh();

        // Channel state validation.
        Channel storage c = channels[ticket.channelId];
        if (c.deposit == 0) revert ChannelNotFound();
        if (c.closureInitiated && block.number >= c.unlockBlock) revert ChannelLocked();

        address client = channelClient[ticket.channelId];
        address provider = channelProvider[ticket.channelId];

        if (client != ticket.client) revert("Client mismatch");
        if (provider != ticket.provider) revert("Provider mismatch");
        if (!providers[ticket.provider].registered) revert NotRegistered();

        // ECDSA signature verification.
        bytes32 hash = getHash(ticket);
        address signer = _recoverSigner(hash, sig);
        if (signer != ticket.client) revert BadSigner();

        // Timing validation: Block has been mined aur lookback historical limits me hai.
        if (block.number <= ticket.futureBlock) revert("Block not mined yet");
        if (block.number > ticket.futureBlock + blockLookback) {
            revert InvalidBlock();
        }

        bytes32 bh = blockhash(ticket.futureBlock);
        if (bh == bytes32(0)) revert("Missing blockhash");

        // Salt reveal verify karo.
        bytes32 salt = saltRevealed[ticket.saltCommit];
        if (salt == bytes32(0)) revert SaltNotRevealed();

        // Salt target block mine hone se pehle ka committed hona chahiye.
        if (saltCommitBlock[ticket.saltCommit] >= ticket.futureBlock) {
            revert SaltCommittedTooLate();
        }

        if (saltOwner[ticket.saltCommit] != ticket.provider) {
            revert("Salt not from provider");
        }

        // Single claim validation: 25% total cap check.
        uint256 available = c.deposit - c.spent;
        uint256 maxAllowed = (available * maxTicketPct) / 100;
        if (ticket.amount > maxAllowed) revert TicketExceedsLimit();

        // Entropy Generation: Target blockhash + Provider revealed salt + Nullifier unique variables.
        bytes32 entropy = keccak256(abi.encodePacked(bh, salt, nullifier));

        // Lottery Outcome evaluation: Probability match.
        bool won = (uint256(entropy) % probabDenom) < ticket.winProbab;

        // Tx process hone par nullifier ko consumption list me daal do (Jeete ya Haare ticket dobara nahi chalega).
        usedNullifiers[nullifier] = true;

        if (won) {
            _payProvider(ticket.channelId, ticket.amount);
        } else {
            emit TicketLost(nullifier, ticket.channelId, ticket.provider, ticket.amount);
        }

        emit TicketClaimed(
            nullifier,
            ticket.channelId,
            ticket.provider,
            ticket.amount,
            won
        );
    }

    // --- View Helpers ---

    function getChannel(uint256 channelId)
        external
        view
        returns (
            address client,
            address provider,
            uint256 deposit,
            uint256 spent,
            uint256 unlockBlock,
            bool closureInitiated
        )
    {
        Channel storage c = channels[channelId];
        return (
            channelClient[channelId],
            channelProvider[channelId],
            c.deposit,
            c.spent,
            c.unlockBlock,
            c.closureInitiated
        );
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
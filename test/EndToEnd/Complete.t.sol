// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../../src/Contract.sol";

// Testing provider registry, off-chain probabilistic payments, and commit-reveal workflow
contract CipherTest is Test {
    CipherContract public broker;

    // Hardcoded test actors and signatures setup
    address public client;
    address public provider = address(0xBEEF);
    uint256 public clientPk = 0xA11CE; // Client private key for vm.sign

    function setUp() public {
        client = vm.addr(clientPk);
        broker = new CipherContract();

        // Funding initial balances so test actors can stake & fund channels
        vm.deal(provider, 10 ether);
        vm.deal(client, 10 ether);

        // Provider registration (MIN_PROVIDER_STAKE = 1 ether)
        vm.prank(provider);
        broker.registerProvider{value: 1 ether}();

        // Client opens payment channel with 5 ether deposit
        vm.prank(client);
        broker.openChannel{value: 5 ether}(provider);
    }

    // Helper: Handles the commit-reveal cycle for salt randomness off-chain/on-chain
    function _commitRevealSalt() internal returns (bytes32) {
        bytes32 salt = keccak256(abi.encodePacked("secret"));
        bytes32 commit = keccak256(abi.encodePacked(salt));

        // Step 1: Provider submits commitment
        vm.prank(provider);
        broker.commitSalt(commit);

        // Step 2: Provider reveals underlying salt pre-image
        vm.prank(provider);
        broker.revealSalt(commit, salt);

        return commit;
    }

    // Helper: ECDSA signature generation matching ECDSA/MessageHashUtils spec
    function _signTicket(CipherContract.Ticket memory ticket) internal view returns (bytes memory) {
        bytes32 digest = broker.getHash(ticket);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(clientPk, digest);
        return abi.encodePacked(r, s, v);
    }

    // PROVIDER REGISTRATION & UNSTAKING TESTS 
    function test_RegisterAndUnregister() public {
        assertTrue(broker.isProvider(provider));
        assertEq(broker.stakeOf(provider), 1 ether);

        // Initiate unbonding time-lock window
        vm.prank(provider);
        broker.requestUnstake();

        // Warp past UNBONDING_PERIOD (~7200 blocks)
        // Delay complete skip krne ke liye roll kr standard block window forward
        vm.roll(block.number + 7200 + 1);

        uint256 before = provider.balance;
        vm.prank(provider);
        broker.withdrawStake();

        // Verification: Ensure provider un-registered properly and stake returned
        assertFalse(broker.isProvider(provider));
        assertEq(provider.balance - before, 1 ether);
    }


    function test_OpenAndCloseChannel() public {
        uint256 id = 1;
        (address cl, address pr, uint256 deposit, uint256 spent, uint256 unlockBlock) = broker.getChannel(id);
        
        assertEq(cl, client);
        assertEq(pr, provider);
        assertEq(deposit, 5 ether);
        assertEq(spent, 0);
        assertEq(unlockBlock, 0);

        // Client initiates channel unlock request
        vm.prank(client);
        broker.closeChannel(id);

        // Unlock block must be scheduled in future to give provider time to redeem outstanding tickets
        (, , , , unlockBlock) = broker.getChannel(id);
        assertTrue(unlockBlock > 0);
    }

    //  COMMIT-REVEAL SYSTEM TESTS
    function test_CommitAndRevealSalt() public {
        bytes32 salt = keccak256(abi.encodePacked("test"));
        bytes32 commit = keccak256(abi.encodePacked(salt));

        vm.prank(provider);
        broker.commitSalt(commit);

        vm.prank(provider);
        broker.revealSalt(commit, salt);

        // Verify state persistence of pre-image reveal
        assertEq(broker.getSalt(commit), salt);
    }

    //  TICKET CLAIM & PROBABILISTIC PAYOUT TESTS 
    function test_WinningTicketPaysOut() public {
        bytes32 commit = _commitRevealSalt();

        // Setting up a guaranteed winning ticket (winProb = 100%)
        uint256 futureBlock = block.number + 5;
        CipherContract.Ticket memory ticket = CipherContract.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.5 ether,
            nonce: 1,
            futureBlock: futureBlock,
            winProbab: 100,
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        // Need to roll past futureBlock for randomness blockhash confirmation
        vm.roll(futureBlock + 1);

        uint256 before = provider.balance;
        vm.prank(provider);
        broker.claimTicket(ticket, sig);

        // Verify payout and double-spend nullifier tracking
        assertEq(provider.balance - before, 0.5 ether);
        assertTrue(broker.isNullifierUsed(broker._getNullifier(ticket)));

        (, , , uint256 spent, ) = broker.getChannel(1);
        assertEq(spent, 0.5 ether);
    }

    function test_LosingTicketDoesNotPayOut() public {
        bytes32 commit = _commitRevealSalt();

        // Setting guaranteed losing condition probability threshold
        uint256 futureBlock = block.number + 5;
        CipherContract.Ticket memory ticket = CipherContract.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.5 ether,
            nonce: 2,
            futureBlock: futureBlock,
            winProbab: 1, // Extremely low win condition
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        vm.roll(futureBlock + 1);

        uint256 before = provider.balance;
        vm.prank(provider);
        broker.claimTicket(ticket, sig);

        // Money remains in channel, but nullifier consumed anyway so ticket can't be replayed!
        assertEq(provider.balance, before);
        assertTrue(broker.isNullifierUsed(broker._getNullifier(ticket)));
    }

    // SECURITY TESTS
    function test_ReplayTicketFails() public {
        bytes32 commit = _commitRevealSalt();

        uint256 futureBlock = block.number + 5;
        CipherContract.Ticket memory ticket = CipherContract.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.5 ether,
            nonce: 3,
            futureBlock: futureBlock,
            winProbab: 1,
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        vm.roll(futureBlock + 1);

        // First attempt succeeds
        vm.prank(provider);
        broker.claimTicket(ticket, sig);

        // THE FAMOUS DOUBLE SPEND ATTACK Replay attempt must revert
        vm.prank(provider);
        vm.expectRevert(CipherContract.TicketUsed.selector);
        broker.claimTicket(ticket, sig);
    }

    function test_InvalidSignatureFails() public {
        bytes32 commit = _commitRevealSalt();

        uint256 futureBlock = block.number + 5;
        CipherContract.Ticket memory ticket = CipherContract.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.5 ether,
            nonce: 4,
            futureBlock: futureBlock,
            winProbab: 50,
            saltCommit: commit
        });

        // Sign with an unauthorized private key (0xDEAD)
        bytes32 digest = broker.getHash(ticket);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.roll(futureBlock + 1);
        vm.prank(provider);
        
        // Custom error check for cryptographic signer validation
        vm.expectRevert(CipherContract.BadSigner.selector);
        broker.claimTicket(ticket, sig);
    }

    function test_AntiDrainProtection() public {
        bytes32 commit = _commitRevealSalt();

        uint256 futureBlock = block.number + 5;
        
        // Attempting to claim amount exceeding channel limit balance threshold
        CipherContract.Ticket memory ticket = CipherContract.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 2 ether, // Ticket value higher than remaining liquid capacity
            nonce: 5,
            futureBlock: futureBlock,
            winProbab: 100,
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        vm.roll(futureBlock + 1);
        vm.prank(provider);
        
        // Prevents malicious provider draining logic
        vm.expectRevert(CipherContract.TicketExceedsLimit.selector);
        broker.claimTicket(ticket, sig);
    }

    // FUZZ TESTING 
    function testFuzz_WinProbability(uint8 winProbab) public {
        // Bound random inputs to valid percentage range
        vm.assume(winProbab >= 1 && winProbab <= 100);

        bytes32 commit = _commitRevealSalt();

        uint256 futureBlock = block.number + 5;
        CipherContract.Ticket memory ticket = CipherContract.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.1 ether,
            nonce: uint256(keccak256(abi.encodePacked(winProbab))),
            futureBlock: futureBlock,
            winProbab: winProbab,
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        vm.roll(futureBlock + 1);

        vm.prank(provider);
        broker.claimTicket(ticket, sig);

        // Verification: Regardless of win/loss outcome, nullifier must be consumed
        assertTrue(broker.isNullifierUsed(broker._getNullifier(ticket)));
    }
}
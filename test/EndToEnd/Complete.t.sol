// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/ProviderRegistration.sol";
import "../src/ChannelManager.sol";
import "../src/ClaimTicket.sol";

contract CipherTest is Test {
    ProviderRegistration public reg;
    ChannelManager public cm;
    TicketLottery public tl;

    address public client = address(0xCA11);
    address public provider = address(0xBEEF);
    uint256 public clientPk = 0xA11CE;

    function setUp() public {
        // Deploy and wire up
        reg = new ProviderRegistration();
        tl = new TicketLottery(address(cm), address(reg));
        cm = new ChannelManager(address(reg), address(tl));

        // Fund both parties
        vm.deal(provider, 10 ether);
        vm.deal(client, 10 ether);

        // Register provider (shared setup for most tests)
        vm.prank(provider);
        reg.registerProvider{value: 10 ether}();

        // Open a channel (shared setup)
        vm.prank(client);
        cm.openChannel{value: 5 ether}(provider);
    }

    // helpers

    function _commitRevealSalt() internal returns (bytes32) {
        bytes32 salt = keccak256(abi.encodePacked("secret"));
        bytes32 commit = keccak256(abi.encodePacked(salt));

        vm.prank(provider);
        tl.commitSalt(commit);

        vm.prank(provider);
        tl.revealSalt(commit, salt);

        return commit;
    }

    function _signTicket(TicketLottery.Ticket memory ticket) internal view returns (bytes memory) {
        bytes32 digest = tl.getHash(ticket);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(clientPk, digest);
        return abi.encodePacked(r, s, v);
    }

    // tests

    function test_RegisterAndUnregister() public {
        assertTrue(reg.isRegistered(provider));
        assertEq(reg.stakeOf(provider), 10 ether);

        uint256 before = provider.balance;
        vm.prank(provider);
        reg.unregisterProvider();

        assertFalse(reg.isRegistered(provider));
        assertEq(provider.balance - before, 10 ether);
    }

    function test_OpenAndCloseChannel() public {
        uint256 id = 1; // first channel
        (address cl, address pr, uint256 deposit, , , bool closed) = cm.getChannel(id);
        assertEq(cl, client);
        assertEq(pr, provider);
        assertEq(deposit, 5 ether);
        assertFalse(closed);

        uint256 before = client.balance;
        vm.prank(client);
        cm.closeChannel(id);

        (, , , , , closed) = cm.getChannel(id);
        assertTrue(closed);
        assertEq(client.balance - before, 5 ether);
    }

    function test_CommitAndRevealSalt() public {
        bytes32 salt = keccak256(abi.encodePacked("test"));
        bytes32 commit = keccak256(abi.encodePacked(salt));

        vm.prank(provider);
        tl.commitSalt(commit);

        vm.prank(provider);
        tl.revealSalt(commit, salt);

        assertEq(tl.getSalt(commit), salt);
    }

    function test_WinningTicketPaysOut() public {
        bytes32 commit = _commitRevealSalt();

        uint256 futureBlock = block.number + 5;
        TicketLottery.Ticket memory ticket = TicketLottery.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.5 ether,
            nonce: 1,
            futureBlock: futureBlock,
            winProb: 100, // guaranteed win
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        // mine to the target block
        vm.roll(futureBlock + 1);

        uint256 before = provider.balance;
        vm.prank(provider);
        tl.claimTicket(ticket, sig);

        assertEq(provider.balance - before, 0.5 ether);

        // nullifier is marked
        bytes32 nullifier = tl._getNullifier(ticket);
        assertTrue(tl.isNullifierUsed(nullifier));

        // channel spent
        (, , , uint256 spent, , ) = cm.getChannel(1);
        assertEq(spent, 0.5 ether);
    }

    function test_LosingTicketDoesNotPayOut() public {
        bytes32 commit = _commitRevealSalt();

        uint256 futureBlock = block.number + 5;
        TicketLottery.Ticket memory ticket = TicketLottery.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.5 ether,
            nonce: 2,
            futureBlock: futureBlock,
            winProb: 1, // 1% chance (virtually guaranteed loss)
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        vm.roll(futureBlock + 1);

        uint256 before = provider.balance;
        vm.prank(provider);
        tl.claimTicket(ticket, sig);

        // no payout
        assertEq(provider.balance, before);

        // still marks nullifier to prevent replay
        bytes32 nullifier = tl._getNullifier(ticket);
        assertTrue(tl.isNullifierUsed(nullifier));
    }

    function test_ReplayTicketFails() public {
        bytes32 commit = _commitRevealSalt();

        uint256 futureBlock = block.number + 5;
        TicketLottery.Ticket memory ticket = TicketLottery.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.5 ether,
            nonce: 3,
            futureBlock: futureBlock,
            winProb: 1,
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        vm.roll(futureBlock + 1);

        // first claim lost but marks nullifier
        vm.prank(provider);
        tl.claimTicket(ticket, sig);

        // second claim with same ticket
        vm.prank(provider);
        vm.expectRevert(TicketLottery.TicketUsed.selector);
        tl.claimTicket(ticket, sig);
    }

    function test_InvalidSignatureFails() public {
        bytes32 commit = _commitRevealSalt();

        uint256 futureBlock = block.number + 5;
        TicketLottery.Ticket memory ticket = TicketLottery.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.5 ether,
            nonce: 4,
            futureBlock: futureBlock,
            winProb: 50,
            saltCommit: commit
        });

        // sign with a random key 
        bytes32 digest = tl.getHash(ticket);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xDEAD, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.roll(futureBlock + 1);
        vm.prank(provider);
        vm.expectRevert(TicketLottery.BadSigner.selector);
        tl.claimTicket(ticket, sig);
    }

    function test_AntiDrainProtection() public {
        bytes32 commit = _commitRevealSalt();

        // 2 ETH is 40% of the 5 ETH channel, which exceeds the 25% limit
        uint256 futureBlock = block.number + 5;
        TicketLottery.Ticket memory ticket = TicketLottery.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 2 ether,
            nonce: 5,
            futureBlock: futureBlock,
            winProb: 100,
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        vm.roll(futureBlock + 1);
        vm.prank(provider);
        vm.expectRevert("Ticket exceeds limit");
        tl.claimTicket(ticket, sig);
    }

    function testFuzz_WinProbability(uint8 winProb) public {
        // only test valid range
        vm.assume(winProb >= 1 && winProb <= 100);
        if (winProb > 100) winProb = 100;

        bytes32 commit = _commitRevealSalt();

        uint256 futureBlock = block.number + 5;
        TicketLottery.Ticket memory ticket = TicketLottery.Ticket({
            channelId: 1,
            client: client,
            provider: provider,
            amount: 0.1 ether,
            nonce: uint256(keccak256(abi.encodePacked(winProb))),
            futureBlock: futureBlock,
            winProb: winProb,
            saltCommit: commit
        });

        bytes memory sig = _signTicket(ticket);

        vm.roll(futureBlock + 1);

        uint256 before = provider.balance;
        vm.prank(provider);
        tl.claimTicket(ticket, sig);

        // either won or lost but either way the nullifier is used
        bytes32 nullifier = tl._getNullifier(ticket);
        assertTrue(tl.isNullifierUsed(nullifier));
    }
}
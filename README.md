Built with Foundry | Solidity 0.8.24 

This repository is the settlement layer that handles the money part of the protocol.

Originally, this was split into three separate contracts. Now, all functionality has been unified into a single contract `Contract.sol` (containing `CipherContract`) for better gas efficiency, lower contract deployment costs, and simpler state integration.

The contract handles three main responsibilities together:

### 1. Provider Registration (Staking)

This is the identity system. Anyone who wants to be a provider has to stake some ETH (at least one ether). If a provider cheats, that deposit can be taken away (slashed). This contract handles registration, unstake requests (which enter a 7200-block unbonding period to prevent exit scams), and stake withdrawals.

### 2. Channel Management

This holds the money. Clients deposit ETH into payment channels. Each channel tracks the relationship between one client and one provider. The contract tracks how much is deposited and how much has already been spent. When a ticket wins, this contract sends the payment directly to the provider. It also handles closing channels (with an unbonding safety lock) and refunding whatever is left.

### 3. Claim Ticket (Settlement & Randomness)

Clients sign tickets off-chain with no gas fees. Providers collect these tickets and only submit the winning ones on-chain. The contract verifies the signature, checks that the ticket hasn't been used before (using a nullifier map to prevent replay attacks), generates randomness, and pays out if the ticket wins.

---

### Protocol Workflow (Step-by-Step)

Here is how a file download and payment settlement flows through the protocol:

1.  **Provider Registration**: The provider locks at least `1 ETH` in the contract using `registerProvider()`. They are now registered on-chain.
2.  **Opening a Channel**: The client opens a payment channel using `openChannel(provider)` and deposits some ETH.
3.  **Salt Commitment**: Off-chain, the provider picks a secret value (a `salt`) and hashes it. On-chain, they submit this hash using `commitSalt()`. This must be done *before* the client signs any tickets targeting that block.
4.  **Micropayment Tickets**: The client requests a chunk of a file. The provider encrypts the chunk and sends it with a cryptographic proof. The client validates the proof and sends the provider a signed `Ticket` containing:
    *   The payout `amount`
    *   A unique `nonce`
    *   A target `futureBlock`
    *   A winning probability `winProbab`
    *   The provider's `saltCommit`
5.  **Key Reveal**: The provider receives the ticket and reveals the chunk's decryption key to the client.
6.  **Salt Reveal**: Once the `futureBlock` is mined, the provider reveals their secret salt pre-image on-chain via `revealSalt()`.
7.  **Claiming Wins**: If the provider finds that a ticket is a winner (calculated using the blockhash of `futureBlock` + the revealed `salt` + the ticket's unique `nullifier`), they call `claimTicket()`.
8.  **Pull-Payment Settlement**: If `claimTicket()` verifies that the ticket is valid and has won, the ticket amount is credited to the provider's `pendingWithdrawals` mapping.
9.  **Withdrawal**: The provider calls `withdrawPending()` to safely withdraw all their accumulated payouts from the contract.

---

### How the randomness works

We use a two-step commit-reveal scheme:

1.  **Commit**: First, the provider picks a secret number called a salt. They hash it and submit the hash (`commitSalt`) to the contract. This happens before the target block is mined. The provider is now locked in — they cannot change their salt later.
2.  **Reveal**: Second, the target block gets mined. The blockhash is now public. The provider reveals their salt (`revealSalt`) by submitting the original value. The contract checks that the hash matches the earlier commitment. It also checks that the salt was committed before the block was mined.
3.  **Lottery Payout**: Finally, the contract combines the blockhash, the salt, and the ticket's unique nullifier to produce a random number. If that number falls below the ticket's win probability threshold, the ticket wins and the provider gets paid.

### Why the salt timing matters

Originally, a provider could wait until after the block was mined, then try thousands of salts off-chain until they found one that made the ticket win, and only then commit and reveal it. That completely breaks the system — the provider would win almost every time. 

Now, by enforcing that the salt must be committed *before* the target block is mined (`saltCommitBlock[ticket.saltCommit] < ticket.futureBlock`), the provider cannot predict the blockhash or manipulate the lottery outcome.

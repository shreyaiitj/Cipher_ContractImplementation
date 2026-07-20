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

### How the randomness works

We use a two-step commit-reveal scheme:

1.  **Commit**: First, the provider picks a secret number called a salt. They hash it and submit the hash (`commitSalt`) to the contract. This happens before the target block is mined. The provider is now locked in — they cannot change their salt later.
2.  **Reveal**: Second, the target block gets mined. The blockhash is now public. The provider reveals their salt (`revealSalt`) by submitting the original value. The contract checks that the hash matches the earlier commitment. It also checks that the salt was committed before the block was mined.
3.  **Lottery Payout**: Finally, the contract combines the blockhash, the salt, and the ticket's unique nullifier to produce a random number. If that number falls below the ticket's win probability threshold, the ticket wins and the provider gets paid.

### Why the salt timing matters

Originally, a provider could wait until after the block was mined, then try thousands of salts off-chain until they found one that made the ticket win, and only then commit and reveal it. That completely breaks the system — the provider would win almost every time. 

Now, by enforcing that the salt must be committed *before* the target block is mined (`saltCommitBlock[ticket.saltCommit] < ticket.futureBlock`), the provider cannot predict the blockhash or manipulate the lottery outcome.

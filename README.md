# Escrow Smart Contract

A secure escrow smart contract implementation for the Stacks blockchain, written in Clarity. This contract facilitates safe transactions between buyers and sellers with the oversight of approved escrow agents.

## Overview

The Escrow Smart Contract provides a trustless mechanism for conducting transactions where funds are held in escrow until predetermined conditions are met. The contract includes comprehensive security features including address validation, blacklisting capabilities, and agent approval systems.

## Key Features

- **Secure Fund Holding**: STX tokens are locked in the contract until transaction completion
- **Multi-Party Validation**: Requires distinct buyer, seller, and approved agent addresses
- **Fee Management**: Configurable escrow fees (default: 0.1% or 10 basis points)
- **Access Control**: Owner-managed agent approval and address blacklisting
- **Address Validation**: Comprehensive input validation and security checks
- **Status Tracking**: Transaction states (Pending, Completed, Canceled)

## Contract Architecture

### Core Data Structures

- **Escrows Map**: Stores transaction details including parties, amounts, fees, and status
- **Approved Agents**: Whitelist of authorized escrow agents
- **Blacklisted Addresses**: Security measure to prevent malicious actors
- **Valid Addresses**: Registry of validated participant addresses

### Transaction States

- `STATUS-PENDING (0)`: Transaction created, awaiting completion
- `STATUS-COMPLETED (1)`: Transaction successfully completed
- `STATUS-CANCELED (2)`: Transaction canceled and funds returned

## Public Functions

### Administrative Functions

#### `add-approved-agent(address: principal)`
- **Access**: Contract owner only
- **Purpose**: Adds an address to the approved agents list
- **Validation**: Ensures address is not reserved, blacklisted, or invalid

#### `remove-approved-agent(address: principal)`
- **Access**: Contract owner only
- **Purpose**: Removes an agent from the approved list
- **Effect**: Also removes from valid addresses registry

#### `blacklist-address(address: principal)`
- **Access**: Contract owner only
- **Purpose**: Adds an address to the blacklist
- **Effect**: Removes from valid addresses and approved agents

#### `set-escrow-fee(new-fee: uint)`
- **Access**: Contract owner only
- **Purpose**: Updates the escrow fee (maximum 10% or 1000 basis points)

#### `transfer-ownership(new-addr: principal)`
- **Access**: Contract owner only
- **Purpose**: Transfers contract ownership to a new address

### Transaction Functions

#### `create-escrow(seller-addr: principal, agent-addr: principal, amount: uint)`
- **Access**: Any valid address (becomes the buyer)
- **Purpose**: Creates a new escrow transaction
- **Process**:
  1. Validates all input addresses
  2. Ensures agent is approved
  3. Calculates and includes escrow fee
  4. Transfers total amount (amount + fee) to contract
  5. Creates escrow record with unique ID
- **Returns**: Escrow ID for tracking

## Security Features

### Address Validation
- Prevents use of contract addresses, owner address, or tx-sender as participants
- Ensures all parties are different principals
- Validates against blacklist and requires agent approval

### Input Sanitization
- Comprehensive validation of all principal parameters
- Amount validation (must be greater than 0)
- Fee calculation with overflow protection

### Access Control
- Owner-only administrative functions
- Agent approval requirement for escrow creation
- Blacklist functionality for security

## Error Codes

- `ERR-NOT-AUTHORIZED (100)`: Unauthorized access attempt
- `ERR-INVALID-AMOUNT (103)`: Invalid transaction amount
- `ERR-INVALID-SELLER (108)`: Invalid seller address
- `ERR-INVALID-AGENT (109)`: Agent not approved or invalid
- `ERR-SAME-PARTY (110)`: Duplicate addresses in transaction
- `ERR-INVALID-ADDRESS (112)`: Address validation failed
- `ERR-BLACKLISTED (113)`: Address is blacklisted

## Usage Example

```clarity
;; 1. Contract owner adds an approved agent
(contract-call? .escrow add-approved-agent 'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7)

;; 2. Buyer creates escrow (1000 STX to seller via agent)
(contract-call? .escrow create-escrow 
    'SP1H1733V5MZ3SZ9XRW9FKYGEZT0JDGEB8Y634C7R    ;; seller
    'SP2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKNRV9EJ7    ;; agent
    u1000000)                                        ;; 1000 STX (in microSTX)
```

## Fee Structure

- Default fee: 10 basis points (0.1%)
- Example: 1000 STX transaction = 1 STX fee
- Maximum fee: 1000 basis points (10%)
- Fees are calculated and transferred automatically during escrow creation

## Security Considerations

1. **Agent Trust**: Only use approved agents from trusted sources
2. **Address Verification**: Ensure all addresses are correct before transaction
3. **Amount Limits**: Consider transaction size and associated risks
4. **Contract Upgrades**: Monitor for contract updates and security patches

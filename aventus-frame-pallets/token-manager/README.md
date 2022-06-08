# Token Manager

A module for handling all tokens are managed on the AvN. It is used within the AvN for lifting, transferring and lowering back to Ethereum Ethereum-based fungible tokens.

- Module
- Call
- Storage
- Config
- Event

## Overview

---

The token-manager pallet handles how tokens are managed on the AvN. It keeps track of the account balance of the individual tokens, the nonce of the account for all tokens held by the account, etc. Because the, AvN is designed to be a L2, all tokens must be lifted from a compatible L1.  

## Interface

---

### Dispatchable Functions

- `proxy`
- `signed_transfer`
- `lower`
- `signed_lower`

## AvN Pallet Dependencies

- `pallet_avn`

<!-- language: none -->

    This pallet currently does not compile as the pallet it's dependent on is yet to be made available. Check back soon!

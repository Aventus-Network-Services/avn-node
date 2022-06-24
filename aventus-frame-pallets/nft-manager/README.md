# NFT Manager

A module for minting and managing NFTs.

- Module
- Call
- Storage
- Event

## Overview

---

This pallet integrates NFTs into the Aventus blockchain on an infrastructure level allowing for the minting of NFTs without smart contracts. This pallet is used for the minting, listing and transferring of NFTs, including batch NFTs.

## Interface

---

### Dispatchable Functions

- `mint_single_nft`
- `signed_mint_single_nft`
- `list_nft_open_for_sale`
- `signed_list_nft_open_for_sale`
- `signed_transfer_fiat_nft`
- `signed_cancel_list_fiat_nft`
- `signed_create_batch`
- `signed_mint_batch_nft`
- `signed_list_batch_for_sale`
- `signed_end_batch_sale`

## AvN Pallet Dependencies

- `pallet_avn`
- `ethereum-events`

<!-- language: none -->

    This pallet currently does not compile as the pallet it's dependent on is yet to be made available. Check back soon!

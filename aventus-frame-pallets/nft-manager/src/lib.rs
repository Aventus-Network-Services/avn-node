// This file is part of Aventus.
// Copyright (C) 2022 Aventus Network Services (UK) Ltd.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! # nft-manager pallet

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use core::convert::TryInto;
use frame_support::{
    decl_error, decl_event, decl_module, decl_storage,
    dispatch::{
        DispatchErrorWithPostInfo, DispatchResult, DispatchResultWithPostInfo, Dispatchable,
    },
    ensure,
    traits::IsSubType,
    weights::PostDispatchInfo,
    Parameter,
};
use frame_system::{self as system, ensure_signed};
use pallet_avn::{self as avn};
use pallet_ethereum_events::{self as ethereum_events, ProcessedEventsChecker};
use sp_avn_common::{
    event_types::{
        EthEvent, EthEventId, EventData, NftCancelListingData, NftTransferToData,
        ProcessedEventHandler,
    },
    CallDecoder, InnerCallValidator, Proof,
};
use sp_core::{H160, H256, U256};
use sp_io::hashing::keccak_256;
use sp_runtime::traits::{Hash, IdentifyAccount, Member, Verify};
use sp_std::prelude::*;

pub mod nft_data;
use crate::nft_data::*;

pub mod default_weights;
pub use default_weights::WeightInfo;

const SINGLE_NFT_ID_CONTEXT: &'static [u8; 1] = b"A";
#[allow(dead_code)]
const BATCH_NFT_ID_CONTEXT: &'static [u8; 1] = b"B";
pub const SIGNED_MINT_SINGLE_NFT_CONTEXT: &'static [u8] =
    b"authorization for mint single nft operation";
pub const SIGNED_LIST_NFT_OPEN_FOR_SALE_CONTEXT: &'static [u8] =
    b"authorization for list nft open for sale operation";
pub const SIGNED_TRANSFER_FIAT_NFT_CONTEXT: &'static [u8] =
    b"authorization for transfer fiat nft operation";
pub const SIGNED_CANCEL_LIST_FIAT_NFT_CONTEXT: &'static [u8] =
    b"authorization for cancel list fiat nft for sale operation";

const MAX_NUMBER_OF_ROYALTIES: u32 = 50;

pub trait Config: system::Config + avn::Config {
    /// The overarching event type.
    type Event: From<Event<Self>> + Into<<Self as system::Config>::Event>;

    /// The overarching call type.
    type Call: Parameter
        + Dispatchable<Origin = <Self as frame_system::Config>::Origin>
        + IsSubType<Call<Self>>
        + From<Call<Self>>;

    type ProcessedEventsChecker: ProcessedEventsChecker;

    /// A type that can be used to verify signatures
    type Public: IdentifyAccount<AccountId = Self::AccountId>;

    /// The signature type used by accounts/transactions.
    type Signature: Verify<Signer = Self::Public>
        + Member
        + Decode
        + Encode
        + From<sp_core::sr25519::Signature>;

    type WeightInfo: WeightInfo;
}

pub type NftId = U256;
pub type NftInfoId = U256;
pub type NftBatchId = U256;
pub type NftUniqueId = U256;
decl_event!(
    pub enum Event<T>
    where
        AccountId = <T as system::Config>::AccountId,
        MinterTier1Address = H160,
        TotalSupply = u64,
        Relayer = <T as system::Config>::AccountId,
        Hash = <T as system::Config>::Hash,
        OpId = u64,
    {
        SingleNftMinted(NftId, AccountId, MinterTier1Address),
        BatchNftMinted(NftId, NftBatchId, AccountId),
        NewBatchSetup(NftBatchId, MinterTier1Address, TotalSupply),
        NftOpenForSale(NftId, NftSaleType),
        /// EthNftTransfer(NftId, NewOwnerAccountId, NftSaleType, OpId, EthEventId),
        EthNftTransfer(NftId, AccountId, NftSaleType, OpId, EthEventId),
        /// FiatNftTransfer(NftId, SenderAccountId, NewOwnerAccountId, NftSaleType, NftNonce)
        FiatNftTransfer(NftId, AccountId, AccountId, NftSaleType, OpId),
        /// CancelSingleEthNftListing(NftId, NftSaleType, OpId, EthEventId),
        CancelSingleEthNftListing(NftId, NftSaleType, OpId, EthEventId),
        /// CancelSingleFiatNftListing(NftId, NftSaleType, NftNonce)
        CancelSingleFiatNftListing(NftId, NftSaleType, OpId),
        CallDispatched(Relayer, Hash),
    }
);

decl_error! {
    pub enum Error for Module<T: Config> {
        NftAlreadyExists,
        /// When specifying rates, parts_per_million must not be greater than 1 million
        RoyaltyRateIsNotValid,
        /// When specifying rates, sum of parts_per_millions must not be greater than 1 million
        TotalRoyaltyRateIsNotValid,
        T1AuthorityIsMandatory,
        ExternalRefIsMandatory,
        /// The external reference is already used
        ExternalRefIsAlreadyInUse,
        /// There is not data associated with an nftInfoId
        NftInfoMissing,
        NftIdDoesNotExist,
        UnsupportedMarket,
        /// Signed extrinsic with a proof must be called by the signer of the proof
        SenderIsNotSigner,
        SenderIsNotOwner,
        NftAlreadyListed,
        NftIsLocked,
        NftNotListedForSale,
        NftNotListedForEthereumSale,
        NftNotListedForFiatSale,
        NoTier1EventForNftOperation,
        /// The op_id did not match the nft token nonce for the operation
        NftNonceMismatch,
        UnauthorizedTransaction,
        UnauthorizedProxyTransaction,
        UnauthorizedSignedLiftNftOpenForSaleTransaction,
        UnauthorizedSignedMintSingleNftTransaction,
        UnauthorizedSignedTransferFiatNftTransaction,
        UnauthorizedSignedCancelListFiatNftTransaction,
        TransactionNotSupported,
        TransferToIsMandatory
    }
}

decl_storage! {
    trait Store for Module<T: Config> as NftManager {
        /// A mapping between NFT Id and data
        pub Nfts get(fn nfts): map hasher(blake2_128_concat) NftId => Nft<T::AccountId>;
        /// A mapping between NFT info Id and info data
        pub NftInfos get(fn nft_infos): map hasher(blake2_128_concat) NftInfoId => NftInfo;
        /// A mapping between the external batch id and its nft Ids
        pub NftBatches get(fn nft_batches): map hasher(blake2_128_concat) NftBatchId => Vec<NftId>;
        /// A mapping between the external batch id and its corresponding NtfInfoId
        pub BatchInfoId get(fn batch_info_id): map hasher(blake2_128_concat) NftBatchId => NftInfoId;
        /// A mapping between an ExternalRef and a flag to show that an NFT has used it
        pub UsedExternalReferences get(fn is_external_ref_used) : map hasher(blake2_128_concat) Vec<u8> => bool;
        /// The Id that will be used when creating the new NftInfo record
        pub NextInfoId get(fn next_info_id): NftInfoId;
        /// The Id that will be used when creating the new single Nft
        pub NextSingleNftUniqueId get(fn next_unique_id): U256;
        /// A mapping that keeps all the nfts that are open to sale in a specific market
        pub NftOpenForSale get(fn get_nft_open_for_sale_on): map hasher(blake2_128_concat) NftId => NftSaleType;
    }
}

decl_module! {
    pub struct Module<T: Config> for enum Call where origin: T::Origin {
        type Error = Error<T>;

        fn deposit_event() = default;

        /// Mint a single NFT
        //
        // # <weight>
        //  Keys:
        //   R - number of royalties
        //   - 1 iteration through all royalties O(R).
        //   - 3 DbReads O(1).
        //   - 3 DbWrites O(1).
        //   - 1 Event emitted O(1).
        // Total Complexity: O(1 + R)
        // # </weight>
        #[weight = T::WeightInfo::mint_single_nft(MAX_NUMBER_OF_ROYALTIES)]
        fn mint_single_nft(origin,
            unique_external_ref: Vec<u8>,
            royalties: Vec<Royalty>,
            t1_authority: H160) -> DispatchResult
        {
            let sender = ensure_signed(origin)?;
            Self::validate_mint_single_nft_request(&unique_external_ref, &royalties, t1_authority)?;

            // We trust the input for the value of t1_authority
            let nft_id = Self::generate_nft_id_single_mint(&t1_authority, Self::get_nft_unique_id_and_advance());
            ensure!(Nfts::<T>::contains_key(&nft_id) == false, Error::<T>::NftAlreadyExists);

            // No errors allowed after this point because `get_info_id_and_advance` mutates storage
            let info_id = Self::get_info_id_and_advance();
            let (nft, info) = Self::insert_nft_into_chain(
                info_id, royalties, t1_authority, nft_id, unique_external_ref, sender
            );

            Self::deposit_event(RawEvent::SingleNftMinted(nft.nft_id, nft.owner, info.t1_authority));

            Ok(())
        }

        /// Mint a single NFT signed by nft owner
        //
        // # <weight>
        //  Keys: R - number of royalties
        //  - 2 * Iteration through all royalties: O(R).
        //  - DbReads: Nfts, NextSingleNftUniqueId, UsedExternalReferences, NextInfoId: O(1)
        //  - DbWrites: NextSingleNftUniqueId, NextInfoId, NftInfos, Nfts, UsedExternalReferences: O(1)
        //  - One codec encode operation: O(1).
        //  - One signature verification operation: O(1).
        //  - Event Emitted: O(1)
        //  Total Complexity: `O(1 + R)`
        // # </weight>
        #[weight = T::WeightInfo::signed_mint_single_nft(MAX_NUMBER_OF_ROYALTIES)]
        fn signed_mint_single_nft(origin,
            proof: Proof<T::Signature, T::AccountId>,
            unique_external_ref: Vec<u8>,
            royalties: Vec<Royalty>,
            t1_authority: H160) -> DispatchResult
        {
            let sender = ensure_signed(origin)?;
            ensure!(sender == proof.signer, Error::<T>::SenderIsNotSigner);
            Self::validate_mint_single_nft_request(&unique_external_ref, &royalties, t1_authority)?;

            let signed_payload = Self::encode_mint_single_nft_params(&proof, &unique_external_ref, &royalties, &t1_authority);
            ensure!(
                Self::verify_signature(&proof, &signed_payload.as_slice()).is_ok(),
                Error::<T>::UnauthorizedSignedMintSingleNftTransaction
            );

            // We trust the input for the value of t1_authority
            let nft_id = Self::generate_nft_id_single_mint(&t1_authority, Self::get_nft_unique_id_and_advance());
            ensure!(Nfts::<T>::contains_key(&nft_id) == false, Error::<T>::NftAlreadyExists);

            // No errors allowed after this point because `get_info_id_and_advance` mutates storage
            let info_id = Self::get_info_id_and_advance();
            let (nft, info) = Self::insert_nft_into_chain(
                info_id, royalties, t1_authority, nft_id, unique_external_ref, proof.signer
            );

            Self::deposit_event(RawEvent::SingleNftMinted(nft.nft_id, nft.owner, info.t1_authority));

            Ok(())
        }

        /// List an nft open for sale
        //
        // # <weight>
        //  - DbReads: 2 * Nfts, NftOpenForSale: O(1)
        //  - DbWrites: Nfts, NftOpenForSale: O(1)
        //  - Event Emitted: O(1)
        //  Total Complexity: `O(1)`
        // # </weight>
        #[weight = T::WeightInfo::list_nft_open_for_sale()]
        fn list_nft_open_for_sale(origin,
            nft_id: NftId,
            market: NftSaleType,
        ) -> DispatchResult
        {
            let sender = ensure_signed(origin)?;
            Self::validate_open_for_sale_request(sender, nft_id, market.clone())?;
            Self::open_nft_for_sale(&nft_id, &market);
            Self::deposit_event(RawEvent::NftOpenForSale(nft_id, market));
            Ok(())
        }

        /// List an nft open for sale by a relayer
        //
        // # <weight>
        //  - DbReads: 2 * Nfts, NftOpenForSale: O(1)
        //  - DbWrites: Nfts, NftOpenForSale: O(1)
        //  - One codec encode operation: O(1).
        //  - One signature verification operation: O(1).
        //  - Event Emitted: O(1)
        //  Total Complexity: `O(1)`
        // # </weight>
        #[weight = T::WeightInfo::signed_list_nft_open_for_sale()]
        fn signed_list_nft_open_for_sale(origin,
            proof: Proof<T::Signature, T::AccountId>,
            nft_id: NftId,
            market: NftSaleType,
        ) -> DispatchResult
        {
            let sender = ensure_signed(origin)?;
            ensure!(sender == proof.signer, Error::<T>::SenderIsNotSigner);
            Self::validate_open_for_sale_request(sender, nft_id, market.clone())?;

            let signed_payload = Self::encode_list_nft_for_sale_params(&proof, &nft_id, &market);
            ensure!(
                Self::verify_signature(&proof, &signed_payload.as_slice()).is_ok(),
                Error::<T>::UnauthorizedSignedLiftNftOpenForSaleTransaction
            );

            Self::open_nft_for_sale(&nft_id, &market);
            Self::deposit_event(RawEvent::NftOpenForSale(nft_id, market));

            Ok(())
        }

        /// Transfer a nft open for sale on fiat market to a new owner by a relayer
        //
        // # <weight>
        //  - DbReads: 2 * Nfts, 4* NftOpenForSale: O(1)
        //  - DbWrites: Nfts, NftOpenForSale : O(1)
        //  - One codec encode operation: O(1).
        //  - One signature verification operation: O(1).
        //  - Event Emitted: FiatNftTransfer: O(1)
        //  Total Complexity: `O(1)`
        // # </weight>
        #[weight = T::WeightInfo::signed_transfer_fiat_nft()]
        fn signed_transfer_fiat_nft(origin,
            proof: Proof<T::Signature, T::AccountId>,
            nft_id: U256,
            t2_transfer_to_public_key: H256,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            ensure!(sender == proof.signer, Error::<T>::SenderIsNotSigner);
            ensure!(t2_transfer_to_public_key.is_zero() == false, Error::<T>::TransferToIsMandatory);
            Self::validate_nft_open_for_fiat_sale(sender.clone(), nft_id)?;

            let nft = Self::nfts(nft_id);
            let signed_payload = Self::encode_transfer_fiat_nft_params(&proof, &nft_id, &t2_transfer_to_public_key);
            ensure!(
                Self::verify_signature(&proof, &signed_payload.as_slice()).is_ok(),
                Error::<T>::UnauthorizedSignedTransferFiatNftTransaction
            );

            let new_nft_owner = T::AccountId::decode(&mut t2_transfer_to_public_key.as_bytes())
                .expect("32 bytes will always decode into an AccountId");
            let market = Self::get_nft_open_for_sale_on(nft_id);

            Self::transfer_nft(&nft_id, new_nft_owner.clone())?;
            Self::deposit_event(RawEvent::FiatNftTransfer(nft_id, sender, new_nft_owner, market, nft.nonce));

            Ok(())
        }

        /// Cancel a nft open for sale on fiat market by a relayer
        //
        // # <weight>
        //  - DbReads: 2* Nfts, 4 * NftOpenForSale: O(1)
        //  - DbWrites: Nfts, NftOpenForSale: O(1)
        //  - One codec encode operation: O(1).
        //  - One signature verification operation: O(1).
        //  - Event Emitted: CancelSingleFiatNftListing: O(1)
        //  Total Complexity: `O(1)`
        // # </weight>
        #[weight = T::WeightInfo::signed_cancel_list_fiat_nft()]
        fn signed_cancel_list_fiat_nft(origin,
            proof: Proof<T::Signature, T::AccountId>,
            nft_id: U256,
        ) -> DispatchResult {
            let sender = ensure_signed(origin)?;
            ensure!(sender == proof.signer, Error::<T>::SenderIsNotSigner);
            Self::validate_nft_open_for_fiat_sale(sender.clone(), nft_id)?;

            let nft = Self::nfts(nft_id);
            let signed_payload = Self::encode_cancel_list_fiat_nft_params(&proof, &nft_id);
            ensure!(
                Self::verify_signature(&proof, &signed_payload.as_slice()).is_ok(),
                Error::<T>::UnauthorizedSignedCancelListFiatNftTransaction
            );

            let market = Self::get_nft_open_for_sale_on(nft_id);

            Self::unlist_nft_for_sale(nft_id)?;
            Self::deposit_event(RawEvent::CancelSingleFiatNftListing(nft_id, market, nft.nonce));

            Ok(())
        }

        /// This extrinsic allows a relayer to dispatch a call from this pallet for a sender.
        /// Currently only `signed_list_nft_open_for_sale` is allowed
        ///
        /// As a general rule, every function that can be proxied should follow this convention:
        /// - its first argument (after origin) should be a public verification key and a signature
        //
        // # <weight>
        // - One get proof operation: O(1)
        // - One hash of operation: O(1)
        // - One signed transfer operation: O(1)
        // - One event emitted: O(1)
        // Total Complexity: `O(1)`
        // # </weight>
        #[weight = T::WeightInfo::proxy_signed_list_nft_open_for_sale()
            .max(T::WeightInfo::proxy_signed_mint_single_nft(MAX_NUMBER_OF_ROYALTIES))
            .max(T::WeightInfo::proxy_signed_transfer_fiat_nft())
            .max(T::WeightInfo::proxy_signed_cancel_list_fiat_nft())]
        pub fn proxy(origin, call: Box<<T as Config>::Call>) -> DispatchResultWithPostInfo {
            let relayer = ensure_signed(origin)?;

            let proof = Self::get_proof(&*call)?;
            ensure!(relayer == proof.relayer, Error::<T>::UnauthorizedProxyTransaction);

            let call_hash: T::Hash = T::Hashing::hash_of(&call);
            call.clone().dispatch(frame_system::RawOrigin::Signed(proof.signer).into()).map(|_| ()).map_err(|e| e.error)?;
            Self::deposit_event(RawEvent::CallDispatched(relayer, call_hash));

            return Self::get_dispatch_result_with_post_info(call);
        }
    }
}

impl<T: Config> Module<T> {
    fn validate_mint_single_nft_request(
        unique_external_ref: &Vec<u8>,
        royalties: &Vec<Royalty>,
        t1_authority: H160,
    ) -> DispatchResult {
        ensure!(
            unique_external_ref.len() > 0,
            Error::<T>::ExternalRefIsMandatory
        );
        ensure!(
            Self::is_external_ref_used(&unique_external_ref) == false,
            Error::<T>::ExternalRefIsAlreadyInUse
        );
        ensure!(
            t1_authority.is_zero() == false,
            Error::<T>::T1AuthorityIsMandatory
        );

        // TODO: Review this comment https://github.com/Aventus-Network-Services/avn-tier2/pull/763#discussion_r617360380
        let invalid_rates_found = royalties.iter().any(|r| !r.rate.is_valid());
        ensure!(
            invalid_rates_found == false,
            Error::<T>::RoyaltyRateIsNotValid
        );

        let rate_total = royalties
            .iter()
            .map(|r| r.rate.parts_per_million)
            .sum::<u32>();
        ensure!(
            rate_total <= 1_000_000,
            Error::<T>::TotalRoyaltyRateIsNotValid
        );

        Ok(())
    }

    fn validate_open_for_sale_request(
        sender: T::AccountId,
        nft_id: NftId,
        market: NftSaleType,
    ) -> DispatchResult {
        ensure!(
            market != NftSaleType::Unknown,
            Error::<T>::UnsupportedMarket
        );
        ensure!(
            <Nfts<T>>::contains_key(&nft_id) == true,
            Error::<T>::NftIdDoesNotExist
        );
        ensure!(
            <NftOpenForSale>::contains_key(&nft_id) == false,
            Error::<T>::NftAlreadyListed
        );

        let nft = Self::nfts(nft_id);
        ensure!(nft.owner == sender, Error::<T>::SenderIsNotOwner);
        ensure!(nft.is_locked == false, Error::<T>::NftIsLocked);

        Ok(())
    }

    fn validate_nft_open_for_fiat_sale(sender: T::AccountId, nft_id: NftId) -> DispatchResult {
        ensure!(
            <NftOpenForSale>::contains_key(nft_id) == true,
            Error::<T>::NftNotListedForSale
        );
        ensure!(
            Self::get_nft_open_for_sale_on(nft_id) == NftSaleType::Fiat,
            Error::<T>::NftNotListedForFiatSale
        );

        let nft = Self::nfts(nft_id);
        ensure!(nft.owner == sender, Error::<T>::SenderIsNotOwner);
        ensure!(nft.is_locked == false, Error::<T>::NftIsLocked);

        Ok(())
    }

    /// Returns the next available info id and increases the storage item by 1
    fn get_info_id_and_advance() -> NftInfoId {
        let id = Self::next_info_id();
        <NextInfoId>::mutate(|n| *n += U256::from(1));

        return id;
    }

    #[allow(dead_code)]
    fn get_nft_info_for_batch(batch_id: &NftBatchId) -> Result<Option<NftInfo>, Error<T>> {
        if BatchInfoId::contains_key(&batch_id) == false {
            return Ok(None);
        }

        let existing_nft_info_id = BatchInfoId::get(&batch_id);
        ensure!(
            NftInfos::contains_key(&existing_nft_info_id),
            Error::<T>::NftInfoMissing
        );

        return Ok(Some(NftInfos::get(existing_nft_info_id)));
    }

    #[allow(dead_code)]
    fn nft_info_data_match(
        info: &NftInfo,
        royalties: &Vec<Royalty>,
        minter: &H160,
        total_supply: &u64,
    ) -> bool {
        return (royalties, minter, total_supply).encode()
            == (info.royalties.clone(), info.t1_authority, info.total_supply).encode();
    }

    fn get_nft_unique_id_and_advance() -> NftUniqueId {
        let id = Self::next_unique_id();
        <NextSingleNftUniqueId>::mutate(|n| *n += U256::from(1));

        return id;
    }

    fn insert_nft_into_chain(
        info_id: NftInfoId,
        royalties: Vec<Royalty>,
        t1_authority: H160,
        nft_id: NftId,
        unique_external_ref: Vec<u8>,
        owner: T::AccountId,
    ) -> (Nft<T::AccountId>, NftInfo) {
        let info = NftInfo::new(info_id, royalties, t1_authority);
        let nft = Nft::new(nft_id, info_id, unique_external_ref, owner);

        <NftInfos>::insert(info.info_id, &info);
        <Nfts<T>>::insert(nft.nft_id, &nft);

        <UsedExternalReferences>::insert(&nft.unique_external_ref, true);
        return (nft, info);
    }

    fn open_nft_for_sale(nft_id: &NftId, market: &NftSaleType) {
        <NftOpenForSale>::insert(nft_id, market);
        <Nfts<T>>::mutate(nft_id, |nft| {
            nft.nonce += 1u64;
        });
    }

    /// The NftId for a single mint is calculated by this formula: uint256(keccak256(“A”, contract_address, unique_id))
    // TODOs: Confirm that the data are packed the same as encodePacked.
    // TODOs: Confirm that which data needs to be in BE format.
    fn generate_nft_id_single_mint(contract: &H160, unique_id: NftUniqueId) -> U256 {
        let mut data_to_hash = SINGLE_NFT_ID_CONTEXT.to_vec();

        data_to_hash.append(&mut contract[..].to_vec());

        let mut unique_id_be = [0u8; 32];
        unique_id.to_big_endian(&mut unique_id_be);
        data_to_hash.append(&mut unique_id_be.to_vec());

        let hash = keccak_256(&data_to_hash);

        return U256::from(hash);
    }

    /// The NftId for a Batch Sale is calculated by this formula: uint256(keccak256(“B”, contract_address, batchId, unique_id))
    // TODOs: Confirm that the data are packed the same as encodePacked.
    // TODOs: Confirm that which data needs to be in BE format.
    #[allow(dead_code)]
    fn generate_nft_id_batch_sale(contract: &H160, batch_id: &U256, sales_index: &u64) -> U256 {
        let mut data_to_hash = BATCH_NFT_ID_CONTEXT.to_vec();

        data_to_hash.append(&mut contract[..].to_vec());

        let mut batch_id_be = [0u8; 32];
        batch_id.to_big_endian(&mut batch_id_be);
        data_to_hash.append(&mut batch_id_be.to_vec());

        data_to_hash.append(&mut sales_index.to_be_bytes().to_vec());

        let hash = keccak_256(&data_to_hash);

        return U256::from(hash);
    }

    fn remove_listing_from_open_for_sale(nft_id: &NftId) -> DispatchResult {
        ensure!(
            <NftOpenForSale>::contains_key(nft_id) == true,
            Error::<T>::NftNotListedForSale
        );
        <NftOpenForSale>::remove(nft_id);
        Ok(())
    }

    fn transfer_eth_nft(event_id: &EthEventId, data: &NftTransferToData) -> DispatchResult {
        let market = Self::get_nft_open_for_sale_on(data.nft_id);
        ensure!(
            market == NftSaleType::Ethereum,
            Error::<T>::NftNotListedForEthereumSale
        );
        ensure!(
            data.op_id == Self::nfts(data.nft_id).nonce,
            Error::<T>::NftNonceMismatch
        );
        ensure!(
            T::ProcessedEventsChecker::check_event(event_id),
            Error::<T>::NoTier1EventForNftOperation
        );

        let new_nft_owner = T::AccountId::decode(&mut data.t2_transfer_to_public_key.as_bytes())
            .expect("32 bytes will always decode into an AccountId");
        Self::transfer_nft(&data.nft_id, new_nft_owner.clone())?;
        Self::deposit_event(RawEvent::EthNftTransfer(
            data.nft_id,
            new_nft_owner,
            market,
            data.op_id,
            event_id.clone(),
        ));

        Ok(())
    }

    fn transfer_nft(nft_id: &NftId, new_nft_owner: T::AccountId) -> DispatchResult {
        Self::remove_listing_from_open_for_sale(nft_id)?;
        <Nfts<T>>::mutate(nft_id, |nft| {
            nft.owner = new_nft_owner.clone();
            nft.nonce += 1u64;
        });

        Ok(())
    }

    fn cancel_eth_nft_listing(
        event_id: &EthEventId,
        data: &NftCancelListingData,
    ) -> DispatchResult {
        let market = Self::get_nft_open_for_sale_on(data.nft_id);
        ensure!(
            market == NftSaleType::Ethereum,
            Error::<T>::NftNotListedForEthereumSale
        );
        ensure!(
            data.op_id == Self::nfts(data.nft_id).nonce,
            Error::<T>::NftNonceMismatch
        );
        ensure!(
            T::ProcessedEventsChecker::check_event(event_id),
            Error::<T>::NoTier1EventForNftOperation
        );

        Self::unlist_nft_for_sale(data.nft_id)?;
        Self::deposit_event(RawEvent::CancelSingleEthNftListing(
            data.nft_id,
            market,
            data.op_id,
            event_id.clone(),
        ));

        Ok(())
    }

    fn unlist_nft_for_sale(nft_id: NftId) -> DispatchResult {
        Self::remove_listing_from_open_for_sale(&nft_id)?;
        <Nfts<T>>::mutate(nft_id, |nft| {
            nft.nonce += 1u64;
        });

        Ok(())
    }

    fn verify_signature(
        proof: &Proof<T::Signature, T::AccountId>,
        signed_payload: &[u8],
    ) -> Result<(), Error<T>> {
        match proof.signature.verify(signed_payload, &proof.signer) {
            true => Ok(()),
            false => Err(<Error<T>>::UnauthorizedTransaction.into()),
        }
    }

    fn get_dispatch_result_with_post_info(
        call: Box<<T as Config>::Call>,
    ) -> DispatchResultWithPostInfo {
        match call.is_sub_type() {
            Some(call) => {
                let final_weight = match call {
                    Call::signed_mint_single_nft(_, _, royalties, _) => {
                        T::WeightInfo::proxy_signed_mint_single_nft(
                            royalties.len().try_into().unwrap(),
                        )
                    }
                    Call::signed_list_nft_open_for_sale(_, _, _) => {
                        T::WeightInfo::proxy_signed_list_nft_open_for_sale()
                    }
                    Call::signed_transfer_fiat_nft(_, _, _) => {
                        T::WeightInfo::proxy_signed_transfer_fiat_nft()
                    }
                    Call::signed_cancel_list_fiat_nft(_, _) => {
                        T::WeightInfo::proxy_signed_cancel_list_fiat_nft()
                    }
                    _ => T::WeightInfo::proxy_signed_list_nft_open_for_sale().max(
                        T::WeightInfo::proxy_signed_mint_single_nft(MAX_NUMBER_OF_ROYALTIES),
                    ),
                };
                Ok(Some(final_weight).into())
            }
            None => Err(DispatchErrorWithPostInfo {
                error: Error::<T>::TransactionNotSupported.into(),
                post_info: PostDispatchInfo {
                    actual_weight: None, // None which stands for the worst case static weight
                    pays_fee: Default::default(),
                },
            }),
        }
    }

    fn encode_mint_single_nft_params(
        proof: &Proof<T::Signature, T::AccountId>,
        unique_external_ref: &Vec<u8>,
        royalties: &Vec<Royalty>,
        t1_authority: &H160,
    ) -> Vec<u8> {
        return (
            SIGNED_MINT_SINGLE_NFT_CONTEXT,
            &proof.relayer,
            unique_external_ref,
            royalties,
            t1_authority,
        )
            .encode();
    }

    fn encode_list_nft_for_sale_params(
        proof: &Proof<T::Signature, T::AccountId>,
        nft_id: &NftId,
        market: &NftSaleType,
    ) -> Vec<u8> {
        let nft = Self::nfts(nft_id);
        return (
            SIGNED_LIST_NFT_OPEN_FOR_SALE_CONTEXT,
            &proof.relayer,
            nft_id,
            market,
            nft.nonce,
        )
            .encode();
    }

    fn encode_transfer_fiat_nft_params(
        proof: &Proof<T::Signature, T::AccountId>,
        nft_id: &NftId,
        recipient: &H256,
    ) -> Vec<u8> {
        let nft = Self::nfts(nft_id);
        return (
            SIGNED_TRANSFER_FIAT_NFT_CONTEXT,
            &proof.relayer,
            nft_id,
            recipient,
            nft.nonce,
        )
            .encode();
    }

    fn encode_cancel_list_fiat_nft_params(
        proof: &Proof<T::Signature, T::AccountId>,
        nft_id: &NftId,
    ) -> Vec<u8> {
        let nft = Self::nfts(nft_id);
        return (
            SIGNED_CANCEL_LIST_FIAT_NFT_CONTEXT,
            &proof.relayer,
            nft_id,
            nft.nonce,
        )
            .encode();
    }

    fn get_encoded_call_param(
        call: &<T as Config>::Call,
    ) -> Option<(&Proof<T::Signature, T::AccountId>, Vec<u8>)> {
        let call = match call.is_sub_type() {
            Some(call) => call,
            None => return None,
        };

        match call {
            Call::signed_mint_single_nft(proof, external_ref, royalties, t1_authority) => {
                return Some((
                    proof,
                    Self::encode_mint_single_nft_params(
                        proof,
                        external_ref,
                        royalties,
                        t1_authority,
                    ),
                ))
            }
            Call::signed_list_nft_open_for_sale(proof, nft_id, market) => {
                return Some((
                    proof,
                    Self::encode_list_nft_for_sale_params(proof, nft_id, market),
                ))
            }
            Call::signed_transfer_fiat_nft(proof, nft_id, recipient) => {
                return Some((
                    proof,
                    Self::encode_transfer_fiat_nft_params(proof, nft_id, recipient),
                ))
            }
            Call::signed_cancel_list_fiat_nft(proof, nft_id) => {
                return Some((
                    proof,
                    Self::encode_cancel_list_fiat_nft_params(proof, nft_id),
                ))
            }
            _ => return None,
        }
    }
}

impl<T: Config + ethereum_events::Config> ProcessedEventHandler for Module<T> {
    fn on_event_processed(event: &EthEvent) -> DispatchResult {
        return match &event.event_data {
            EventData::LogNftTransferTo(data) => Self::transfer_eth_nft(&event.event_id, data),
            EventData::LogNftCancelListing(data) => {
                Self::cancel_eth_nft_listing(&event.event_id, data)
            }
            _ => Ok(()),
        };
    }
}

impl<T: Config> CallDecoder for Module<T> {
    type AccountId = T::AccountId;
    type Signature = <T as Config>::Signature;
    type Error = Error<T>;
    type Call = <T as Config>::Call;

    fn get_proof(
        call: &Self::Call,
    ) -> Result<Proof<Self::Signature, Self::AccountId>, Self::Error> {
        let call = match call.is_sub_type() {
            Some(call) => call,
            None => return Err(Error::TransactionNotSupported),
        };

        match call {
            Call::signed_mint_single_nft(
                proof,
                _unique_external_ref,
                _royalties,
                _t1_authority,
            ) => return Ok(proof.clone()),
            Call::signed_list_nft_open_for_sale(proof, _nft_id, _market) => {
                return Ok(proof.clone())
            }
            Call::signed_transfer_fiat_nft(proof, _nft_id, _t2_transfer_to_public_key) => {
                return Ok(proof.clone())
            }
            Call::signed_cancel_list_fiat_nft(proof, _nft_id) => return Ok(proof.clone()),
            _ => return Err(Error::TransactionNotSupported),
        }
    }
}

impl<T: Config> InnerCallValidator for Module<T> {
    type Call = <T as Config>::Call;

    fn signature_is_valid(call: &Box<Self::Call>) -> bool {
        if let Some((proof, signed_payload)) = Self::get_encoded_call_param(call) {
            return Self::verify_signature(&proof, &signed_payload.as_slice()).is_ok();
        }

        return false;
    }
}

#[cfg(test)]
#[path = "tests/mock.rs"]
mod mock;

#[cfg(test)]
#[path = "../../avn/src/tests/extension_builder.rs"]
pub mod extension_builder;

#[cfg(test)]
#[path = "tests/single_mint_nft_tests.rs"]
pub mod single_mint_nft_tests;

#[cfg(test)]
#[path = "tests/open_for_sale_tests.rs"]
pub mod open_for_sale_tests;

#[cfg(test)]
#[path = "tests/proxy_signed_mint_single_nft_tests.rs"]
pub mod proxy_signed_mint_single_nft_tests;

#[cfg(test)]
#[path = "tests/proxy_signed_list_nft_open_for_sale_tests.rs"]
pub mod proxy_signed_list_nft_open_for_sale_tests;

#[cfg(test)]
#[path = "tests/proxy_signed_transfer_fiat_nft_tests.rs"]
pub mod proxy_signed_transfer_fiat_nft_tests;

#[cfg(test)]
#[path = "tests/proxy_signed_cancel_list_fiat_nft_tests.rs"]
pub mod proxy_signed_cancel_list_fiat_nft_tests;

#[cfg(test)]
#[path = "tests/transfer_to_tests.rs"]
pub mod transfer_to_tests;

#[cfg(test)]
#[path = "tests/cancel_single_nft_listing_tests.rs"]
pub mod cancel_single_nft_listing_tests;

mod benchmarking;

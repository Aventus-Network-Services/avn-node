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

//! nft-manager pallet benchmarking.

#![cfg(feature = "runtime-benchmarks")]

use super::*;
use frame_benchmarking::benchmarks;
use frame_system::{EventRecord, RawOrigin};
use hex_literal::hex;
use pallet_avn::{self as avn};
use sp_core::H256;
use sp_runtime::RuntimeAppPublic;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

fn assert_last_event<T: Config>(generic_event: <T as Config>::Event) {
    assert_last_nth_event::<T>(generic_event, 1);
}

fn assert_last_nth_event<T: Config>(generic_event: <T as Config>::Event, n: u32) {
    let events = frame_system::Module::<T>::events();
    let system_event: <T as frame_system::Config>::Event = generic_event.into();
    // compare to the last event record
    let EventRecord { event, .. } = &events[events.len().saturating_sub(n as usize)];
    assert_eq!(event, &system_event);
}

fn into_bytes<T: Config>(account: &<T as avn::Config>::AuthorityId) -> [u8; 32] {
    let bytes = account.encode();
    let mut vector: [u8; 32] = Default::default();
    vector.copy_from_slice(&bytes[0..32]);
    return vector;
}

fn get_proof<T: Config>(
    signer: T::AccountId,
    relayer: T::AccountId,
    signature: &[u8],
) -> Proof<T::Signature, T::AccountId> {
    return Proof {
        signer: signer.clone(),
        relayer: relayer.clone(),
        signature: sp_core::sr25519::Signature::from_slice(signature).into(),
    };
}

struct MintSingleNft<T: Config> {
    relayer: T::AccountId,
    nft_owner: T::AccountId,
    nft_id: U256,
    info_id: U256,
    unique_external_ref: Vec<u8>,
    royalties: Vec<Royalty>,
    t1_authority: H160,
    signature: Vec<u8>,
}

impl<T: Config> MintSingleNft<T> {
    fn new(number_of_royalties: u32) -> Self {
        let relayer_account: H256 = H256(hex!(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));
        let relayer_account_account_id =
            T::AccountId::decode(&mut relayer_account.as_bytes()).expect("valid lower account id");

        let mnemonic: &str =
            "kiss mule sheriff twice make bike twice improve rate quote draw enough";
        let nft_owner_key_pair =
            <T as avn::Config>::AuthorityId::generate_pair(Some(mnemonic.as_bytes().to_vec()));
        let account_bytes = into_bytes::<T>(&nft_owner_key_pair);
        let nft_owner_account_id = T::AccountId::decode(&mut &account_bytes.encode()[..]).unwrap();

        let nft_id = U256::from([
            144, 32, 76, 127, 69, 26, 191, 42, 121, 72, 235, 94, 179, 147, 69, 29, 167, 189, 8, 44,
            104, 83, 241, 253, 146, 114, 166, 195, 200, 254, 120, 78,
        ]);

        let unique_external_ref = String::from("Offchain location of NFT").into_bytes();
        let royalties = Self::setup_royalties(number_of_royalties);
        let t1_authority = H160(hex!("0000000000000000000000000000000000000001"));

        let signed_payload = (
            SIGNED_MINT_SINGLE_NFT_CONTEXT,
            &relayer_account_account_id,
            &unique_external_ref,
            &royalties,
            t1_authority,
        );
        let signature = nft_owner_key_pair
            .sign(&signed_payload.encode().as_slice())
            .unwrap()
            .encode();

        return MintSingleNft {
            relayer: relayer_account_account_id,
            nft_owner: nft_owner_account_id,
            nft_id: nft_id,
            info_id: U256::zero(),
            unique_external_ref: unique_external_ref,
            royalties: royalties,
            t1_authority: t1_authority,
            signature: signature,
        };
    }

    fn setup_royalties(number_of_royalties: u32) -> Vec<Royalty> {
        let mut royalties: Vec<Royalty> = Vec::new();
        for _r in 0..number_of_royalties {
            royalties.push(Royalty {
                recipient_t1_address: H160(hex!("afdf36201bf70F1232111b5c6a9a424558755134")),
                rate: RoyaltyRate {
                    parts_per_million: 1u32,
                },
            });
        }
        royalties
    }

    fn setup(self) -> Self {
        <Nfts<T>>::remove(&self.nft_id);
        NftInfos::remove(&self.nft_id);
        UsedExternalReferences::remove(&self.unique_external_ref);
        return self;
    }

    fn generate_signed_mint_single_nft(&self) -> <T as Config>::Call {
        let proof: Proof<T::Signature, T::AccountId> = get_proof::<T>(
            self.nft_owner.clone(),
            self.relayer.clone(),
            &self.signature,
        );
        return Call::signed_mint_single_nft(
            proof,
            self.unique_external_ref.clone(),
            self.royalties.clone(),
            self.t1_authority,
        )
        .into();
    }
}

struct ListNftOpenForSale<T: Config> {
    relayer: T::AccountId,
    nft_owner: T::AccountId,
    nft_id: NftId,
    nft: Nft<T::AccountId>,
    market: NftSaleType,
    signature: [u8; 64],
}

impl<T: Config> ListNftOpenForSale<T> {
    fn new() -> Self {
        let relayer_account: H256 = H256(hex!(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));
        let relayer_account_account_id =
            T::AccountId::decode(&mut relayer_account.as_bytes()).expect("valid lower account id");

        let mnemonic: &str =
            "kiss mule sheriff twice make bike twice improve rate quote draw enough";
        let nft_owner_key_pair =
            <T as avn::Config>::AuthorityId::generate_pair(Some(mnemonic.as_bytes().to_vec()));
        let account_bytes = into_bytes::<T>(&nft_owner_key_pair);
        let nft_owner_account_id = T::AccountId::decode(&mut &account_bytes.encode()[..]).unwrap();

        let nft_id = U256::from(1u8);
        let nft = Nft::new(
            nft_id,
            U256::one(),
            String::from("Offchain location of NFT").into_bytes(),
            nft_owner_account_id.clone(),
        );

        // Signature is generated using the script in `scripts/benchmarking`.
        let signature = hex!("6a767c9fb339b8ba6438f146f133ffd72b4d4b6745483f630a2dfdfecc57f240153ada88864251da658b837c661d82078e9c8eba8d09d47e487a3ab2b8d71a87");

        return ListNftOpenForSale {
            relayer: relayer_account_account_id,
            nft_owner: nft_owner_account_id,
            nft_id: nft_id,
            nft: nft,
            market: NftSaleType::Ethereum,
            signature: signature,
        };
    }

    fn setup(self) -> Self {
        <Nfts<T>>::insert(self.nft_id, self.nft.clone());
        NftOpenForSale::remove(&self.nft_id);
        return self;
    }

    fn generate_signed_list_nft_open_for_sale_call(&self) -> <T as Config>::Call {
        let proof: Proof<T::Signature, T::AccountId> = get_proof::<T>(
            self.nft_owner.clone(),
            self.relayer.clone(),
            &self.signature,
        );
        return Call::signed_list_nft_open_for_sale(proof, self.nft_id, self.market).into();
    }
}

struct TransferFiatNft<T: Config> {
    relayer: T::AccountId,
    nft_owner: T::AccountId,
    nft_id: NftId,
    nft: Nft<T::AccountId>,
    t2_transfer_to_public_key: H256,
    new_nft_owner_account: T::AccountId,
    op_id: u64,
    signature: Vec<u8>,
}

impl<T: Config> TransferFiatNft<T> {
    fn new() -> Self {
        let relayer_account: H256 = H256(hex!(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));
        let relayer_account_account_id =
            T::AccountId::decode(&mut relayer_account.as_bytes()).expect("valid lower account id");

        let mnemonic: &str =
            "kiss mule sheriff twice make bike twice improve rate quote draw enough";
        let nft_owner_key_pair =
            <T as avn::Config>::AuthorityId::generate_pair(Some(mnemonic.as_bytes().to_vec()));
        let account_bytes = into_bytes::<T>(&nft_owner_key_pair);
        let nft_owner_account_id = T::AccountId::decode(&mut &account_bytes.encode()[..]).unwrap();

        let nft_id = U256::from(1u8);
        let nft = Nft::new(
            nft_id,
            U256::one(),
            String::from("Offchain location of NFT").into_bytes(),
            nft_owner_account_id.clone(),
        );

        let t2_transfer_to_public_key = H256::from([1; 32]);
        let new_nft_owner_account = T::AccountId::decode(&mut t2_transfer_to_public_key.as_bytes())
            .expect("32 bytes will always decode into an AccountId");

        let op_id = 0;

        let signed_payload = (
            SIGNED_TRANSFER_FIAT_NFT_CONTEXT,
            &relayer_account_account_id,
            nft_id,
            t2_transfer_to_public_key,
            op_id,
        );
        let signature = nft_owner_key_pair
            .sign(&signed_payload.encode().as_slice())
            .unwrap()
            .encode();

        return TransferFiatNft {
            relayer: relayer_account_account_id,
            nft_owner: nft_owner_account_id,
            nft_id: nft_id,
            nft: nft,
            t2_transfer_to_public_key: t2_transfer_to_public_key,
            new_nft_owner_account: new_nft_owner_account,
            op_id: op_id,
            signature: signature,
        };
    }

    fn setup(self) -> Self {
        <Nfts<T>>::insert(self.nft_id, self.nft.clone());
        NftOpenForSale::insert(&self.nft_id, NftSaleType::Fiat);
        return self;
    }

    fn generate_signed_transfer_fiat_nft_call(&self) -> <T as Config>::Call {
        let proof: Proof<T::Signature, T::AccountId> = get_proof::<T>(
            self.nft_owner.clone(),
            self.relayer.clone(),
            &self.signature,
        );
        return Call::signed_transfer_fiat_nft(proof, self.nft_id, self.t2_transfer_to_public_key)
            .into();
    }
}

struct CancelListFiatNft<T: Config> {
    relayer: T::AccountId,
    nft_owner: T::AccountId,
    nft_id: NftId,
    nft: Nft<T::AccountId>,
    op_id: u64,
    signature: Vec<u8>,
}

impl<T: Config> CancelListFiatNft<T> {
    fn new() -> Self {
        let relayer_account: H256 = H256(hex!(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));
        let relayer_account_account_id =
            T::AccountId::decode(&mut relayer_account.as_bytes()).expect("valid lower account id");

        let mnemonic: &str =
            "kiss mule sheriff twice make bike twice improve rate quote draw enough";
        let nft_owner_key_pair =
            <T as avn::Config>::AuthorityId::generate_pair(Some(mnemonic.as_bytes().to_vec()));
        let account_bytes = into_bytes::<T>(&nft_owner_key_pair);
        let nft_owner_account_id = T::AccountId::decode(&mut &account_bytes.encode()[..]).unwrap();

        let nft_id = U256::from(1u8);
        let nft = Nft::new(
            nft_id,
            U256::one(),
            String::from("Offchain location of NFT").into_bytes(),
            nft_owner_account_id.clone(),
        );

        let op_id = 0;

        let signed_payload = (
            SIGNED_CANCEL_LIST_FIAT_NFT_CONTEXT,
            &relayer_account_account_id,
            nft_id,
            op_id,
        );
        let signature = nft_owner_key_pair
            .sign(&signed_payload.encode().as_slice())
            .unwrap()
            .encode();

        return CancelListFiatNft {
            relayer: relayer_account_account_id,
            nft_owner: nft_owner_account_id,
            nft_id: nft_id,
            nft: nft,
            op_id: op_id,
            signature: signature,
        };
    }

    fn setup(self) -> Self {
        <Nfts<T>>::insert(self.nft_id, self.nft.clone());
        NftOpenForSale::insert(&self.nft_id, NftSaleType::Fiat);
        return self;
    }

    fn generate_signed_cancel_list_fiat_nft_call(&self) -> <T as Config>::Call {
        let proof: Proof<T::Signature, T::AccountId> = get_proof::<T>(
            self.nft_owner.clone(),
            self.relayer.clone(),
            &self.signature,
        );
        return Call::signed_cancel_list_fiat_nft(proof, self.nft_id).into();
    }
}

benchmarks! {
    mint_single_nft {
        let r in 1 .. MAX_NUMBER_OF_ROYALTIES;
        let mint_nft: MintSingleNft<T> = MintSingleNft::new(r).setup();
    }: _(
        RawOrigin::<T::AccountId>::Signed(mint_nft.nft_owner.clone()),
        mint_nft.unique_external_ref.clone(),
        mint_nft.royalties.clone(),
        mint_nft.t1_authority
    )
    verify {
        assert_eq!(true, Nfts::<T>::contains_key(&mint_nft.nft_id));
        assert_eq!(
            Nft::new(mint_nft.nft_id, mint_nft.info_id, mint_nft.unique_external_ref.clone(), mint_nft.nft_owner.clone()),
            Nfts::<T>::get(&mint_nft.nft_id)
        );
        assert_eq!(true, <NftInfos>::contains_key(&mint_nft.info_id));
        assert_eq!(
            NftInfo::new(mint_nft.info_id, mint_nft.royalties, mint_nft.t1_authority),
            NftInfos::get(&mint_nft.info_id)
        );
        assert_eq!(true, UsedExternalReferences::contains_key(&mint_nft.unique_external_ref));
        assert_eq!(true, UsedExternalReferences::get(mint_nft.unique_external_ref));
        assert_last_event::<T>(RawEvent::SingleNftMinted(
            mint_nft.nft_id,
            mint_nft.nft_owner,
            mint_nft.t1_authority
        ).into());
    }

    signed_mint_single_nft {
        let r in 1 .. MAX_NUMBER_OF_ROYALTIES;
        let mint_nft: MintSingleNft<T> = MintSingleNft::new(r).setup();
        let proof: Proof<T::Signature, T::AccountId> = get_proof::<T>(
            mint_nft.nft_owner.clone(),
            mint_nft.relayer.clone(),
            &mint_nft.signature
        );
    }: _(
        RawOrigin::<T::AccountId>::Signed(mint_nft.nft_owner.clone()),
        proof,
        mint_nft.unique_external_ref.clone(),
        mint_nft.royalties.clone(),
        mint_nft.t1_authority
    )
    verify {
        assert_eq!(true, Nfts::<T>::contains_key(&mint_nft.nft_id));
        assert_eq!(
            Nft::new(mint_nft.nft_id, mint_nft.info_id, mint_nft.unique_external_ref.clone(), mint_nft.nft_owner.clone()),
            Nfts::<T>::get(&mint_nft.nft_id)
        );
        assert_eq!(true, <NftInfos>::contains_key(&mint_nft.info_id));
        assert_eq!(
            NftInfo::new(mint_nft.info_id, mint_nft.royalties, mint_nft.t1_authority),
            NftInfos::get(&mint_nft.info_id)
        );
        assert_eq!(true, UsedExternalReferences::contains_key(&mint_nft.unique_external_ref));
        assert_eq!(true, UsedExternalReferences::get(mint_nft.unique_external_ref));
        assert_last_event::<T>(RawEvent::SingleNftMinted(
            mint_nft.nft_id,
            mint_nft.nft_owner,
            mint_nft.t1_authority
        ).into());
    }

    list_nft_open_for_sale {
        let owner_account_bytes = [1u8;32];
        let nft_owner_account_id = T::AccountId::decode(&mut &owner_account_bytes[..]).unwrap();
        let nft_id = U256::from(1u8);
        let nft = Nft::new(
            nft_id,
            U256::one(),
            String::from("Offchain location of NFT").into_bytes(),
            nft_owner_account_id.clone(),
        );
        let market = NftSaleType::Ethereum;

        <Nfts<T>>::insert(nft_id, nft.clone());
        let original_nonce = Nfts::<T>::get(nft_id).nonce;
    }: _(
        RawOrigin::<T::AccountId>::Signed(nft_owner_account_id),
        nft_id,
        market.clone()
    )
    verify {
        assert_eq!(original_nonce + 1u64, Nfts::<T>::get(&nft_id).nonce);
        assert_eq!(true, NftOpenForSale::contains_key(&nft_id));
        assert_last_event::<T>(RawEvent::NftOpenForSale(nft_id, market).into());
    }

    signed_list_nft_open_for_sale {
        let open_for_sale: ListNftOpenForSale<T> = ListNftOpenForSale::new().setup();
        let original_nonce = Nfts::<T>::get(open_for_sale.nft_id).nonce;
        let proof: Proof<T::Signature, T::AccountId> = get_proof::<T>(
            open_for_sale.nft_owner.clone(),
            open_for_sale.relayer.clone(),
            &open_for_sale.signature
        );
    }: _(
        RawOrigin::<T::AccountId>::Signed(open_for_sale.nft_owner),
        proof,
        open_for_sale.nft_id,
        open_for_sale.market
    )
    verify {
        assert_eq!(original_nonce + 1u64, Nfts::<T>::get(&open_for_sale.nft_id).nonce);
        assert_eq!(true, NftOpenForSale::contains_key(&open_for_sale.nft_id));
        assert_last_event::<T>(RawEvent::NftOpenForSale(open_for_sale.nft_id, open_for_sale.market).into());
    }

    signed_transfer_fiat_nft {
        let transfer_fiat_nft: TransferFiatNft<T> = TransferFiatNft::new().setup();
        let original_nonce = Nfts::<T>::get(transfer_fiat_nft.nft_id).nonce;
        let proof: Proof<T::Signature, T::AccountId> = get_proof::<T>(
            transfer_fiat_nft.nft_owner.clone(),
            transfer_fiat_nft.relayer.clone(),
            &transfer_fiat_nft.signature
        );
    }: _(
        RawOrigin::<T::AccountId>::Signed(transfer_fiat_nft.nft_owner.clone()),
        proof,
        transfer_fiat_nft.nft_id,
        transfer_fiat_nft.t2_transfer_to_public_key
    )
    verify {
        assert_eq!(original_nonce + 1u64, Nfts::<T>::get(&transfer_fiat_nft.nft_id).nonce);
        assert_eq!(false, NftOpenForSale::contains_key(&transfer_fiat_nft.nft_id));
        assert_eq!(transfer_fiat_nft.new_nft_owner_account, Nfts::<T>::get(&transfer_fiat_nft.nft_id).owner);
        assert_last_event::<T>(RawEvent::FiatNftTransfer(
            transfer_fiat_nft.nft_id,
            transfer_fiat_nft.nft_owner,
            transfer_fiat_nft.new_nft_owner_account,
            NftSaleType::Fiat,
            transfer_fiat_nft.op_id
        ).into());
    }

    signed_cancel_list_fiat_nft {
        let cancel_list_fiat_nft: CancelListFiatNft<T> = CancelListFiatNft::new().setup();
        let original_nonce = Nfts::<T>::get(cancel_list_fiat_nft.nft_id).nonce;
        let proof: Proof<T::Signature, T::AccountId> = get_proof::<T>(
            cancel_list_fiat_nft.nft_owner.clone(),
            cancel_list_fiat_nft.relayer.clone(),
            &cancel_list_fiat_nft.signature
        );
    }: _(
        RawOrigin::<T::AccountId>::Signed(cancel_list_fiat_nft.nft_owner.clone()),
        proof,
        cancel_list_fiat_nft.nft_id
    )
    verify {
        assert_eq!(original_nonce + 1u64, Nfts::<T>::get(&cancel_list_fiat_nft.nft_id).nonce);
        assert_eq!(false, NftOpenForSale::contains_key(&cancel_list_fiat_nft.nft_id));
        assert_eq!(cancel_list_fiat_nft.nft_owner, Nfts::<T>::get(&cancel_list_fiat_nft.nft_id).owner);
        assert_last_event::<T>(RawEvent::CancelSingleFiatNftListing(
            cancel_list_fiat_nft.nft_id,
            NftSaleType::Fiat,
            cancel_list_fiat_nft.op_id
        ).into());
    }

    proxy_signed_mint_single_nft {
        let r in 1 .. MAX_NUMBER_OF_ROYALTIES;
        let mint_nft: MintSingleNft<T> = MintSingleNft::new(r).setup();
        let call: <T as Config>::Call = mint_nft.generate_signed_mint_single_nft();
        let boxed_call: Box<<T as Config>::Call> = Box::new(call);
        let call_hash: T::Hash = T::Hashing::hash_of(&boxed_call);
    }: proxy(RawOrigin::<T::AccountId>::Signed(mint_nft.relayer.clone()), boxed_call)
    verify {
        assert_eq!(true, Nfts::<T>::contains_key(&mint_nft.nft_id));
        assert_eq!(
            Nft::new(mint_nft.nft_id, mint_nft.info_id, mint_nft.unique_external_ref.clone(), mint_nft.nft_owner.clone()),
            Nfts::<T>::get(&mint_nft.nft_id)
        );
        assert_eq!(true, <NftInfos>::contains_key(&mint_nft.info_id));
        assert_eq!(
            NftInfo::new(mint_nft.info_id, mint_nft.royalties, mint_nft.t1_authority),
            NftInfos::get(&mint_nft.info_id)
        );
        assert_eq!(true, UsedExternalReferences::contains_key(&mint_nft.unique_external_ref));
        assert_eq!(true, UsedExternalReferences::get(mint_nft.unique_external_ref));
        assert_last_event::<T>(RawEvent::CallDispatched(mint_nft.relayer.clone(), call_hash).into());
        assert_last_nth_event::<T>(RawEvent::SingleNftMinted(
            mint_nft.nft_id,
            mint_nft.nft_owner,
            mint_nft.t1_authority
        ).into(), 2);
    }

    proxy_signed_list_nft_open_for_sale {
        let open_for_sale: ListNftOpenForSale<T> = ListNftOpenForSale::new().setup();
        let original_nonce = Nfts::<T>::get(open_for_sale.nft_id).nonce;
        let call: <T as Config>::Call = open_for_sale.generate_signed_list_nft_open_for_sale_call();
        let boxed_call: Box<<T as Config>::Call> = Box::new(call);
        let call_hash: T::Hash = T::Hashing::hash_of(&boxed_call);
    }: proxy(RawOrigin::<T::AccountId>::Signed(open_for_sale.relayer.clone()), boxed_call)
    verify {
        assert_eq!(original_nonce + 1u64, Nfts::<T>::get(&open_for_sale.nft_id).nonce);
        assert_eq!(true, NftOpenForSale::contains_key(&open_for_sale.nft_id));
        assert_last_event::<T>(RawEvent::CallDispatched(open_for_sale.relayer.clone(), call_hash).into());
        assert_last_nth_event::<T>(RawEvent::NftOpenForSale(open_for_sale.nft_id, open_for_sale.market).into(), 2);
    }

    proxy_signed_transfer_fiat_nft {
        let transfer_fiat_nft: TransferFiatNft<T> = TransferFiatNft::new().setup();
        let original_nonce = Nfts::<T>::get(transfer_fiat_nft.nft_id).nonce;
        let call: <T as Config>::Call = transfer_fiat_nft.generate_signed_transfer_fiat_nft_call();
        let boxed_call: Box<<T as Config>::Call> = Box::new(call);
        let call_hash: T::Hash = T::Hashing::hash_of(&boxed_call);
    }: proxy(RawOrigin::<T::AccountId>::Signed(transfer_fiat_nft.relayer.clone()), boxed_call)
    verify {
        assert_eq!(original_nonce + 1u64, Nfts::<T>::get(&transfer_fiat_nft.nft_id).nonce);
        assert_eq!(false, NftOpenForSale::contains_key(&transfer_fiat_nft.nft_id));
        assert_eq!(transfer_fiat_nft.new_nft_owner_account, Nfts::<T>::get(&transfer_fiat_nft.nft_id).owner);
        assert_last_event::<T>(RawEvent::CallDispatched(transfer_fiat_nft.relayer.clone(), call_hash).into());
        assert_last_nth_event::<T>(RawEvent::FiatNftTransfer(
            transfer_fiat_nft.nft_id,
            transfer_fiat_nft.nft_owner,
            transfer_fiat_nft.new_nft_owner_account,
            NftSaleType::Fiat,
            transfer_fiat_nft.op_id
        ).into(), 2);
    }

    proxy_signed_cancel_list_fiat_nft {
        let cancel_list_fiat_nft: CancelListFiatNft<T> = CancelListFiatNft::new().setup();
        let original_nonce = Nfts::<T>::get(cancel_list_fiat_nft.nft_id).nonce;
        let call: <T as Config>::Call = cancel_list_fiat_nft.generate_signed_cancel_list_fiat_nft_call();
        let boxed_call: Box<<T as Config>::Call> = Box::new(call);
        let call_hash: T::Hash = T::Hashing::hash_of(&boxed_call);
    }: proxy(RawOrigin::<T::AccountId>::Signed(cancel_list_fiat_nft.relayer.clone()), boxed_call)
    verify {
        assert_eq!(original_nonce + 1u64, Nfts::<T>::get(&cancel_list_fiat_nft.nft_id).nonce);
        assert_eq!(false, NftOpenForSale::contains_key(&cancel_list_fiat_nft.nft_id));
        assert_eq!(cancel_list_fiat_nft.nft_owner, Nfts::<T>::get(&cancel_list_fiat_nft.nft_id).owner);
        assert_last_event::<T>(RawEvent::CallDispatched(cancel_list_fiat_nft.relayer.clone(), call_hash).into());
        assert_last_nth_event::<T>(RawEvent::CancelSingleFiatNftListing(
            cancel_list_fiat_nft.nft_id,
            NftSaleType::Fiat,
            cancel_list_fiat_nft.op_id
        ).into(), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::*;
    use frame_support::assert_ok;

    #[test]
    fn benchmarks() {
        let mut ext = ExtBuilder::build_default().as_externality();

        ext.execute_with(|| {
            assert_ok!(test_benchmark_mint_single_nft::<TestRuntime>());
            assert_ok!(test_benchmark_signed_mint_single_nft::<TestRuntime>());
            assert_ok!(test_benchmark_list_nft_open_for_sale::<TestRuntime>());
            assert_ok!(test_benchmark_signed_list_nft_open_for_sale::<TestRuntime>());
            assert_ok!(test_benchmark_signed_transfer_fiat_nft::<TestRuntime>());
            assert_ok!(test_benchmark_signed_cancel_list_fiat_nft::<TestRuntime>());
            assert_ok!(test_benchmark_proxy_signed_mint_single_nft::<TestRuntime>());
            assert_ok!(test_benchmark_proxy_signed_list_nft_open_for_sale::<
                TestRuntime,
            >());
            assert_ok!(test_benchmark_proxy_signed_transfer_fiat_nft::<TestRuntime>());
            assert_ok!(test_benchmark_proxy_signed_cancel_list_fiat_nft::<
                TestRuntime,
            >());
        });
    }
}

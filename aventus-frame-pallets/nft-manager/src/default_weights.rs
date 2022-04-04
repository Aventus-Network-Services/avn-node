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

//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 2.0.0

#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::weights::{constants::RocksDbWeight as DbWeight, Weight};
use sp_std::marker::PhantomData;

pub trait WeightInfo {
	fn mint_single_nft(r: u32) -> Weight;
	fn list_nft_open_for_sale() -> Weight;
	fn signed_mint_single_nft(r: u32) -> Weight;
	fn signed_list_nft_open_for_sale() -> Weight;
	fn signed_transfer_fiat_nft() -> Weight;
	fn signed_cancel_list_fiat_nft() -> Weight;
	fn proxy_signed_mint_single_nft(r: u32) -> Weight;
	fn proxy_signed_list_nft_open_for_sale() -> Weight;
	fn proxy_signed_transfer_fiat_nft() -> Weight;
	fn proxy_signed_cancel_list_fiat_nft() -> Weight;
}

/// Weights for pallet_nft_manager
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn mint_single_nft(r: u32) -> Weight {
		(126_475_000 as Weight)
			// Standard Error: 24_000
			.saturating_add((496_000 as Weight).saturating_mul(r as Weight))
			.saturating_add(DbWeight::get().reads(4 as Weight))
			.saturating_add(DbWeight::get().writes(5 as Weight))
	}
	fn signed_mint_single_nft(r: u32) -> Weight {
		(249_656_000 as Weight)
			// Standard Error: 31_000
			.saturating_add((1_233_000 as Weight).saturating_mul(r as Weight))
			.saturating_add(DbWeight::get().reads(4 as Weight))
			.saturating_add(DbWeight::get().writes(5 as Weight))
	}
	fn list_nft_open_for_sale() -> Weight {
		(81_207_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn signed_list_nft_open_for_sale() -> Weight {
		(216_052_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn signed_transfer_fiat_nft() -> Weight {
		(247_421_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn signed_cancel_list_fiat_nft() -> Weight {
		(244_191_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn proxy_signed_mint_single_nft(r: u32) -> Weight {
		(284_271_000 as Weight)
			// Standard Error: 28_000
			.saturating_add((1_818_000 as Weight).saturating_mul(r as Weight))
			.saturating_add(DbWeight::get().reads(4 as Weight))
			.saturating_add(DbWeight::get().writes(5 as Weight))
	}
	fn proxy_signed_list_nft_open_for_sale() -> Weight {
		(250_911_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn proxy_signed_transfer_fiat_nft() -> Weight {
		(271_720_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn proxy_signed_cancel_list_fiat_nft() -> Weight {
		(275_950_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
}

// For backwards compatibility and tests
impl crate::WeightInfo for () {
	fn mint_single_nft(r: u32) -> Weight {
		(163_697_000 as Weight)
			.saturating_add((990_000 as Weight).saturating_mul(r as Weight))
			.saturating_add(DbWeight::get().reads(4 as Weight))
			.saturating_add(DbWeight::get().writes(5 as Weight))
	}
	fn list_nft_open_for_sale() -> Weight {
		(118_372_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn signed_mint_single_nft(r: u32) -> Weight {
		(291_875_000 as Weight)
			.saturating_add((2_086_000 as Weight).saturating_mul(r as Weight))
			.saturating_add(DbWeight::get().reads(4 as Weight))
			.saturating_add(DbWeight::get().writes(5 as Weight))
	}
	fn signed_list_nft_open_for_sale() -> Weight {
		(251_944_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn signed_transfer_fiat_nft() -> Weight {
		(296_426_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn signed_cancel_list_fiat_nft() -> Weight {
		(290_946_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn proxy_signed_mint_single_nft(r: u32) -> Weight {
		(343_867_000 as Weight)
			.saturating_add((3_044_000 as Weight).saturating_mul(r as Weight))
			.saturating_add(DbWeight::get().reads(4 as Weight))
			.saturating_add(DbWeight::get().writes(5 as Weight))
	}
	fn proxy_signed_list_nft_open_for_sale() -> Weight {
		(293_805_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn proxy_signed_transfer_fiat_nft() -> Weight {
		(332_467_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
	fn proxy_signed_cancel_list_fiat_nft() -> Weight {
		(325_967_000 as Weight)
			.saturating_add(DbWeight::get().reads(2 as Weight))
			.saturating_add(DbWeight::get().writes(2 as Weight))
	}
}

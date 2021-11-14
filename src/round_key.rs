// Copyright © 2020–2021 SitD <sitd0813@gmail.com>
//
// This file is subject to the terms of the MIT License.
// If a copy of the MIT License was not distributed with this file, you can obtain one at https://opensource.org/licenses/MIT.

//! LEA Round Key

use core::marker::PhantomData;

use cipher::consts::{U16, U24, U32, U144, U168, U192};
use cipher::generic_array::{ArrayLength, GenericArray};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub trait RoundKey {
	type KeySize: ArrayLength<u8>;
	type RkSize: ArrayLength<u32>;

	fn generate(key: &GenericArray<u8, Self::KeySize>) -> GenericArray<u32, Self::RkSize>;
}

pub type Rk144 = Rk<U144>;
pub type Rk168 = Rk<U168>;
pub type Rk192 = Rk<U192>;

pub struct Rk<RkSize> where
RkSize: ArrayLength<u32> {
	_p: PhantomData<RkSize>
}

#[allow(non_upper_case_globals)]
const δ: [u32; 8] = [0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC, 0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957];

impl RoundKey for Rk<U144> {
	type KeySize = U16;
	type RkSize = U144;

	fn generate(key: &GenericArray<u8, Self::KeySize>) -> GenericArray<u32, Self::RkSize> {
		let mut rk_t = unsafe { *key.as_ptr().cast::<[u32; 4]>() };
		cfg_if::cfg_if! {
			if #[cfg(target_endian = "big")] {
				rk_t[0] = rk_t[0].swap_bytes();
				rk_t[1] = rk_t[1].swap_bytes();
				rk_t[2] = rk_t[2].swap_bytes();
				rk_t[3] = rk_t[3].swap_bytes();
			}
		}

		let mut rk = GenericArray::default();

		for i in 0..24 {
			rk_t[0] = rk_t[0].wrapping_add(δ[i % 4].rotate_left(i as u32 + 0)).rotate_left(1);
			rk_t[1] = rk_t[1].wrapping_add(δ[i % 4].rotate_left(i as u32 + 1)).rotate_left(3);
			rk_t[2] = rk_t[2].wrapping_add(δ[i % 4].rotate_left(i as u32 + 2)).rotate_left(6);
			rk_t[3] = rk_t[3].wrapping_add(δ[i % 4].rotate_left(i as u32 + 3)).rotate_left(11);

			rk[6 * i + 0] = rk_t[0];
			rk[6 * i + 1] = rk_t[1];
			rk[6 * i + 2] = rk_t[2];
			rk[6 * i + 3] = rk_t[1];
			rk[6 * i + 4] = rk_t[3];
			rk[6 * i + 5] = rk_t[1];
		}

		#[cfg(feature = "zeroize")]
		rk_t.zeroize();

		rk
	}
}

impl RoundKey for Rk<U168> {
	type KeySize = U24;
	type RkSize = U168;

	fn generate(key: &GenericArray<u8, Self::KeySize>) -> GenericArray<u32, Self::RkSize> {
		let mut rk_t = unsafe { *key.as_ptr().cast::<[u32; 6]>() };
		cfg_if::cfg_if! {
			if #[cfg(target_endian = "big")] {
				rk_t[0] = rk_t[0].swap_bytes();
				rk_t[1] = rk_t[1].swap_bytes();
				rk_t[2] = rk_t[2].swap_bytes();
				rk_t[3] = rk_t[3].swap_bytes();
				rk_t[4] = rk_t[4].swap_bytes();
				rk_t[5] = rk_t[5].swap_bytes();
			}
		}

		let mut rk = GenericArray::default();

		for i in 0..28 {
			rk_t[0] = rk_t[0].wrapping_add(δ[i % 6].rotate_left(i as u32 + 0)).rotate_left(1);
			rk_t[1] = rk_t[1].wrapping_add(δ[i % 6].rotate_left(i as u32 + 1)).rotate_left(3);
			rk_t[2] = rk_t[2].wrapping_add(δ[i % 6].rotate_left(i as u32 + 2)).rotate_left(6);
			rk_t[3] = rk_t[3].wrapping_add(δ[i % 6].rotate_left(i as u32 + 3)).rotate_left(11);
			rk_t[4] = rk_t[4].wrapping_add(δ[i % 6].rotate_left(i as u32 + 4)).rotate_left(13);
			rk_t[5] = rk_t[5].wrapping_add(δ[i % 6].rotate_left(i as u32 + 5)).rotate_left(17);

			rk[6 * i + 0] = rk_t[0];
			rk[6 * i + 1] = rk_t[1];
			rk[6 * i + 2] = rk_t[2];
			rk[6 * i + 3] = rk_t[3];
			rk[6 * i + 4] = rk_t[4];
			rk[6 * i + 5] = rk_t[5];
		}

		#[cfg(feature = "zeroize")]
		rk_t.zeroize();

		rk
	}
}

impl RoundKey for Rk<U192> {
	type KeySize = U32;
	type RkSize = U192;

	fn generate(key: &GenericArray<u8, Self::KeySize>) -> GenericArray<u32, Self::RkSize> {
		let mut rk_t = unsafe { *key.as_ptr().cast::<[u32; 8]>() };
		cfg_if::cfg_if! {
			if #[cfg(target_endian = "big")] {
				rk_t[0] = rk_t[0].swap_bytes();
				rk_t[1] = rk_t[1].swap_bytes();
				rk_t[2] = rk_t[2].swap_bytes();
				rk_t[3] = rk_t[3].swap_bytes();
				rk_t[4] = rk_t[4].swap_bytes();
				rk_t[5] = rk_t[5].swap_bytes();
				rk_t[6] = rk_t[6].swap_bytes();
				rk_t[7] = rk_t[7].swap_bytes();
			}
		}

		let mut rk = GenericArray::default();

		for i in 0..32 {
			rk_t[(6 * i + 0) % 8] = rk_t[(6 * i + 0) % 8].wrapping_add(δ[i % 8].rotate_left(i as u32 + 0)).rotate_left(1);
			rk_t[(6 * i + 1) % 8] = rk_t[(6 * i + 1) % 8].wrapping_add(δ[i % 8].rotate_left(i as u32 + 1)).rotate_left(3);
			rk_t[(6 * i + 2) % 8] = rk_t[(6 * i + 2) % 8].wrapping_add(δ[i % 8].rotate_left(i as u32 + 2)).rotate_left(6);
			rk_t[(6 * i + 3) % 8] = rk_t[(6 * i + 3) % 8].wrapping_add(δ[i % 8].rotate_left(i as u32 + 3)).rotate_left(11);
			rk_t[(6 * i + 4) % 8] = rk_t[(6 * i + 4) % 8].wrapping_add(δ[i % 8].rotate_left(i as u32 + 4)).rotate_left(13);
			rk_t[(6 * i + 5) % 8] = rk_t[(6 * i + 5) % 8].wrapping_add(δ[i % 8].rotate_left(i as u32 + 5)).rotate_left(17);

			rk[6 * i + 0] = rk_t[(6 * i + 0) % 8];
			rk[6 * i + 1] = rk_t[(6 * i + 1) % 8];
			rk[6 * i + 2] = rk_t[(6 * i + 2) % 8];
			rk[6 * i + 3] = rk_t[(6 * i + 3) % 8];
			rk[6 * i + 4] = rk_t[(6 * i + 4) % 8];
			rk[6 * i + 5] = rk_t[(6 * i + 5) % 8];
		}

		#[cfg(feature = "zeroize")]
		rk_t.zeroize();

		rk
	}
}
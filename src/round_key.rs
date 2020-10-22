// Copyright © 2020 SitD <sitd0813@gmail.com>
//
// This file is subject to the terms of the MIT License.
// If a copy of the MIT License was not distributed with this file, you can obtain one at https://opensource.org/licenses/MIT.

//! LEA Round Key

use core::{marker::PhantomData, mem};

use cipher::{
	consts::{U16, U24, U32, U144, U168, U192},
	generic_array::{ArrayLength, GenericArray}
};

pub trait RoundKey {
	type KeySize: ArrayLength<u8>;
	type RkSize: ArrayLength<u32>;

	fn new(key: &GenericArray<u8, Self::KeySize>) -> GenericArray<u32, Self::RkSize>;
}

pub type Rk144 = Rk<U144>;
pub type Rk168 = Rk<U168>;
pub type Rk192 = Rk<U192>;

pub struct Rk<RkSize> where
RkSize: ArrayLength<u32> {
	_p: PhantomData<RkSize>
}

const DELTA: [u32; 8] = [0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC, 0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957];

impl RoundKey for Rk<U144> {
	type KeySize = U16;
	type RkSize = U144;

	fn new(key: &GenericArray<u8, Self::KeySize>) -> GenericArray<u32, Self::RkSize> {
		cfg_if::cfg_if! {
			if #[cfg(target_endian = "big")] {
				let mut key = unsafe { mem::transmute::<_, &[u32; 4]>(key) }.clone();
				key[0] = key[0].swap_bytes();
				key[1] = key[1].swap_bytes();
				key[2] = key[2].swap_bytes();
				key[3] = key[3].swap_bytes();
			} else {
				let key = unsafe { mem::transmute::<_, &[u32; 4]>(key) };
			}
		}

		let mut rk = GenericArray::default();
	
		rk[0] = key[0].wrapping_add(DELTA[0]).rotate_left(1);
		rk[1] = key[1].wrapping_add(DELTA[0].rotate_left(1)).rotate_left(3);
		rk[2] = key[2].wrapping_add(DELTA[0].rotate_left(2)).rotate_left(6);
		rk[3] = rk[1];
		rk[4] = key[3].wrapping_add(DELTA[0].rotate_left(3)).rotate_left(11);
		rk[5] = rk[1];

		for i in 1..24 {
			rk[6 * i] = rk[6 * (i - 1)].wrapping_add(DELTA[i % 4].rotate_left(i as u32)).rotate_left(1);
			rk[6 * i + 1] = rk[6 * (i - 1) + 1].wrapping_add(DELTA[i % 4].rotate_left(i as u32 + 1)).rotate_left(3);
			rk[6 * i + 2] = rk[6 * (i - 1) + 2].wrapping_add(DELTA[i % 4].rotate_left(i as u32 + 2)).rotate_left(6);
			rk[6 * i + 3] = rk[6 * i + 1];
			rk[6 * i + 4] = rk[6 * (i - 1) + 4].wrapping_add(DELTA[i % 4].rotate_left(i as u32 + 3)).rotate_left(11);
			rk[6 * i + 5] = rk[6 * i + 1];
		}

		rk
	}
}

impl RoundKey for Rk<U168> {
	type KeySize = U24;
	type RkSize = U168;

	fn new(key: &GenericArray<u8, Self::KeySize>) -> GenericArray<u32, Self::RkSize> {
		cfg_if::cfg_if! {
			if #[cfg(target_endian = "big")] {
				let mut key = unsafe { mem::transmute::<_, &[u32; 6]>(key) }.clone();
				key[0] = key[0].swap_bytes();
				key[1] = key[1].swap_bytes();
				key[2] = key[2].swap_bytes();
				key[3] = key[3].swap_bytes();
				key[4] = key[4].swap_bytes();
				key[5] = key[5].swap_bytes();
			} else {
				let key = unsafe { mem::transmute::<_, &[u32; 6]>(key) };
			}
		}

		let mut rk = GenericArray::default();
	
		rk[0] = key[0].wrapping_add(DELTA[0]).rotate_left(1);
		rk[1] = key[1].wrapping_add(DELTA[0].rotate_left(1)).rotate_left(3);
		rk[2] = key[2].wrapping_add(DELTA[0].rotate_left(2)).rotate_left(6);
		rk[3] = key[3].wrapping_add(DELTA[0].rotate_left(3)).rotate_left(11);
		rk[4] = key[4].wrapping_add(DELTA[0].rotate_left(4)).rotate_left(13);
		rk[5] = key[5].wrapping_add(DELTA[0].rotate_left(5)).rotate_left(17);

		for i in 1..28 {
			rk[6 * i] = rk[6 * (i - 1)].wrapping_add(DELTA[i % 6].rotate_left(i as u32)).rotate_left(1);
			rk[6 * i + 1] = rk[6 * (i - 1) + 1].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 1)).rotate_left(3);
			rk[6 * i + 2] = rk[6 * (i - 1) + 2].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 2)).rotate_left(6);
			rk[6 * i + 3] = rk[6 * (i - 1) + 3].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 3)).rotate_left(11);
			rk[6 * i + 4] = rk[6 * (i - 1) + 4].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 4)).rotate_left(13);
			rk[6 * i + 5] = rk[6 * (i - 1) + 5].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 5)).rotate_left(17);
		}

		rk
	}
}

impl RoundKey for Rk<U192> {
	type KeySize = U32;
	type RkSize = U192;

	fn new(key: &GenericArray<u8, Self::KeySize>) -> GenericArray<u32, Self::RkSize> {
		cfg_if::cfg_if! {
			if #[cfg(target_endian = "big")] {
				let mut key = unsafe { mem::transmute::<_, &[u32; 8]>(key) }.clone();
				key[0] = key[0].swap_bytes();
				key[1] = key[1].swap_bytes();
				key[2] = key[2].swap_bytes();
				key[3] = key[3].swap_bytes();
				key[4] = key[4].swap_bytes();
				key[5] = key[5].swap_bytes();
				key[6] = key[6].swap_bytes();
				key[7] = key[7].swap_bytes();
			} else {
				let key = unsafe { mem::transmute::<_, &[u32; 8]>(key) };
			}
		}

		let mut rk = GenericArray::default();

		let mut t = key.clone();
		for i in 0..32 {
			t[(6 * i) % 8] = t[(6 * i) % 8].wrapping_add(DELTA[i % 8].rotate_left(i as u32)).rotate_left(1);
			t[(6 * i + 1) % 8] = t[(6 * i + 1) % 8].wrapping_add(DELTA[i % 8].rotate_left(i as u32 + 1)).rotate_left(3);
			t[(6 * i + 2) % 8] = t[(6 * i + 2) % 8].wrapping_add(DELTA[i % 8].rotate_left(i as u32 + 2)).rotate_left(6);
			t[(6 * i + 3) % 8] = t[(6 * i + 3) % 8].wrapping_add(DELTA[i % 8].rotate_left(i as u32 + 3)).rotate_left(11);
			t[(6 * i + 4) % 8] = t[(6 * i + 4) % 8].wrapping_add(DELTA[i % 8].rotate_left(i as u32 + 4)).rotate_left(13);
			t[(6 * i + 5) % 8] = t[(6 * i + 5) % 8].wrapping_add(DELTA[i % 8].rotate_left(i as u32 + 5)).rotate_left(17);
			rk[6 * i] = t[(6 * i) % 8];
			rk[6 * i + 1] = t[(6 * i + 1) % 8];
			rk[6 * i + 2] = t[(6 * i + 2) % 8];
			rk[6 * i + 3] = t[(6 * i + 3) % 8];
			rk[6 * i + 4] = t[(6 * i + 4) % 8];
			rk[6 * i + 5] = t[(6 * i + 5) % 8];
		}

		rk
	}
}
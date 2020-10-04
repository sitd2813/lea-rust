// Copyright © 2020 SitD <sitd0813@gmail.com>
//
// This file is subject to the terms of the MIT License.
// If a copy of the MIT License was not distributed with this file, you can obtain one at https://opensource.org/licenses/MIT.

//! LEA
//!
//! * Example
//! ```
//! use lea::{
//! 	block_cipher::{
//! 		generic_array::arr,
//! 		BlockCipher, NewBlockCipher
//! 	},
//! 	Lea128
//! };
//!
//! let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
//! let ptxt = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
//! let ctxt = arr![u8; 0x9F, 0xC8, 0x4E, 0x35, 0x28, 0xC6, 0xC6, 0x18, 0x55, 0x32, 0xC7, 0xA7, 0x04, 0x64, 0x8B, 0xFD];
//!
//! let lea128 = Lea128::new(&key);
//!
//! // Encryption
//! let mut block = ptxt.clone();
//! lea128.encrypt_block(&mut block);
//! assert_eq!(block, ctxt);
//!
//! // Decryption
//! let mut block = ctxt.clone();
//! lea128.decrypt_block(&mut block);
//! assert_eq!(block, ptxt);
//! ```

#![no_std]

#[cfg(feature = "feature-ctr")]
pub mod ctr;
#[cfg(feature = "feature-poly1305")]
pub mod poly1305;

pub use block_cipher;

use block_cipher::{
	consts::{U8, U16, U24, U32, U144, U168, U192},
	generic_array::{ArrayLength, GenericArray},
	BlockCipher, NewBlockCipher, Key
};
use zeroize::Zeroize;

pub type Block = GenericArray<u8, U16>;

macro_rules! generate_lea {
	($name:ident, $round_key_new:ident, $round_key_size:ty, $key_size:ty) => {
		#[derive(Clone, Debug)]
		pub struct $name {
			round_key: GenericArray<u32, $round_key_size>,
		}

		impl Drop for $name {
			fn drop(&mut self) {
				self.round_key.as_mut_slice().zeroize();
			}
		}
		
		impl BlockCipher for $name {
			type BlockSize = U16;
			type ParBlocks = U8;
		
			fn encrypt_block(&self, block: &mut Block) {
				encrypt_block(&self.round_key, block);
			}
		
			fn decrypt_block(&self, block: &mut Block) {
				decrypt_block(&self.round_key, block);
			}
		}

		impl NewBlockCipher for $name {
			type KeySize = $key_size;

			fn new(key: &Key<Self>) -> Self {
				Self { round_key: $round_key_new(key) }
			}
		}
	};
}

generate_lea!(Lea128, round_key_128_new, U144, U16);
generate_lea!(Lea192, round_key_192_new, U168, U24);
generate_lea!(Lea256, round_key_256_new, U192, U32);

const DELTA: [u32; 8] = [0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC, 0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957];

fn round_key_128_new(key_u8: &Key<Lea128>) -> GenericArray<u32, U144> {
	cfg_if::cfg_if! {
		if #[cfg(target_endian = "big")] {
			let mut key = unsafe { &*(key_u8.as_ptr() as *const [u32; 4]) };
			key[0] = key[0].swap_bytes();
			key[1] = key[1].swap_bytes();
			key[2] = key[2].swap_bytes();
			key[3] = key[3].swap_bytes();
		} else {
			let key = unsafe { &*(key_u8.as_ptr() as *const [u32; 4]) };
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

fn round_key_192_new(key_u8: &Key<Lea192>) -> GenericArray<u32, U168> {
	cfg_if::cfg_if! {
		if #[cfg(target_endian = "big")] {
			let mut key = unsafe { &*(key_u8.as_ptr() as *const [u32; 6]) };
			key[0] = key[0].swap_bytes();
			key[1] = key[1].swap_bytes();
			key[2] = key[2].swap_bytes();
			key[3] = key[3].swap_bytes();
			key[4] = key[4].swap_bytes();
			key[5] = key[5].swap_bytes();
		} else {
			let key = unsafe { &*(key_u8.as_ptr() as *const [u32; 6]) };
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

fn round_key_256_new(key_u8: &Key<Lea256>) -> GenericArray<u32, U192> {
	cfg_if::cfg_if! {
		if #[cfg(target_endian = "big")] {
			let mut key = unsafe { &*(key_u8.as_ptr() as *const [u32; 8]) };
			key[0] = key[0].swap_bytes();
			key[1] = key[1].swap_bytes();
			key[2] = key[2].swap_bytes();
			key[3] = key[3].swap_bytes();
			key[4] = key[4].swap_bytes();
			key[5] = key[5].swap_bytes();
			key[6] = key[6].swap_bytes();
			key[7] = key[7].swap_bytes();
		} else {
			let key = unsafe { &*(key_u8.as_ptr() as *const [u32; 8]) };
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

fn encrypt_block<L: ArrayLength<u32>>(rk: &GenericArray<u32, L>, block: &mut Block) {
	cfg_if::cfg_if! {
		if #[cfg(target_endian = "big")] {
			let mut block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };
			block[0] = block[0].swap_bytes();
			block[1] = block[1].swap_bytes();
			block[2] = block[2].swap_bytes();
			block[3] = block[3].swap_bytes();
		} else {
			let block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };
		}
	}

	// 24 rounds for 128-bit key
	block[3] = (block[2] ^ rk[4]).wrapping_add(block[3] ^ rk[5]).rotate_right(3);
	block[2] = (block[1] ^ rk[2]).wrapping_add(block[2] ^ rk[3]).rotate_right(5);
	block[1] = (block[0] ^ rk[0]).wrapping_add(block[1] ^ rk[1]).rotate_left(9);
	block[0] = (block[3] ^ rk[10]).wrapping_add(block[0] ^ rk[11]).rotate_right(3);
	block[3] = (block[2] ^ rk[8]).wrapping_add(block[3] ^ rk[9]).rotate_right(5);
	block[2] = (block[1] ^ rk[6]).wrapping_add(block[2] ^ rk[7]).rotate_left(9);
	block[1] = (block[0] ^ rk[16]).wrapping_add(block[1] ^ rk[17]).rotate_right(3);
	block[0] = (block[3] ^ rk[14]).wrapping_add(block[0] ^ rk[15]).rotate_right(5);
	block[3] = (block[2] ^ rk[12]).wrapping_add(block[3] ^ rk[13]).rotate_left(9);
	block[2] = (block[1] ^ rk[22]).wrapping_add(block[2] ^ rk[23]).rotate_right(3);
	block[1] = (block[0] ^ rk[20]).wrapping_add(block[1] ^ rk[21]).rotate_right(5);
	block[0] = (block[3] ^ rk[18]).wrapping_add(block[0] ^ rk[19]).rotate_left(9);

	block[3] = (block[2] ^ rk[28]).wrapping_add(block[3] ^ rk[29]).rotate_right(3);
	block[2] = (block[1] ^ rk[26]).wrapping_add(block[2] ^ rk[27]).rotate_right(5);
	block[1] = (block[0] ^ rk[24]).wrapping_add(block[1] ^ rk[25]).rotate_left(9);
	block[0] = (block[3] ^ rk[34]).wrapping_add(block[0] ^ rk[35]).rotate_right(3);
	block[3] = (block[2] ^ rk[32]).wrapping_add(block[3] ^ rk[33]).rotate_right(5);
	block[2] = (block[1] ^ rk[30]).wrapping_add(block[2] ^ rk[31]).rotate_left(9);
	block[1] = (block[0] ^ rk[40]).wrapping_add(block[1] ^ rk[41]).rotate_right(3);
	block[0] = (block[3] ^ rk[38]).wrapping_add(block[0] ^ rk[39]).rotate_right(5);
	block[3] = (block[2] ^ rk[36]).wrapping_add(block[3] ^ rk[37]).rotate_left(9);
	block[2] = (block[1] ^ rk[46]).wrapping_add(block[2] ^ rk[47]).rotate_right(3);
	block[1] = (block[0] ^ rk[44]).wrapping_add(block[1] ^ rk[45]).rotate_right(5);
	block[0] = (block[3] ^ rk[42]).wrapping_add(block[0] ^ rk[43]).rotate_left(9);

	block[3] = (block[2] ^ rk[52]).wrapping_add(block[3] ^ rk[53]).rotate_right(3);
	block[2] = (block[1] ^ rk[50]).wrapping_add(block[2] ^ rk[51]).rotate_right(5);
	block[1] = (block[0] ^ rk[48]).wrapping_add(block[1] ^ rk[49]).rotate_left(9);
	block[0] = (block[3] ^ rk[58]).wrapping_add(block[0] ^ rk[59]).rotate_right(3);
	block[3] = (block[2] ^ rk[56]).wrapping_add(block[3] ^ rk[57]).rotate_right(5);
	block[2] = (block[1] ^ rk[54]).wrapping_add(block[2] ^ rk[55]).rotate_left(9);
	block[1] = (block[0] ^ rk[64]).wrapping_add(block[1] ^ rk[65]).rotate_right(3);
	block[0] = (block[3] ^ rk[62]).wrapping_add(block[0] ^ rk[63]).rotate_right(5);
	block[3] = (block[2] ^ rk[60]).wrapping_add(block[3] ^ rk[61]).rotate_left(9);
	block[2] = (block[1] ^ rk[70]).wrapping_add(block[2] ^ rk[71]).rotate_right(3);
	block[1] = (block[0] ^ rk[68]).wrapping_add(block[1] ^ rk[69]).rotate_right(5);
	block[0] = (block[3] ^ rk[66]).wrapping_add(block[0] ^ rk[67]).rotate_left(9);

	block[3] = (block[2] ^ rk[76]).wrapping_add(block[3] ^ rk[77]).rotate_right(3);
	block[2] = (block[1] ^ rk[74]).wrapping_add(block[2] ^ rk[75]).rotate_right(5);
	block[1] = (block[0] ^ rk[72]).wrapping_add(block[1] ^ rk[73]).rotate_left(9);
	block[0] = (block[3] ^ rk[82]).wrapping_add(block[0] ^ rk[83]).rotate_right(3);
	block[3] = (block[2] ^ rk[80]).wrapping_add(block[3] ^ rk[81]).rotate_right(5);
	block[2] = (block[1] ^ rk[78]).wrapping_add(block[2] ^ rk[79]).rotate_left(9);
	block[1] = (block[0] ^ rk[88]).wrapping_add(block[1] ^ rk[89]).rotate_right(3);
	block[0] = (block[3] ^ rk[86]).wrapping_add(block[0] ^ rk[87]).rotate_right(5);
	block[3] = (block[2] ^ rk[84]).wrapping_add(block[3] ^ rk[85]).rotate_left(9);
	block[2] = (block[1] ^ rk[94]).wrapping_add(block[2] ^ rk[95]).rotate_right(3);
	block[1] = (block[0] ^ rk[92]).wrapping_add(block[1] ^ rk[93]).rotate_right(5);
	block[0] = (block[3] ^ rk[90]).wrapping_add(block[0] ^ rk[91]).rotate_left(9);

	block[3] = (block[2] ^ rk[100]).wrapping_add(block[3] ^ rk[101]).rotate_right(3);
	block[2] = (block[1] ^ rk[98]).wrapping_add(block[2] ^ rk[99]).rotate_right(5);
	block[1] = (block[0] ^ rk[96]).wrapping_add(block[1] ^ rk[97]).rotate_left(9);
	block[0] = (block[3] ^ rk[106]).wrapping_add(block[0] ^ rk[107]).rotate_right(3);
	block[3] = (block[2] ^ rk[104]).wrapping_add(block[3] ^ rk[105]).rotate_right(5);
	block[2] = (block[1] ^ rk[102]).wrapping_add(block[2] ^ rk[103]).rotate_left(9);
	block[1] = (block[0] ^ rk[112]).wrapping_add(block[1] ^ rk[113]).rotate_right(3);
	block[0] = (block[3] ^ rk[110]).wrapping_add(block[0] ^ rk[111]).rotate_right(5);
	block[3] = (block[2] ^ rk[108]).wrapping_add(block[3] ^ rk[109]).rotate_left(9);
	block[2] = (block[1] ^ rk[118]).wrapping_add(block[2] ^ rk[119]).rotate_right(3);
	block[1] = (block[0] ^ rk[116]).wrapping_add(block[1] ^ rk[117]).rotate_right(5);
	block[0] = (block[3] ^ rk[114]).wrapping_add(block[0] ^ rk[115]).rotate_left(9);

	block[3] = (block[2] ^ rk[124]).wrapping_add(block[3] ^ rk[125]).rotate_right(3);
	block[2] = (block[1] ^ rk[122]).wrapping_add(block[2] ^ rk[123]).rotate_right(5);
	block[1] = (block[0] ^ rk[120]).wrapping_add(block[1] ^ rk[121]).rotate_left(9);
	block[0] = (block[3] ^ rk[130]).wrapping_add(block[0] ^ rk[131]).rotate_right(3);
	block[3] = (block[2] ^ rk[128]).wrapping_add(block[3] ^ rk[129]).rotate_right(5);
	block[2] = (block[1] ^ rk[126]).wrapping_add(block[2] ^ rk[127]).rotate_left(9);
	block[1] = (block[0] ^ rk[136]).wrapping_add(block[1] ^ rk[137]).rotate_right(3);
	block[0] = (block[3] ^ rk[134]).wrapping_add(block[0] ^ rk[135]).rotate_right(5);
	block[3] = (block[2] ^ rk[132]).wrapping_add(block[3] ^ rk[133]).rotate_left(9);
	block[2] = (block[1] ^ rk[142]).wrapping_add(block[2] ^ rk[143]).rotate_right(3);
	block[1] = (block[0] ^ rk[140]).wrapping_add(block[1] ^ rk[141]).rotate_right(5);
	block[0] = (block[3] ^ rk[138]).wrapping_add(block[0] ^ rk[139]).rotate_left(9);

	// 28 rounds for 192-bit key
	if L::USIZE / 6 >= 28 {
		block[3] = (block[2] ^ rk[148]).wrapping_add(block[3] ^ rk[149]).rotate_right(3);
		block[2] = (block[1] ^ rk[146]).wrapping_add(block[2] ^ rk[147]).rotate_right(5);
		block[1] = (block[0] ^ rk[144]).wrapping_add(block[1] ^ rk[145]).rotate_left(9);
		block[0] = (block[3] ^ rk[154]).wrapping_add(block[0] ^ rk[155]).rotate_right(3);
		block[3] = (block[2] ^ rk[152]).wrapping_add(block[3] ^ rk[153]).rotate_right(5);
		block[2] = (block[1] ^ rk[150]).wrapping_add(block[2] ^ rk[151]).rotate_left(9);
		block[1] = (block[0] ^ rk[160]).wrapping_add(block[1] ^ rk[161]).rotate_right(3);
		block[0] = (block[3] ^ rk[158]).wrapping_add(block[0] ^ rk[159]).rotate_right(5);
		block[3] = (block[2] ^ rk[156]).wrapping_add(block[3] ^ rk[157]).rotate_left(9);
		block[2] = (block[1] ^ rk[166]).wrapping_add(block[2] ^ rk[167]).rotate_right(3);
		block[1] = (block[0] ^ rk[164]).wrapping_add(block[1] ^ rk[165]).rotate_right(5);
		block[0] = (block[3] ^ rk[162]).wrapping_add(block[0] ^ rk[163]).rotate_left(9);
	}

	// 32 rounds for 256-bit key
	if L::USIZE / 6 >= 32 {
		block[3] = (block[2] ^ rk[172]).wrapping_add(block[3] ^ rk[173]).rotate_right(3);
		block[2] = (block[1] ^ rk[170]).wrapping_add(block[2] ^ rk[171]).rotate_right(5);
		block[1] = (block[0] ^ rk[168]).wrapping_add(block[1] ^ rk[169]).rotate_left(9);
		block[0] = (block[3] ^ rk[178]).wrapping_add(block[0] ^ rk[179]).rotate_right(3);
		block[3] = (block[2] ^ rk[176]).wrapping_add(block[3] ^ rk[177]).rotate_right(5);
		block[2] = (block[1] ^ rk[174]).wrapping_add(block[2] ^ rk[175]).rotate_left(9);
		block[1] = (block[0] ^ rk[184]).wrapping_add(block[1] ^ rk[185]).rotate_right(3);
		block[0] = (block[3] ^ rk[182]).wrapping_add(block[0] ^ rk[183]).rotate_right(5);
		block[3] = (block[2] ^ rk[180]).wrapping_add(block[3] ^ rk[181]).rotate_left(9);
		block[2] = (block[1] ^ rk[190]).wrapping_add(block[2] ^ rk[191]).rotate_right(3);
		block[1] = (block[0] ^ rk[188]).wrapping_add(block[1] ^ rk[189]).rotate_right(5);
		block[0] = (block[3] ^ rk[186]).wrapping_add(block[0] ^ rk[187]).rotate_left(9);
	}

	cfg_if::cfg_if! {
		if #[cfg(target_endian = "big")] {
			block[0] = block[0].swap_bytes();
			block[1] = block[1].swap_bytes();
			block[2] = block[2].swap_bytes();
			block[3] = block[3].swap_bytes();
		}
	}
}

fn decrypt_block<L: ArrayLength<u32>>(rk: &GenericArray<u32, L>, block: &mut Block) {
	cfg_if::cfg_if! {
		if #[cfg(target_endian = "big")] {
			let mut block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };
			block[0] = block[0].swap_bytes();
			block[1] = block[1].swap_bytes();
			block[2] = block[2].swap_bytes();
			block[3] = block[3].swap_bytes();
		} else {
			let block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };
		}
	}

	// 32 rounds for 256-bit key
	if L::USIZE / 6 >= 32 {
		block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ rk[186]) ^ rk[187];
		block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ rk[188]) ^ rk[189];
		block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ rk[190]) ^ rk[191];
		block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ rk[180]) ^ rk[181];
		block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ rk[182]) ^ rk[183];
		block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ rk[184]) ^ rk[185];
		block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ rk[174]) ^ rk[175];
		block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ rk[176]) ^ rk[177];
		block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ rk[178]) ^ rk[179];
		block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ rk[168]) ^ rk[169];
		block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ rk[170]) ^ rk[171];
		block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ rk[172]) ^ rk[173];
	}
	
	// 28 rounds for 192-bit key
	if L::USIZE / 6 >= 28 {
		block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ rk[162]) ^ rk[163];
		block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ rk[164]) ^ rk[165];
		block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ rk[166]) ^ rk[167];
		block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ rk[156]) ^ rk[157];
		block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ rk[158]) ^ rk[159];
		block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ rk[160]) ^ rk[161];
		block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ rk[150]) ^ rk[151];
		block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ rk[152]) ^ rk[153];
		block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ rk[154]) ^ rk[155];
		block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ rk[144]) ^ rk[145];
		block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ rk[146]) ^ rk[147];
		block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ rk[148]) ^ rk[149];
	}
	
	// 24 rounds for 128-bit key
	block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ rk[138]) ^ rk[139];
	block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ rk[140]) ^ rk[141];
	block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ rk[142]) ^ rk[143];
	block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ rk[132]) ^ rk[133];
	block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ rk[134]) ^ rk[135];
	block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ rk[136]) ^ rk[137];
	block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ rk[126]) ^ rk[127];
	block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ rk[128]) ^ rk[129];
	block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ rk[130]) ^ rk[131];
	block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ rk[120]) ^ rk[121];
	block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ rk[122]) ^ rk[123];
	block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ rk[124]) ^ rk[125];
	
	block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ rk[114]) ^ rk[115];
	block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ rk[116]) ^ rk[117];
	block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ rk[118]) ^ rk[119];
	block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ rk[108]) ^ rk[109];
	block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ rk[110]) ^ rk[111];
	block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ rk[112]) ^ rk[113];
	block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ rk[102]) ^ rk[103];
	block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ rk[104]) ^ rk[105];
	block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ rk[106]) ^ rk[107];
	block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ rk[96]) ^ rk[97];
	block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ rk[98]) ^ rk[99];
	block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ rk[100]) ^ rk[101];
	
	block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ rk[90]) ^ rk[91];
	block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ rk[92]) ^ rk[93];
	block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ rk[94]) ^ rk[95];
	block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ rk[84]) ^ rk[85];
	block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ rk[86]) ^ rk[87];
	block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ rk[88]) ^ rk[89];
	block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ rk[78]) ^ rk[79];
	block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ rk[80]) ^ rk[81];
	block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ rk[82]) ^ rk[83];
	block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ rk[72]) ^ rk[73];
	block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ rk[74]) ^ rk[75];
	block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ rk[76]) ^ rk[77];
	
	block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ rk[66]) ^ rk[67];
	block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ rk[68]) ^ rk[69];
	block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ rk[70]) ^ rk[71];
	block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ rk[60]) ^ rk[61];
	block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ rk[62]) ^ rk[63];
	block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ rk[64]) ^ rk[65];
	block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ rk[54]) ^ rk[55];
	block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ rk[56]) ^ rk[57];
	block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ rk[58]) ^ rk[59];
	block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ rk[48]) ^ rk[49];
	block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ rk[50]) ^ rk[51];
	block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ rk[52]) ^ rk[53];
	
	block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ rk[42]) ^ rk[43];
	block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ rk[44]) ^ rk[45];
	block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ rk[46]) ^ rk[47];
	block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ rk[36]) ^ rk[37];
	block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ rk[38]) ^ rk[39];
	block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ rk[40]) ^ rk[41];
	block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ rk[30]) ^ rk[31];
	block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ rk[32]) ^ rk[33];
	block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ rk[34]) ^ rk[35];
	block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ rk[24]) ^ rk[25];
	block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ rk[26]) ^ rk[27];
	block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ rk[28]) ^ rk[29];
	
	block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ rk[18]) ^ rk[19];
	block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ rk[20]) ^ rk[21];
	block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ rk[22]) ^ rk[23];
	block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ rk[12]) ^ rk[13];
	block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ rk[14]) ^ rk[15];
	block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ rk[16]) ^ rk[17];
	block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ rk[6]) ^ rk[7];
	block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ rk[8]) ^ rk[9];
	block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ rk[10]) ^ rk[11];
	block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ rk[0]) ^ rk[1];
	block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ rk[2]) ^ rk[3];
	block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ rk[4]) ^ rk[5];

	cfg_if::cfg_if! {
		if #[cfg(target_endian = "big")] {
			block[0] = block[0].swap_bytes();
			block[1] = block[1].swap_bytes();
			block[2] = block[2].swap_bytes();
			block[3] = block[3].swap_bytes();
		}
	}
}

#[cfg(test)]
mod tests {
	use block_cipher::generic_array::arr;

	use super::*;

	pub struct TestVector<T> where
	T: BlockCipher + NewBlockCipher {
		key:  Key<T>,
		ptxt: Block,
		ctxt: Block
	}

	#[test]
	fn lea128() {
		let test_vector: TestVector<Lea128> = TestVector {
			key:  arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0],
			ptxt: arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F],
			ctxt: arr![u8; 0x9F, 0xC8, 0x4E, 0x35, 0x28, 0xC6, 0xC6, 0x18, 0x55, 0x32, 0xC7, 0xA7, 0x04, 0x64, 0x8B, 0xFD]
		};

		let lea128 = Lea128::new(&test_vector.key);

		// Encryption
		let mut block = test_vector.ptxt.clone();
		lea128.encrypt_block(&mut block);
		assert_eq!(block, test_vector.ctxt);

		// Decryption
		let mut block = test_vector.ctxt.clone();
		lea128.decrypt_block(&mut block);
		assert_eq!(block, test_vector.ptxt);
	}

	#[test]
	fn lea192() {
		let test_vector: TestVector<Lea192> = TestVector {
			key:  arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,	0xC3, 0xD2, 0xE1, 0xF0, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87],
			ptxt: arr![u8; 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F],
			ctxt: arr![u8; 0x6F, 0xB9, 0x5E, 0x32, 0x5A, 0xAD, 0x1B, 0x87, 0x8C, 0xDC, 0xF5, 0x35, 0x76, 0x74, 0xC6, 0xF2]
		};

		let lea192 = Lea192::new(&test_vector.key);

		// Encryption
		let mut block = test_vector.ptxt.clone();
		lea192.encrypt_block(&mut block);
		assert_eq!(block, test_vector.ctxt);

		// Decryption
		let mut block = test_vector.ctxt.clone();
		lea192.decrypt_block(&mut block);
		assert_eq!(block, test_vector.ptxt);
	}

	#[test]
	fn lea256() {
		let test_vector: TestVector<Lea256> = TestVector {
			key:  arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,	0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F],
			ptxt: arr![u8; 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F],
			ctxt: arr![u8; 0xD6, 0x51, 0xAF, 0xF6, 0x47, 0xB1, 0x89, 0xC1, 0x3A, 0x89, 0x00, 0xCA, 0x27, 0xF9, 0xE1, 0x97]
		};

		let lea256 = Lea256::new(&test_vector.key);

		// Encryption
		let mut block = test_vector.ptxt.clone();
		lea256.encrypt_block(&mut block);
		assert_eq!(block, test_vector.ctxt);

		// Decryption
		let mut block = test_vector.ctxt.clone();
		lea256.decrypt_block(&mut block);
		assert_eq!(block, test_vector.ptxt);
	}
}
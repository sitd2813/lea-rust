// This file is the part of `lea-rust`.
//
// Author: SitD <sitd0813@gmail.com>
//
// This file is licensed under the Unlicense.
// See LICENSE.txt for more information or you can obtain a copy at <http://unlicense.org/>.

//! LEA-128/192/256 implementations
//!
//! * Examples
//!
//! Encryption
//! ```
//! use lea::Lea128;
//! use lea::block_cipher_trait::BlockCipher;
//! use lea::generic_array::GenericArray;
//! use lea::generic_array::arr;
//! use lea::generic_array::arr_impl;
//!
//! let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
//! let lea = Lea128::new(&key);
//!
//! let mut block = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
//!
//! lea.encrypt_block(&mut block);
//!
//! let cipher = arr![u8; 0x9F, 0xC8, 0x4E, 0x35, 0x28, 0xC6, 0xC6, 0x18, 0x55, 0x32, 0xC7, 0xA7, 0x04, 0x64, 0x8B, 0xFD];
//!
//! assert_eq!(block, cipher);
//! ```
//!
//! Decryption
//! ```
//! use lea::Lea128;
//! use lea::block_cipher_trait::BlockCipher;
//! use lea::generic_array::GenericArray;
//! use lea::generic_array::arr;
//! use lea::generic_array::arr_impl;
//!
//! let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
//! let lea = Lea128::new(&key);
//!
//! let mut block = arr![u8; 0x9F, 0xC8, 0x4E, 0x35, 0x28, 0xC6, 0xC6, 0x18, 0x55, 0x32, 0xC7, 0xA7, 0x04, 0x64, 0x8B, 0xFD];
//!
//! lea.decrypt_block(&mut block);
//!
//! let plain = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
//!
//! assert_eq!(block, plain);
//! ```

#![no_std]

pub extern crate block_cipher_trait;
pub extern crate generic_array;
pub extern crate stream_cipher;

mod ctr;
pub use ctr::{Lea128Ctr, Lea192Ctr, Lea256Ctr};
mod gcm;

//--- General implementation ---//
use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_endian = "big")] {
        use core::convert::TryInto;

        use crate::generic_array::typenum::{U4, U6};
    }
}

use crate::block_cipher_trait::BlockCipher;
use crate::generic_array::typenum::{U8, U16, U24, U32, U192};
use crate::generic_array::GenericArray;

static DELTA: [u32; 8] = [
    0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC, 0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957,
];

struct RoundKey {
    rk: GenericArray<u32, U192>,
    round: u32,
}

impl RoundKey {
    fn new_128(key_u8: &GenericArray<u8, U16>) -> Self {
        let mut rk = GenericArray::default();
        let round = 24;

        cfg_if! {
            if #[cfg(target_endian = "big")] {
                let mut key = GenericArray::<u32, U4>::default();
                for (key_u8, key) in (*key_u8).chunks(4).zip(&mut key) {
                    *key = u32::from_le_bytes(key_u8.try_into().unwrap());
                }
            } else if #[cfg(target_endian = "little")] {
                #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
                let key = unsafe { &*(key_u8.as_ptr() as *const [u32; 4]) };
            }
        }

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

        Self { rk, round }
    }

    fn new_192(key_u8: &GenericArray<u8, U24>) -> Self {
        let mut rk = GenericArray::default();
        let round = 28;

        cfg_if! {
            if #[cfg(target_endian = "big")] {
                let mut key = GenericArray::<u32, U6>::default();
                for (key_u8, key) in (*key_u8).chunks(4).zip(&mut key) {
                    *key = u32::from_le_bytes(key_u8.try_into().unwrap());
                }
            } else if #[cfg(target_endian = "little")] {
                #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
                let key = unsafe { &*(key_u8.as_ptr() as *const [u32; 6]) };
            }
        }

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

        Self { rk, round }
    }

    fn new_256(key_u8: &GenericArray<u8, U32>) -> Self {
        let mut rk = GenericArray::default();
        let round = 32;

        cfg_if! {
            if #[cfg(target_endian = "big")] {
                let mut key = GenericArray::<u32, U8>::default();
                for (key_u8, key) in (*key_u8).chunks(4).zip(&mut key) {
                    *key = u32::from_le_bytes(key_u8.try_into().unwrap());
                }
            } else if #[cfg(target_endian = "little")] {
                #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
                let key = unsafe { &*(key_u8.as_ptr() as *const [u32; 8]) };
            }
        }

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

        Self { rk, round }
    }
}

pub struct Lea128 {
    round_key: RoundKey,
}

impl BlockCipher for Lea128 {
    type BlockSize = U16;
    type KeySize = U16;
    type ParBlocks = U8;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            round_key: RoundKey::new_128(key),
        }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        encrypt_block(&self.round_key, block);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        decrypt_block(&self.round_key, block);
    }
}

pub struct Lea192 {
    round_key: RoundKey,
}

impl BlockCipher for Lea192 {
    type BlockSize = U16;
    type KeySize = U24;
    type ParBlocks = U8;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            round_key: RoundKey::new_192(key),
        }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        encrypt_block(&self.round_key, block);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        decrypt_block(&self.round_key, block);
    }
}

pub struct Lea256 {
    round_key: RoundKey,
}

impl BlockCipher for Lea256 {
    type BlockSize = U16;
    type KeySize = U32;
    type ParBlocks = U8;

    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self {
            round_key: RoundKey::new_256(key),
        }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        encrypt_block(&self.round_key, block);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        decrypt_block(&self.round_key, block);
    }
}

fn encrypt_block(round_key: &RoundKey, block: &mut GenericArray<u8, U16>) {
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
    let block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };

    // 100% slower but smaller binary size
    // let mut i = 0;
    // for _ in 0..(round_key.round >> 2) {
    //     for [a, b, c, d] in &[[3, 2, 1, 0], [0, 3, 2, 1], [1, 0, 3, 2], [2, 1, 0, 3]] {
    //         block[*a] = (block[*b] ^ round_key.rk[4 + 6 * i])
    //             .wrapping_add(block[*a] ^ round_key.rk[5 + 6 * i])
    //             .rotate_right(3);
    //         block[*b] = (block[*c] ^ round_key.rk[2 + 6 * i])
    //             .wrapping_add(block[*b] ^ round_key.rk[3 + 6 * i])
    //             .rotate_right(5);
    //         block[*c] = (block[*d] ^ round_key.rk[6 * i])
    //             .wrapping_add(block[*c] ^ round_key.rk[1 + 6 * i])
    //             .rotate_left(9);
    //         i += 1;
    //     }
    // }

    block[3] = (block[2] ^ round_key.rk[4]).wrapping_add(block[3] ^ round_key.rk[5]).rotate_right(3);
    block[2] = (block[1] ^ round_key.rk[2]).wrapping_add(block[2] ^ round_key.rk[3]).rotate_right(5);
    block[1] = (block[0] ^ round_key.rk[0]).wrapping_add(block[1] ^ round_key.rk[1]).rotate_left(9);
    block[0] = (block[3] ^ round_key.rk[10]).wrapping_add(block[0] ^ round_key.rk[11]).rotate_right(3);
    block[3] = (block[2] ^ round_key.rk[8]).wrapping_add(block[3] ^ round_key.rk[9]).rotate_right(5);
    block[2] = (block[1] ^ round_key.rk[6]).wrapping_add(block[2] ^ round_key.rk[7]).rotate_left(9);
    block[1] = (block[0] ^ round_key.rk[16]).wrapping_add(block[1] ^ round_key.rk[17]).rotate_right(3);
    block[0] = (block[3] ^ round_key.rk[14]).wrapping_add(block[0] ^ round_key.rk[15]).rotate_right(5);
    block[3] = (block[2] ^ round_key.rk[12]).wrapping_add(block[3] ^ round_key.rk[13]).rotate_left(9);
    block[2] = (block[1] ^ round_key.rk[22]).wrapping_add(block[2] ^ round_key.rk[23]).rotate_right(3);
    block[1] = (block[0] ^ round_key.rk[20]).wrapping_add(block[1] ^ round_key.rk[21]).rotate_right(5);
    block[0] = (block[3] ^ round_key.rk[18]).wrapping_add(block[0] ^ round_key.rk[19]).rotate_left(9);

    block[3] = (block[2] ^ round_key.rk[28]).wrapping_add(block[3] ^ round_key.rk[29]).rotate_right(3);
    block[2] = (block[1] ^ round_key.rk[26]).wrapping_add(block[2] ^ round_key.rk[27]).rotate_right(5);
    block[1] = (block[0] ^ round_key.rk[24]).wrapping_add(block[1] ^ round_key.rk[25]).rotate_left(9);
    block[0] = (block[3] ^ round_key.rk[34]).wrapping_add(block[0] ^ round_key.rk[35]).rotate_right(3);
    block[3] = (block[2] ^ round_key.rk[32]).wrapping_add(block[3] ^ round_key.rk[33]).rotate_right(5);
    block[2] = (block[1] ^ round_key.rk[30]).wrapping_add(block[2] ^ round_key.rk[31]).rotate_left(9);
    block[1] = (block[0] ^ round_key.rk[40]).wrapping_add(block[1] ^ round_key.rk[41]).rotate_right(3);
    block[0] = (block[3] ^ round_key.rk[38]).wrapping_add(block[0] ^ round_key.rk[39]).rotate_right(5);
    block[3] = (block[2] ^ round_key.rk[36]).wrapping_add(block[3] ^ round_key.rk[37]).rotate_left(9);
    block[2] = (block[1] ^ round_key.rk[46]).wrapping_add(block[2] ^ round_key.rk[47]).rotate_right(3);
    block[1] = (block[0] ^ round_key.rk[44]).wrapping_add(block[1] ^ round_key.rk[45]).rotate_right(5);
    block[0] = (block[3] ^ round_key.rk[42]).wrapping_add(block[0] ^ round_key.rk[43]).rotate_left(9);

    block[3] = (block[2] ^ round_key.rk[52]).wrapping_add(block[3] ^ round_key.rk[53]).rotate_right(3);
    block[2] = (block[1] ^ round_key.rk[50]).wrapping_add(block[2] ^ round_key.rk[51]).rotate_right(5);
    block[1] = (block[0] ^ round_key.rk[48]).wrapping_add(block[1] ^ round_key.rk[49]).rotate_left(9);
    block[0] = (block[3] ^ round_key.rk[58]).wrapping_add(block[0] ^ round_key.rk[59]).rotate_right(3);
    block[3] = (block[2] ^ round_key.rk[56]).wrapping_add(block[3] ^ round_key.rk[57]).rotate_right(5);
    block[2] = (block[1] ^ round_key.rk[54]).wrapping_add(block[2] ^ round_key.rk[55]).rotate_left(9);
    block[1] = (block[0] ^ round_key.rk[64]).wrapping_add(block[1] ^ round_key.rk[65]).rotate_right(3);
    block[0] = (block[3] ^ round_key.rk[62]).wrapping_add(block[0] ^ round_key.rk[63]).rotate_right(5);
    block[3] = (block[2] ^ round_key.rk[60]).wrapping_add(block[3] ^ round_key.rk[61]).rotate_left(9);
    block[2] = (block[1] ^ round_key.rk[70]).wrapping_add(block[2] ^ round_key.rk[71]).rotate_right(3);
    block[1] = (block[0] ^ round_key.rk[68]).wrapping_add(block[1] ^ round_key.rk[69]).rotate_right(5);
    block[0] = (block[3] ^ round_key.rk[66]).wrapping_add(block[0] ^ round_key.rk[67]).rotate_left(9);

    block[3] = (block[2] ^ round_key.rk[76]).wrapping_add(block[3] ^ round_key.rk[77]).rotate_right(3);
    block[2] = (block[1] ^ round_key.rk[74]).wrapping_add(block[2] ^ round_key.rk[75]).rotate_right(5);
    block[1] = (block[0] ^ round_key.rk[72]).wrapping_add(block[1] ^ round_key.rk[73]).rotate_left(9);
    block[0] = (block[3] ^ round_key.rk[82]).wrapping_add(block[0] ^ round_key.rk[83]).rotate_right(3);
    block[3] = (block[2] ^ round_key.rk[80]).wrapping_add(block[3] ^ round_key.rk[81]).rotate_right(5);
    block[2] = (block[1] ^ round_key.rk[78]).wrapping_add(block[2] ^ round_key.rk[79]).rotate_left(9);
    block[1] = (block[0] ^ round_key.rk[88]).wrapping_add(block[1] ^ round_key.rk[89]).rotate_right(3);
    block[0] = (block[3] ^ round_key.rk[86]).wrapping_add(block[0] ^ round_key.rk[87]).rotate_right(5);
    block[3] = (block[2] ^ round_key.rk[84]).wrapping_add(block[3] ^ round_key.rk[85]).rotate_left(9);
    block[2] = (block[1] ^ round_key.rk[94]).wrapping_add(block[2] ^ round_key.rk[95]).rotate_right(3);
    block[1] = (block[0] ^ round_key.rk[92]).wrapping_add(block[1] ^ round_key.rk[93]).rotate_right(5);
    block[0] = (block[3] ^ round_key.rk[90]).wrapping_add(block[0] ^ round_key.rk[91]).rotate_left(9);

    block[3] = (block[2] ^ round_key.rk[100]).wrapping_add(block[3] ^ round_key.rk[101]).rotate_right(3);
    block[2] = (block[1] ^ round_key.rk[98]).wrapping_add(block[2] ^ round_key.rk[99]).rotate_right(5);
    block[1] = (block[0] ^ round_key.rk[96]).wrapping_add(block[1] ^ round_key.rk[97]).rotate_left(9);
    block[0] = (block[3] ^ round_key.rk[106]).wrapping_add(block[0] ^ round_key.rk[107]).rotate_right(3);
    block[3] = (block[2] ^ round_key.rk[104]).wrapping_add(block[3] ^ round_key.rk[105]).rotate_right(5);
    block[2] = (block[1] ^ round_key.rk[102]).wrapping_add(block[2] ^ round_key.rk[103]).rotate_left(9);
    block[1] = (block[0] ^ round_key.rk[112]).wrapping_add(block[1] ^ round_key.rk[113]).rotate_right(3);
    block[0] = (block[3] ^ round_key.rk[110]).wrapping_add(block[0] ^ round_key.rk[111]).rotate_right(5);
    block[3] = (block[2] ^ round_key.rk[108]).wrapping_add(block[3] ^ round_key.rk[109]).rotate_left(9);
    block[2] = (block[1] ^ round_key.rk[118]).wrapping_add(block[2] ^ round_key.rk[119]).rotate_right(3);
    block[1] = (block[0] ^ round_key.rk[116]).wrapping_add(block[1] ^ round_key.rk[117]).rotate_right(5);
    block[0] = (block[3] ^ round_key.rk[114]).wrapping_add(block[0] ^ round_key.rk[115]).rotate_left(9);

    block[3] = (block[2] ^ round_key.rk[124]).wrapping_add(block[3] ^ round_key.rk[125]).rotate_right(3);
    block[2] = (block[1] ^ round_key.rk[122]).wrapping_add(block[2] ^ round_key.rk[123]).rotate_right(5);
    block[1] = (block[0] ^ round_key.rk[120]).wrapping_add(block[1] ^ round_key.rk[121]).rotate_left(9);
    block[0] = (block[3] ^ round_key.rk[130]).wrapping_add(block[0] ^ round_key.rk[131]).rotate_right(3);
    block[3] = (block[2] ^ round_key.rk[128]).wrapping_add(block[3] ^ round_key.rk[129]).rotate_right(5);
    block[2] = (block[1] ^ round_key.rk[126]).wrapping_add(block[2] ^ round_key.rk[127]).rotate_left(9);
    block[1] = (block[0] ^ round_key.rk[136]).wrapping_add(block[1] ^ round_key.rk[137]).rotate_right(3);
    block[0] = (block[3] ^ round_key.rk[134]).wrapping_add(block[0] ^ round_key.rk[135]).rotate_right(5);
    block[3] = (block[2] ^ round_key.rk[132]).wrapping_add(block[3] ^ round_key.rk[133]).rotate_left(9);
    block[2] = (block[1] ^ round_key.rk[142]).wrapping_add(block[2] ^ round_key.rk[143]).rotate_right(3);
    block[1] = (block[0] ^ round_key.rk[140]).wrapping_add(block[1] ^ round_key.rk[141]).rotate_right(5);
    block[0] = (block[3] ^ round_key.rk[138]).wrapping_add(block[0] ^ round_key.rk[139]).rotate_left(9);

    if round_key.round > 24 {
        block[3] = (block[2] ^ round_key.rk[148]).wrapping_add(block[3] ^ round_key.rk[149]).rotate_right(3);
        block[2] = (block[1] ^ round_key.rk[146]).wrapping_add(block[2] ^ round_key.rk[147]).rotate_right(5);
        block[1] = (block[0] ^ round_key.rk[144]).wrapping_add(block[1] ^ round_key.rk[145]).rotate_left(9);
        block[0] = (block[3] ^ round_key.rk[154]).wrapping_add(block[0] ^ round_key.rk[155]).rotate_right(3);
        block[3] = (block[2] ^ round_key.rk[152]).wrapping_add(block[3] ^ round_key.rk[153]).rotate_right(5);
        block[2] = (block[1] ^ round_key.rk[150]).wrapping_add(block[2] ^ round_key.rk[151]).rotate_left(9);
        block[1] = (block[0] ^ round_key.rk[160]).wrapping_add(block[1] ^ round_key.rk[161]).rotate_right(3);
        block[0] = (block[3] ^ round_key.rk[158]).wrapping_add(block[0] ^ round_key.rk[159]).rotate_right(5);
        block[3] = (block[2] ^ round_key.rk[156]).wrapping_add(block[3] ^ round_key.rk[157]).rotate_left(9);
        block[2] = (block[1] ^ round_key.rk[166]).wrapping_add(block[2] ^ round_key.rk[167]).rotate_right(3);
        block[1] = (block[0] ^ round_key.rk[164]).wrapping_add(block[1] ^ round_key.rk[165]).rotate_right(5);
        block[0] = (block[3] ^ round_key.rk[162]).wrapping_add(block[0] ^ round_key.rk[163]).rotate_left(9);
    }

    if round_key.round > 28 {
        block[3] = (block[2] ^ round_key.rk[172]).wrapping_add(block[3] ^ round_key.rk[173]).rotate_right(3);
        block[2] = (block[1] ^ round_key.rk[170]).wrapping_add(block[2] ^ round_key.rk[171]).rotate_right(5);
        block[1] = (block[0] ^ round_key.rk[168]).wrapping_add(block[1] ^ round_key.rk[169]).rotate_left(9);
        block[0] = (block[3] ^ round_key.rk[178]).wrapping_add(block[0] ^ round_key.rk[179]).rotate_right(3);
        block[3] = (block[2] ^ round_key.rk[176]).wrapping_add(block[3] ^ round_key.rk[177]).rotate_right(5);
        block[2] = (block[1] ^ round_key.rk[174]).wrapping_add(block[2] ^ round_key.rk[175]).rotate_left(9);
        block[1] = (block[0] ^ round_key.rk[184]).wrapping_add(block[1] ^ round_key.rk[185]).rotate_right(3);
        block[0] = (block[3] ^ round_key.rk[182]).wrapping_add(block[0] ^ round_key.rk[183]).rotate_right(5);
        block[3] = (block[2] ^ round_key.rk[180]).wrapping_add(block[3] ^ round_key.rk[181]).rotate_left(9);
        block[2] = (block[1] ^ round_key.rk[190]).wrapping_add(block[2] ^ round_key.rk[191]).rotate_right(3);
        block[1] = (block[0] ^ round_key.rk[188]).wrapping_add(block[1] ^ round_key.rk[189]).rotate_right(5);
        block[0] = (block[3] ^ round_key.rk[186]).wrapping_add(block[0] ^ round_key.rk[187]).rotate_left(9);
    }
}

fn decrypt_block(round_key: &RoundKey, block: &mut GenericArray<u8, U16>) {
    #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
    let block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };

    // 5% slower but smaller binary size
    // let mut i = 0;
    // let t = round_key.round as usize * 6 - 1;
    // for _ in 0..(round_key.round >> 2) {
    //     for [a, b, c, d] in &[[0, 1, 2, 3], [3, 0, 1, 2], [2, 3, 0, 1], [1, 2, 3, 0]] {
    //         block[*a] = block[*a]
    //             .rotate_right(9)
    //             .wrapping_sub(block[*d] ^ round_key.rk[t - 5 - 6 * i])
    //             ^ round_key.rk[t - 4 - 6 * i];
    //         block[*b] = block[*b]
    //             .rotate_left(5)
    //             .wrapping_sub(block[*a] ^ round_key.rk[t - 3 - 6 * i])
    //             ^ round_key.rk[t - 2 - 6 * i];
    //         block[*c] = block[*c]
    //             .rotate_left(3)
    //             .wrapping_sub(block[*b] ^ round_key.rk[t - 1 - 6 * i])
    //             ^ round_key.rk[t - 6 * i];
    //         i += 1;
    //     }
    // }

    if round_key.round > 28 {
        block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ round_key.rk[186]) ^ round_key.rk[187];
        block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ round_key.rk[188]) ^ round_key.rk[189];
        block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ round_key.rk[190]) ^ round_key.rk[191];
        block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ round_key.rk[180]) ^ round_key.rk[181];
        block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ round_key.rk[182]) ^ round_key.rk[183];
        block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ round_key.rk[184]) ^ round_key.rk[185];
        block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ round_key.rk[174]) ^ round_key.rk[175];
        block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ round_key.rk[176]) ^ round_key.rk[177];
        block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ round_key.rk[178]) ^ round_key.rk[179];
        block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ round_key.rk[168]) ^ round_key.rk[169];
        block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ round_key.rk[170]) ^ round_key.rk[171];
        block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ round_key.rk[172]) ^ round_key.rk[173];
    }

    if round_key.round > 24 {
        block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ round_key.rk[162]) ^ round_key.rk[163];
        block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ round_key.rk[164]) ^ round_key.rk[165];
        block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ round_key.rk[166]) ^ round_key.rk[167];
        block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ round_key.rk[156]) ^ round_key.rk[157];
        block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ round_key.rk[158]) ^ round_key.rk[159];
        block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ round_key.rk[160]) ^ round_key.rk[161];
        block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ round_key.rk[150]) ^ round_key.rk[151];
        block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ round_key.rk[152]) ^ round_key.rk[153];
        block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ round_key.rk[154]) ^ round_key.rk[155];
        block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ round_key.rk[144]) ^ round_key.rk[145];
        block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ round_key.rk[146]) ^ round_key.rk[147];
        block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ round_key.rk[148]) ^ round_key.rk[149];
    }

    block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ round_key.rk[138]) ^ round_key.rk[139];
    block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ round_key.rk[140]) ^ round_key.rk[141];
    block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ round_key.rk[142]) ^ round_key.rk[143];
    block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ round_key.rk[132]) ^ round_key.rk[133];
    block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ round_key.rk[134]) ^ round_key.rk[135];
    block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ round_key.rk[136]) ^ round_key.rk[137];
    block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ round_key.rk[126]) ^ round_key.rk[127];
    block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ round_key.rk[128]) ^ round_key.rk[129];
    block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ round_key.rk[130]) ^ round_key.rk[131];
    block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ round_key.rk[120]) ^ round_key.rk[121];
    block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ round_key.rk[122]) ^ round_key.rk[123];
    block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ round_key.rk[124]) ^ round_key.rk[125];

    block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ round_key.rk[114]) ^ round_key.rk[115];
    block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ round_key.rk[116]) ^ round_key.rk[117];
    block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ round_key.rk[118]) ^ round_key.rk[119];
    block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ round_key.rk[108]) ^ round_key.rk[109];
    block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ round_key.rk[110]) ^ round_key.rk[111];
    block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ round_key.rk[112]) ^ round_key.rk[113];
    block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ round_key.rk[102]) ^ round_key.rk[103];
    block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ round_key.rk[104]) ^ round_key.rk[105];
    block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ round_key.rk[106]) ^ round_key.rk[107];
    block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ round_key.rk[96]) ^ round_key.rk[97];
    block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ round_key.rk[98]) ^ round_key.rk[99];
    block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ round_key.rk[100]) ^ round_key.rk[101];

    block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ round_key.rk[90]) ^ round_key.rk[91];
    block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ round_key.rk[92]) ^ round_key.rk[93];
    block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ round_key.rk[94]) ^ round_key.rk[95];
    block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ round_key.rk[84]) ^ round_key.rk[85];
    block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ round_key.rk[86]) ^ round_key.rk[87];
    block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ round_key.rk[88]) ^ round_key.rk[89];
    block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ round_key.rk[78]) ^ round_key.rk[79];
    block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ round_key.rk[80]) ^ round_key.rk[81];
    block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ round_key.rk[82]) ^ round_key.rk[83];
    block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ round_key.rk[72]) ^ round_key.rk[73];
    block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ round_key.rk[74]) ^ round_key.rk[75];
    block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ round_key.rk[76]) ^ round_key.rk[77];

    block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ round_key.rk[66]) ^ round_key.rk[67];
    block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ round_key.rk[68]) ^ round_key.rk[69];
    block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ round_key.rk[70]) ^ round_key.rk[71];
    block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ round_key.rk[60]) ^ round_key.rk[61];
    block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ round_key.rk[62]) ^ round_key.rk[63];
    block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ round_key.rk[64]) ^ round_key.rk[65];
    block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ round_key.rk[54]) ^ round_key.rk[55];
    block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ round_key.rk[56]) ^ round_key.rk[57];
    block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ round_key.rk[58]) ^ round_key.rk[59];
    block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ round_key.rk[48]) ^ round_key.rk[49];
    block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ round_key.rk[50]) ^ round_key.rk[51];
    block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ round_key.rk[52]) ^ round_key.rk[53];

    block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ round_key.rk[42]) ^ round_key.rk[43];
    block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ round_key.rk[44]) ^ round_key.rk[45];
    block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ round_key.rk[46]) ^ round_key.rk[47];
    block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ round_key.rk[36]) ^ round_key.rk[37];
    block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ round_key.rk[38]) ^ round_key.rk[39];
    block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ round_key.rk[40]) ^ round_key.rk[41];
    block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ round_key.rk[30]) ^ round_key.rk[31];
    block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ round_key.rk[32]) ^ round_key.rk[33];
    block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ round_key.rk[34]) ^ round_key.rk[35];
    block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ round_key.rk[24]) ^ round_key.rk[25];
    block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ round_key.rk[26]) ^ round_key.rk[27];
    block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ round_key.rk[28]) ^ round_key.rk[29];

    block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ round_key.rk[18]) ^ round_key.rk[19];
    block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ round_key.rk[20]) ^ round_key.rk[21];
    block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ round_key.rk[22]) ^ round_key.rk[23];
    block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ round_key.rk[12]) ^ round_key.rk[13];
    block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ round_key.rk[14]) ^ round_key.rk[15];
    block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ round_key.rk[16]) ^ round_key.rk[17];
    block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ round_key.rk[6]) ^ round_key.rk[7];
    block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ round_key.rk[8]) ^ round_key.rk[9];
    block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ round_key.rk[10]) ^ round_key.rk[11];
    block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ round_key.rk[0]) ^ round_key.rk[1];
    block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ round_key.rk[2]) ^ round_key.rk[3];
    block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ round_key.rk[4]) ^ round_key.rk[5];
}

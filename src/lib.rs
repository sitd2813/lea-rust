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

//#![no_std]

pub extern crate block_cipher_trait;
pub extern crate stream_cipher;

pub use block_cipher_trait::generic_array;

pub mod ctr;
pub use ctr::{Lea128Ctr, Lea192Ctr, Lea256Ctr};
// pub mod gcm;

//--- General implementation ---//
use cfg_if::cfg_if;

use block_cipher_trait::BlockCipher;
use generic_array::ArrayLength;
use generic_array::GenericArray;
use generic_array::typenum::{U8, U16, U24, U32, U144, U168, U192};

static DELTA: [u32; 8] = [
    0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC, 0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957,
];

fn round_key_128_new(key_u8: &GenericArray<u8, U16>) -> GenericArray<u32, U144> {
    let mut rk = GenericArray::default();

    cfg_if! {
        if #[cfg(target_endian = "big")] {
            use core::convert::TryInto;
            use generic_array::typenum::U4;

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

    rk
}

fn round_key_192_new(key_u8: &GenericArray<u8, U24>) -> GenericArray<u32, U168> {
    let mut rk = GenericArray::default();

    cfg_if! {
        if #[cfg(target_endian = "big")] {
            use core::convert::TryInto;
            use generic_array::typenum::U6;

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

    rk
}

fn round_key_256_new(key_u8: &GenericArray<u8, U32>) -> GenericArray<u32, U192> {
    let mut rk = GenericArray::default();

    cfg_if! {
        if #[cfg(target_endian = "big")] {
            use core::convert::TryInto;

            let mut key = GenericArray::<u32, U8>::default();
            for (key_u8, key) in (*key_u8).chunks(4).zip(key.iter_mut()) {
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

    rk
}

macro_rules! generate_lea {
    ($name:ident, $round_key_new:ident, $round_key_size:ty, $key_size:ty) => {
        pub struct $name {
            round_key: GenericArray<u32, $round_key_size>,
        }
        
        impl BlockCipher for $name {
            type BlockSize = U16;
            type KeySize = $key_size;
            type ParBlocks = U8;
        
            fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
                let round_key = $round_key_new(key);
        
                Self { round_key }
            }
        
            fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
                encrypt_block(&self.round_key, block);
            }
        
            fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
                decrypt_block(&self.round_key, block);
            }
        }
    };
}

generate_lea!(Lea128, round_key_128_new, U144, U16);
generate_lea!(Lea192, round_key_192_new, U168, U24);
generate_lea!(Lea256, round_key_256_new, U192, U32);

fn encrypt_block<L: ArrayLength<u32>>(round_key: &GenericArray<u32, L>, block: &mut GenericArray<u8, U16>) {
    cfg_if! {
        if #[cfg(target_endian = "big")] {
            use core::convert::TryInto;
            use generic_array::typenum::U4;

            let block_u8 = block;
            let mut block = GenericArray::<u32, U4>::default();

            for (b_u8, b) in (*block_u8).chunks(4).zip(block.iter_mut()) {
                *b = u32::from_le_bytes(b_u8.try_into().unwrap());
            }
        } else if #[cfg(target_endian = "little")] {
            #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
            let block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };
        }
    }

    let mut i = 0;
    for _ in 0..(L::USIZE / 24) {
        for &[a, b, c, d] in [[3, 2, 1, 0], [0, 3, 2, 1], [1, 0, 3, 2], [2, 1, 0, 3]].iter() {
            block[a] = (block[b] ^ round_key[6 * i + 4]).wrapping_add(block[a] ^ round_key[6 * i + 5]).rotate_right(3);
            block[b] = (block[c] ^ round_key[6 * i + 2]).wrapping_add(block[b] ^ round_key[6 * i + 3]).rotate_right(5);
            block[c] = (block[d] ^ round_key[6 * i]).wrapping_add(block[c] ^ round_key[6 * i + 1]).rotate_left(9);
            i += 1;
        }
    }

    cfg_if! {
        if #[cfg(target_endian = "big")] {
            let mut i = 0;
            for b in block.iter() {
                let b_to_u8 = b.to_le_bytes();
                for b_to_u8 in b_to_u8.iter() {
                    block_u8[i] = *b_to_u8;
                    i += 1;
                }
            }
        }
    }
}

fn decrypt_block<L: ArrayLength<u32>>(round_key: &GenericArray<u32, L>, block: &mut GenericArray<u8, U16>) {
    cfg_if! {
        if #[cfg(target_endian = "big")] {
            use core::convert::TryInto;
            use generic_array::typenum::U4;

            let block_u8 = block;
            let mut block = GenericArray::<u32, U4>::default();

            for (b_u8, b) in (*block_u8).chunks(4).zip(block.iter_mut()) {
                *b = u32::from_le_bytes(b_u8.try_into().unwrap());
            }
        } else if #[cfg(target_endian = "little")] {
            #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
            let block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };
        }
    }

    let mut i = 0;
    let t = L::USIZE - 1;
    for _ in 0..(L::USIZE / 24) {
        for &[a, b, c, d] in [[0, 1, 2, 3], [3, 0, 1, 2], [2, 3, 0, 1], [1, 2, 3, 0]].iter() {
            block[a] = block[a].rotate_right(9).wrapping_sub(block[d] ^ round_key[t - 6 * i - 5]) ^ round_key[t - 6 * i - 4];
            block[b] = block[b].rotate_left(5).wrapping_sub(block[a] ^ round_key[t - 6 * i - 3]) ^ round_key[t - 6 * i - 2];
            block[c] = block[c].rotate_left(3).wrapping_sub(block[b] ^ round_key[t - 6 * i - 1]) ^ round_key[t - 6 * i];
            i += 1;
        }
    }

    cfg_if! {
        if #[cfg(target_endian = "big")] {
            let mut i = 0;
            for b in block.iter() {
                let b_to_u8 = b.to_le_bytes();
                for b_to_u8 in b_to_u8.iter() {
                    block_u8[i] = *b_to_u8;
                    i += 1;
                }
            }
        }
    }
}

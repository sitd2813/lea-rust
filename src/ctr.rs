// This file is the part of `lea-rust`.
//
// Author: SitD <sitd0813@gmail.com>
//
// This file is licensed under the MIT License.
// See LICENSE.txt for more information or you can obtain a copy at <https://opensource.org/licenses/MIT>.

//! LEA-128/192/256-CTR implementation
//!
//! * Examples
//!
//! Encryption
//! ```
//! use lea::ctr::Lea128Ctr;
//! use lea::stream_cipher::{NewStreamCipher, StreamCipher};
//! use lea::generic_array::arr;
//! use lea::generic_array::arr_impl;
//!
//! let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
//! let counter = arr![u8; 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
//! let mut lea128ctr = Lea128Ctr::new(&key, &counter);
//!
//! let mut data = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 
//!                         0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
//!                         0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
//!
//! lea128ctr.encrypt(&mut data);
//!
//! let cipher = arr![u8; 0x73, 0xB1, 0x2D, 0xA4, 0x4D, 0xFA, 0x06, 0x13, 0x99, 0x0A, 0xE8, 0xC1, 0x47, 0x87, 0x56, 0x62,
//!                       0xFB, 0x56, 0xC3, 0xEF, 0xBF, 0xDB, 0x23, 0xFE, 0x2A, 0x01, 0x13, 0x8B, 0x3A, 0x69, 0x2B, 0x4A,
//!                       0x9C, 0x47, 0xAE, 0x10, 0x64, 0x6C, 0x38, 0xD5, 0xBD, 0x80, 0xBA, 0x62, 0xF6, 0xB2, 0xA0, 0xFB];
//!
//! assert_eq!(data, cipher);
//! ```
//!
//! Decryption
//! ```
//! use lea::ctr::Lea128Ctr;
//! use lea::stream_cipher::{NewStreamCipher, StreamCipher};
//! use lea::generic_array::arr;
//! use lea::generic_array::arr_impl;
//!
//! let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
//! let counter = arr![u8; 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
//! let mut lea128ctr = Lea128Ctr::new(&key, &counter);
//!
//! let mut data = arr![u8; 0x73, 0xB1, 0x2D, 0xA4, 0x4D, 0xFA, 0x06, 0x13, 0x99, 0x0A, 0xE8, 0xC1, 0x47, 0x87, 0x56, 0x62,
//!                         0xFB, 0x56, 0xC3, 0xEF, 0xBF, 0xDB, 0x23, 0xFE, 0x2A, 0x01, 0x13, 0x8B, 0x3A, 0x69, 0x2B, 0x4A,
//!                         0x9C, 0x47, 0xAE, 0x10, 0x64, 0x6C, 0x38, 0xD5, 0xBD, 0x80, 0xBA, 0x62, 0xF6, 0xB2, 0xA0, 0xFB];
//!
//! lea128ctr.decrypt(&mut data);
//!
//! let plain = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 
//!                      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
//!                      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
//!
//! assert_eq!(data, plain);
//! ```

use cfg_if::cfg_if;

use crate::{Lea128, Lea192, Lea256};
use crate::block_cipher_trait::BlockCipher;
use crate::generic_array::ArrayLength;
use crate::generic_array::GenericArray;
use crate::generic_array::typenum::{U16, U24, U32};
use crate::stream_cipher::{NewStreamCipher, StreamCipher};

macro_rules! generate_lea_ctr {
    ($name:ident, $cipher:ident, $key_size:ty) => {
        pub struct $name {
            cipher: $cipher,
            nonce: GenericArray<u8, U16>,
        }

        impl NewStreamCipher for $name {
            type KeySize = $key_size;
            type NonceSize = U16;
        
            fn new(key: &GenericArray<u8, Self::KeySize>, nonce: &GenericArray<u8, Self::NonceSize>) -> Self {
                let cipher = $cipher::new(&key);
                let nonce = *nonce;
        
                Self { cipher, nonce }
            }
        }
        
        impl StreamCipher for $name {
            fn encrypt(&mut self, data: &mut [u8]) {
                encrypt(&self.cipher, &self.nonce, data);
            }
        
            fn decrypt(&mut self, data: &mut [u8]) {
                encrypt(&self.cipher, &self.nonce, data);
            }
        }
    };
}

generate_lea_ctr!(Lea128Ctr, Lea128, U16);
generate_lea_ctr!(Lea192Ctr, Lea192, U24);
generate_lea_ctr!(Lea256Ctr, Lea256, U32);

fn encrypt<C: BlockCipher>(cipher: &C, nonce: &GenericArray<u8, C::BlockSize>, data: &mut [u8]) {
    let mut counter = nonce.clone();

    data.chunks_mut(16).for_each(|data_16| {
        let block = &mut (counter.clone());
        cipher.encrypt_block(block);

        data_16.iter_mut().zip(block.iter()).for_each(|(d, b)| {
            *d ^= *b;
        });

        increment_counter(&mut counter);
    });
}

fn increment_counter<L: ArrayLength<u8>>(counter: &mut GenericArray<u8, L>) {
    cfg_if! {
        if #[cfg(target_endian = "big")] {
            for n in counter.iter_mut() {
                *n += 1;
                if *n != 0 {
                    break;
                }
            }
        } else if #[cfg(target_endian = "little")] {
            #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
            unsafe { *(counter.as_mut_ptr() as *mut u128) += 1 };
        }
    }
}
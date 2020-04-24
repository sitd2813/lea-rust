// This file is the part of `lea-rust`.
//
// Author: SitD <sitd0813@gmail.com>
//
// This file is licensed under the Unlicense.
// See LICENSE.txt for more information or you can obtain a copy at <http://unlicense.org/>.

//! LEA-128/192/256-CTR implementation

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(target_endian = "big")] {
        use core::convert::TryInto;
    }
}

use stream_cipher::{NewStreamCipher, StreamCipher};

use crate::{Lea128, Lea192, Lea256};
use crate::block_cipher_trait::BlockCipher;
use crate::generic_array::ArrayLength;
use crate::generic_array::GenericArray;
use crate::generic_array::typenum::{U16, U24, U32};

macro_rules! generate_ctr {
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

generate_ctr!(Lea128Ctr, Lea128, U16);
generate_ctr!(Lea192Ctr, Lea192, U24);
generate_ctr!(Lea256Ctr, Lea256, U32);

fn encrypt<C: BlockCipher>(cipher: &C, nonce: &GenericArray<u8, C::BlockSize>, data: &mut [u8]) {
    let mut counter = nonce.clone();

    for data in data.chunks_mut(16) {
        let mut block = counter.clone();
        cipher.encrypt_block(&mut block);

        for (d, b) in data.iter_mut().zip(block) {
            *d ^= b;
        }

        increment_counter(&mut counter);
    }
}

fn increment_counter<L: ArrayLength<u8>>(counter: &mut GenericArray<u8, L>) {
    cfg_if! {
        if #[cfg(target_endian = "big")] {
            let incremented = u128::from_le_bytes((*counter).try_into().unwrap()).wrapping_add(1);
            for (n, i) in counter.iter_mut().zip(incremented.to_le_bytes().iter()) {
                *n = *i;
            }
        } else if #[cfg(target_endian = "little")] {
            #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
            unsafe { *(counter.as_mut_ptr() as *mut u128) += 1 };
        }
    }
}
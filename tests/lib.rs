// This file is the part of `lea-rust`.
//
// Author: SitD <sitd0813@gmail.com>
//
// This file is licensed under the Unlicense.
// See LICENSE.txt for more information or you can obtain a copy at <http://unlicense.org/>.

#![cfg(test)]
#![no_std]

use lea::block_cipher_trait::BlockCipher;
use lea::generic_array::GenericArray;
use lea::{Lea128, Lea192, Lea256};

// Lea256
#[test]
fn lea256_encrypt_block() {
    let key = b"hello123hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea256 = Lea256::new(&key);

    let plain = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
    let mut plain = GenericArray::clone_from_slice(&plain);

    lea256.encrypt_block(&mut plain);

    let cipher = [10, 141, 70, 151, 126, 206, 87, 170, 229, 76, 210, 23, 64, 128, 20, 224];
    let cipher = GenericArray::clone_from_slice(&cipher);

    assert_eq!(plain, cipher);
}

#[test]
fn lea256_decrypt_block() {
    let key = b"hello123hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea256 = Lea256::new(&key);

    let cipher = [10, 141, 70, 151, 126, 206, 87, 170, 229, 76, 210, 23, 64, 128, 20, 224];
    let mut cipher = GenericArray::clone_from_slice(&cipher);

    lea256.decrypt_block(&mut cipher);

    let plain = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
    let plain = GenericArray::clone_from_slice(&plain);

    assert_eq!(cipher, plain);
}

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

//--- Lea128 ---//
#[test]
fn lea128_encrypt_block() {
    let key = b"hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea128 = Lea128::new(&key);

    let block = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
    let mut block = GenericArray::clone_from_slice(&block);

    lea128.encrypt_block(&mut block);

    let cipher = [197, 91, 145, 96, 2, 100, 101, 165, 95, 8, 20, 34, 19, 26, 220, 80];
    let cipher = GenericArray::clone_from_slice(&cipher);

    assert_eq!(block, cipher);
}

#[test]
fn lea128_decrypt_block() {
    let key = b"hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea128 = Lea128::new(&key);

    let block = [197, 91, 145, 96, 2, 100, 101, 165, 95, 8, 20, 34, 19, 26, 220, 80];
    let mut block = GenericArray::clone_from_slice(&block);

    lea128.decrypt_block(&mut block);

    let plain = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
    let plain = GenericArray::clone_from_slice(&plain);

    assert_eq!(block, plain);
}

//--- Lea192 ---//
#[test]
fn lea192_encrypt_block() {
    let key = b"hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea192 = Lea192::new(&key);

    let block = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
    let mut block = GenericArray::clone_from_slice(&block);

    lea192.encrypt_block(&mut block);

    let cipher = [20, 7, 163, 165, 144, 196, 226, 9, 26, 225, 176, 155, 7, 64, 182, 215];
    let cipher = GenericArray::clone_from_slice(&cipher);

    assert_eq!(block, cipher);
}

#[test]
fn lea192_decrypt_block() {
    let key = b"hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea192 = Lea192::new(&key);

    let block = [20, 7, 163, 165, 144, 196, 226, 9, 26, 225, 176, 155, 7, 64, 182, 215];
    let mut block = GenericArray::clone_from_slice(&block);

    lea192.decrypt_block(&mut block);

    let plain = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
    let plain = GenericArray::clone_from_slice(&plain);

    assert_eq!(block, plain);
}

//--- Lea256 ---//
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

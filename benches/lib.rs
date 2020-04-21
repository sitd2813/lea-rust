// This file is the part of `lea-rust`.
//
// Author: SitD <sitd0813@gmail.com>
//
// This file is licensed under the Unlicense.
// See LICENSE.txt for more information or you can obtain a copy at <http://unlicense.org/>.

#![cfg(test)]
#![feature(test)]
#![no_std]

extern crate test;

use test::Bencher;

use lea::block_cipher_trait::BlockCipher;
use lea::generic_array::GenericArray;
use lea::{Lea128, Lea192, Lea256};

//--- Lea128 ---//
#[bench]
fn lea128_generate_key(b: &mut Bencher) {
    let key = b"hello123hello123";
    let key = GenericArray::clone_from_slice(key);

    b.iter(|| {
        Lea128::new(&key);
    });
}

#[bench]
fn lea128_encrypt_block(b: &mut Bencher) {
    let key = b"hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea128 = Lea128::new(&key);

    let plain = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
    let mut plain = GenericArray::clone_from_slice(&plain);

    b.iter(|| {
        lea128.encrypt_block(&mut plain);
    });
}

#[bench]
fn lea128_decrypt_block(b: &mut Bencher) {
    let key = b"hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea128 = Lea128::new(&key);

    let cipher = [10, 141, 70, 151, 126, 206, 87, 170, 229, 76, 210, 23, 64, 128, 20, 224];
    let mut cipher = GenericArray::clone_from_slice(&cipher);

    b.iter(|| {
        lea128.decrypt_block(&mut cipher);
    });
}

//--- Lea192 ---//
#[bench]
fn lea192_generate_key(b: &mut Bencher) {
    let key = b"hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);

    b.iter(|| {
        Lea192::new(&key);
    });
}

#[bench]
fn lea192_encrypt_block(b: &mut Bencher) {
    let key = b"hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea192 = Lea192::new(&key);

    let plain = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
    let mut plain = GenericArray::clone_from_slice(&plain);

    b.iter(|| {
        lea192.encrypt_block(&mut plain);
    });
}

#[bench]
fn lea192_decrypt_block(b: &mut Bencher) {
    let key = b"hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea192 = Lea192::new(&key);

    let cipher = [10, 141, 70, 151, 126, 206, 87, 170, 229, 76, 210, 23, 64, 128, 20, 224];
    let mut cipher = GenericArray::clone_from_slice(&cipher);

    b.iter(|| {
        lea192.decrypt_block(&mut cipher);
    });
}

//--- Lea256 ---//
#[bench]
fn lea256_generate_key(b: &mut Bencher) {
    let key = b"hello123hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);

    b.iter(|| {
        Lea256::new(&key);
    });
}

#[bench]
fn lea256_encrypt_block(b: &mut Bencher) {
    let key = b"hello123hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea256 = Lea256::new(&key);

    let plain = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
    let mut plain = GenericArray::clone_from_slice(&plain);

    b.iter(|| {
        lea256.encrypt_block(&mut plain);
    });
}

#[bench]
fn lea256_decrypt_block(b: &mut Bencher) {
    let key = b"hello123hello123hello123hello123";
    let key = GenericArray::clone_from_slice(key);
    let lea256 = Lea256::new(&key);

    let cipher = [10, 141, 70, 151, 126, 206, 87, 170, 229, 76, 210, 23, 64, 128, 20, 224];
    let mut cipher = GenericArray::clone_from_slice(&cipher);

    b.iter(|| {
        lea256.decrypt_block(&mut cipher);
    });
}

// This file is the part of `lea-rust`.
//
// Author: SitD <sitd0813@gmail.com>
//
// This file is licensed under the MIT License.
// See LICENSE.txt for more information or you can obtain a copy at <https://opensource.org/licenses/MIT>.

#![cfg(test)]
#![feature(test)]
#![no_std]

extern crate test;

use test::Bencher;

use lea::block_cipher_trait::BlockCipher;
use lea::generic_array::GenericArray;
use lea::generic_array::arr;
use lea::generic_array::arr_impl;
use lea::generic_array::typenum::U16384;
use lea::stream_cipher::{NewStreamCipher, StreamCipher};

use lea::{Lea128, Lea192, Lea256};
use lea::ctr::{Lea128Ctr, Lea192Ctr, Lea256Ctr};

//--- Lea128 ---//
#[bench]
fn lea128_generate_key(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];

    b.iter(|| {
        Lea128::new(&key);
    });
}

#[bench]
fn lea128_encrypt_block(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
    let lea128 = Lea128::new(&key);

    let mut block = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    b.iter(|| {
        lea128.encrypt_block(&mut block);
    });
}

#[bench]
fn lea128_decrypt_block(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
    let lea128 = Lea128::new(&key);

    let mut block = arr![u8; 0x9F, 0xC8, 0x4E, 0x35, 0x28, 0xC6, 0xC6, 0x18, 0x55, 0x32, 0xC7, 0xA7, 0x04, 0x64, 0x8B, 0xFD];

    b.iter(|| {
        lea128.decrypt_block(&mut block);
    });
}

//--- Lea192 ---//
#[bench]
fn lea192_generate_key(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,
                       0xC3, 0xD2, 0xE1, 0xF0, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87];

    b.iter(|| {
        Lea192::new(&key);
    });
}

#[bench]
fn lea192_encrypt_block(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,
                       0xC3, 0xD2, 0xE1, 0xF0, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87];
    let lea192 = Lea192::new(&key);

    let mut block = arr![u8; 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F];

    b.iter(|| {
        lea192.encrypt_block(&mut block);
    });
}

#[bench]
fn lea192_decrypt_block(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,
                       0xC3, 0xD2, 0xE1, 0xF0, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87];
    let lea192 = Lea192::new(&key);

    let mut block = arr![u8; 0x6F, 0xB9, 0x5E, 0x32, 0x5A, 0xAD, 0x1B, 0x87, 0x8C, 0xDC, 0xF5, 0x35, 0x76, 0x74, 0xC6, 0xF2];

    b.iter(|| {
        lea192.decrypt_block(&mut block);
    });
}

//--- Lea256 ---//
#[bench]
fn lea256_generate_key(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
                       0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F];

    b.iter(|| {
        Lea256::new(&key);
    });
}

#[bench]
fn lea256_encrypt_block(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
                       0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F];
    let lea256 = Lea256::new(&key);

    let mut block = arr![u8; 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

    b.iter(|| {
        lea256.encrypt_block(&mut block);
    });
}

#[bench]
fn lea256_decrypt_block(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
                       0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F];
    let lea256 = Lea256::new(&key);

    let mut block = arr![u8; 0xD6, 0x51, 0xAF, 0xF6, 0x47, 0xB1, 0x89, 0xC1, 0x3A, 0x89, 0x00, 0xCA, 0x27, 0xF9, 0xE1, 0x97];

    b.iter(|| {
        lea256.decrypt_block(&mut block);
    });
}

//--- Lea128Ctr ---//
#[bench]
fn lea128ctr_encrypt(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
    let counter = arr![u8; 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let mut lea128ctr = Lea128Ctr::new(&key, &counter);

    let mut data = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 
                            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

    b.iter(|| {
        lea128ctr.encrypt(&mut data);
    });
}

#[bench]
fn lea128ctr_decrypt(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
    let counter = arr![u8; 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let mut lea128ctr = Lea128Ctr::new(&key, &counter);

    let mut data = arr![u8; 0x73, 0xB1, 0x2D, 0xA4, 0x4D, 0xFA, 0x06, 0x13, 0x99, 0x0A, 0xE8, 0xC1, 0x47, 0x87, 0x56, 0x62,
                            0xFB, 0x56, 0xC3, 0xEF, 0xBF, 0xDB, 0x23, 0xFE, 0x2A, 0x01, 0x13, 0x8B, 0x3A, 0x69, 0x2B, 0x4A,
                            0x9C, 0x47, 0xAE, 0x10, 0x64, 0x6C, 0x38, 0xD5, 0xBD, 0x80, 0xBA, 0x62, 0xF6, 0xB2, 0xA0, 0xFB];

    b.iter(|| {
        lea128ctr.decrypt(&mut data);
    });
}

//--- Lea192Ctr ---//
#[bench]
fn lea192ctr_encrypt(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,
                       0xC3, 0xD2, 0xE1, 0xF0, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87];
    let counter = arr![u8; 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let mut lea192ctr = Lea192Ctr::new(&key, &counter);

    let mut data = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 
                            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

    b.iter(|| {
        lea192ctr.encrypt(&mut data);
    });
}

#[bench]
fn lea192ctr_decrypt(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4,
                       0xC3, 0xD2, 0xE1, 0xF0, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87];
    let counter = arr![u8; 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let mut lea192ctr = Lea192Ctr::new(&key, &counter);

    let mut data = arr![u8; 0x72, 0xD9, 0x7F, 0x5B, 0xAA, 0x16, 0xCE, 0xDB, 0xE5, 0xAE, 0xFF, 0x42, 0xA7, 0x5D, 0xF3, 0x8A,
                            0x19, 0x08, 0x4C, 0xE9, 0xC3, 0x65, 0x7B, 0x23, 0x37, 0xE5, 0x73, 0x18, 0xD0, 0xCA, 0xF4, 0x7A,
                            0x80, 0x1C, 0x2E, 0x5D, 0x5F, 0x87, 0x08, 0x05, 0x11, 0xBB, 0xD8, 0xDB, 0x94, 0x0E, 0x6D, 0xC7];

    b.iter(|| {
        lea192ctr.decrypt(&mut data);
    });
}

//--- Lea256Ctr ---//
#[bench]
fn lea256ctr_encrypt(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
                       0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F];
    let counter = arr![u8; 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let mut lea256ctr = Lea256Ctr::new(&key, &counter);

    let mut data = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 
                        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
                        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

    b.iter(|| {
        lea256ctr.encrypt(&mut data);
    });
}

#[bench]
fn lea256ctr_encrypt_16384(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
                       0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F];
    let nonce = arr![u8; 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let mut lea256ctr = Lea256Ctr::new(&key, &nonce);

    let mut data: GenericArray<u8, U16384> = GenericArray::default();

    b.iter(|| {
        lea256ctr.encrypt(&mut data);
    });
}

#[bench]
fn lea256ctr_decrypt(b: &mut Bencher) {
    let key = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0,
                       0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F];
    let counter = arr![u8; 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let mut lea256ctr = Lea256Ctr::new(&key, &counter);

    let mut data = arr![u8; 0x15, 0x39, 0xF7, 0xA2, 0x1C, 0x0F, 0x16, 0x07, 0x6D, 0x90, 0xFB, 0xEB, 0x03, 0x97, 0xD4, 0x40,
                            0x2D, 0xFD, 0x4E, 0xB0, 0x44, 0x0B, 0x28, 0x3D, 0xE7, 0xE3, 0x0C, 0x36, 0x0D, 0x71, 0xF1, 0x47,
                            0x0E, 0x8B, 0xAF, 0xD2, 0x88, 0x3B, 0xA8, 0x08, 0x8D, 0x0C, 0x5D, 0xA7, 0xA9, 0x14, 0xAE, 0x90];

    b.iter(|| {
        lea256ctr.decrypt(&mut data);
    });
}
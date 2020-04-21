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
//! use lea::Lea256;
//! use lea::block_cipher_trait::BlockCipher;
//! use lea::generic_array::GenericArray;
//!
//! let key = b"hello123hello123hello123hello123";
//! let key = GenericArray::clone_from_slice(key);
//! let lea256 = Lea256::new(&key);
//!
//! let block = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
//! let mut block = GenericArray::clone_from_slice(&block);
//!
//! lea256.encrypt_block(&mut block);
//!
//! let cipher = [10, 141, 70, 151, 126, 206, 87, 170, 229, 76, 210, 23, 64, 128, 20, 224];
//! let cipher = GenericArray::clone_from_slice(&cipher);
//!
//! assert_eq!(block, cipher);
//! ```
//!
//! Decryption
//! ```
//! use lea::Lea256;
//! use lea::block_cipher_trait::BlockCipher;
//! use lea::generic_array::GenericArray;
//!
//! let key = b"hello123hello123hello123hello123";
//! let key = GenericArray::clone_from_slice(key);
//! let lea256 = Lea256::new(&key);
//!
//! let block = [10, 141, 70, 151, 126, 206, 87, 170, 229, 76, 210, 23, 64, 128, 20, 224];
//! let mut block = GenericArray::clone_from_slice(&block);
//!
//! lea256.decrypt_block(&mut block);
//!
//! let plain = [104, 101, 108, 108, 111, 44, 32, 116, 104, 105, 115, 32, 105, 115, 32, 117];
//! let plain = GenericArray::clone_from_slice(&plain);
//!
//! assert_eq!(block, plain);
//! ```

#![no_std]

pub extern crate block_cipher_trait;
pub use block_cipher_trait::generic_array;

mod ctr;
mod gcm;

//--- General implementation ---//
use crate::block_cipher_trait::BlockCipher;
use crate::generic_array::typenum::{U16, U192, U24, U32, U8};
use crate::generic_array::GenericArray;

type Block = GenericArray<u8, U16>;
type Key128 = GenericArray<u8, U16>;
type Key192 = GenericArray<u8, U24>;
type Key256 = GenericArray<u8, U32>;

static DELTA: [u32; 8] = [0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC, 0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957];

struct RoundKey {
    rk: GenericArray<u32, U192>,
    round: u32,
}

impl RoundKey {
    fn new_128(key: &Key128) -> Self {
        let mut rk = GenericArray::default();

        let key = unsafe { &*(key.as_ptr() as *const [u32; 4]) };
        let mut t = *key;
        for i in 0..24 {
            t[0] = t[0].wrapping_add(DELTA[i % 4].rotate_left(i as u32)).rotate_left(1);
            t[1] = t[1].wrapping_add(DELTA[i % 4].rotate_left(i as u32 + 1)).rotate_left(3);
            t[2] = t[2].wrapping_add(DELTA[i % 4].rotate_left(i as u32 + 2)).rotate_left(6);
            t[3] = t[3].wrapping_add(DELTA[i % 4].rotate_left(i as u32 + 3)).rotate_left(11);
            rk[6 * i] = t[0];
            rk[6 * i + 1] = t[1];
            rk[6 * i + 2] = t[2];
            rk[6 * i + 3] = t[1];
            rk[6 * i + 4] = t[3];
            rk[6 * i + 5] = t[1];
        }

        Self { rk, round: 24 }
    }

    fn new_192(key: &Key192) -> Self {
        let mut rk = GenericArray::default();

        let key = unsafe { &*(key.as_ptr() as *const [u32; 6]) };
        let mut t = *key;
        for i in 0..28 {
            t[0] = t[0].wrapping_add(DELTA[i % 6].rotate_left(i as u32)).rotate_left(1);
            t[1] = t[1].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 1)).rotate_left(3);
            t[2] = t[2].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 2)).rotate_left(6);
            t[3] = t[3].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 3)).rotate_left(11);
            t[4] = t[4].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 4)).rotate_left(13);
            t[5] = t[5].wrapping_add(DELTA[i % 6].rotate_left(i as u32 + 5)).rotate_left(17);
            rk[6 * i] = t[0];
            rk[6 * i + 1] = t[1];
            rk[6 * i + 2] = t[2];
            rk[6 * i + 3] = t[3];
            rk[6 * i + 4] = t[4];
            rk[6 * i + 5] = t[5];
        }

        Self { rk, round: 28 }
    }

    fn new_256(key: &Key256) -> Self {
        let mut rk = GenericArray::default();

        let key = unsafe { &*(key.as_ptr() as *const [u32; 8]) };
        let mut t = *key;
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

        Self { rk, round: 32 }
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
        Self { round_key: RoundKey::new_128(key) }
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
        Self { round_key: RoundKey::new_192(key) }
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
        Self { round_key: RoundKey::new_256(key) }
    }

    fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        encrypt_block(&self.round_key, block);
    }

    fn decrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
        decrypt_block(&self.round_key, block);
    }
}

fn encrypt_block(round_key: &RoundKey, block: &mut Block) {
    let block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };

    let mut i = 0;
    for _ in 0..(round_key.round >> 2) {
        for [a, b, c, d] in &[[3, 2, 1, 0], [0, 3, 2, 1], [1, 0, 3, 2], [2, 1, 0, 3]] {
            block[*a] = (block[*b] ^ round_key.rk[4 + 6 * i]).wrapping_add(block[*a] ^ round_key.rk[5 + 6 * i]).rotate_right(3);
            block[*b] = (block[*c] ^ round_key.rk[2 + 6 * i]).wrapping_add(block[*b] ^ round_key.rk[3 + 6 * i]).rotate_right(5);
            block[*c] = (block[*d] ^ round_key.rk[6 * i]).wrapping_add(block[*c] ^ round_key.rk[1 + 6 * i]).rotate_left(9);
            i += 1;
        }
    }

    // // 15% faster but bigger binary
    // block[3] = (block[2] ^ key.round_key[4]).wrapping_add(block[3] ^ key.round_key[5]).rotate_right(3);
    // block[2] = (block[1] ^ key.round_key[2]).wrapping_add(block[2] ^ key.round_key[3]).rotate_right(5);
    // block[1] = (block[0] ^ key.round_key[0]).wrapping_add(block[1] ^ key.round_key[1]).rotate_left(9);
    // block[0] = (block[3] ^ key.round_key[10]).wrapping_add(block[0] ^ key.round_key[11]).rotate_right(3);
    // block[3] = (block[2] ^ key.round_key[8]).wrapping_add(block[3] ^ key.round_key[9]).rotate_right(5);
    // block[2] = (block[1] ^ key.round_key[6]).wrapping_add(block[2] ^ key.round_key[7]).rotate_left(9);
    // block[1] = (block[0] ^ key.round_key[16]).wrapping_add(block[1] ^ key.round_key[17]).rotate_right(3);
    // block[0] = (block[3] ^ key.round_key[14]).wrapping_add(block[0] ^ key.round_key[15]).rotate_right(5);
    // block[3] = (block[2] ^ key.round_key[12]).wrapping_add(block[3] ^ key.round_key[13]).rotate_left(9);
    // block[2] = (block[1] ^ key.round_key[22]).wrapping_add(block[2] ^ key.round_key[23]).rotate_right(3);
    // block[1] = (block[0] ^ key.round_key[20]).wrapping_add(block[1] ^ key.round_key[21]).rotate_right(5);
    // block[0] = (block[3] ^ key.round_key[18]).wrapping_add(block[0] ^ key.round_key[19]).rotate_left(9);

    // block[3] = (block[2] ^ key.round_key[28]).wrapping_add(block[3] ^ key.round_key[29]).rotate_right(3);
    // block[2] = (block[1] ^ key.round_key[26]).wrapping_add(block[2] ^ key.round_key[27]).rotate_right(5);
    // block[1] = (block[0] ^ key.round_key[24]).wrapping_add(block[1] ^ key.round_key[25]).rotate_left(9);
    // block[0] = (block[3] ^ key.round_key[34]).wrapping_add(block[0] ^ key.round_key[35]).rotate_right(3);
    // block[3] = (block[2] ^ key.round_key[32]).wrapping_add(block[3] ^ key.round_key[33]).rotate_right(5);
    // block[2] = (block[1] ^ key.round_key[30]).wrapping_add(block[2] ^ key.round_key[31]).rotate_left(9);
    // block[1] = (block[0] ^ key.round_key[40]).wrapping_add(block[1] ^ key.round_key[41]).rotate_right(3);
    // block[0] = (block[3] ^ key.round_key[38]).wrapping_add(block[0] ^ key.round_key[39]).rotate_right(5);
    // block[3] = (block[2] ^ key.round_key[36]).wrapping_add(block[3] ^ key.round_key[37]).rotate_left(9);
    // block[2] = (block[1] ^ key.round_key[46]).wrapping_add(block[2] ^ key.round_key[47]).rotate_right(3);
    // block[1] = (block[0] ^ key.round_key[44]).wrapping_add(block[1] ^ key.round_key[45]).rotate_right(5);
    // block[0] = (block[3] ^ key.round_key[42]).wrapping_add(block[0] ^ key.round_key[43]).rotate_left(9);

    // block[3] = (block[2] ^ key.round_key[52]).wrapping_add(block[3] ^ key.round_key[53]).rotate_right(3);
    // block[2] = (block[1] ^ key.round_key[50]).wrapping_add(block[2] ^ key.round_key[51]).rotate_right(5);
    // block[1] = (block[0] ^ key.round_key[48]).wrapping_add(block[1] ^ key.round_key[49]).rotate_left(9);
    // block[0] = (block[3] ^ key.round_key[58]).wrapping_add(block[0] ^ key.round_key[59]).rotate_right(3);
    // block[3] = (block[2] ^ key.round_key[56]).wrapping_add(block[3] ^ key.round_key[57]).rotate_right(5);
    // block[2] = (block[1] ^ key.round_key[54]).wrapping_add(block[2] ^ key.round_key[55]).rotate_left(9);
    // block[1] = (block[0] ^ key.round_key[64]).wrapping_add(block[1] ^ key.round_key[65]).rotate_right(3);
    // block[0] = (block[3] ^ key.round_key[62]).wrapping_add(block[0] ^ key.round_key[63]).rotate_right(5);
    // block[3] = (block[2] ^ key.round_key[60]).wrapping_add(block[3] ^ key.round_key[61]).rotate_left(9);
    // block[2] = (block[1] ^ key.round_key[70]).wrapping_add(block[2] ^ key.round_key[71]).rotate_right(3);
    // block[1] = (block[0] ^ key.round_key[68]).wrapping_add(block[1] ^ key.round_key[69]).rotate_right(5);
    // block[0] = (block[3] ^ key.round_key[66]).wrapping_add(block[0] ^ key.round_key[67]).rotate_left(9);

    // block[3] = (block[2] ^ key.round_key[76]).wrapping_add(block[3] ^ key.round_key[77]).rotate_right(3);
    // block[2] = (block[1] ^ key.round_key[74]).wrapping_add(block[2] ^ key.round_key[75]).rotate_right(5);
    // block[1] = (block[0] ^ key.round_key[72]).wrapping_add(block[1] ^ key.round_key[73]).rotate_left(9);
    // block[0] = (block[3] ^ key.round_key[82]).wrapping_add(block[0] ^ key.round_key[83]).rotate_right(3);
    // block[3] = (block[2] ^ key.round_key[80]).wrapping_add(block[3] ^ key.round_key[81]).rotate_right(5);
    // block[2] = (block[1] ^ key.round_key[78]).wrapping_add(block[2] ^ key.round_key[79]).rotate_left(9);
    // block[1] = (block[0] ^ key.round_key[88]).wrapping_add(block[1] ^ key.round_key[89]).rotate_right(3);
    // block[0] = (block[3] ^ key.round_key[86]).wrapping_add(block[0] ^ key.round_key[87]).rotate_right(5);
    // block[3] = (block[2] ^ key.round_key[84]).wrapping_add(block[3] ^ key.round_key[85]).rotate_left(9);
    // block[2] = (block[1] ^ key.round_key[94]).wrapping_add(block[2] ^ key.round_key[95]).rotate_right(3);
    // block[1] = (block[0] ^ key.round_key[92]).wrapping_add(block[1] ^ key.round_key[93]).rotate_right(5);
    // block[0] = (block[3] ^ key.round_key[90]).wrapping_add(block[0] ^ key.round_key[91]).rotate_left(9);

    // block[3] = (block[2] ^ key.round_key[100]).wrapping_add(block[3] ^ key.round_key[101]).rotate_right(3);
    // block[2] = (block[1] ^ key.round_key[98]).wrapping_add(block[2] ^ key.round_key[99]).rotate_right(5);
    // block[1] = (block[0] ^ key.round_key[96]).wrapping_add(block[1] ^ key.round_key[97]).rotate_left(9);
    // block[0] = (block[3] ^ key.round_key[106]).wrapping_add(block[0] ^ key.round_key[107]).rotate_right(3);
    // block[3] = (block[2] ^ key.round_key[104]).wrapping_add(block[3] ^ key.round_key[105]).rotate_right(5);
    // block[2] = (block[1] ^ key.round_key[102]).wrapping_add(block[2] ^ key.round_key[103]).rotate_left(9);
    // block[1] = (block[0] ^ key.round_key[112]).wrapping_add(block[1] ^ key.round_key[113]).rotate_right(3);
    // block[0] = (block[3] ^ key.round_key[110]).wrapping_add(block[0] ^ key.round_key[111]).rotate_right(5);
    // block[3] = (block[2] ^ key.round_key[108]).wrapping_add(block[3] ^ key.round_key[109]).rotate_left(9);
    // block[2] = (block[1] ^ key.round_key[118]).wrapping_add(block[2] ^ key.round_key[119]).rotate_right(3);
    // block[1] = (block[0] ^ key.round_key[116]).wrapping_add(block[1] ^ key.round_key[117]).rotate_right(5);
    // block[0] = (block[3] ^ key.round_key[114]).wrapping_add(block[0] ^ key.round_key[115]).rotate_left(9);

    // block[3] = (block[2] ^ key.round_key[124]).wrapping_add(block[3] ^ key.round_key[125]).rotate_right(3);
    // block[2] = (block[1] ^ key.round_key[122]).wrapping_add(block[2] ^ key.round_key[123]).rotate_right(5);
    // block[1] = (block[0] ^ key.round_key[120]).wrapping_add(block[1] ^ key.round_key[121]).rotate_left(9);
    // block[0] = (block[3] ^ key.round_key[130]).wrapping_add(block[0] ^ key.round_key[131]).rotate_right(3);
    // block[3] = (block[2] ^ key.round_key[128]).wrapping_add(block[3] ^ key.round_key[129]).rotate_right(5);
    // block[2] = (block[1] ^ key.round_key[126]).wrapping_add(block[2] ^ key.round_key[127]).rotate_left(9);
    // block[1] = (block[0] ^ key.round_key[136]).wrapping_add(block[1] ^ key.round_key[137]).rotate_right(3);
    // block[0] = (block[3] ^ key.round_key[134]).wrapping_add(block[0] ^ key.round_key[135]).rotate_right(5);
    // block[3] = (block[2] ^ key.round_key[132]).wrapping_add(block[3] ^ key.round_key[133]).rotate_left(9);
    // block[2] = (block[1] ^ key.round_key[142]).wrapping_add(block[2] ^ key.round_key[143]).rotate_right(3);
    // block[1] = (block[0] ^ key.round_key[140]).wrapping_add(block[1] ^ key.round_key[141]).rotate_right(5);
    // block[0] = (block[3] ^ key.round_key[138]).wrapping_add(block[0] ^ key.round_key[139]).rotate_left(9);

    // // round > 24
    // block[3] = (block[2] ^ key.round_key[148]).wrapping_add(block[3] ^ key.round_key[149]).rotate_right(3);
    // block[2] = (block[1] ^ key.round_key[146]).wrapping_add(block[2] ^ key.round_key[147]).rotate_right(5);
    // block[1] = (block[0] ^ key.round_key[144]).wrapping_add(block[1] ^ key.round_key[145]).rotate_left(9);
    // block[0] = (block[3] ^ key.round_key[154]).wrapping_add(block[0] ^ key.round_key[155]).rotate_right(3);
    // block[3] = (block[2] ^ key.round_key[152]).wrapping_add(block[3] ^ key.round_key[153]).rotate_right(5);
    // block[2] = (block[1] ^ key.round_key[150]).wrapping_add(block[2] ^ key.round_key[151]).rotate_left(9);
    // block[1] = (block[0] ^ key.round_key[160]).wrapping_add(block[1] ^ key.round_key[161]).rotate_right(3);
    // block[0] = (block[3] ^ key.round_key[158]).wrapping_add(block[0] ^ key.round_key[159]).rotate_right(5);
    // block[3] = (block[2] ^ key.round_key[156]).wrapping_add(block[3] ^ key.round_key[157]).rotate_left(9);
    // block[2] = (block[1] ^ key.round_key[166]).wrapping_add(block[2] ^ key.round_key[167]).rotate_right(3);
    // block[1] = (block[0] ^ key.round_key[164]).wrapping_add(block[1] ^ key.round_key[165]).rotate_right(5);
    // block[0] = (block[3] ^ key.round_key[162]).wrapping_add(block[0] ^ key.round_key[163]).rotate_left(9);

    // // round > 28
    // block[3] = (block[2] ^ key.round_key[172]).wrapping_add(block[3] ^ key.round_key[173]).rotate_right(3);
    // block[2] = (block[1] ^ key.round_key[170]).wrapping_add(block[2] ^ key.round_key[171]).rotate_right(5);
    // block[1] = (block[0] ^ key.round_key[168]).wrapping_add(block[1] ^ key.round_key[169]).rotate_left(9);
    // block[0] = (block[3] ^ key.round_key[178]).wrapping_add(block[0] ^ key.round_key[179]).rotate_right(3);
    // block[3] = (block[2] ^ key.round_key[176]).wrapping_add(block[3] ^ key.round_key[177]).rotate_right(5);
    // block[2] = (block[1] ^ key.round_key[174]).wrapping_add(block[2] ^ key.round_key[175]).rotate_left(9);
    // block[1] = (block[0] ^ key.round_key[184]).wrapping_add(block[1] ^ key.round_key[185]).rotate_right(3);
    // block[0] = (block[3] ^ key.round_key[182]).wrapping_add(block[0] ^ key.round_key[183]).rotate_right(5);
    // block[3] = (block[2] ^ key.round_key[180]).wrapping_add(block[3] ^ key.round_key[181]).rotate_left(9);
    // block[2] = (block[1] ^ key.round_key[190]).wrapping_add(block[2] ^ key.round_key[191]).rotate_right(3);
    // block[1] = (block[0] ^ key.round_key[188]).wrapping_add(block[1] ^ key.round_key[189]).rotate_right(5);
    // block[0] = (block[3] ^ key.round_key[186]).wrapping_add(block[0] ^ key.round_key[187]).rotate_left(9);
}

fn decrypt_block(round_key: &RoundKey, block: &mut Block) {
    let block = unsafe { &mut *(block.as_mut_ptr() as *mut [u32; 4]) };

    let mut i = 0;
    let t = round_key.round as usize * 6 - 1;
    for _ in 0..(round_key.round >> 2) {
        for [a, b, c, d] in &[[0, 1, 2, 3], [3, 0, 1, 2], [2, 3, 0, 1], [1, 2, 3, 0]] {
            block[*a] = block[*a].rotate_right(9).wrapping_sub(block[*d] ^ round_key.rk[t - 5 - 6 * i]) ^ round_key.rk[t - 4 - 6 * i];
            block[*b] = block[*b].rotate_left(5).wrapping_sub(block[*a] ^ round_key.rk[t - 3 - 6 * i]) ^ round_key.rk[t - 2 - 6 * i];
            block[*c] = block[*c].rotate_left(3).wrapping_sub(block[*b] ^ round_key.rk[t - 1 - 6 * i]) ^ round_key.rk[t - 6 * i];
            i += 1;
        }
    }

    // // 1% faster but bigger binary
    // // round > 28
    // block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ key.round_key[186]) ^ key.round_key[187];
    // block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ key.round_key[188]) ^ key.round_key[189];
    // block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ key.round_key[190]) ^ key.round_key[191];
    // block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ key.round_key[180]) ^ key.round_key[181];
    // block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ key.round_key[182]) ^ key.round_key[183];
    // block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ key.round_key[184]) ^ key.round_key[185];
    // block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ key.round_key[174]) ^ key.round_key[175];
    // block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ key.round_key[176]) ^ key.round_key[177];
    // block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ key.round_key[178]) ^ key.round_key[179];
    // block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ key.round_key[168]) ^ key.round_key[169];
    // block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ key.round_key[170]) ^ key.round_key[171];
    // block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ key.round_key[172]) ^ key.round_key[173];

    // // round > 24
    // block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ key.round_key[162]) ^ key.round_key[163];
    // block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ key.round_key[164]) ^ key.round_key[165];
    // block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ key.round_key[166]) ^ key.round_key[167];
    // block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ key.round_key[156]) ^ key.round_key[157];
    // block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ key.round_key[158]) ^ key.round_key[159];
    // block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ key.round_key[160]) ^ key.round_key[161];
    // block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ key.round_key[150]) ^ key.round_key[151];
    // block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ key.round_key[152]) ^ key.round_key[153];
    // block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ key.round_key[154]) ^ key.round_key[155];
    // block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ key.round_key[144]) ^ key.round_key[145];
    // block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ key.round_key[146]) ^ key.round_key[147];
    // block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ key.round_key[148]) ^ key.round_key[149];

    // block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ key.round_key[138]) ^ key.round_key[139];
    // block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ key.round_key[140]) ^ key.round_key[141];
    // block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ key.round_key[142]) ^ key.round_key[143];
    // block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ key.round_key[132]) ^ key.round_key[133];
    // block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ key.round_key[134]) ^ key.round_key[135];
    // block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ key.round_key[136]) ^ key.round_key[137];
    // block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ key.round_key[126]) ^ key.round_key[127];
    // block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ key.round_key[128]) ^ key.round_key[129];
    // block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ key.round_key[130]) ^ key.round_key[131];
    // block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ key.round_key[120]) ^ key.round_key[121];
    // block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ key.round_key[122]) ^ key.round_key[123];
    // block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ key.round_key[124]) ^ key.round_key[125];

    // block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ key.round_key[114]) ^ key.round_key[115];
    // block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ key.round_key[116]) ^ key.round_key[117];
    // block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ key.round_key[118]) ^ key.round_key[119];
    // block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ key.round_key[108]) ^ key.round_key[109];
    // block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ key.round_key[110]) ^ key.round_key[111];
    // block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ key.round_key[112]) ^ key.round_key[113];
    // block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ key.round_key[102]) ^ key.round_key[103];
    // block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ key.round_key[104]) ^ key.round_key[105];
    // block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ key.round_key[106]) ^ key.round_key[107];
    // block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ key.round_key[96]) ^ key.round_key[97];
    // block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ key.round_key[98]) ^ key.round_key[99];
    // block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ key.round_key[100]) ^ key.round_key[101];

    // block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ key.round_key[90]) ^ key.round_key[91];
    // block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ key.round_key[92]) ^ key.round_key[93];
    // block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ key.round_key[94]) ^ key.round_key[95];
    // block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ key.round_key[84]) ^ key.round_key[85];
    // block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ key.round_key[86]) ^ key.round_key[87];
    // block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ key.round_key[88]) ^ key.round_key[89];
    // block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ key.round_key[78]) ^ key.round_key[79];
    // block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ key.round_key[80]) ^ key.round_key[81];
    // block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ key.round_key[82]) ^ key.round_key[83];
    // block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ key.round_key[72]) ^ key.round_key[73];
    // block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ key.round_key[74]) ^ key.round_key[75];
    // block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ key.round_key[76]) ^ key.round_key[77];

    // block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ key.round_key[66]) ^ key.round_key[67];
    // block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ key.round_key[68]) ^ key.round_key[69];
    // block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ key.round_key[70]) ^ key.round_key[71];
    // block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ key.round_key[60]) ^ key.round_key[61];
    // block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ key.round_key[62]) ^ key.round_key[63];
    // block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ key.round_key[64]) ^ key.round_key[65];
    // block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ key.round_key[54]) ^ key.round_key[55];
    // block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ key.round_key[56]) ^ key.round_key[57];
    // block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ key.round_key[58]) ^ key.round_key[59];
    // block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ key.round_key[48]) ^ key.round_key[49];
    // block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ key.round_key[50]) ^ key.round_key[51];
    // block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ key.round_key[52]) ^ key.round_key[53];

    // block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ key.round_key[42]) ^ key.round_key[43];
    // block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ key.round_key[44]) ^ key.round_key[45];
    // block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ key.round_key[46]) ^ key.round_key[47];
    // block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ key.round_key[36]) ^ key.round_key[37];
    // block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ key.round_key[38]) ^ key.round_key[39];
    // block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ key.round_key[40]) ^ key.round_key[41];
    // block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ key.round_key[30]) ^ key.round_key[31];
    // block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ key.round_key[32]) ^ key.round_key[33];
    // block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ key.round_key[34]) ^ key.round_key[35];
    // block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ key.round_key[24]) ^ key.round_key[25];
    // block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ key.round_key[26]) ^ key.round_key[27];
    // block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ key.round_key[28]) ^ key.round_key[29];

    // block[0] = block[0].rotate_right(9).wrapping_sub(block[3] ^ key.round_key[18]) ^ key.round_key[19];
    // block[1] = block[1].rotate_left(5).wrapping_sub(block[0] ^ key.round_key[20]) ^ key.round_key[21];
    // block[2] = block[2].rotate_left(3).wrapping_sub(block[1] ^ key.round_key[22]) ^ key.round_key[23];
    // block[3] = block[3].rotate_right(9).wrapping_sub(block[2] ^ key.round_key[12]) ^ key.round_key[13];
    // block[0] = block[0].rotate_left(5).wrapping_sub(block[3] ^ key.round_key[14]) ^ key.round_key[15];
    // block[1] = block[1].rotate_left(3).wrapping_sub(block[0] ^ key.round_key[16]) ^ key.round_key[17];
    // block[2] = block[2].rotate_right(9).wrapping_sub(block[1] ^ key.round_key[6]) ^ key.round_key[7];
    // block[3] = block[3].rotate_left(5).wrapping_sub(block[2] ^ key.round_key[8]) ^ key.round_key[9];
    // block[0] = block[0].rotate_left(3).wrapping_sub(block[3] ^ key.round_key[10]) ^ key.round_key[11];
    // block[1] = block[1].rotate_right(9).wrapping_sub(block[0] ^ key.round_key[0]) ^ key.round_key[1];
    // block[2] = block[2].rotate_left(5).wrapping_sub(block[1] ^ key.round_key[2]) ^ key.round_key[3];
    // block[3] = block[3].rotate_left(3).wrapping_sub(block[2] ^ key.round_key[4]) ^ key.round_key[5];
}

// Copyright © 2020–2022 Gihun Nam <sitd0813@gmail.com>
//
// This file and its content are subject to the terms of the MIT License (the "License").
// If a copy of the License was not distributed with this file, you can obtain one at https://opensource.org/licenses/MIT.

//! LEA-CCM
//!
//! * Example
//! ```
//! use lea::{ccm::aead, prelude::*, Lea128Ccm};
//!
//! let key = arr![u8; 0x67, 0x0F, 0xD2, 0x86, 0xDF, 0x28, 0x3C, 0x66, 0x2D, 0xB8, 0x64, 0xA6, 0x81, 0xB9, 0xAB, 0x35];
//! let nonce = arr![u8; 0xE5, 0x9E, 0x05, 0x4A, 0x7E, 0x8B, 0x58, 0x40];
//! let tag = arr![u8; 0xE3, 0xE9, 0x85, 0xF0, 0xD9, 0xA5, 0x9D, 0xB0, 0xB7, 0xB4, 0xEF, 0x63, 0x19, 0x4D, 0x62, 0xFB];
//! let associated_data = vec![];
//! let ptxt = [0x0E, 0xC5, 0x26, 0xA3, 0xBE, 0x68, 0x6C, 0x8B];
//! let ctxt = [0x90, 0xB7, 0x61, 0x8D, 0x8A, 0x50, 0x72, 0x3C];
//!
//! // Valid nonce sizes are `U7`, `U8`, `U9`, `U10`, `U11`, `U12`, `U13`.
//! let mut lea128ccm = Lea128Ccm::<U8>::new(&key);
//!
//! // Encryption
//! let mut buffer = ptxt.clone();
//! let calculated_tag: Result<_, aead::Error> = lea128ccm.encrypt_in_place_detached(&nonce, &associated_data, &mut buffer);
//! assert_eq!(buffer, ctxt);
//! assert_eq!(calculated_tag.unwrap(), tag);
//!
//! // Decryption
//! let mut buffer = ctxt.clone();
//! let _: Result<(), aead::Error> = lea128ccm.decrypt_in_place_detached(&nonce, &associated_data, &mut buffer, &tag);
//! assert_eq!(buffer, ptxt);
//! ```

pub use ccm::aead;

use aead::consts::U16;
use ccm::Ccm;

use crate::{Lea128, Lea192, Lea256};

pub type Lea128Ccm<NonceSize> = Ccm<Lea128, U16, NonceSize>;
pub type Lea192Ccm<NonceSize> = Ccm<Lea192, U16, NonceSize>;
pub type Lea256Ccm<NonceSize> = Ccm<Lea256, U16, NonceSize>;

#[cfg(test)]
mod tests {
	extern crate alloc;

	use alloc::{vec::Vec, vec};

	use crate::{ccm::aead::Error, prelude::*, Lea128Ccm, Lea192Ccm, Lea256Ccm};

	struct TestCase<T> where
	T: AeadInPlace + NewAead {
		key: GenericArray<u8, <T as NewAead>::KeySize>,
		nonce: GenericArray<u8, <T as AeadCore>::NonceSize>,
		tag: GenericArray<u8, <T as AeadCore>::TagSize>,
		associated_data: Vec<u8>,
		ptxt: Vec<u8>,
		ctxt: Vec<u8>
	}

	#[test]
	fn lea128ccm() -> Result<(), Error> {
		let test_cases: [TestCase<Lea128Ccm<U8>>; 4] = [
			TestCase {
				key: arr![u8; 0x67, 0x0F, 0xD2, 0x86, 0xDF, 0x28, 0x3C, 0x66, 0x2D, 0xB8, 0x64, 0xA6, 0x81, 0xB9, 0xAB, 0x35],
				nonce: arr![u8; 0xE5, 0x9E, 0x05, 0x4A, 0x7E, 0x8B, 0x58, 0x40],
				tag: arr![u8; 0xE3, 0xE9, 0x85, 0xF0, 0xD9, 0xA5, 0x9D, 0xB0, 0xB7, 0xB4, 0xEF, 0x63, 0x19, 0x4D, 0x62, 0xFB],
				associated_data: vec![],
				ptxt: vec![0x0E, 0xC5, 0x26, 0xA3, 0xBE, 0x68, 0x6C, 0x8B],
				ctxt: vec![0x90, 0xB7, 0x61, 0x8D, 0x8A, 0x50, 0x72, 0x3C]
			},
			TestCase {
				key: arr![u8; 0x37, 0xD2, 0x28, 0xE3, 0xEE, 0xC6, 0x44, 0xE6, 0x1C, 0xD9, 0x75, 0x59, 0xF3, 0x07, 0x15, 0x3D],
				nonce: arr![u8; 0x3E, 0x7B, 0xF2, 0x34, 0xEA, 0x03, 0xF7, 0x94],
				tag: arr![u8; 0x1A, 0xBA, 0x3E, 0x51, 0xF6, 0x1C, 0xC1, 0xFB, 0x92, 0x80, 0xE4, 0x25, 0x74, 0x15, 0xB4, 0xE7],
				associated_data: vec![0xC6, 0xC2, 0x08, 0xBA, 0x87, 0x25, 0x2D, 0xA1, 0x0F, 0x18, 0xF3, 0xB3],
				ptxt: vec![0xEF, 0x79, 0x0F, 0xDE, 0x2A, 0xCC, 0x45, 0xEB, 0x3C, 0x31, 0x88, 0x0B, 0x5A, 0x94, 0x63, 0xB3, 0xFC, 0x24, 0x97, 0xAA, 0x99, 0x06, 0x06, 0x61, 0xB1, 0x4A, 0xCF, 0x82, 0x11, 0x1E, 0xBB, 0xCB],
				ctxt: vec![0x4C, 0xBA, 0x88, 0x60, 0x51, 0xFE, 0xFD, 0x51, 0x89, 0x6A, 0x24, 0xBE, 0xCD, 0x52, 0x45, 0xE5, 0x39, 0xDB, 0xBD, 0xD2, 0x42, 0x61, 0xA3, 0xFF, 0x9B, 0xFA, 0x00, 0xF3, 0x0B, 0xAB, 0x95, 0x84]
			},
			TestCase {
				key: arr![u8; 0x27, 0xFA, 0xCF, 0x92, 0xF5, 0x73, 0xF9, 0x98, 0x98, 0xB3, 0xFC, 0x80, 0x4B, 0x98, 0x95, 0x23],
				nonce: arr![u8; 0x56, 0xD9, 0xE7, 0x29, 0x90, 0x85, 0x1D, 0x20],
				tag: arr![u8; 0xFA, 0xCE, 0x22, 0x3E, 0xBF, 0x81, 0x4F, 0x2F, 0x6A, 0x04, 0x8B, 0x89, 0x25, 0xA1, 0xD1, 0xE0],
				associated_data: vec![0x22, 0xAC, 0x50, 0xCC, 0x8D, 0x5B, 0xAB, 0xBE, 0xEF, 0xCE, 0xCD, 0x28, 0x82, 0xE2, 0x6E, 0xF0, 0x65, 0xC9, 0x46, 0x03, 0x9F, 0x01, 0x2A, 0xEC],
				ptxt: vec![0x61, 0x87, 0x79, 0xA5, 0x8B, 0x48, 0xB6, 0xAD, 0x72, 0xD8, 0x76, 0x5A, 0xE0, 0x66, 0x7D, 0x71, 0x5D, 0xF0, 0x24, 0xF4, 0xAD, 0xB3, 0xFE, 0x3B, 0x9A, 0xE6, 0xBA, 0x46, 0xF4, 0xA7, 0x4B, 0x52, 0xD5, 0x36, 0x47, 0xAA, 0x29, 0x61, 0x8D, 0xC0, 0x6E, 0x3F, 0x2B, 0x7C, 0xB9, 0x21, 0x7F, 0xD4, 0xFA, 0xC6, 0x9C, 0x9D, 0x80, 0xCE, 0xEE, 0xA1],
				ctxt: vec![0xD5, 0xEA, 0x35, 0x92, 0xA9, 0xC4, 0xE4, 0x89, 0x33, 0x1D, 0xAC, 0x5C, 0x52, 0xBF, 0x5A, 0xF3, 0xB6, 0x55, 0x31, 0x66, 0x54, 0xEF, 0x3D, 0x2B, 0x45, 0xC4, 0x73, 0x3E, 0xE5, 0x17, 0x12, 0x50, 0xD7, 0xDD, 0x0C, 0x3B, 0x50, 0xCA, 0x84, 0x7F, 0xA8, 0xA9, 0x24, 0xAF, 0x0A, 0xA6, 0x8A, 0xB3, 0x3E, 0xF8, 0x39, 0xEB, 0x7F, 0x25, 0x97, 0x9F]
			},
			TestCase {
				key: arr![u8; 0xFC, 0x7B, 0x06, 0x83, 0x23, 0xAE, 0xB7, 0xCE, 0x61, 0xD2, 0xF7, 0x4A, 0x78, 0x2E, 0x41, 0x98],
				nonce: arr![u8; 0x53, 0x93, 0x6E, 0x35, 0x47, 0x92, 0x21, 0x51],
				tag: arr![u8; 0xC9, 0x10, 0x5C, 0x6C, 0x26, 0x76, 0xBC, 0x52, 0x6C, 0xC2, 0xB5, 0xA7, 0x31, 0x5A, 0x44, 0x34],
				associated_data: vec![0x99, 0xEC, 0x62, 0xDE, 0x40, 0x4A, 0x89, 0xE7, 0xED, 0x2E, 0x5E, 0x23, 0x49, 0x2A, 0x7E, 0xCA, 0x7D, 0x50, 0x01, 0xA7, 0xF8, 0xE9, 0x59, 0x6F, 0x6C, 0x6A, 0x7D, 0x51, 0x1A, 0xA3, 0x48, 0xCE, 0x50, 0x3A, 0x1B, 0xCB],
				ptxt: vec![0x30, 0x58, 0xCA, 0xE4, 0xB2, 0xA2, 0xB6, 0x04, 0xED, 0x6B, 0x36, 0x32, 0x92, 0x27, 0x3C, 0xAE, 0xB9, 0x23, 0x35, 0x3D, 0xE0, 0x74, 0x30, 0xC1, 0x30, 0x2E, 0x43, 0x0C, 0x03, 0xD6, 0x2A, 0xF6, 0xA4, 0x19, 0x32, 0xAD, 0x55, 0xBD, 0x56, 0x4D, 0x97, 0xD9, 0xA7, 0xB1, 0xA5, 0x41, 0xF1, 0x88, 0x42, 0x45, 0x9B, 0xAB, 0xB4, 0x9B, 0xCF, 0xAE, 0x11, 0x99, 0xDB, 0xB4, 0xB9, 0xA7, 0xD7, 0x88, 0x24, 0xF5, 0x88, 0xEA, 0xDE, 0x69, 0x85, 0x27, 0xCF, 0xDC, 0x98, 0xED, 0xC0, 0x85, 0x67, 0x5C],
				ctxt: vec![0xD0, 0x1B, 0x10, 0x10, 0x12, 0x0E, 0xA3, 0xAD, 0xBF, 0x58, 0x15, 0x63, 0x3C, 0x71, 0x72, 0xEE, 0xCF, 0x1D, 0x79, 0x66, 0x5B, 0x93, 0xE5, 0xE5, 0xFA, 0x74, 0x73, 0x6E, 0x38, 0x95, 0xEB, 0x4A, 0x33, 0x9B, 0x74, 0xB9, 0x65, 0xE3, 0x5E, 0xF8, 0x28, 0xA8, 0xEC, 0x82, 0x2A, 0x7F, 0xB0, 0xBD, 0x8D, 0xF3, 0xA1, 0x67, 0x42, 0x2B, 0xDE, 0x34, 0xC0, 0x22, 0xCB, 0x2E, 0x5D, 0x45, 0x8C, 0xDD, 0xD2, 0xC6, 0x7E, 0x4E, 0xFE, 0xB9, 0x75, 0xCE, 0x2A, 0xA3, 0xD9, 0xB2, 0x5B, 0x37, 0x46, 0xE1]
			}
		];

		for test_case in test_cases {
			let lea128ccm = Lea128Ccm::new(&test_case.key);

			// Encryption
			let mut buffer = test_case.ptxt.clone();
			let tag = lea128ccm.encrypt_in_place_detached(&test_case.nonce, &test_case.associated_data, &mut buffer)?;
			assert_eq!(buffer, test_case.ctxt);
			assert_eq!(tag, test_case.tag);

			// Decryption
			let mut buffer = test_case.ctxt.clone();
			lea128ccm.decrypt_in_place_detached(&test_case.nonce, &test_case.associated_data, &mut buffer, &test_case.tag)?;
			assert_eq!(buffer, test_case.ptxt);
		}

		Ok(())
	}

	#[test]
	fn lea192ccm() -> Result<(), Error> {
		let test_cases: [TestCase<Lea192Ccm<U8>>; 4] = [
			TestCase {
				key: arr![u8; 0x1B, 0xB5, 0x54, 0x60, 0xF2, 0xC5, 0xA1, 0x3F, 0x43, 0x4D, 0xD8, 0x6E, 0x7B, 0x97, 0x6A, 0xA9, 0x38, 0x54, 0x96, 0x42, 0x53, 0x8D, 0x8C, 0xBA],
				nonce: arr![u8; 0x1E, 0xDC, 0xD3, 0x8E, 0xEA, 0xDB, 0xE8, 0x53],
				tag: arr![u8; 0x17, 0xE8, 0x93, 0x50, 0xFA, 0xC5, 0x19, 0xF3, 0x9D, 0xFC, 0x24, 0x23, 0xCD, 0x35, 0xB1, 0x9B],
				associated_data: vec![],
				ptxt: vec![0xCD, 0xDD, 0x28, 0x05, 0xA2, 0xDC, 0xEF, 0x9D],
				ctxt: vec![0x81, 0x1E, 0xB4, 0x2B, 0xCF, 0xF3, 0x9E, 0x42]
			},
			TestCase {
				key: arr![u8; 0xCC, 0x08, 0xEC, 0xA9, 0xA6, 0xC2, 0x23, 0x15, 0x6C, 0x90, 0x9E, 0x32, 0xAB, 0x54, 0x09, 0x0E, 0x04, 0xC2, 0x96, 0x1F, 0xE7, 0x15, 0xE7, 0x91],
				nonce: arr![u8; 0x9F, 0x00, 0x2E, 0xDF, 0x8F, 0xE8, 0x93, 0xA1],
				tag: arr![u8; 0x73, 0x28, 0x10, 0xCF, 0xC5, 0xE5, 0xB5, 0x21, 0xE3, 0x60, 0xA3, 0x32, 0x1C, 0x46, 0xCB, 0x8E],
				associated_data: vec![0xBB, 0x50, 0xD6, 0xA5, 0x8A, 0x95, 0x35, 0x40, 0xCA, 0xDB, 0x90, 0xE6],
				ptxt: vec![0xF4, 0x47, 0xCB, 0xF9, 0xB1, 0x6F, 0x74, 0xDF, 0x9E, 0x0E, 0xA5, 0x57, 0x4C, 0xFD, 0x2C, 0x0D, 0x8C, 0x5E, 0xEA, 0x6C, 0xE9, 0x1A, 0x79, 0xB3, 0x75, 0x8F, 0x12, 0x4B, 0xC9, 0x82, 0xAD, 0x58],
				ctxt: vec![0xF5, 0x49, 0xC8, 0x53, 0xB0, 0x34, 0x7E, 0xA2, 0x9C, 0x9D, 0x3B, 0x35, 0xAD, 0x61, 0xE2, 0x96, 0x51, 0xE2, 0xCF, 0x66, 0x59, 0x2A, 0xA7, 0x1A, 0x2C, 0x34, 0x7C, 0xAE, 0x02, 0xE0, 0xD5, 0x75]
			},
			TestCase {
				key: arr![u8; 0xBF, 0xBA, 0xB3, 0x37, 0xD0, 0x49, 0xFE, 0xB2, 0x8C, 0xCF, 0x85, 0x17, 0xB3, 0x96, 0xB8, 0x23, 0xDF, 0x63, 0x9A, 0xDE, 0xC5, 0xA9, 0x23, 0x73],
				nonce: arr![u8; 0xB8, 0xFD, 0xE3, 0x3F, 0x6F, 0xCA, 0xE9, 0x28],
				tag: arr![u8; 0x20, 0x98, 0xEA, 0x38, 0x70, 0x26, 0xFD, 0x17, 0x97, 0x87, 0x00, 0xFE, 0x3E, 0x66, 0x2C, 0xBE],
				associated_data: vec![0x07, 0x46, 0xE3, 0x30, 0x4B, 0xA4, 0x87, 0x49, 0x34, 0x8C, 0x31, 0x6C, 0xAC, 0xC8, 0xCD, 0xE5, 0x97, 0x40, 0xF7, 0xF1, 0x14, 0x28, 0x61, 0x8A],
				ptxt: vec![0x00, 0x78, 0x75, 0x82, 0xBD, 0x9C, 0x3C, 0xCF, 0x31, 0x6D, 0x7F, 0x26, 0x11, 0x61, 0x2C, 0xCB, 0x5F, 0xFE, 0xFA, 0xA7, 0x31, 0x95, 0x50, 0x9B, 0xB5, 0x2C, 0x64, 0x14, 0x72, 0xBC, 0xA0, 0xDF, 0xD0, 0x9D, 0x49, 0x3F, 0xDB, 0x3E, 0x62, 0x3D, 0x44, 0x19, 0xCE, 0x40, 0xA8, 0xE6, 0xB6, 0xDD, 0x15, 0x0F, 0x2A, 0xF0, 0xCB, 0x65, 0x0B, 0xEC],
				ctxt: vec![0xEA, 0x78, 0x4E, 0x44, 0x46, 0x73, 0x53, 0xD4, 0x86, 0xDA, 0x0A, 0xF3, 0xA2, 0xFA, 0xC3, 0xD5, 0x99, 0x77, 0x45, 0xE9, 0x1B, 0x07, 0xBE, 0x39, 0x7F, 0xE7, 0x23, 0xEB, 0x4C, 0x06, 0x03, 0x70, 0x93, 0xBF, 0xBA, 0x38, 0x40, 0x14, 0xB4, 0x44, 0xF7, 0xA5, 0x50, 0x19, 0x18, 0x06, 0xCD, 0x6D, 0x60, 0x1E, 0x96, 0xC2, 0xB2, 0xBF, 0x24, 0xB7]
			},
			TestCase {
				key: arr![u8; 0xE7, 0xAC, 0xDF, 0xF5, 0x10, 0x56, 0xB4, 0x3B, 0x32, 0x59, 0xAF, 0x7C, 0x19, 0xE1, 0x9C, 0x62, 0x9D, 0xF8, 0xB0, 0x64, 0x25, 0xF9, 0x24, 0xDF],
				nonce: arr![u8; 0x6A, 0x47, 0x23, 0x68, 0x7E, 0x3E, 0xE6, 0x61],
				tag: arr![u8; 0x06, 0xF2, 0xEE, 0x36, 0x31, 0x66, 0x0F, 0xC5, 0xF7, 0x63, 0x3B, 0xDA, 0x92, 0xB1, 0x63, 0x73],
				associated_data: vec![0x0C, 0x6A, 0x1E, 0xCA, 0xE1, 0xF7, 0x92, 0x5A, 0xAB, 0x69, 0x09, 0xCE, 0x01, 0x8E, 0x6A, 0x82, 0xA4, 0xB0, 0x22, 0x3E, 0x05, 0x0E, 0xC6, 0x52, 0x07, 0x8E, 0xF9, 0xE5, 0x05, 0xAC, 0x91, 0x8A, 0x17, 0xB6, 0xF5, 0x14],
				ptxt: vec![0x91, 0x3B, 0xC9, 0xAC, 0xCD, 0xC1, 0xCE, 0x20, 0x2B, 0xB6, 0x03, 0x7E, 0x55, 0xA9, 0x11, 0xE2, 0xC8, 0xBA, 0xE5, 0x8C, 0x90, 0x4F, 0x9F, 0x35, 0x52, 0x09, 0xAB, 0xA3, 0x90, 0xF7, 0x2D, 0x7C, 0x29, 0x09, 0xA3, 0x58, 0x1F, 0xC7, 0xC6, 0x19, 0x9D, 0x42, 0xB0, 0x7F, 0x39, 0x4B, 0x44, 0xF7, 0x76, 0xE4, 0xCB, 0xB4, 0x8D, 0xF4, 0xDB, 0x01, 0x6D, 0x3F, 0x7D, 0xD6, 0x00, 0x94, 0x8E, 0xA9, 0xB0, 0x48, 0x66, 0x86, 0x2A, 0xE4, 0xB8, 0x62, 0x61, 0x1B, 0xB9, 0xAD, 0xD6, 0xFF, 0x85, 0x26],
				ctxt: vec![0x9C, 0x19, 0xA6, 0x87, 0xDD, 0xD1, 0x18, 0x30, 0x3A, 0x23, 0x53, 0xC2, 0x45, 0x67, 0xE2, 0x46, 0xFE, 0x43, 0x30, 0x31, 0x30, 0x2D, 0xB7, 0xFC, 0x0A, 0x08, 0x89, 0xCF, 0x6D, 0xCA, 0xE5, 0xD4, 0xA4, 0x4C, 0x6D, 0x05, 0x45, 0xDA, 0xCA, 0xBF, 0x07, 0x4D, 0xA5, 0xC9, 0x01, 0x3A, 0xCA, 0x42, 0x1B, 0x2D, 0xE0, 0x29, 0xA7, 0xE1, 0x84, 0x0C, 0x0C, 0x2B, 0x86, 0x39, 0x02, 0x02, 0x31, 0x4F, 0xEC, 0x7E, 0xA5, 0xBA, 0x37, 0xE0, 0xCD, 0x42, 0x2D, 0x05, 0x61, 0x32, 0xB3, 0xD9, 0xE8, 0x2B]
			}
		];

		for test_case in test_cases {
			let lea192ccm = Lea192Ccm::new(&test_case.key);

			// Encryption
			let mut buffer = test_case.ptxt.clone();
			let tag = lea192ccm.encrypt_in_place_detached(&test_case.nonce, &test_case.associated_data, &mut buffer)?;
			assert_eq!(buffer, test_case.ctxt);
			assert_eq!(tag, test_case.tag);

			// Decryption
			let mut buffer = test_case.ctxt.clone();
			lea192ccm.decrypt_in_place_detached(&test_case.nonce, &test_case.associated_data, &mut buffer, &test_case.tag)?;
			assert_eq!(buffer, test_case.ptxt);
		}

		Ok(())
	}

	#[test]
	fn lea256ccm() -> Result<(), Error> {
		let test_cases: [TestCase<Lea256Ccm<U8>>; 4] = [
			TestCase {
				key: arr![u8; 0x18, 0x74, 0xBE, 0xF3, 0x86, 0xE4, 0x76, 0xF1, 0x5C, 0x34, 0x4F, 0x49, 0xEE, 0xF7, 0xE0, 0x44, 0x2E, 0xE2, 0x5B, 0x60, 0x74, 0x80, 0x6D, 0xA3, 0x7F, 0x27, 0x66, 0x2F, 0xB7, 0x2B, 0x9A, 0x17],
				nonce: arr![u8; 0xB4, 0x51, 0x07, 0x71, 0x04, 0x87, 0x38, 0xAC],
				tag: arr![u8; 0xC8, 0xC1, 0x44, 0xE3, 0x7E, 0x26, 0x4B, 0x1E, 0x6F, 0x45, 0xD3, 0x80, 0xFE, 0xEA, 0xDE, 0x5D],
				associated_data: vec![],
				ptxt: vec![0x29, 0xD2, 0x69, 0x24, 0xE2, 0x87, 0xEB, 0xF4],
				ctxt: vec![0xCA, 0x66, 0x67, 0xB7, 0x11, 0xCF, 0xAA, 0x47]
			},
			TestCase {
				key: arr![u8; 0x47, 0x38, 0xBA, 0x5E, 0x65, 0x2B, 0x37, 0x26, 0x91, 0x59, 0xD5, 0x19, 0x97, 0xF2, 0x53, 0x07, 0xD2, 0x6B, 0x9F, 0x39, 0x3A, 0x77, 0xF6, 0x06, 0x9E, 0x33, 0x4D, 0xA1, 0x2D, 0xA0, 0xF0, 0x35],
				nonce: arr![u8; 0x3B, 0x57, 0x69, 0x34, 0x42, 0x78, 0xA3, 0xEC],
				tag: arr![u8; 0x86, 0xF4, 0xD3, 0x77, 0xF6, 0xB2, 0x02, 0x49, 0xCC, 0x95, 0xE5, 0xCC, 0x59, 0x09, 0x9E, 0x26],
				associated_data: vec![0x27, 0xE4, 0x4F, 0x5B, 0xBF, 0xAC, 0x87, 0x44, 0x92, 0xC9, 0xB1, 0x82],
				ptxt: vec![0xDF, 0x0D, 0xA7, 0x9D, 0xE0, 0x59, 0x15, 0x9B, 0x4E, 0x11, 0x22, 0x18, 0x28, 0xCD, 0x52, 0x99, 0xB1, 0x51, 0xAA, 0x1E, 0xB8, 0xC0, 0x16, 0xF6, 0x1B, 0x0C, 0x09, 0xD7, 0x8E, 0xB1, 0x63, 0x2E],
				ctxt: vec![0xF4, 0x97, 0x59, 0xFC, 0x38, 0x20, 0xE7, 0xFC, 0x2F, 0x06, 0x9E, 0x70, 0xFE, 0xB9, 0xB1, 0x21, 0x36, 0x9E, 0x7C, 0x54, 0xAA, 0xA0, 0x69, 0x17, 0x44, 0x06, 0xE7, 0x61, 0x78, 0xD0, 0xAE, 0xA7]
			},
			TestCase {
				key: arr![u8; 0x6B, 0xAB, 0xC0, 0x32, 0x3B, 0xB2, 0x89, 0x7C, 0xAA, 0xC0, 0x8E, 0x22, 0xDD, 0xF8, 0xB7, 0x77, 0xAB, 0x61, 0x3C, 0xE7, 0xA5, 0xDF, 0xC4, 0x87, 0x53, 0x62, 0xCF, 0xF0, 0xC1, 0x5D, 0x51, 0x4E],
				nonce: arr![u8; 0x3A, 0x7A, 0x9F, 0xB4, 0x54, 0x8C, 0x8F, 0xB3],
				tag: arr![u8; 0xC8, 0x1B, 0x88, 0xF5, 0x1F, 0x87, 0x42, 0x5D, 0x6E, 0x60, 0x24, 0xD5, 0xDE, 0x8D, 0x57, 0x9A],
				associated_data: vec![0x2D, 0xC4, 0xDB, 0x2A, 0xF3, 0x29, 0xC7, 0x5F, 0xAA, 0x42, 0x04, 0x4F, 0x29, 0x15, 0xD3, 0x43, 0x66, 0x56, 0x6E, 0xA4, 0xF4, 0xD8, 0xA3, 0x10],
				ptxt: vec![0xCA, 0x47, 0xC2, 0xAD, 0x46, 0x19, 0xB9, 0xBE, 0x72, 0xC2, 0x7E, 0x74, 0x85, 0x27, 0xAD, 0x06, 0xAD, 0x56, 0x73, 0x04, 0x0B, 0x74, 0xAA, 0xE8, 0xFF, 0xF6, 0x45, 0xEE, 0xA7, 0x15, 0xEF, 0x25, 0xA2, 0x7B, 0xEF, 0xC6, 0x1A, 0x43, 0x4F, 0xC5, 0x01, 0x20, 0x3D, 0xA7, 0x9A, 0xDC, 0xB1, 0x93, 0x3C, 0x05, 0x50, 0xAB, 0x53, 0xE3, 0x91, 0x9D],
				ctxt: vec![0x8C, 0x48, 0x9B, 0xB9, 0x06, 0x5F, 0x30, 0x00, 0xF9, 0x64, 0xAC, 0x1D, 0xED, 0x5E, 0x8B, 0x51, 0xB7, 0x69, 0x2A, 0x6C, 0x3F, 0xC7, 0xF9, 0xFB, 0xFB, 0x14, 0x79, 0x64, 0x08, 0x6C, 0x45, 0x46, 0x55, 0xCD, 0xB7, 0x81, 0x19, 0x4F, 0x9C, 0xA2, 0x64, 0x38, 0xE3, 0x96, 0x5F, 0xEC, 0x4D, 0x06, 0x0B, 0x38, 0xF9, 0xBF, 0x07, 0xE7, 0xC1, 0x56]
			},
			TestCase {
				key: arr![u8; 0x96, 0xC1, 0x79, 0xD8, 0x96, 0x75, 0x7D, 0xA9, 0xCB, 0x21, 0xDB, 0xAB, 0xB7, 0xCE, 0xC7, 0x4D, 0xDA, 0x87, 0x71, 0x12, 0x7C, 0x0C, 0xE5, 0xE8, 0xA6, 0xCB, 0x30, 0xB6, 0x72, 0x0B, 0xC5, 0x34],
				nonce: arr![u8; 0x84, 0x6B, 0x1F, 0xFF, 0xD9, 0x8B, 0xA7, 0xED],
				tag: arr![u8; 0xD1, 0x09, 0x94, 0xE9, 0x44, 0x09, 0x7E, 0xBE, 0xDE, 0x83, 0x7E, 0x6E, 0xF1, 0xE5, 0x01, 0xBF],
				associated_data: vec![0xC0, 0x09, 0xD7, 0x9D, 0x25, 0xAF, 0xA0, 0x53, 0x15, 0xEA, 0x09, 0x03, 0x7F, 0x7E, 0x1A, 0xAC, 0x38, 0x79, 0xF8, 0xE8, 0x42, 0x65, 0x51, 0xC0, 0x4E, 0xC2, 0xFA, 0xC4, 0x7F, 0xB4, 0xD7, 0x5C, 0x71, 0xF8, 0xFC, 0x59],
				ptxt: vec![0x7A, 0x1C, 0x11, 0xCF, 0x30, 0xF0, 0xFB, 0x27, 0x2B, 0x38, 0xB9, 0x70, 0x0C, 0xA3, 0x8B, 0xF6, 0xBD, 0x01, 0x5A, 0x16, 0xFB, 0xB0, 0x54, 0x50, 0x12, 0x57, 0xD7, 0x9E, 0xE8, 0xD7, 0x90, 0x04, 0x3D, 0x7F, 0xE4, 0x69, 0x31, 0x80, 0x8E, 0xA5, 0x07, 0xA0, 0x8A, 0xDB, 0x28, 0x32, 0x32, 0x09, 0x6B, 0x45, 0xA8, 0xDD, 0x93, 0x1C, 0x73, 0xCB, 0x1A, 0xDE, 0x6D, 0x5C, 0x2D, 0x8F, 0xDC, 0xC9, 0xF7, 0x3F, 0xDF, 0xC8, 0x22, 0x81, 0x0C, 0xA6, 0x9B, 0x1F, 0x57, 0x96, 0x96, 0x0C, 0x35, 0x49],
				ctxt: vec![0x7F, 0x37, 0x37, 0x79, 0x8D, 0x13, 0x80, 0xD7, 0x60, 0x04, 0x6B, 0xE6, 0x83, 0x8D, 0xD1, 0x74, 0xE9, 0x66, 0x3D, 0x0E, 0xC2, 0x6D, 0xDE, 0x70, 0xA3, 0xFF, 0xA6, 0xA4, 0x6A, 0x2F, 0xB9, 0xD0, 0x1D, 0x25, 0x18, 0x97, 0x3C, 0xE0, 0xC3, 0x1C, 0x24, 0xB2, 0x75, 0x41, 0xE9, 0xBA, 0xF5, 0xEC, 0x89, 0x01, 0xD8, 0x43, 0xF3, 0x7A, 0x65, 0x94, 0xED, 0xF3, 0xB0, 0x2C, 0x26, 0x17, 0x98, 0x10, 0xE5, 0x94, 0x68, 0x36, 0xD6, 0x4E, 0xAF, 0xE0, 0xDF, 0xC5, 0x57, 0xEB, 0xEA, 0x2E, 0xD3, 0x35]
			}
		];

		for test_case in test_cases {
			let lea256ccm = Lea256Ccm::new(&test_case.key);

			// Encryption
			let mut buffer = test_case.ptxt.clone();
			let tag = lea256ccm.encrypt_in_place_detached(&test_case.nonce, &test_case.associated_data, &mut buffer)?;
			assert_eq!(buffer, test_case.ctxt);
			assert_eq!(tag, test_case.tag);

			// Decryption
			let mut buffer = test_case.ctxt.clone();
			lea256ccm.decrypt_in_place_detached(&test_case.nonce, &test_case.associated_data, &mut buffer, &test_case.tag)?;
			assert_eq!(buffer, test_case.ptxt);
		}

		Ok(())
	}
}
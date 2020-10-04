// Copyright © 2020 SitD <sitd0813@gmail.com>
//
// This file is subject to the terms of the MIT License.
// If a copy of the MIT License was not distributed with this file, you can obtain one at https://opensource.org/licenses/MIT.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use aes::{Aes128, Aes192, Aes256};
use lea::{
	block_cipher::{
		generic_array::arr,
		BlockCipher, NewBlockCipher
	},
	Lea128, Lea192, Lea256
};

fn criterion_benches(c: &mut Criterion) {
	let key128 = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0];
	let key192 = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87];
	let key256 = arr![u8; 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F];

	let mut block = arr![u8; 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

	let aes128 = Aes128::new(&key128);
	let aes192 = Aes192::new(&key192);
	let aes256 = Aes256::new(&key256);

	c.bench_function("[lea_vs_aes] Aes<128&192&256>::new", |b| { b.iter(|| {
		black_box(Aes128::new(&key128));
		black_box(Aes192::new(&key192));
		black_box(Aes256::new(&key256));
	}) });
	c.bench_function("[lea_vs_aes] Aes<128&192&256>::encrypt_block", |b| { b.iter(|| {
		aes128.encrypt_block(&mut block);
		aes192.encrypt_block(&mut block);
		aes256.encrypt_block(&mut block);
	}) });
	c.bench_function("[lea_vs_aes] Aes<128&192&256>::decrypt_block", |b| { b.iter(|| {
		aes128.decrypt_block(&mut block);
		aes192.decrypt_block(&mut block);
		aes256.decrypt_block(&mut block);
	}) });

	let lea128 = Lea128::new(&key128);
	let lea192 = Lea192::new(&key192);
	let lea256 = Lea256::new(&key256);

	c.bench_function("[lea_vs_aes] Lea<128&192&256>::new", |b| { b.iter(|| {
		black_box(Lea128::new(&key128));
		black_box(Lea192::new(&key192));
		black_box(Lea256::new(&key256));
	}) });
	c.bench_function("[lea_vs_aes] Lea<128&192&256>::encrypt_block", |b| { b.iter(|| {
		lea128.encrypt_block(&mut block);
		lea192.encrypt_block(&mut block);
		lea256.encrypt_block(&mut block);
	}) });
	c.bench_function("[lea_vs_aes] Lea<128&192&256>::decrypt_block", |b| { b.iter(|| {
		lea128.decrypt_block(&mut block);
		lea192.decrypt_block(&mut block);
		lea256.decrypt_block(&mut block);
	}) });

	black_box(block);
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
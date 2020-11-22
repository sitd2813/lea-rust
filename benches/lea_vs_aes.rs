// Copyright © 2020 SitD <sitd0813@gmail.com>
//
// This file is subject to the terms of the MIT License.
// If a copy of the MIT License was not distributed with this file, you can obtain one at https://opensource.org/licenses/MIT.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use aes::{Aes128, Aes192, Aes256};
use lea::{
	block::{generic_array::arr, BlockCipher, NewBlockCipher},
	Lea128, Lea192, Lea256
};

fn criterion_benches(c: &mut Criterion) {
	let key128 = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
	let key192 = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
	let key256 = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

	let mut block = arr![u8; 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];

	let aes128 = Aes128::new(&key128);
	let aes192 = Aes192::new(&key192);
	let aes256 = Aes256::new(&key256);

	c.bench_function("[lea_vs_aes] (Aes128&Aes192&Aes256)::new", |b| { b.iter(|| {
		black_box(Aes128::new(&key128));
		black_box(Aes192::new(&key192));
		black_box(Aes256::new(&key256));
	}) });
	c.bench_function("[lea_vs_aes] (Aes128&Aes192&Aes256)::encrypt_block", |b| { b.iter(|| {
		aes128.encrypt_block(&mut block);
		aes192.encrypt_block(&mut block);
		aes256.encrypt_block(&mut block);
	}) });
	c.bench_function("[lea_vs_aes] (Aes128&Aes192&Aes256)::decrypt_block", |b| { b.iter(|| {
		aes128.decrypt_block(&mut block);
		aes192.decrypt_block(&mut block);
		aes256.decrypt_block(&mut block);
	}) });

	let lea128 = Lea128::new(&key128);
	let lea192 = Lea192::new(&key192);
	let lea256 = Lea256::new(&key256);

	c.bench_function("[lea_vs_aes] (Lea128&Lea192&Lea256)::new", |b| { b.iter(|| {
		black_box(Lea128::new(&key128));
		black_box(Lea192::new(&key192));
		black_box(Lea256::new(&key256));
	}) });
	c.bench_function("[lea_vs_aes] (Lea128&Lea192&Lea256)::encrypt_block", |b| { b.iter(|| {
		lea128.encrypt_block(&mut block);
		lea192.encrypt_block(&mut block);
		lea256.encrypt_block(&mut block);
	}) });
	c.bench_function("[lea_vs_aes] (Lea128&Lea192&Lea256)::decrypt_block", |b| { b.iter(|| {
		lea128.decrypt_block(&mut block);
		lea192.decrypt_block(&mut block);
		lea256.decrypt_block(&mut block);
	}) });

	black_box(block);
}

criterion_group!(benches, criterion_benches);
criterion_main!(benches);
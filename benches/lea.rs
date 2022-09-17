// Copyright © 2021–2022 Gihun Nam <sitd0813@gmail.com>
//
// This file and its content are subject to the terms of the MIT License (the "License").
// If a copy of the License was not distributed with this file, you can obtain one at https://opensource.org/licenses/MIT.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use criterion_cycles_per_byte::CyclesPerByte;

use lea::{prelude::*, Lea128, Lea192, Lea256};

fn criterion_benches(c: &mut Criterion<CyclesPerByte>) {
	let mut block = Default::default();

	let lea128 = Lea128::new(&Default::default());
	c.bench_function("[lea] Lea128::new", |b| { b.iter(|| {
		black_box(Lea128::new(&Default::default()));
	}) });
	c.bench_function("[lea] Lea128::encrypt_block", |b| { b.iter(|| {
		lea128.encrypt_block(&mut block);
	}) });
	c.bench_function("[lea] Lea128::decrypt_block", |b| { b.iter(|| {
		lea128.decrypt_block(&mut block);
	}) });

	let lea192 = Lea192::new(&Default::default());
	c.bench_function("[lea] Lea192::new", |b| { b.iter(|| {
		black_box(Lea192::new(&Default::default()));
	}) });
	c.bench_function("[lea] Lea192::encrypt_block", |b| { b.iter(|| {
		lea192.encrypt_block(&mut block);
	}) });
	c.bench_function("[lea] Lea192::decrypt_block", |b| { b.iter(|| {
		lea192.decrypt_block(&mut block);
	}) });

	let lea256 = Lea256::new(&Default::default());
	c.bench_function("[lea] Lea256::new", |b| { b.iter(|| {
		black_box(Lea256::new(&Default::default()));
	}) });
	c.bench_function("[lea] Lea256::encrypt_block", |b| { b.iter(|| {
		lea256.encrypt_block(&mut block);
	}) });
	c.bench_function("[lea] Lea256::decrypt_block", |b| { b.iter(|| {
		lea256.decrypt_block(&mut block);
	}) });

	black_box(block);
}

criterion_group!(
	name = benches;
	config = Criterion::default().with_measurement(CyclesPerByte);
	targets = criterion_benches
);
criterion_main!(benches);

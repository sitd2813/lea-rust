// Copyright © 2021–2022 Gihun Nam <sitd0813@gmail.com>
//
// This file and its content are subject to the terms of the MIT License (the "License").
// If a copy of the License was not distributed with this file, you can obtain one at https://opensource.org/licenses/MIT.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use criterion_cycles_per_byte::CyclesPerByte;

use lea::{prelude::*, Lea128Ccm, Lea192Ccm, Lea256Ccm};

fn criterion_benches(c: &mut Criterion<CyclesPerByte>) {
	let data = [0; 16];
	let mut buffer = data;
	let nonce = Default::default();

	let lea128ccm = Lea128Ccm::<U13>::new(&Default::default());
	c.bench_function("[lea-ccm] Lea128Ccm::encrypt_in_place_detached", |b| { b.iter(|| {
		black_box(lea128ccm.encrypt_in_place_detached(&nonce, &[], &mut buffer).unwrap());
	}) });
	let mut lea128ccm_buffer = data;
	let lea128ccm_tag = lea128ccm.encrypt_in_place_detached(&nonce, &[], &mut lea128ccm_buffer).unwrap();
	c.bench_function("[lea-ccm] Lea128Ccm::decrypt_in_place_detached", |b| { b.iter(|| {
		black_box(lea128ccm.decrypt_in_place_detached(&nonce, &[], &mut lea128ccm_buffer.clone(), &lea128ccm_tag).unwrap());
	}) });

	let lea192ccm = Lea192Ccm::<U13>::new(&Default::default());
	c.bench_function("[lea-ccm] Lea192Ccm::encrypt_in_place_detached", |b| { b.iter(|| {
		black_box(lea192ccm.encrypt_in_place_detached(&nonce, &[], &mut buffer).unwrap());
	}) });
	let mut lea192ccm_buffer = data;
	let lea192ccm_tag = lea192ccm.encrypt_in_place_detached(&nonce, &[], &mut lea192ccm_buffer).unwrap();
	c.bench_function("[lea-ccm] Lea192Ccm::decrypt_in_place_detached", |b| { b.iter(|| {
		black_box(lea192ccm.decrypt_in_place_detached(&nonce, &[], &mut lea192ccm_buffer.clone(), &lea192ccm_tag).unwrap());
	}) });

	let lea256ccm = Lea256Ccm::<U13>::new(&Default::default());
	c.bench_function("[lea-ccm] Lea256Ccm::encrypt_in_place_detached", |b| { b.iter(|| {
		black_box(lea256ccm.encrypt_in_place_detached(&nonce, &[], &mut buffer).unwrap());
	}) });
	let mut lea256ccm_buffer = data;
	let lea256ccm_tag = lea256ccm.encrypt_in_place_detached(&nonce, &[], &mut lea256ccm_buffer).unwrap();
	c.bench_function("[lea-ccm] Lea256Ccm::decrypt_in_place_detached", |b| { b.iter(|| {
		black_box(lea256ccm.decrypt_in_place_detached(&nonce, &[], &mut lea256ccm_buffer.clone(), &lea256ccm_tag).unwrap());
	}) });

	black_box(data);
}

criterion_group!(
	name = benches;
	config = Criterion::default().with_measurement(CyclesPerByte);
	targets = criterion_benches
);
criterion_main!(benches);
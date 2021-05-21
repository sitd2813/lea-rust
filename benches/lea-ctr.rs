// Copyright © 2021 SitD <sitd0813@gmail.com>
//
// This file is subject to the terms of the MIT License.
// If a copy of the MIT License was not distributed with this file, you can obtain one at https://opensource.org/licenses/MIT.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use criterion_cycles_per_byte::CyclesPerByte;

use lea::{prelude::*, Lea128Ctr, Lea192Ctr, Lea256Ctr};

fn criterion_benches(c: &mut Criterion<CyclesPerByte>) {
	let mut data = [0; 16];

	let mut lea128ctr = Lea128Ctr::new(&Default::default(), &Default::default());
	c.bench_function("[lea-ctr] Lea128Ctr::apply_keystream", |b| { b.iter(|| {
		lea128ctr.apply_keystream(&mut data);
	}) });

	let mut lea192ctr = Lea192Ctr::new(&Default::default(), &Default::default());
	c.bench_function("[lea-ctr] Lea192Ctr::apply_keystream", |b| { b.iter(|| {
		lea192ctr.apply_keystream(&mut data);
	}) });

	let mut lea256ctr = Lea256Ctr::new(&Default::default(), &Default::default());
	c.bench_function("[lea-ctr] Lea256Ctr::apply_keystream", |b| { b.iter(|| {
		lea256ctr.apply_keystream(&mut data);
	}) });

	black_box(data);
}

criterion_group!(
	name = benches;
	config = Criterion::default().with_measurement(CyclesPerByte);
	targets = criterion_benches
);
criterion_main!(benches);
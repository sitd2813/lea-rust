# Changelog

All notable changes to this project will be documented in this file.

## [0.5.4] (XXXX-XX-XX)

### ✨Upgrade

- `criterion` (`0.3.*` → `0.4.*`)
- `criterion-cycles-per-byte` (`0.1.*` → `0.4.*`)

## [0.5.3] (2022-09-17)

### 🛠️Fix

- UB caused by misaligned pointers (by @clubby789)

## [0.5.2] (2022-02-04)

### 🔄Change

- Optimized round key generation, resulting in 5–10% faster `Lea128::new`, `Lea192::new`, and `Lea256::new`.

## [0.5.1] (2021-11-14)

### ✨

- `ctr` (`0.7.*` → `0.8.*`)
- Rust edition (2018 → 2021)

## [0.5.0] (2021-05-21)

### ➕Add

- Feature `zeroize`
- Module `lea::prelude`

### 🔄Change

- Default features (`["ccm", "ctr"]` → `[]`).

### ➖Remove

- Redundant benchmarks

### ✨Upgrade

- `cipher` (`0.2.*` → `0.3.*`)

## [0.4.0] (2020-11-22)

### ➕Add

- LEA-CCM
- More LEA-CTR test cases

### 🔄Change

- Renamed block cipher trait module (`lea::block_cipher` → `lea::block`)
- Renamed stream cipher trait module (`lea::stream_cipher` → `lea::stream`)
- Renamed LEA-CTR feature (`feature-ctr` → `ctr`)

### ➖Remove

- `lea::Block`

## [0.3.1] (2020-10-22)

### 🔄Change

- Block cipher trait crate (`block-cipher` → `cipher`)
- Round key implementation is separated from [`lib.rs`](./src/lib.rs) to [`round_key.rs`](./src/round_key.rs).

## [0.3.0] (2020-10-04)

[0.5.3]: https://github.com/sitd2813/lea-rust/compare/0.5.2...0.5.3
[0.5.2]: https://github.com/sitd2813/lea-rust/compare/0.5.1...0.5.2
[0.5.1]: https://github.com/sitd2813/lea-rust/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/sitd2813/lea-rust/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/sitd2813/lea-rust/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/sitd2813/lea-rust/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/sitd2813/lea-rust/releases/tag/0.3.0

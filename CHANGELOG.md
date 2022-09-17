# Changelog

All notable changes to this project will be documented in this file.

## [0.5.3] (2022-09-17)

### Fixed

- UB caused by misaligned pointers (by @clubby789)

## [0.5.2] (2022-02-04)

### Changed

- Round key generation is optimized, resulting in 5 to 10% faster `Lea128::new`, `Lea192::new`, and `Lea256::new`.

## [0.5.1] (2021-11-14)

### Changed

- Dependency `ctr = 0.7.*` is updated to `ctr = 0.8.*`.
- Rust edition is updated from 2018 to 2021.

## [0.5.0] (2021-05-21)

### Added

- Feature `zeroize` is added.
- Module `lea::prelude` is added.

### Changed

- Default features `["ccm", "ctr"]` are changed to `[]`.
- Dependency `cipher = "0.2.*"` is updated to `cipher = "0.3.*"`. Other dependencies are also updated accordingly.

### Removed

- Redundant benchmarks are removed.

## [0.4.0] (2020-11-22)

### Added

- LEA-CCM is added.
- More LEA-CTR test cases are added.

### Changed

- Block cipher trait module is renamed from `lea::block_cipher` to `lea::block`.
- Stream cipher trait module is renamed from `lea::stream_cipher` to `lea::stream`.
- LEA-CTR feature is renamed from `feature-ctr` to `ctr`.

### Removed

- `lea::Block` is removed.

## [0.3.1] (2020-10-22)

### Changed

- Block cipher trait crate is changed from `block-cipher` to `cipher`.
- Round key implementation is separated from [`lib.rs`](./src/lib.rs) to [`round_key.rs`](./src/round_key.rs).

## [0.3.0] (2020-10-04)

[0.5.3]: https://github.com/sitd0813/lea-rust/compare/0.5.2...0.5.3
[0.5.2]: https://github.com/sitd0813/lea-rust/compare/0.5.1...0.5.2
[0.5.1]: https://github.com/sitd0813/lea-rust/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/sitd0813/lea-rust/compare/0.4.0...0.5.0
[0.4.0]: https://github.com/sitd0813/lea-rust/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/sitd0813/lea-rust/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/sitd0813/lea-rust/releases/tag/0.3.0

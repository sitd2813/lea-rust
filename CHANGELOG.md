# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] – 2020-11-22

### Added

- LEA-CCM is added.
- More LEA-CTR test cases are added.

### Changed

- Block cipher trait module is renamed from `lea::block_cipher` to `lea:block`.
- Stream cipher trait module is renamed from `lea::stream_cipher` to `lea::stream`.
- LEA-CTR feature is renamed from `feature-ctr` to `ctr`.

### Removed

- `lea::Block` is removed.

## [0.3.1] – 2020-10-22

### Changed

- Block cipher trait crate changed from `block-cipher` to `cipher`.
- Round key implementation separated from [`lib.rs`](./src/lib.rs) to [`round_key.rs`](./src/round_key.rs).

## [0.3.0] – 2020-10-04

[0.4.0]: https://github.com/sitd0813/lea-rust/compare/0.3.1...0.4.0
[0.3.1]: https://github.com/sitd0813/lea-rust/compare/0.3.0...0.3.1
[0.3.0]: https://github.com/sitd0813/lea-rust/releases/tag/0.3.0
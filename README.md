# **lea-rust**

 [![crates.io](https://img.shields.io/crates/v/lea.svg)](https://crates.io/crates/lea)
 [![doc.rs](https://docs.rs/lea/badge.svg)](https://docs.rs/lea)

 **lea-rust** is an implementation of a 128-bit ARX block cipher LEA written in Rust.

## LEA(Lightweight Encryption Algorithm)

 LEA(Lightweight Encryption Algorithm) is a 128-bit ARX block cipher algorithm developed by the South Korean National Security Research Institute in 2013. Designed to be faster and more lightweight, it maintains enough security to be the replacement of the AES.

 See <https://seed.kisa.or.kr/kisa/algorithm/EgovLeaInfo.do> for more information.

## Supports:

 * LEA Block Cipher
 * LEA Counter Mode (CTR)

## Warning!

 * I implemented the algorithm according to the specification sheet and the reference implementation written in C. However, I do not guarantee the security of this implementation.
 * The implementation itself is endian-agnostic, but it is not tested on the big-endian device.

## License

 **lea-rust** is subject to the terms of the [`MIT License`](./LICENSE.txt).

 If a copy of the MIT License was not distributed with this file, you can obtain one at <https://opensource.org/licenses/MIT>.

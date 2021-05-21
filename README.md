# **lea-rust**

[![crates.io](https://img.shields.io/crates/v/lea.svg)](https://crates.io/crates/lea)
[![doc.rs](https://docs.rs/lea/badge.svg)](https://docs.rs/lea)

**lea-rust** is an implementation of a 128-bit ARX block cipher LEA written in pure Rust.

## LEA(Lightweight Encryption Algorithm)

LEA(Lightweight Encryption Algorithm) is a 128-bit ARX block cipher algorithm developed by the South Korean National Security Research Institute in 2013. Designed to be faster and more lightweight, it maintains enough security to be the replacement of the AES.

See <https://en.wikipedia.org/wiki/LEA_(cipher)> and <https://seed.kisa.or.kr/kisa/algorithm/EgovLeaInfo.do> for more information.

## Features

| Feature   | Description                              | Default |
| --------- | ---------------------------------------- | ------- |
| `ccm`     | LEA-CCM                                  | false   |
| `ctr`     | LEA-CTR                                  | false   |
| `zeroize` | Zeroize memory containing sensitive data | false   |

## Security

- **Warning**: This implementation has been tested on little-endian devices only.
- **Warning**: This implementation has not received any security audit.

## License

Copyright © 2020–2021 SitD <sitd0813@gmail.com>

This project is subject to the terms of the [`MIT License`](./LICENSE.txt).
If a copy of the MIT License was not distributed with this file, you can obtain one at <https://opensource.org/licenses/MIT>.

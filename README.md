# Async++ Network library
This library provides a c++20 coroutine wrapper for networking and IO related functionality.
It is an addition to [async++](https://github.com/asyncpp/asyncpp) which provides general coroutine tasks and support classes.

The library supports multiple IO backends for the various operating systems:
- select (Linux, MacOS)
- io_uring (Linux 5.1+)
- IOCP (Windows)

Features include:
- Asynchronous socket IO
- Asynchronous file IO (only on uring & IOCP)
- Convenient handling of ips and endpoints
- Coroutine ready wrapper for OpenSSL TLS
- Asynchronous DNS client with support for TSIG
- Ability to cancel most operations using stop_tokens
- Support for error handling using std::error_code or exceptions

Tested and supported compilers:
| Linux                                                                 | Windows                                                             | MacOS (best effort)                                                      |
|-----------------------------------------------------------------------|---------------------------------------------------------------------|--------------------------------------------------------------------------|
| [![ubuntu-2404_clang-16][img_ubuntu-2404_clang-16]][Compiler-Support] | [![windows-2025_msvc17][img_windows-2025_msvc17]][Compiler-Support] | [![macos-15-arm_clang-18][img_macos-15-arm_clang-18]][Compiler-Support]  |
| [![ubuntu-2404_clang-17][img_ubuntu-2404_clang-17]][Compiler-Support] | [![windows-2022_msvc17][img_windows-2022_msvc17]][Compiler-Support] | [![macos-14-arm_clang-15][img_macos-14-arm_clang-15]][Compiler-Support]  |
| [![ubuntu-2404_clang-18][img_ubuntu-2404_clang-18]][Compiler-Support] |                                                                     | [![macos-13_clang-15][img_macos-13_clang-15]][Compiler-Support]          |                                                                     |
| [![ubuntu-2404_gcc-12][img_ubuntu-2404_gcc-12]][Compiler-Support]     |                                                                     |                                                                          |
| [![ubuntu-2404_gcc-13][img_ubuntu-2404_gcc-13]][Compiler-Support]     |                                                                     |                                                                          |
| [![ubuntu-2404_gcc-14][img_ubuntu-2404_gcc-14]][Compiler-Support]     |                                                                     |                                                                          |
| [![ubuntu-2204_clang-13][img_ubuntu-2204_clang-13]][Compiler-Support] |                                                                     |                                                                          |
| [![ubuntu-2204_clang-14][img_ubuntu-2204_clang-14]][Compiler-Support] |                                                                     |                                                                          |
| [![ubuntu-2204_clang-15][img_ubuntu-2204_clang-15]][Compiler-Support] |                                                                     |                                                                          |
| [![ubuntu-2204_gcc-11][img_ubuntu-2204_gcc-11]][Compiler-Support]     |                                                                     |
| [![ubuntu-2204_gcc-10][img_ubuntu-2204_gcc-10]][Compiler-Support]     |                                                                     |


[img_ubuntu-2404_clang-16]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2404_clang-16/shields.json
[img_ubuntu-2404_clang-17]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2404_clang-17/shields.json
[img_ubuntu-2404_clang-18]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2404_clang-18/shields.json
[img_ubuntu-2404_gcc-12]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2404_gcc-12/shields.json
[img_ubuntu-2404_gcc-13]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2404_gcc-13/shields.json
[img_ubuntu-2404_gcc-14]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2404_gcc-14/shields.json
[img_ubuntu-2204_clang-13]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_clang-13/shields.json
[img_ubuntu-2204_clang-14]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_clang-14/shields.json
[img_ubuntu-2204_clang-15]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_clang-15/shields.json
[img_ubuntu-2204_gcc-11]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_gcc-11/shields.json
[img_ubuntu-2204_gcc-10]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_gcc-10/shields.json
[img_windows-2025_msvc17]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/windows-2025_msvc17/shields.json
[img_windows-2022_msvc17]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/windows-2022_msvc17/shields.json
[img_macos-15-arm_clang-18]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-15-arm_clang-18/shields.json
[img_macos-14-arm_clang-15]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-14-arm_clang-15/shields.json
[img_macos-13_clang-15]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-13_clang-15/shields.json
[Compiler-Support]: https://github.com/asyncpp/asyncpp-io/actions/workflows/compiler-support.yml

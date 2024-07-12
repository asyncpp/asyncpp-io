# Async++ Network library
This library provides a c++20 coroutine wrapper for networking and IO related functionality.
It is an addition to [async++](https://github.com/asyncpp/asyncpp) which provides general coroutine tasks and support classes.

This library is developed and tested on Ubuntu linux. There is also experimental support for MacOS.
Windows support is planned but not yet finished.

Tested and supported compilers:
| Linux                                                                 | MacOS (best effort)                                                 |
|-----------------------------------------------------------------------|---------------------------------------------------------------------|
| [![ubuntu-2004_clang-10][img_ubuntu-2004_clang-10]][Compiler-Support] | [![macos-12_clang-15][img_macos-12_clang-15]][Compiler-Support]     |
| [![ubuntu-2004_clang-11][img_ubuntu-2004_clang-11]][Compiler-Support] | [![macos-12_gcc-12][img_macos-12_gcc-12]][Compiler-Support]         |
| [![ubuntu-2004_clang-12][img_ubuntu-2004_clang-12]][Compiler-Support] | [![macos-12_gcc-14][img_macos-12_gcc-14]][Compiler-Support]         |
| [![ubuntu-2004_gcc-10][img_ubuntu-2004_gcc-10]][Compiler-Support]     | [![macos-13_clang-15][img_macos-13_clang-15]][Compiler-Support]     |
| [![ubuntu-2204_clang-13][img_ubuntu-2204_clang-13]][Compiler-Support] | [![macos-13_gcc-12][img_macos-13_gcc-12]][Compiler-Support]         |
| [![ubuntu-2204_clang-14][img_ubuntu-2204_clang-14]][Compiler-Support] | [![macos-13_gcc-14][img_macos-13_gcc-14]][Compiler-Support]         |
| [![ubuntu-2204_clang-15][img_ubuntu-2204_clang-15]][Compiler-Support] | [![macos-14_clang-15][img_macos-14_clang-15]][Compiler-Support]     |
| [![ubuntu-2204_gcc-11][img_ubuntu-2204_gcc-11]][Compiler-Support]     | [![macos-14_gcc-12][img_macos-14_gcc-12]][Compiler-Support]         |
| [![ubuntu-2204_gcc-10][img_ubuntu-2204_gcc-10]][Compiler-Support]     | [![macos-14_gcc-14][img_macos-14_gcc-14]][Compiler-Support]         |


[img_ubuntu-2004_clang-10]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2004_clang-10/shields.json
[img_ubuntu-2004_clang-11]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2004_clang-11/shields.json
[img_ubuntu-2004_clang-12]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2004_clang-12/shields.json
[img_ubuntu-2004_gcc-10]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2004_gcc-10/shields.json
[img_ubuntu-2204_clang-13]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_clang-13/shields.json
[img_ubuntu-2204_clang-14]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_clang-14/shields.json
[img_ubuntu-2204_clang-15]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_clang-15/shields.json
[img_ubuntu-2204_gcc-10]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_gcc-10/shields.json
[img_ubuntu-2204_gcc-11]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/ubuntu-2204_gcc-11/shields.json
[img_windows-2019_msvc16]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/windows-2019_msvc16/shields.json
[img_windows-2022_msvc17]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/windows-2022_msvc17/shields.json
[img_macos-12_clang-15]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-12_clang-15/shields.json
[img_macos-12_gcc-12]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-12_gcc-12/shields.json
[img_macos-12_gcc-14]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-12_gcc-14/shields.json
[img_macos-13_clang-15]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-13_clang-15/shields.json
[img_macos-13_gcc-12]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-13_gcc-12/shields.json
[img_macos-13_gcc-14]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-13_gcc-14/shields.json
[img_macos-14_clang-15]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-14_clang-15/shields.json
[img_macos-14_gcc-12]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-14_gcc-12/shields.json
[img_macos-14_gcc-14]: https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/asyncpp/asyncpp-io/badges/compiler/macos-14_gcc-14/shields.json
[Compiler-Support]: https://github.com/asyncpp/asyncpp-io/actions/workflows/compiler-support.yml
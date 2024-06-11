# Circuit Definition Library for =nil; Foundation's Cryptography Suite

[![Run tests](https://github.com/NilFoundation/zkllvm-blueprint/actions/workflows/run_tests.yml/badge.svg)](https://github.com/NilFoundation/zkllvm-blueprint/actions/workflows/run_tests.yml)

## Dependencies

- [Boost](https://boost.org) (>= 1.76)
- [cmake](https://cmake.org/) (>=3.21.4)
- Following dependencies must be built and installed from sources:
  - [CMake Modules](https://github.com/BoostCMake/cmake_modules.git)
  - [crypto3](https://github.com/nilfoundation/crypto3.git)

## Building and installation

```bash
cmake -B build -DCMAKE_INSTALL_PREFIX=/path/to/install
make -C build install
```

> Note: if you got an error on `find_package` during cmake configuration, make sure that you provided paths to the installed dependencies (for example, via `CMAKE_PREFIX_PATH` environment variable)

## Nix support
This repository provides Nix flake, so once you have installed Nix with flake support, you can use single command to fetch all the dependencies and build:

```bash
nix build ?submodules=1#
```

To activate Nix development environment:

```bash
nix develop
```

To run all tests:

```bash
nix flake check -L ?submodules=1#
```

To build/develop/test with local crypto3 version, add an argument `--override-input nil_crypto3 /path/to/local/crypto3` to any of the above commands.

# Fast Fourier Transforms

nil; Foundation C++ Computer Algebra System Fast Fourier Transforms

## Building

This library uses Boost CMake build modules (https://github.com/BoostCMake/cmake_modules.git). To actually include this
library in a project it is required to:

1. Add [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodule to taget project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as
   submodules to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) (Look
   at [crypto3](https://github.com/nilfoundation/crypto3.git) for the example)

## Dependencies

### Internal

* [Pairings](https://github.com/NilFoundation/pairing)
* [Finite fields](https://github.com/NilFoundation/ff)

### External

* [Boost](https://boost.org) (>= 1.58)

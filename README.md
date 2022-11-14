# Polynomial Arithmetics, Fast Fourier Transforms for =nil; Crypto3 C++ Cryptography Suite 

Crypto3.Math extends the =nil; Foundation's Crypto3.Algebra and provides a set of Fast Fourier Transforms evaluation algorithms and Polynomial Arithmetics implemented in way C++ standard library implies: concepts, algorithms, predictable behavior, latest standard features support and clean architecture without compromising security and performance.

## Building

This library uses Boost CMake build modules (https://github.com/BoostCMake/cmake_modules.git). To actually include this
library in a project it is required to:

1. Add [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodule to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as
   submodules to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) (Look
   at [crypto3](https://github.com/nilfoundation/crypto3.git) for the example)

## Dependencies

### Internal

* [Algebra](https://github.com/NilFoundation/crypto3-algebra)
* [Multiprecision](https://github.com/NilFoundation/crypto3-multiprecision)

### External

* [Boost](https://boost.org) (>= 1.58)

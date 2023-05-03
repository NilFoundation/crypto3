# Circuits Traspiler Library for =nil; Foundation's zkLLVM circuit compiler

[![Run tests](https://github.com/NilFoundation/zkllvm-transpiler/actions/workflows/run_tests.yml/badge.svg)](https://github.com/NilFoundation/zkllvm-transpiler/actions/workflows/run_tests.yml)

## Building

This library uses Boost CMake build modules (https://github.com/BoostCMake/cmake_modules.git).
To actually include this library in a project it is required to:

1. Add [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodule to target project repository.
2. Add all the internal dependencies using [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) as submodules to target project repository.
3. Initialize parent project with [CMake Modules](https://github.com/BoostCMake/cmake_modules.git) (Look at [crypto3](https://github.com/nilfoundation/crypto3.git) for the example)

## Run examples
This library is used in [ZKLLVM]{https://github.com/NilFoundation/zkllvm} transpiler binary.
It produces gate argument for EVM from zkllvm-assigner which consists of circuit.crct and assignment.tbl file.
It can also create test proof to check gate argument by [evm-placeholder-verification]{https://github.com/NilFoundation/zkllvm}
To build transpiler app follow ZKLLVM instructions to prepare evironment and input data. Use this branch [ZKLLVM](https://github.com/NilFoundation/zkllvm/tree/64-add-optimize-option-to-transpiler-app).

1. Build transpiler binary file
```bash
make -C ${ZKLLVM_BUILD:-build} transpiler -j$(nproc) 
```
2. Let `input_folder` is a folder contains transpiler input(`circuit.crct` and `assignment.tbl` file). Let `output_folder` is a folder for transpiler output. Run to generate gate argument files:
```bash
${ZKLLVM_BUILD:-build}/bin/transpiler/transpiler -m gen-gate-argument -i input_folder -o output_folder
```
Use --optimize-gates option to place small sequental gates to one .sol file
Run to generate test proof:
```bash
${ZKLLVM_BUILD:-build}/bin/transpiler/transpiler -m gen-test-proof -i input_folder -o output_folder
```
3. Copy `output_folder` to `evm-placeholder-verification/examples`. Use this branch [evm-placholder-verification](https://github.com/NilFoundation/evm-placeholder-verification/tree/37-merge-33-and-17) 

4. Run python scripts from the folder `evm-placeholder-verification/test` to verify test proof
```bash
python3 web3_deploy_gate_argument.py examples/output_folder
python3 web3_placeholder_verify_deployed_test.py examples/output_folder
```
## Dependencies

### Internal

Crypto3 suite:

* [Crypto3.Algebra](https://github.com/nilfoundation/crypto3-algebra.git).
* [Crypto3.Math](https://github.com/nilfoundation/crypto3-math.git).
* [Crypto3.Multiprecision](https://github.com/nilfoundation/crypto3-multiprecision.git).
* [Crypto3.ZK](https://github.com/nilfoundation/crypto3-zk.git).

zkLLVM compiler ecosystem:

* [zkLLVM Blueprint](https://github.com/NilFoundation/zkllvm-blueprint.git).

### External
* [Boost](https://boost.org) (>= 1.76)
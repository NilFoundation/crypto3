---
description: Scaffold project using crypto3 library
---

# Quickstart (Scaffold)

This guide will set up a project scaffold using crypto3 and run an example. This will enable you to test ideas quickly and further explore the API’s of the suite. This guide will use a generic setup.

## Pre-requisites

Please ensure you have set up your environment by following the guide [here](environment-setup.md).

## Scaffold Setup

#### Get crypto3 scaffold

```shell
git clone git@github.com:NilFoundation/crypto3-template.git
cd crypto3-template
```

#### Project structure

The project is an example of generic usage of the suite, adding the whole crypto3 suite as a sub-module dependency.

```
root
├── libs : submodule including the repository for crypto3 suite
├── src  
│   ├── bls 
│   │  │──── src: source for bls signing example.
```

#### Build/test scaffold

* Clone sub-modules recursively

```shell
git submodule update --init --recursive
```

* Build: The project is built using the cmake system.

```shell
mkdir build && cd build && cmake .. && make
```

* Run executable

```shell
./src/bls/bls_sig
```

You should see the output `Verified signature successfully` on your console.

## Conclusion

Congratulations! You now have the environment to start experimenting with the crypto3 suite. You can now explore [modules](broken-reference/) in the suite. Modules also have examples/tests in their repositories, ex: [algebra examples](https://github.com/NilFoundation/crypto3-algebra/tree/master/example).

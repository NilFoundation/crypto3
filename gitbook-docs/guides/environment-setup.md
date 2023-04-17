---
description: Environment setup for crypto3 suite
---

# Environment Setup

In this guide, we set up packages/libraries we require in order to compile projects using the crypto3 library.

## Installation

### Linux

The following dependencies need to be installed.

* [boost](https://www.boost.org/) >= 1.74.0
* [cmake](https://cmake.org/) >= 3.5
* [clang](https://clang.llvm.org/) >= 14.0.6

Please execute the below to fetch the packages required or adapt the command to your package manager.

```shell
sudo apt install build-essential libssl-dev libboost-all-dev cmake clang git
```

Once the base packages are installed, please see the [quickstart](quickstart.md) guide to set up a scaffold project or [installation](environment-setup.md#installation) on how you can integrate crypto3 with your existing project.

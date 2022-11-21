---
description: Adding crypto3 suite to your project
---

# Installation

This guide assumes all dependencies described in the [Quickstart](quickstart.md) guide have been installed.

## Usage

crypto3 should be added to a project as a git [sub-module](https://git-scm.com/book/en/v2/Git-Tools-Submodules). crypto3 suite can be used as follows:

1. Generic.
2. Selective.

{% hint style="info" %}
The suite is used as a header-only and is currently statically linked. Future versions will allow dynamic linking.
{% endhint %}

{% hint style="info" %}
The suite is compatible with x86 and ARM architectures
{% endhint %}

### Generic

Generic usage of cryptography suite consists of all modules listed [here](https://github.com/orgs/NilFoundation/teams/nil-crypto3/repositories) at team repository.

The generic module can be added to your C++ project as follows

```shell
git submodule add https://github.com/NilFoundation/crypto3.git <dir>
```

### Selective

Developer can select to include a one or more modules to reduce the sources of resulting project and dependencies tree height. This however does require the developer to manually resolve all required dependencies and stay up-to date regarding compatibility across modules.

Selective modules can be added to your project as follows:

```shell
git submodule add https://github.com/NilFoundation/crypto3-<lib>.git <dir>
```

## Include

To compile anything in crypto3, you need a directory containing the crypto3 sub-module directory in your `#include` path. Since all of crypto3 header files have the `.hpp` extension, and live in the `crypto3\<lib>` sub-directory of the crypto3 root, your crypto3 include directives will look like

```cpp
#include <nil/crypto3/pubkey/algorithm/sign.hpp>
```

## CMake

We recommend using CMake to provide paths/linker flags.

```cmake
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/<submodule-directory>")
```

Linker commands&#x20;

```cmake
target_link_libraries(${PROJECT_TARGET} <crypto3_library>)
```

Example:

```cmake
add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/libs/crypto3")
target_link_libraries(${PROJECT_TARGET} crypto3::algebra)
```


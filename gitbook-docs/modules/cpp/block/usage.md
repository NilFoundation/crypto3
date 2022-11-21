# Usage {#block_ciphers_usage_manual}

@tableofcontents

## Quick Start

The easiest way to use Crypto3.Block library is to use an algorithm with explicit key initialization and
 implicit state usage. Following example encrypts byte sequence with AES block cipher:
 
```cpp

#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/algorithm/encrypt.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {

    std::string input = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
                        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";

    std::string key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";


    std::string out = encrypt<block::aes<128>>(input.begn(), input.end(), key);

    assert(out == "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
                    "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
}
 
```

Similar technique is available for ranges:

```cpp

#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/algorithm/encrypt.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {

    std::string input = "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
                        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";

    std::string key = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";


    std::string out = encrypt<block::aes<128>>(input, key);

    assert(out == "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
                    "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4");
}
 
```

## Stateful encryption

In case of accumulative encryption requirement is present, following example demonstrates 
[accumulator](@ref block::accumulator_set) usage:

```cpp
#include <nil/crypto3/block/aria.hpp>
#include <nil/crypto3/block/algorithm/encrypt.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {
   block::accumulator_set<block::aria> acc;
}
```
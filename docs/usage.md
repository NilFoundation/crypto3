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
    std::string key = "000102030405060708090a0b0c0d0e0f";
    std::string input = "00112233445566778899aabbccddeeff", out = "";
    encrypt<block::aes<128>>(input.begin(), input.end(), key.begin(), key.end(), out.end());
    assert(out == "d718fbd6ab644c739da95f3be6451778");
}
 
```

Similar technique is available for ranges:

```cpp

#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/algorithm/encrypt.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {
   std::string key = "000102030405060708090a0b0c0d0e0f";
   std::string input = "00112233445566778899aabbccddeeff";
   std::string out = encrypt<block::aes<128>>(input, key);
   assert(out == "d718fbd6ab644c739da95f3be6451778");
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
# Block Ciphers Manual {#block_ciphers_manual} #

## Quick Start ##

The easiest way to use Crypto3.Block library is to use an algorithm with explicit key initialization and
 implicit state usage. Following example encrypts byte sequence with Aria block cipher:
 
```cpp

#include <nil/crypto3/block/aria.hpp>
#include <nil/crypto3/block/algorithm/encrypt.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {
    
}
 
```

Similar technique is available for ranges:

```cpp

#include <nil/crypto3/block/aria.hpp>
#include <nil/crypto3/block/algorithm/encrypt.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {
    
}
 
```

## Stateful encryption ##

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
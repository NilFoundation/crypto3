---
description: Crypto3.Block ciphers
---

# ciphers

The following block ciphers are implemented by the library:

* aes
* shacal/shcal-2
* kasumi
* md4/md5
* rijndael

All block ciphers implemented in the algebra library conform to the concept of a block type. They can be swapped in any policies or schemes and taken as input in the crypto3 suite. A block must conform to the traits defined in `block/include/nil/crypto3/detail/type_traits.hpp`

## Usage

`Block` ciphers are defined under the namespace `nil::crypto3::block` and header need to be included `ex: nil/crypto3/block/aes.hpp`

### Exampe#1

```cpp
#include <nil/crypto3/block/aes.hpp>
#include <nil/crypto3/block/algorithm/encrypt.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {
    std::vector<char> input = {'\x00', '\x11', '\x22', '\x33', '\x44', '\x55', '\x66', '\x77',
                               '\x88', '\x99', '\xaa', '\xbb', '\xcc', '\xdd', '\xee', '\xff'};
    std::vector<char> key = {'\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07',
                             '\x08', '\x09', '\x0a', '\x0b', '\x0c', '\x0d', '\x0e', '\x0f'};

    std::string out = encrypt<block::rijndael<128, 128>>(input, key);

    return 0;
}
```

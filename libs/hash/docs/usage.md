# Usage {#hashes_usage_manual}

@tableofcontents

## Quick Start

The easiest way to use Crypto3.Hash library is to use an algorithm with implicit state usage. Following example hash
byte sequence with MD5 hashes:

```cpp

#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {
    std::string input = "abc";
    std::string out = hash<hashes::md5>(input.begin(), input.end());
    assert(out == "900150983cd24fb0d6963f7d28e17f72");
}
 
```

Similar technique is available for ranges:

```cpp

#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {
    std::string input = "abc";
    std::string out = hashes<hash::md5>(input);
    assert(out == "900150983cd24fb0d6963f7d28e17f72");
}
 
```

## Stateful hashing

In case of accumulative hashes requirement is present, following example demonstrates
[accumulator](@ref accumulator_set) usage:

```cpp
#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

using namespace nil::crypto3;

int main(int argc, char *argv[]) {
    accumulator_set<hashes::md5> acc;
    std::string input = "abc";
    hash<hashes::md5>(input.begin(), input.end(), acc);
    std::string out = std::to_string(extract::hash<hashes::md5>(acc));
    assert(out == "900150983cd24fb0d6963f7d28e17f72");
}
```
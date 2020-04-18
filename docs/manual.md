# Manual # {#codec_manual}

@tableofcontents

## Basic Example

```
#include <string>

#include <nil/crypto3/codec/base.hpp>
#include <nil/crypto3/codec/algorithm/encode.hpp>

using namespace nil::crypto3::codec;

int main(int argc, char *argv[]) {
    std::string data = "Weird German 2 byte thing: Ã."
    
    std::string result = encode<base64>(data);
    
    return !(result == "V2VpcmQgR2VybWFuIDIgYnl0ZSB0aGluZzogw58u");
}

```
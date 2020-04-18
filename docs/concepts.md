# Concepts # {#stream_ciphers_concepts}

@tableofcontents

## Stream Ciphers Concept ## {#stream_ciphers_concept}

A ```StreamCipher``` is an object intended to compute non-isomorphic permutations over variable-sized ```Integral``` blobs of data.

### Requirements

The type ```X``` satisfies ```StreamCipher``` if

Given
* ```BlockType```, the type named by ```X::block_type```
* ```KeyScheduleType```, the type named by ```X::key_schedule_type```

The following type members must be valid and have their specified effects

|Expression                   |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::block_type```          |```BlockType```         |```BlockType``` type is a ```SequenceContainer``` of type ```T``` or ```std::array<T>```|
|```X::word_type```           |```WordType```          |```WordType``` type satisfies ```Integral``` concept|
|```X::key_type```            |```KeyType```           |```KeyType``` type is a ```SequenceContainer``` of type ```T```|
|```X::round_constants_type```|```RoundConstantsType```|```RoundConstantsType``` type satisfies ```Integral``` concept|

The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::word_bits```  |```std::size_t```|```Integral``` bits amount in ```WordType```|
|```X::key_bits```   |```std::size_t```|```Integral``` bits amount in ```KeyType```|
|```X::block_bits``` |```std::size_t```|```Integral``` bits amount in ```BlockType```|
|```X::block_words```|```std::size_t```|```Integral``` amount of ```WordType``` values in ```BlockType```|
|```X::rounds```     |```std::size_t```|```Integral``` amount of rounds the algorithm does.|

The following expressions must be valid and have their specified effects

|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X(key_type)```|Constructs stateful ```StreamCipher``` object with input key of ```key_type```|```StreamCipher```|
|```X.encrypt(block_type)```|Encrypts a block of data in decoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```StreamCipher``` object inner state of ```key_type``` type.|```block_type```|
|```X.decrypt(block_type)```|Decrypts a block of data in encoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```StreamCipher``` object inner state of ```key_type``` type.|```block_type```|

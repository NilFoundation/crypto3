# Concepts # {#block_ciphers_concepts}

@tableofcontents

## BlockCipher Concept ## {#block_cipher_concept}

A ```BlockCipher``` is an object intended to compute non-isomorphic permutations over particular sized integers (e.g. rijndael).

### Requirements ### {#block_ciphers_concepts_requirements}

The type ```X``` satisfies ```BlockCipher``` if

Given
* ```WordType```, the type named by ```X::word_type```
* ```KeyType```, the type named by ```X::key_type```
* ```BlockType```, the type named by ```X::block_type```
* ```RoundConstantsType```, the type named by ```X::round_constants_type```
* ```StreamProcessor```, the type template named by ```X::stream_processor```

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
|```X(key_type)```|Constructs stateful ```BlockCipher``` object with input key of ```key_type```|```BlockCipher```|
|```X.encrypt(block_type)```|Encrypts a block of data in decoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```BlockCipher``` object inner state of ```key_type``` type.|```block_type```|
|```X.decrypt(block_type)```|Decrypts a block of data in encoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```BlockCipher``` object inner state of ```key_type``` type.|```block_type```|

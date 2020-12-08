# Concepts # {#mac_concepts}

@tableofcontents

## MessageAuthenticationCode Concept ## {#mac_concept}

A ```MessageAuthenticationCode``` is an object intended to compute non-isomorphic permutations over particular sized
integers (e.g. rijndael).

### Requirements ### {#mac_concepts_requirements}

The type ```X``` satisfies ```MessageAuthenticationCode``` if

Given

* ```KeyType```, the type named by ```X::key_type```
* ```BlockType```, the type named by ```X::block_type```
* ```DigestType```, the type named by ```X::digest_type```

The following type members must be valid and have their specified effects

|Expression                   |Type            |Requirements and Notes         |
|-----------------------------|----------------|-------------------------------|
|```X::block_type```          |```BlockType``` |```BlockType``` type is a ```SequenceContainer``` of type ```T``` or ```std::array<T>```|
|```X::word_type```           |```WordType```  |```WordType``` type satisfies ```Integral``` concept|
|```X::digest_type```         |```DigestType```|```DigestType``` type is a ```SequenceContainer``` of type ```T```|

The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::digest_bits```|```std::size_t```|```Integral``` bits amount in ```DigestType```|
|```X::key_bits```   |```std::size_t```|```Integral``` bits amount in ```KeyType```|
|```X::block_bits``` |```std::size_t```|```Integral``` bits amount in ```BlockType```|
|```X::block_words```|```std::size_t```|```Integral``` amount of ```WordType``` values in ```BlockType```|

The following expressions must be valid and have their specified effects

|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X(key_type)```|Constructs stateful ```MessageAuthenticationCode``` object with input key of ```key_type```|```MessageAuthenticationCode```|

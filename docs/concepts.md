# Concepts # {#hashes_concepts}

@tableofcontents

## Hash Concept ## {#hash_concept}

A ```Hash``` is a function object for which the output depends only on the input and has a very low probability of
yielding the same output given different input values.

### Requirements ### {#hash_concepts_requirements}

The type ```X``` satisfies ```Hash``` if:

Given

* ```WordType```, the type named by ```X::word_type```
* ```BlockType```, the type named by ```X::block_type```
* ```DigestType```, the type named by ```X::digest_type```
* ```StreamProcessor```, the type template named by ```X::stream_processor```

The following type members must be valid and have their specified effects

|Expression                   |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::block_type```          |```BlockType```         |```BlockType``` type is a ```SequenceContainer``` of type ```T``` or ```std::array<T>```|
|```X::word_type```           |```WordType```          |```WordType``` type satisfies ```Integral``` concept|
|```X::digest_type```         |```DigestType```        |```DigestType``` type is a ```SequenceContainer``` of type ```T``` or ```std::array<T>```|

The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::word_bits```  |```std::size_t```|```Integral``` bits amount in ```WordType```|
|```X::block_bits``` |```std::size_t```|```Integral``` bits amount in ```BlockType```|
|```X::digest_bits```|```std::size_t```|```Integral``` bits amount in ```DigestType```|
|```X::block_words```|```std::size_t```|```Integral``` amount of ```WordType``` values in ```BlockType```|


  
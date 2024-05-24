# Concepts # {#codec_concepts}

@tableofcontents

## Codec Concept ## {#codec_concept}

A ```Codec``` is an object intended to compute isomorphic integral permutations (e.g. base64).

### Requirements ### {#codec_concept_requirements}

The type ```X``` satisfies ```Codec``` if

Given
* ```EncodedBlock```, the type named by ```X::encoded_block_type```
* ```DecodedBlock```, the type named by ```X::decoded_block_type```
* ```StreamProcessor```, the type template named by ```X::stream_processor```

The following type members must be valid and have their specified effects

|Expression                 |Type              |Requirements and Notes         |
|---------------------------|------------------|-------------------------------|
|```X::encoded_block_type```|```EncodedBlock```|```EncodedBlock``` type is a ```SequenceContainer``` of an ```Integral``` type ```T``` or ```std::array<T>```|
|```X::decoded_block_type```|```DecodedBlock```|```DecodedBlock``` type is a ```SequenceContainer``` of an ```Integral``` type ```T``` or ```std::array<T>```|
|```X::encoded_value_type```|```EncodedBlock::value_type```|```EncodedBlock``` type is a ```SequenceContainer``` of an ```Integral``` type ```T```|
|```X::decoded_block_type```|```DecodedBlock::value_type```|```DecodedBlock``` type is a ```SequenceContainer``` of an ```Integral``` type ```T```|

The following static data member definitions must be valid and have their specified effects

|Expression                 |Type              |Requirements and Notes         |
|---------------------------|------------------|-------------------------------|
|```X::encoded_block_values```|```std::size_t```|```Integral``` amount of values in ```EncodedBlock```|
|```X::decoded_block_values```|```std::size_t```|```Integral``` amount of values in ```DecodedBlock```|
|```X::encoded_block_bits```|```std::size_t```|```Integral``` bits amount in ```EncodedBlock```|
|```X::decoded_block_bits```|```std::size_t```|```Integral``` bits amount in ```DecodedBlock```|

The following expressions must be valid and have their specified effects

|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X.encode(decoded_block_type)```|Encodes the block of data in decoded format specified for particular algorithm. A block can be of a variable size. Should be a stateless non-mutating function.|```encoded_block_type```|
|```X.decode(encoded_block_type)```|Decodes the block of data in encoded format specified for particular algorithm. A block can be of a variable size. Should be a stateless non-mutating function.|```decoded_block_type```|
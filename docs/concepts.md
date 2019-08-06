# Concepts

## Codec Concept

A ```Codec``` is an object intended to compute isomorphic integral permutations (e.g. base64).

### Requirements

The type ```X``` satisfies ```Codec``` if

Given
* ```EncodedBlock```, the type named by ```X::encoded_block_type```
* ```DecodedBlock```, the type named by ```X::decoded_block_type```
* ```StreamProcessor```, the type template named by ```X::stream_processor```

The following type definitions must be valid and have their specified effects

|Expression                 |Type              |Requirements and Notes         |
|---------------------------|------------------|-------------------------------|
|```X::encoded_block_type```|```EncodedBlock```|```EncodedBlock``` type is an ```Integral``` ```SequenceContainer```|
|```X::decoded_block_type```|```DecodedBlock```|```DecodedBlock``` type is an ```Integral``` ```SequenceContainer```|
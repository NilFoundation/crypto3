# Concepts

## Codec Concept

A ```Codec``` is an object intended to compute homeomorphic(?) integral permutations (e.g. base64).

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



## DynamicStateContainer Concept

A ```DynamicStateContainer``` is a ```CacheConceptContainer``` which is specified for unspecified length  
```Integral```  data insertion.

### Requirements

The type ```X``` satisfies ```DynamicStateContainer``` if:
* ```X``` satisfies ```SinglePassRange```,  ```SequenceContainer```, ```ConceptContainer```, ```CacheConceptContainer```, and

Given
* ```Storage```, the container template type satisfies ```SequenceContainer``` 
* ```Element```, the element type of ```Storage``` satisfies ```Integral```
* ```Cache```, the container template satisfies ```SinglePassRange```, ```ReversibleContainer``` except that 
default-constructed type is not empty and that the complexity of swapping is linear, satisfies the requirements of 
```ContiguousContainer```, and at least partially satisfies the requirements of ```SequenceContainer``` (e.g. 
```std::array```). 
* ```CacheElement```, the element type of ```Cache``` satisfies ```Integral```
* ```IntegralPreprocessor```, the 
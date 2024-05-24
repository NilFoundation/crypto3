# Concepts # {#kdf_concepts}

@tableofcontents

## Key Derivation Function Concept ## {#kdf_concept}

A ```KeyDerivationFunction``` is an object intended to compute non-isomorphic permutations from non-fixed size elements
integral field to fixed-size elements integral field,

### Requirements ### {#kdf_concepts_requirements}

The type ```X``` satisfies ```KeyDerivationFunction``` if

Given

* ```MacType```, the type named by ```X::mac_type```
* ```KeyType```, the type named by ```X::key_type```
* ```SaltType```, the type named by ```X::salt_type```
* ```LabelType```, the type named by ```X::label_type```
* ```SecretType```, the type template named by ```X::secret_type```

The following type members must be valid and have their specified effects

|Expression                   |Type              |Requirements and Notes       |
|-----------------------------|------------------|-----------------------------|
|```X::mac_type```            |```MacType```     |```MacType``` type satisfies ```MessageAuthenticationCode``` concept|
|```X::key_type```            |```KeyType```     |```KeyType``` type is a ```SequenceContainer``` of type ```T``` which satisfies ```Integral``` concept|
|```X::salt_type```           |```SaltType```    |```SaltType``` type is a ```SequenceContainer``` of type ```T``` which satisfies ```Integral``` concept|
|```X::label_type```          |```LabelType```   |```LabelType``` type is a ```SequenceContainer``` of type ```T``` which satisfies ```Integral``` concept|
|```X::secret_type```         |```SecretType```  |```SecretType``` type is a ```SequenceContainer``` of type ```T``` which satisfies ```Integral``` concept|

The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::key_bits```   |```std::size_t```|```Integral``` bits amount in ```KeyType```|
|```X::salt_bits```  |```std::size_t```|```Integral``` bits amount in ```SaltType```|
|```X::label_bits``` |```std::size_t```|```Integral``` bits amount in ```LabelType```|
|```X::secret_bits```|```std::size_t```|```Integral``` bits amount in ```SecretType```|

The following expressions must be valid and have their specified effects

|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X(key_type)```|Constructs stateful ```KeyDerivationFunction``` object with input key of ```key_type```|```KeyDerivationFunction```|

# Concepts {#pubkey_concepts}


@tableofcontents

## PublicKeyScheme Concept ## {#pubkey_concept}

A ```PublicKeyScheme``` is a stateless public-keyed cryptographic scheme policy.

### Requirements ### {#pubkey_concepts_requirements}

The type ```X``` satisfies ```PublicKeyScheme``` if:

Given

* ```StreamProcessor```, the type template named by ```X::stream_processor```
* ```PrivateKey```, the type template named by ```X::private_key_type```
* ```PublicKey```, the type template named by ```X::public_key_type```

The following type members must be valid and have their specified effects

|Name               |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::stream_processor```          |```StreamProcessor``         |```StreamProcessor``` object a split the data to blocks, converts them and passes to acummlator reference as  input data of format require.|
|```X::private_key_type```          |```PrivateKey``         |```PrivateKey``` type satisfies ```private_key_concept`` concept.|
|```X::publc_key_type```          |```PublicKey``         |```StreamProcessor``` object a split the data to blocks, converts them and passes to acummlator reference as  input data of format require.|



## Private key Concept ## {#private_key_concept}
A ```PrivateKey``` is function object perfoming operations with private key. For example: signing, decryption.

### Requirements ### {#private_key_concepts_requirements}

The type ```X``` satisfies ``` PrivateKey``` if:

Given

* ```SchemeType```, the type template named by ```X::scheme_type``` 
* ```PrivateKeyType```, the type template named by ```X::private_key_type``` 
* ```PublicKeyType```, the type template named by ```X::public_key_type``` 
* ```SignatureType```, the type template named by ```X::signature_type``` 
* ```InputBlockType```, the type template named by ```X::input_block_type``` 
* ```InputValueType```, the type template named by ```X::input_value_type``` 


|Expression                   |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::scheme_type```         |```SchemeType```        |```SchemeType``` type satisfies ```Pubkey``` concept|
|```X::private_key_type```         |```PrivateKeyType```        |```PrivateKeyType``` is an element of  ```Algebra```|
|```X::public_key_type```         |```PublicKeyType```        |```PublicKeyType``` is an element of  ```Algebra```|
|```X::signature_key_type```         |```SignatureKeyType```        |```SignatureKeyType``` is an element of  ```Algebra```|
|```X::input_block_type```          |```InputBlockType```         |```InputBlockType``` type is a ```SequenceContainer``` of type ```T``` or ```std::vector<T>```|
|```X::input_value_type```           |```InputValueType```          |```InputValueType``` type satisfies ```Integral``` concept|


The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::input_value_bits```  |```std::size_t```|```Integral``` bits amount in ```InputValueType```|
|```X::input_block_bits``` |```std::size_t```|```Integral``` bits amount in ```InputBlockType```|


The following expressions must be valid and have their specified effects
 Given
 * ```BlockType```, the type satisfies ```SequenceContainer``` concept for wich BlockType::value_type is InputValueType


|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X(PrivateKey::private_key_type)```|Constructs stateful ```PrivateKey``` object with input key of ```private_key_type```|```PrivateKey```|
|```X.sign(BlockType)```|Sign a block of data in decoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```PrivateKey``` object inner state of ```private_key_type``` type.|```PrivateKey::signature_type```|
|```X.decrypt(BlockType)```|Decrypts a block of data in encoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```PrivateKey``` object inner state of ```private_key_type``` type.|```BlockType```|


## PublicKey Concept ## {#public_key_concept}
A ```PublicKey``` is function object perfoming operations with public key. For example: verification, encryption.

### Requirements ### {#public_concepts_requirements}

The type ```X``` satisfies ``` PublicKey``` if:

Given

* ```SchemeType```, the type template named by ```X::scheme_type``` 
* ```PrivateKeyType```, the type template named by ```X::private_key_type``` 
* ```PublicKeyType```, the type template named by ```X::public_key_type``` 
* ```SignatureType```, the type template named by ```X::signature_type``` 
* ```InputBlockType```, the type template named by ```X::input_block_type``` 
* ```InputValueType```, the type template named by ```X::input_value_type``` 

|Expression                   |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::scheme_type```         |```SchemeType```        |```SchemeType``` type satisfies ```Pubkey``` concept|
|```X::private_key_type```         |```PrivateKeyType```        |```PrivateKeyType``` is an element of  ```Algebra```|
|```X::public_key_type```         |```PublicKeyType```        |```PublicKeyType``` is an element of  ```Algebra```|
|```X::signature_key_type```         |```SignatureKeyType```        |```SignatureKeyType``` is an element of  ```Algebra```|
|```X::input_block_type```          |```InputBlockType```         |```InputBlockType``` type is a ```SequenceContainer``` of type ```T``` or ```std::vector<T>```|
|```X::input_value_type```           |```InputValueType```          |```InputValueType``` type satisfies ```Integral``` concept|


The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::input_value_bits```  |```std::size_t```|```Integral``` bits amount in ```InputValueType```|
|```X::input_block_bits``` |```std::size_t```|```Integral``` bits amount in ```InputBlockType```|


The following expressions must be valid and have their specified effects
 Given
 * ```BlockType```, the type satisfies ```SequenceContainer``` concept for wich BlockType::value_type is InputValueType


|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X(PublicKey::public_key_type)```|Constructs stateful ```PublicKey``` object with input key of ```public_key_type```|```PublicKey```|
|```X.verify(BlockType)```|Verify a block of data in decoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```PublicKey``` object inner state of ```public_key_type``` type.|```PublicKey::signature_type```|
|```X.encrypt(BlockType)```|Encrypts a block of data in encoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```PublicKey``` object inner state of ```public_key_type``` type.|```BlockType```|


## No key Concept ## {#no_key_concept}
A ```No_key``` is function object perfoming operations with private key. For example: aggregate.

### Requirements ### {#no_key_concepts_requirements}

The type ```X``` satisfies ``` NoKey``` if:

Given

* ```SchemeType```, the type template named by ```X::scheme_type``` 
* ```PrivateKeyType```, the type template named by ```X::private_key_type``` 
* ```PublicKeyType```, the type template named by ```X::public_key_type``` 
* ```SignatureType```, the type template named by ```X::signature_type``` 
* ```InputBlockType```, the type template named by ```X::input_block_type``` 
* ```InputValueType```, the type template named by ```X::input_value_type``` 




|Expression                   |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::scheme_type```         |```SchemeType```        |```SchemeType``` type satisfies ```Pubkey``` concept|
|```X::private_key_type```         |```PrivateKeyType```        |```PrivateKeyType``` is an element of  ```Algebra```|
|```X::public_key_type```         |```PublicKeyType```        |```PublicKeyType``` is an element of  ```Algebra```|
|```X::signature_key_type```         |```SignatureKeyType```        |```SignatureKeyType``` is an element of  ```Algebra```|
|```X::input_block_type```          |```InputBlockType```         |```InputBlockType``` type is a ```SequenceContainer``` of type ```T``` or ```std::vector<T>```|
|```X::input_value_type```           |```InputValueType```          |```InputValueType``` type satisfies ```Integral``` concept|


The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::input_value_bits```  |```std::size_t```|```Integral``` bits amount in ```InputValueType```|
|```X::input_block_bits``` |```std::size_t```|```Integral``` bits amount in ```InputBlockType```|

The following expressions must be valid and have their specified effects
 Given
 * ```BlockType```, the type satisfies ```SequenceContainer``` concept for wich BlockType::value_type is InputValueType

|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X(NoKey::no_key_type)```|Constructs stateful ```NoKey``` object without input key.|```NoKey```|
|```X.aggregate(BlockType)```|Aggregate a block of data in decoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```PrivateKey``` object inner state of ```no_key_type``` type.|```NoKey::signature_type```|
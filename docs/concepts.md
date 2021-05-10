# Concepts {#pubkey_concepts}


@tableofcontents

## PublicKeyScheme Concept ## {#pubkey_concept}

A ```PublicKeyScheme``` is a stateless public-keyed cryptographic scheme policy.

### Requirements ### {#pubkey_concepts_requirements}

The type ```X``` satisfies ```PublicKeyScheme``` if:

Given

* ```StreamProcessor```, the type template named by ```X::stream_processor```
* ```PrivateKey```, the type named by ```X::private_key_type```
* ```PublicKey```, the type named by ```X::public_key_type```

The following type members must be valid and have their specified effects

|Name               |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::stream_processor```          |```StreamProcessor```         |```StreamProcessor``` object splits the data to blocks, converts them and passes to accumulator reference as input data of required format.|
|```X::private_key_type```          |```PrivateKey```         |```PrivateKey``` type satisfies ```private_key_concept``` concept.|
|```X::publc_key_type```          |```PublicKey```         |```PublicKey``` type satisfies ```public_key_concept``` concept.|


## Public key Concept ## {#public_key_concept}
A ```PublicKey``` is function object performing operations with public key. For example: verify, encryption.

### Requirements ### {#public_concepts_requirements}

The type ```X``` satisfies ``` PublicKey``` if:

Given

* ```SchemeType```, the type named by ```X::scheme_type```
* ```PrivateKeyType```, the type named by ```X::private_key_type```
* ```PublicKeyType```, the type named by ```X::public_key_type```
* ```SignatureType```, the type named by ```X::signature_type```
* ```InputBlockType```, the type named by ```X::input_block_type```
* ```InputValueType```, the type named by ```X::input_value_type```


|Expression                   |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::scheme_type```         |```SchemeType```        |```SchemeType``` type satisfies ```PubKey``` concept|
|```X::private_key_type```         |```PrivateKeyType```        |```PrivateKeyType``` type is a low-level representation of a private key object|
|```X::public_key_type```         |```PublicKeyType```        |```PublicKeyType```  type is a low-level representation of a public key object|
|```X::signature_key_type```         |```SignatureKeyType```        |```SignatureKeyType``` is type of signature object returned by signing function and taken by verification function|
|```X::input_block_type```          |```InputBlockType```         |```InputBlockType``` type is a ```SequenceContainer``` of type ```T``` or ```std::vector<T>```|
|```X::input_value_type```           |```InputValueType```          |```InputValueType``` type satisfies ```Integral``` concept|


The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::input_value_bits```  |```std::size_t```|```Integral``` bits amount in ```InputValueType```|
|```X::input_block_bits``` |```std::size_t```|```Integral``` bits amount in ```InputBlockType```|


The following expressions must be valid and have their specified effects
Given
* ```BlockType```, the type satisfies ```SequenceContainer``` concept for which ```BlockType::value_type``` is of type ```X::input_value_type```


|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X(X::public_key_type)```|Constructs stateful ```PublicKey``` object with input key of ```public_key_type```|```PublicKey```|
|```X.verify(BlockType)```|Verify a block of data in decoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```PublicKey``` object inner state of ```public_key_type``` type.|```PublicKey::signature_type```|
|```X.encrypt(BlockType)```|Encrypts a block of data in encoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```PublicKey``` object inner state of ```public_key_type``` type.|```BlockType```|

## Private key Concept ## {#private_key_concept}
A ```PrivateKey``` is function object performing operations with private key. For example: signing, decryption.

### Requirements ### {#private_key_concepts_requirements}

The type ```X``` satisfies ``` PrivateKey``` if:

* The type ```X``` satisfies ```PublicKey```

Given

* ```SchemeType```, the type named by ```X::scheme_type``` 
* ```PrivateKeyType```, the type named by ```X::private_key_type``` 
* ```PublicKeyType```, the type named by ```X::public_key_type``` 
* ```SignatureType```, the type named by ```X::signature_type``` 
* ```InputBlockType```, the type named by ```X::input_block_type``` 
* ```InputValueType```, the type named by ```X::input_value_type``` 

|Expression                   |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::scheme_type```         |```SchemeType```        |```SchemeType``` type satisfies ```PubKey``` concept|
|```X::private_key_type```         |```PrivateKeyType```        |```PrivateKeyType``` type is a low-level representation of a private key object.|
|```X::public_key_type```         |```PublicKeyType```        |```PublicKeyType```  type is a low-level representation of a public key object.|
|```X::signature_key_type```         |```SignatureKeyType```        |```SignatureKeyType``` is type of signature object returned by signing function and taken by verification function.|
|```X::input_block_type```          |```InputBlockType```         |```InputBlockType``` type is a ```SequenceContainer``` of type ```T``` or ```std::vector<T>```|
|```X::input_value_type```           |```InputValueType```          |```InputValueType``` type satisfies ```Integral``` concept|


The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::input_value_bits```  |```std::size_t```|```Integral``` bits amount in ```InputValueType```|
|```X::input_block_bits``` |```std::size_t```|```Integral``` bits amount in ```InputBlockType```|


The following expressions must be valid and have their specified effects
 Given
 * ```BlockType```, the type satisfies ```SequenceContainer``` concept for which ```BlockType::value_type``` is of type ```X::input_value_type```


|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X(X::private_key_type)```|Constructs stateful ```PrivateKey``` object with input key of ```private_key_type```|```PrivateKey```|
|```X.sign(BlockType)```|Sign a block of data in decoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```PrivateKey``` object inner state of ```private_key_type``` type.|```X::signature_type```|
|```X.decrypt(BlockType)```|Decrypts a block of data in encoded format specified for particular algorithm. A block can be of a variable size. Should be a non-mutating function depending only on a ```PrivateKey``` object inner state of ```private_key_type``` type.|```BlockType```|

## No-key Concept ## {#non_key_concept}
A ```NoKey``` is function object performing operations without using of any key. For example: aggregate.

### Requirements ### {#non_key_concepts_requirements}

The type ```X``` satisfies ``` NoKey``` if:

Given

* ```SchemeType```, the type named by ```X::scheme_type``` 
* ```PrivateKeyType```, the type named by ```X::private_key_type``` 
* ```PublicKeyType```, the type named by ```X::public_key_type``` 
* ```SignatureType```, the type named by ```X::signature_type``` 
* ```InputBlockType```, the type named by ```X::input_block_type``` 
* ```InputValueType```, the type named by ```X::input_value_type``` 


|Expression                   |Type                    |Requirements and Notes |
|-----------------------------|------------------------|-----------------------|
|```X::scheme_type```         |```SchemeType```        |```SchemeType``` type satisfies ```Pubkey``` concept|
|```X::private_key_type```         |```PrivateKeyType```        |```PrivateKeyType``` type is a low-level representation of a private key object|
|```X::public_key_type```         |```PublicKeyType```        |```PublicKeyType```  type is a low-level representation of a public key object|
|```X::signature_key_type```         |```SignatureKeyType```        |```SignatureKeyType``` is type of signature object returned by signing function and taken by aggregation function|
|```X::input_block_type```          |```InputBlockType```         |```InputBlockType``` type is a ```SequenceContainer``` of type ```T``` or ```std::vector<T>```|
|```X::input_value_type```           |```InputValueType```          |```InputValueType``` type satisfies ```Integral``` concept|


The following static data member definitions must be valid and have their specified effects

|Expression          |Type             |Requirements and Notes                 |
|--------------------|-----------------|---------------------------------------|
|```X::input_value_bits```  |```std::size_t```|```Integral``` bits amount in ```InputValueType```|
|```X::input_block_bits``` |```std::size_t```|```Integral``` bits amount in ```InputBlockType```|

The following expressions must be valid and have their specified effects
Given
 * ```BlockType```, the type satisfies ```SequenceContainer``` concept for which ```BlockType::value_type``` is of type ```X::input_value_type```

|Expression                 |Requirements      |Return Type                    |
|---------------------------|------------------|-------------------------------|
|```X::aggregate(BlockType)```|Aggregate a block of signatures in decoded format specified for particular algorithm. A block can be of a variable size.|```X::signature_type```|

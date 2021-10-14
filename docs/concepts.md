# Concepts {#pubkey_concepts}

@tableofcontents

## Public key scheme concept ## {#pubkey_concept}

A `PublicKeyScheme` is a stateless asymmetric crypto-scheme policy.

### Requirements ### {#pubkey_concepts_requirements}

The type `X` satisfies `PublicKeyScheme` if at least there exist partial specializations of the templates `public_key<X>` and `private_key<X>` satisfying to the concepts `PublicKey` and `PrivateKey` accordingly.

## Signature public key scheme concept ## {#pubkey_concept}

A `SignaturePublicKeyScheme` is a stateless asymmetric crypto-scheme policy supporting algorithms of signature creation and verification.

### Requirements ### {#pubkey_concepts_requirements}

The type `X` satisfies `SignaturePublicKeyScheme` if it satisfies to the concept `PublicKeyScheme` and at least there exist partial specializations of the templates `public_key<X>` and `private_key<X>` satisfying to the concepts `VerificationPublicKey` and `SigningPrivateKey` accordingly.

## Encryption public key scheme concept ## {#pubkey_concept}

An `EncryptionPublicKeyScheme` is a stateless asymmetric crypto-scheme policy supporting asymmetric encryption and decryption algorithms.

### Requirements ### {#pubkey_concepts_requirements}

The type `X` satisfies `EncryptionPublicKeyScheme` if it satisfies to the concept `PublicKeyScheme` and at least there exist partial specializations of the templates `public_key<X>` and `private_key<X>` satisfying to the concepts `EncryptionPublicKey` and `DecryptionPrivateKey` accordingly.

## Public key concept ## {#pubkey_concept}

A `PublicKey` is a concept of a stateful object containing cryptographic material of public key and defining methods to execute cryptographic algorithms, of some asymmetric crypto-scheme, assuming the use of the public key (for example, signature verification or message encryption).

Implementation of concept `PublicKey` for some asymmetric crypto-scheme policy `Scheme` is assumed to be done by defining partial specialization of template `public_key<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `PublicKey` concept then following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `PublicKeyScheme` concept|
|`X::key_type`|type of internal representation of a public key material|
|`X::internal_accumulator_type`|Type of object intended for accumulation of input message and performing any needed preparation of input data like padding, hashing or encoding|

#### Other requirements

Given

* `x` object of type `X`
* `k` object of type `X::key_type`
* `acc` lvalue of type `X::internal_accumulator_type`
* `r` object of the type satisfying [`SequenceContainer`](https://en.cppreference.com/w/cpp/named_req/SequenceContainer)concept
* `i`, `j` objects of the type satisfying [`LegacyInputIterator`](https://en.cppreference.com/w/cpp/named_req/InputIterator) concept
* `s` object of type `X::signature_type`

|Expression|Return type|Effects|
|---|---|---|
|`X(k)`|`X`|Constructs stateful `PublicKey` object with input public key material `k`|
|`x.init_accumulator(acc)`| |Initialize accumulator `acc`. The method is supposed to be called before call to method `update`|
|`x.update(acc, r)`| |Accumulate input message in `acc` to process it later by executing algorithms supported by `Scheme`|
|`x.update(acc, i, j)`| |Accumulate input message in `acc` to process it later by executing algorithms supported by `Scheme`|

## Signature verification public key concept ## {#pubkey_concept}

A `VerificationPublicKey` is a concept of a stateful object containing cryptographic material of public key and defining methods to execute cryptographic algorithms of particular asymmetric signature crypto-scheme.

Implementation of concept `VerificationPublicKey` for some asymmetric signature crypto-scheme policy `Scheme` is assumed to be done by defining partial specialization of template `public_key<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `VerificationPublicKey` concept then it satisfies to `PublicKey` and following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `SignaturePublicKeyScheme` concept|
|`X::signature_type`|type representing signature of used `Scheme`|

#### Other requirements

Given

* `x` object of type `X`
* `acc` lvalue of type `X::internal_accumulator_type`
* `s` object of type `X::signature_type`

|Expression|Return type|Effects|
|---|---|---|
|`x.verify(acc, s)`|`bool`|Extract accumulator `acc` and process verification using extracted data, input signature `s` and public key material stored in `x`|

## Encryption public key concept ## {#pubkey_concept}

A `EncryptionPublicKey` is a concept of a stateful object containing cryptographic material of public key and defining methods to execute cryptographic algorithms, of particular asymmetric encryption crypto-scheme, assuming the use of the private key.

Implementation of concept `EncryptionPublicKey` for some asymmetric encryption crypto-scheme policy `Scheme` is assumed to be done by defining partial specialization of template `public_key<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `EncryptionPublicKey` concept then it satisfies to `PublicKey` and following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `EncryptionPublicKeyScheme` concept|
|`X::cipher_text_type`|type representing cipher-text of used `Scheme`|

#### Other requirements

Given

* `x` object of type `X`
* `acc` lvalue of type `X::internal_accumulator_type`
* `s` object of type `X::signature_type`

|Expression|Return type|Effects|
|---|---|---|
|`x.encrypt(acc)`|`X::cipher_text_type`|Extract accumulator `acc` and process encryption algorithm using extracted data and public key material stored in `x`|

## Private key concept ## {#pubkey_concept}

A `PrivateKey` is a concept of a stateful object containing cryptographic material of private key and defining methods to execute cryptographic algorithms, of particular asymmetric crypto-scheme, assuming the use of the private key (for example, signature creation or message decryption).

Implementation of concept `PrivateKey` for some asymmetric crypto-scheme policy `Scheme` is assumed to be done by defining partial specialization of template `private_key<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `PrivateKey` concept then following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `PublicKeyScheme` concept|
|`X::key_type`|type of internal representation of a private key material|
|`X::internal_accumulator_type`|Type of object intended for accumulation of input message and possibly performing any needed preparation of input data like padding, hashing or encoding|

#### Other requirements

Given

* `x` object of type `X`
* `k` object of type `X::key_type`
* `acc` lvalue of type `X::internal_accumulator_type`
* `r` object of the type satisfying [`SequenceContainer`](https://en.cppreference.com/w/cpp/named_req/SequenceContainer) concept
* `i`, `j` objects of the type satisfying [`LegacyInputIterator`](https://en.cppreference.com/w/cpp/named_req/InputIterator) concept

|Expression|Return type|Effects|
|---|---|---|
|`X(k)`|`X`|Constructs stateful `PrivateKey` object with input private key material `k`|
|`x.init_accumulator(acc)`| |Initialize accumulator `acc`. The method is supposed to be called before call to method `update`|
|`x.update(acc, r)`| |Accumulate input message in `acc` to process it later by executing algorithms supported by `Scheme`|
|`x.update(acc, i, j)`| |Accumulate input message in `acc` to process it later by executing algorithms supported by `Scheme`|

## Signing private key concept ## {#pubkey_concept}

A `SigningPrivateKey` is a concept of a stateful object containing cryptographic material of private key and defining methods to execute cryptographic algorithms, of some asymmetric encryption crypto-scheme, assuming the use of the private key.

Implementation of concept `SigningPrivateKey` for some asymmetric encryption crypto-scheme policy `Scheme` is assumed to be done by defining partial specialization of template `private_key<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `SigningPrivateKey` concept then it satisfies `PrivateKey` concept and following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `SignaturePublicKeyScheme` concept|
|`X::signature_type`|type representing signature of used `Scheme`|

#### Other requirements

Given

* `x` object of type `X`
* `acc` lvalue of type `X::internal_accumulator_type`

|Expression|Return type|Effects|
|---|---|---|
|`x.sign(acc)`|`X::signature_type`| Extract accumulator `acc` and process signing algorithm using extracted data and private key material stored in object`x`|

## Decryption private key concept ## {#pubkey_concept}

A `DecryptionPrivateKey` is a concept of a stateful object containing cryptographic material of private key and defining methods to execute cryptographic algorithms, of some asymmetric encryption crypto-scheme, assuming the use of the private key.

Implementation of concept `DecryptionPrivateKey` for some asymmetric encryption crypto-scheme policy `Scheme` is assumed to be done by defining partial specialization of template `private_key<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `DecryptionPrivateKey` concept then it satisfies `PrivateKey` concept and following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `EncryptionPublicKeyScheme` concept|
|`X::plain_text_type`|type representing plain-text (decryption result) of used `Scheme`|

#### Other requirements

Given

* `x` object of type `X`
* `acc` lvalue of type `X::internal_accumulator_type`

|Expression|Return type|Effects|
|---|---|---|
|`x.decrypt(acc)`|`X::plain_text_type`|Extract accumulator `acc` and process decryption algorithm using extracted data and private key material stored in object `x`|

## Cryptographic operation concept ## {#pubkey_concept}

A `PublicKeyOperation` is a concept of a stateless policy defining methods to execute an algorithm, supported by some asymmetric crypto-scheme, not assuming the use of a single cryptographic key (for example, [the BLS scheme aggregation algorithm](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/)).

Implementation of concept `PublicKeyOperation` for some asymmetric crypto-scheme policy `Scheme` is assumed to be done by declaration of template named like `algorithm_name_op` and defining partial specialization of this template `algorithm_name_op<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `PublicKeyOperation` concept then following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `PublicKeyScheme` concept|
|`X::internal_accumulator_type`|Type of object intended for accumulation of input message and possibly performing any needed preparation of input data like padding, hashing or encoding|
|`X::result_type`|type of algorithm result|

#### Other requirements

Given

* `acc` lvalue of type `X::internal_accumulator_type`
* `r` object of the type satisfying [`SequenceContainer`](https://en.cppreference.com/w/cpp/named_req/SequenceContainer) concept
* `i`, `j` objects of the type satisfying [`LegacyInputIterator`](https://en.cppreference.com/w/cpp/named_req/InputIterator) concept

|Expression|Return type|Effects|
|---|---|---|
|`X::init_accumulator(acc)`| |Initialize accumulator `acc`. The method is supposed to be called before call to method `update`|
|`X::update(acc, r)`| |Accumulate input data in `acc` to process it later by executing algorithms supported by `Scheme`|
|`X::update(acc, i, j)`| |Accumulate input data in `acc` to process it later by executing algorithms supported by `Scheme`|
|`X::process(acc)`|Extract accumulator `acc` and process algorithm using extracted data|


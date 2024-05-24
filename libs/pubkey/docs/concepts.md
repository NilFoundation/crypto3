# Concepts {#pubkey_concepts}

@tableofcontents

## Public key scheme concept ## {#pubkey_scheme_concept}

A `PublicKeyScheme` is a stateless asymmetric crypto-scheme policy.

### Requirements ### {#pubkey_scheme_concept_requirements}

The type `X` satisfies `PublicKeyScheme` if at least there exist partial specializations of the templates `public_key<X>` and `private_key<X>` satisfying to the concepts `PublicKey` and `PrivateKey` accordingly.

## Signature public key scheme concept ## {#signature_pubkey_concept}

A `SignaturePublicKeyScheme` is a stateless asymmetric crypto-scheme policy supporting algorithms of signature creation and verification.

### Requirements ### {#signature_pubkey_concepts_requirements}

The type `X` satisfies `SignaturePublicKeyScheme` if it satisfies to the concept `PublicKeyScheme` and at least there exist partial specializations of the templates `public_key<X>` and `private_key<X>` satisfying to the concepts `VerificationPublicKey` and `SigningPrivateKey` accordingly.

## Encryption public key scheme concept ## {#encryption_pubkey_concept}

An `EncryptionPublicKeyScheme` is a stateless asymmetric crypto-scheme policy supporting asymmetric encryption and decryption algorithms.

### Requirements ### {#encryption_pubkey_concepts_requirements}

The type `X` satisfies `EncryptionPublicKeyScheme` if it satisfies to the concept `PublicKeyScheme` and at least there exist partial specializations of the templates `public_key<X>` and `private_key<X>` satisfying to the concepts `EncryptionPublicKey` and `DecryptionPrivateKey` accordingly.

## Secret sharing scheme concept ## {#secret_sharing_pubkey_concept}

An `SecretSharingScheme` is a stateless secret sharing crypto-scheme policy.

### Requirements ### {#secret_sharing_pubkey_concepts_requirements}

The type `X` satisfies `SecretSharingScheme` if at least there exist partial specializations of the templates `deal_shares_op<X>` satisfying to the concepts `PublicKeyOperation`, `share_sss<Scheme>` satisfying to the concepts `Share`, `public_share_sss<Scheme>` satisfying to the concepts `PublicShare`, `secret_sss<Scheme>` satisfying to the concepts `Secret` and following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::coeff_type`|type of polynomial coefficients|
|`X::public_coeff_type`|type of public representatives of polynomial coefficients|

## Weighted secret sharing scheme concept ## {#wsss_pubkey_concept}

An `WeightedSecretSharingScheme` is a stateless secret sharing crypto-scheme policy.

### Requirements ### {#wsss_pubkey_concepts_requirements}

The type `X` satisfies `WeightedSecretSharingScheme` if at least there exist partial specializations of the templates `deal_shares_op<X>` satisfying to the concepts `PublicKeyOperation`, `share_sss<Scheme>` satisfying to the concepts `WeightedShare`, `public_share_sss<Scheme>` satisfying to the concepts `WeightedPublicShare`, `secret_sss<Scheme>` satisfying to the concepts `Secret`.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::coeff_type`|type of polynomial coefficients|
|`X::public_coeff_type`|type of public representatives of polynomial coefficients|
|`X::weights_type`|type for defining weights of participants|

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

## Signature verification public key concept ## {#signature_verification_pubkey_concept}

A `VerificationPublicKey` is a concept of a stateful object containing cryptographic material of public key and defining methods to execute cryptographic algorithms of particular asymmetric signature crypto-scheme.

Implementation of concept `VerificationPublicKey` for some asymmetric signature crypto-scheme policy `Scheme` is assumed to be done by defining partial specialization of template `public_key<Scheme>`.

### Requirements ### {#signature_verification_pubkey_concepts_requirements}

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

## Encryption public key concept ## {#encryption_pubkey_concept}

A `EncryptionPublicKey` is a concept of a stateful object containing cryptographic material of public key and defining methods to execute cryptographic algorithms, of particular asymmetric encryption crypto-scheme, assuming the use of the private key.

Implementation of concept `EncryptionPublicKey` for some asymmetric encryption crypto-scheme policy `Scheme` is assumed to be done by defining partial specialization of template `public_key<Scheme>`.

### Requirements ### {#encryption_pubkey_concepts_requirements}

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

## Share concept ## {#pubkey_concept}

A `Share` is a concept of a stateful object containing cryptographic material of share and defining methods to work with it of some secret sharing scheme.

Implementation of concept `Share` for some secret sharing scheme policy `Scheme` is assumed to be done by defining partial specialization of template `share_sss<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `Share` concept then following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `SecretSharingScheme` concept|
|`X::index_type`|integral type for index representation of particular share|
|`X::value_type`|type of share material stored in the object|
|`X::data_type`|type of data stored in the object, contains all of the data stored in the object|

#### Other requirements

|Expression|Return type|Effects|
|---|---|---|
|`x.get_index()`|`X::index_type`|return share index|
|`x.get_value()`|`const X::value_type &`|return share value|
|`x.get_data()`|`const X::data_type &`|return raw data stored in the `x`|
|`static_cast<public_share<typename X::scheme_type>>(x)`|`public_share<typename X::scheme_type>`|convert share to public representative|

## Public representative of share concept ## {#pubkey_concept}

A `PublicShare` is a concept of a stateful object containing cryptographic material of public representative of share and defining methods to work with it for some secret sharing scheme.

Implementation of concept `PublicShare` for some secret sharing scheme policy `Scheme` is assumed to be done by defining partial specialization of template `public_share_sss<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `PublicShare` concept then following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `SecretSharingScheme` concept|
|`X::index_type`|integral type for index representation of particular share|
|`X::value_type`|type of share material stored in the object|
|`X::data_type`|type of data stored in the object, contains all of the data stored in the object|

#### Other requirements

|Expression|Return type|Effects|
|---|---|---|
|`x.get_index()`|`X::index_type`|return share index|
|`x.get_value()`|`const X::value_type &`|return share value|
|`x.get_data()`|`const X::data_type &`|return raw data stored in the `x`|

## Weighted share concept ## {#pubkey_concept}

A `WeightedShare` is a concept of a stateful object containing cryptographic material of share and defining methods to work with it of some weighted secret sharing scheme.

Implementation of concept `WeightedShare` for some weighted secret sharing scheme policy `Scheme` is assumed to be done by defining partial specialization of template `share_sss<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `WeightedShare` concept then it satisfies to the `Share` concept and following expressions must be valid and have their specified effects.

|Expression|Return type|Effects|
|---|---|---|
|`x.get_weight()`|`std::size_t`|return participant weight|

## Public representative of weighted share concept ## {#pubkey_concept}

A `WeightedPublicShare` is a concept of a stateful object containing cryptographic material of public representative of share and defining methods to work with it for some weighted secret sharing scheme.

Implementation of concept `WeightedPublicShare` for some weighted secret sharing scheme policy `Scheme` is assumed to be done by defining partial specialization of template `public_share_sss<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `WeightedPublicShare` concept then it satisfies `PublicShare` concept following expressions must be valid and have their specified effects.

|Expression|Return type|Effects|
|---|---|---|
|`x.get_weight()`|`std::size_t`|return participant weight|

## Secret concept ## {#pubkey_concept}

A `Secret` is a concept of a stateful object containing cryptographic material of secret and defining methods to work with it for some secret sharing scheme.

Implementation of concept `Secret` for some secret sharing scheme policy `Scheme` is assumed to be done by defining partial specialization of template `secret_sss<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `Secret` concept then following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `SecretSharingScheme` concept|
|`X::value_type`|type of secret material stored in the object|

#### Other requirements

|Expression|Return type|Effects|
|---|---|---|
|`x.get_value()`|`const X::value_type &`|return share value|
|`static_cast<public_secret<typename X::scheme_type>>(x)`|`public_secret<typename X::scheme_type>`|convert share to public representative|

## Public representative of secret concept ## {#pubkey_concept}

A `PublicSecret` is a concept of a stateful object containing cryptographic material of public representative of secret and defining methods to work with it for some secret sharing scheme.

Implementation of concept `PublicSecret` for some secret sharing scheme policy `Scheme` is assumed to be done by defining partial specialization of template `public_secret_sss<Scheme>`.

### Requirements ### {#pubkey_concepts_requirements}

If the type `X` satisfies `PublicSecret` concept then following expressions must be valid and have their specified effects.

#### Member types

|Expression|Requirements and Notes|
|---|---|
|`X::scheme_type`|type satisfying `SecretSharingScheme` concept|
|`X::value_type`|type of public representative of secret material stored in the object|

#### Other requirements

|Expression|Return type|Effects|
|---|---|---|
|`x.get_value()`|`const X::value_type &`|return share value|


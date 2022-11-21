# Implementation {#pubkey_impl}

@tableofcontents

Pubkey is responsible for asymmetric cryptography. It implements public key signature and encryption schemes and secret sharing schemes.

Asymmetric schemes usage is split to three stages:

1. Initialization. Implicit stage with creation of accumulator to be used.
2. Accumulation. Performed one or more times. Calling update several times is equivalent to calling it once with all the arguments concatenated. Particularly, during this phase the message for the following signing or encryption is supplied.
3. Finalization. Accumulated data is required to be finalized, padded and prepared to be retrieved by user.

## Architecture Overview {#pubkey_arch}

Pubkey library architecture consists of several parts listed below:

1. Algorithms
2. Asymmetric schemes policies
3. Cryptographic material objects (keys, shares)
4. Cryptographic operation policies (aggregation, aggregate verification, shares dealing etc.)
5. Accumulators (signing, verification, aggregation and other accumulators)
6. Processing Modes (isomorphic, threshold)

The execution of any asymmetric operation (signing, verification, aggregation etc.) go through the following steps:

@dot digraph hash_arch {
bgcolor="#151515"
rankdir="TB"

node [shape="box"]

a [label="Algorithm" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica"]; 
b [label="Accumulator" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica"]; 
c [label="Processing Mode" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica"]; 
d [label="Scheme Policies" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica"];

a -> b; b -> c; c -> d;

} 
@enddot

Detailed descriptions of each step and architecture parts are presented below.

## Algorithms {#pubkey_algorithms}

Implementation of a library is considered to be highly compliant with STL. So the crucial point is to have pubkey to be usable in the same way as STL algorithms do.

STL algorithms library mostly consists of generic iterator and since C++20 range-based algorithms over generic concept-compliant types. Great example is`std::transform` algorithm:

```cpp
template<typename InputIterator, typename OutputIterator, typename UnaryOperation>
OutputIterator transform(InputIterator first, InputIterator last, OutputIterator out, UnaryOperation unary_op);
```

Input values of type `InputIterator` operate over any iterable range, no matter which particular type is supposed to be processed. While `OutputIterator` provides a type-independent output place for the algorithm to put results no matter which particular range this `OutputIterator`represents.

Since C++20 this algorithm got it analogous inside Ranges library as follows:

```cpp
template<typename InputRange, typename OutputRange, typename UnaryOperation>
OutputRange transform(InputRange rng, OutputRange out, UnaryOperation unary_op);
```

This particular modification takes no difference if `InputRange` is a `Container` or something else. The algorithm is generic just as data representation types are.

As much as such algorithms are implemented as generic ones, pubkey algorithms should follow that too, for example:

```cpp
template<typename Scheme, typename InputIterator, typename OutputIterator, typename ProcessingMode>
OutputIterator sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key, OutputIterator out);
```

 * `Scheme` is a policy type which represents the particular asymmetric scheme will be used.
 * `InputIterator` represents the input data coming to be hashed.
 * `OutputIterator` is exactly the same as it was in `std::transform` algorithm - it handles all the output storage operations.
 * `ProcessingMode` is a policy representing a work mode of the scheme, by default isomorphic, which means execute a signing operation as in specification, another example is threshold mode.

The most obvious difference between `std::transform` is a representation of a scheme and mode policies defining the particular behavior of an algorithm.

Analogous interface function template is supposed to work with already pre-initialized accumulator:

```cpp
template<typename Scheme, typename InputIterator, typename ProcessingMode, typename OutputAccumulator>
typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                        OutputAccumulator>::type &
sign(InputIterator first, InputIterator last, OutputAccumulator &acc);
```

`OutputAccumulator` is a pre-initialized accumulator set.

Such interface is not the case when working with `std::transform` as it does not work with the accumulator concept. Passed message is used to update state of passed accumulator `acc`. Such call of `sign` doesn't complete signing algorithm. To retrieve resulted signature accumulator should be finalized, i.e. in the case of accumulator concept it should be extracted.

Another possible interface doesn't accept `OutputIterator` accumulator parameter:

```cpp
template<typename Scheme, typename InputIterator, typename ProcessingMode, typename SigningAccumulator,
        typename StreamSchemeImpl, typename SchemeImpl>
SchemeImpl sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key);
```

Such call return object of internal type (`range_pubkey_impl` or `itr_pubkey_impl`) which is implicitly convertible to accumulator set type, pre-initialized with input data of `InputIterator` type, or to `ProcessingMode::result_type`, which represents result of algorithm execution.

Algorithms are no more than an internal structures initializer wrapper. In this particular case algorithm would initialize accumulator set with accumulator we [`need` ](@ref accumulators::pubkey) inside initialized with `key` and in several cases with other parameters.

Brief survey of available algorithms of pubkey library is presented below.

### Pubkey Algorithms ## {#pubkey_algorithms}

The pubkey algorithm is as follows:

#### sign.hpp

The algorithm is responsible for creating a signature.

The function template `sign` takes as input parameters - a message to be signed, a private key for signing and other possible parameters depending on particular function overloading (for example, an iterator to output the signature). Once executed, the function's result is a signed message.

The supplied private key should be of type `private_key<Scheme>`, so specialization of `private_key` template for intended `Scheme` should be defined (details about `private_key` see below).

The resulted signature is of type `private_key<Scheme>::signature_type` (equivalently `ProcessingMode::result_type`).

#### verify.hpp

The algorithm is responsible for verifying signatures.

Verify is a validation algorithm that outputs true if the signature is a valid for the supplied public key, message and signature, and false otherwise.

The supplied public key should be of type `public_key<Scheme>`, so specialization of `public_key` template for intended `Scheme` should be defined (details about `public_key` see below).

The signature should be supplied in the correct form, namely defined as `public_key<Scheme>::signature_type` (equivalently `ProcessingMode::result_type`).

#### aggregate.hpp

The algorithm for a given list of signatures created for a some list of messages on some private keys generates one aggregated signature that authenticates the same list of messages on the corresponding public keys. Example of such algorithm see [here](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

All signatures should be of type `public_key<Scheme>::signature_type` (equivalently `ProcessingMode::result_type`). Resulted signature is of the same type.

#### aggregate_verify.hpp

The algorithm verifies aggregated signature, created for a given list of messages, using a corresponding list of public key. Example of such algorithm see [here](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

The signature should be of the type `public_key<Scheme>::signature_type` (equivalently `ProcessingMode::result_type`).

#### aggregate_verify_single_msg.hpp

The optimized version of aggregate verification algorithm which should be used if aggregated signatures were created for the same message on the all keys. Example of such algorithm see [here](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

#### deal_shares.hpp

The algorithm deals shares according to the specification of chosen secret sharing scheme `Scheme`. Example of such scheme is Shamir secret sharing scheme.

It accepts range of polynomial coefficients and other parameters like threshold number and number of participants. Coefficients in range are assumed to be of type `Scheme::coeff_type`. The algorithm return vector of dealt shares of type `share_sss<Scheme>`.

#### verify_share.hpp

The algorithm verifies share according to the specification of chosen secret sharing scheme `Scheme`. Example of secret sharing scheme supporting verification of dealt share is Feldman scheme.

It accepts range of public representatives of polynomial coefficients which were used to deal shares and verified share of the type `share_sss<Scheme>`. Public representatives are assumed to be of the type `Scheme::public_coeff_type`. 

#### reconstruct_secret.hpp

The algorithm reconstructs secret value from the participant shares according to the specification of chosen secret sharing scheme `Scheme`.

It accepts range of participant shares of the type `share_sss<Scheme>` and return secret value of the type `secret_sss<Scheme>`. To reconstruct secret correctly number of shares in the input range should be greater or equal to the threshold number specified during shares dealing.

#### reconstruct_public_secret.hpp

The algorithm reconstructs public representative of the secret value from the public representatives of participant shares according to the specification of chosen secret sharing scheme `Scheme`.

It accepts range of public representatives of participant shares of the type `public_share_sss<Scheme>` and return public representative of the secret value of the type `public_secret_sss<Scheme>`. To reconstruct public representative of the secret correctly number of public representatives of participant shares in the input range should be greater or equal to the threshold number specified during shares dealing.

#### deal_share.hpp

The algorithm deals share according to the specification of chosen distributed key generation (DKG) scheme `Scheme`. Example of such scheme is Pedersen distributed key generation protocol.

It accepts range of shares of the type `share_sss<Scheme>` dealt by other participant for current part and return its share of the same type. Except that range it accepts number of participants participating in the protocol execution. 

## Pubkey Policies {#pubkey_policies}

Pubkey policies architecturally are completely stateless. Pubkey policies are required to be compliant with [`PublicKeyScheme` concept](@ref pubkey_concept). Thus, a policy has to contain all the data corresponding to the `PublicKeyScheme` and defined in the [`PublicKeyScheme` concept](@ref pubkey_concept). Particular asymmetric crypto-scheme could support different set of algorithms, so it also should satisfy to the specific concept like `SignaturePublicKeyScheme`, `EncryptionPublicKeyScheme` or `SecretSharingScheme`.

## Objects, containing cryptographic material {#pubkey_objects}

Execution of asymmetric algorithms requires the use of cryptographic material like keys in the cases of signature and encryption crypto-schemes, or shares and secrets in the case of performing secret sharing protocols. To work with these objects several templates are defined in pubkey module:

* `private_key` - the template specialization should be defined for a chosen asymmetric crypto-scheme `Scheme`, i.e. `private_key<Scheme>`. The object of that type contains cryptographic material of the private key for a chosen `Scheme` and defines methods to execute crypto algorithms supported by the crypto-scheme using stored key material. Particular specialization of the `private_key` should satisfy to the one or several defined [concepts](@ref pubkey_concept) depending on which algorithms are supported by the chosen `Scheme`. For example, there exist `SigningPrivateKey` concept for asymmetric signature crypto-schemes, and `DecryptionPrivateKey` for asymmetric encryption crypto-schemes.
* `public_key` - the same as for `private_key` template, but regarding public key material for some asymmetric crypto-scheme and algorithms assuming the use of the public key. Examples of public key concepts are `VerificationPublicKey` concept for asymmetric signature crypto-schemes, and `EncryptionPublicKey` for asymmetric encryption crypto-schemes.
* `share_sss` - the template specialization should be defined for a chosen secret sharing `Scheme`, i.e. `share_sss<Scheme>`, and it should satisfy to the `Share` concept.
* `public_share_sss` - the template specialization should be defined for a chosen secret sharing `Scheme`, i.e. `public_share_sss<Scheme>`, and it should satisfy to the `PublicShare` concept.
* `secret_sss` - the template specialization should be defined for a chosen secret sharing `Scheme`, i.e. `secret_sss<Scheme>`, and it should satisfy to the `Secret` concept.
* `public_secret_sss` - the template specialization should be defined for a chosen secret sharing `Scheme`, i.e. `public_secret_sss<Scheme>`, and it should satisfy to the `PublicSecret` concept.

## Cryptographic operation policies {#pubkey_operations}

To execute algorithms supported by some asymmetric crypto-scheme but not requiring the use of single key (private or public) [`PublicKeyOperation` concept](@ref pubkey_concept) was introduced. Example of such operation is aggregation algorithm, which aggregate several signatures created for some list of messages into a single signature that authenticates all the messages, wherein no need to use any key. Secret sharing algorithms are the other examples of operations not requiring the use of a key material.

Following types of operations are defined in pubkey module:

* `aggregate_op`
* `aggregate_verify_op`
* `aggregate_verify_single_msg_op`
* `deal_shares_op`
* `deal_share_op`
* `reconstruct_public_secret_op`
* `reconstruct_secret_op`
* `verify_share_op`

## Accumulators {#pubkey_accumulators}

Execution of any asymmetric crypto-scheme algorithm contains an accumulation step, which is implemented with [Boost.Accumulators](https://boost.org/libs/accumulators) library.

All the concepts are held.

Pubkey contain pre-defined accumulator sets, which are a `boost::accumulator_set` with pre-filled accumulator type depending on executing algorithm.

Pubkey library defines following types of accumulators:
* signing accumulator
* verification accumulator
* aggregation accumulator
* aggregate verification accumulator (also for the verification of a single message)
* shares dealing accumulator
* share verification accumulator
* secret reconstruction accumulator
* share dealing accumulator

Each of the mentioned accumulators contain private field named internal accumulator. That type of accumulator is dedicated to accumulate input data of the executing algorithm and then during extraction it performs all needed preparation of input data like hashing, padding or encoding. Thus, pubkey accumulators play the role of wrapper of internal accumulator, performing more complex logic on the input data. Then during extraction of pubkey accumulator it extracts its internal accumulator and passes extracted data to the finalization function defined in the chosen operation policy or in the key object (`private_key` or `public_key`).

Internal accumulators used in pubkey module could be classified into two classes:
* pkpad accumulators - in that case accumulators defined in the pkpad module are used as internal accumulators. This module is dedicated to preprocessing data before execution of any asymmetric crypto-scheme algorithm. Example of such preprocessing procedure is hasing of input data before its signing by any asymmetric signature crypto-scheme according to the protocol [EMSA1](https://standards.ieee.org/standard/1363-2000.html). 
* crypto-scheme ad-hoc accumulators - in that case some internal type of the chosen asymmetric crypto-scheme policy is used. Every time new portion of input data is passed to the accumulator it is transmitted to the crypto-scheme policy function defined by the particular [concept](@ref pubkey_concept) where it is processed and accumulated. For example, in such manner accumulators of secret sharing schemes works. Such accumulators type exists due to not all pubkey algorithms process simple data of built-in types, like range of integrals. For example, shares dealing algorithm accepts polynomial coefficients which are of the algebraic field element type from algebra module, so additional logic to process such input data should be defined.

Accumulators caching ability depends on the used internal accumulator type and on the executing algorithm. For example, in the case of signature creation algorithm with hashing of input message, lower in the call stack hashing accumulator will be used. Such type of accumulators supports caching of input data, which means there is an input cache sized as same as particular `Hash::block_type`, which accumulates unprocessed data. Another example is secret reconstruction accumulator which should be fully filled with the input shares before execution of reconstruction process as all the indexes of the input shares should be known to the moment of secret reconstruction.


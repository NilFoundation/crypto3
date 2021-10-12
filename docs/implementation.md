# Implementation {#pubkey_impl}

@tableofcontents

Pubkey is responsible for asymmetric cryptography. It implements public key signature and encryption schemes and secret
sharing schemes.

Asymmetric schemes usage is split to three stages:

1. Initialization. Implicit stage with creation of accumulator to be used.
2. Accumulation. Performed one or more times. Calling update several times is equivalent to calling it once with all the
   arguments concatenated. Particularly, during this phase the message for the following signing or encryption is
   supplied.
3. Finalization. Accumulated data is required to be finalized, padded and prepared to be retrieved by user.

## Architecture Overview {#pubkey_arch}

Pubkey library architecture consists of several parts listed below:

1. Algorithms
2. Asymmetric schemes policies
3. Cryptographic material objects (keys, shares)
4. Cryptographic operations policies (aggregation, aggregate verification, shares dealing etc.)
5. Accumulators (signing, verification, aggregation and other accumulators)
6. Processing Modes

The execution of any asymmetric operation (signing, verification, aggregation etc.) go through the following steps:

@dot digraph hash_arch { color="#222222"; rankdir="TB"
node [shape="box"]

a [label="Algorithm"]; b [label="Accumulator"]; c [label="Processing Mode"]; d [label="Scheme Policies"];

a -> b; b -> c; c -> d; } @enddot

Detailed descriptions of each step and architecture parts are presented below.

## Algorithms {#pubkey_algorithms}

Implementation of a library is considered to be highly compliant with STL. So the crucial point is to have pubkey to be
usable in the same way as STL algorithms do.

STL algorithms library mostly consists of generic iterator and since C++20 range-based algorithms over generic
concept-compliant types. Great example is
`std::transform` algorithm:

```cpp
template<typename InputIterator, typename OutputIterator, typename UnaryOperation>
OutputIterator transform(InputIterator first, InputIterator last, OutputIterator out, UnaryOperation unary_op);
```

Input values of type `InputIterator` operate over any iterable range, no matter which particular type is supposed to be
processed. While `OutputIterator` provides a type-independent output place for the algorithm to put results no matter
which particular range this `OutputIterator`
represents.

Since C++20 this algorithm got it analogous inside Ranges library as follows:

```cpp
template<typename InputRange, typename OutputRange, typename UnaryOperation>
OutputRange transform(InputRange rng, OutputRange out, UnaryOperation unary_op);
```

This particular modification takes no difference if `InputRange` is a
`Container` or something else. The algorithm is generic just as data representation types are.

As much as such algorithms are implemented as generic ones, pubkey algorithms should follow that too, for example:

```cpp
template<typename Scheme, typename InputIterator, typename OutputIterator, typename ProcessingMode>
OutputIterator sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key, OutputIterator out);
```

`Scheme` is a policy type which represents the particular asymmetric scheme will be used.
`InputIterator` represents the input data coming to be hashed.
`OutputIterator` is exactly the same as it was in `std::transform` algorithm - it handles all the output storage
operations.
`ProcessingMode` is a policy representing a work mode of the scheme, by default isomorphic, which means execute a
signing operation as in specification, another example is threshold mode.

The most obvious difference between `std::transform` is a representation of a scheme and mode policies defining the
particular behavior of an algorithm.

Analogous interface function template is supposed to work with already pre-initialized accumulator:

```cpp
template<typename Scheme, typename InputIterator, typename ProcessingMode, typename OutputAccumulator>
typename std::enable_if<boost::accumulators::detail::is_accumulator_set<OutputAccumulator>::value,
                        OutputAccumulator>::type &
sign(InputIterator first, InputIterator last, OutputAccumulator &acc);
```

Such interface is not the case when working with `std::transform` as it does not work with the accumulator concept.

`OutputAccumulator` is a pre-initialized accumulator set.

Another possible interface doesn't accept `OutputIterator` accumulator parameter:

```cpp
template<typename Scheme, typename InputIterator, typename ProcessingMode, typename SigningAccumulator,
        typename StreamSchemeImpl, typename SchemeImpl>
SchemeImpl sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key);
```

Such call return object of internal type (`range_pubkey_impl` or `itr_pubkey_impl`) which implicitly convertible to
accumulator set type, pre-initialized with input data of `InputIterator` type, or
to `typename ProcessingMode::result_type`, which represents result of algorithm execution.

Algorithms are no more than an internal structures initializer wrapper. In this particular case algorithm would
initialize accumulator set with accumulator we [`need` ](@ref accumulators::pubkey) inside initialized with `key` and in
several cases with other parameters.

Brief survey of available algorithms of pubkey library is presented below.

## Pubkey Algorithms ## {#pubkey_algorithms}

The pubkey algorithm is as follows:

### sign.hpp

The algorithm is responsible for creating a signature.

The function template `sign` takes as input parameters - a message to be signed, a private key for signing and other
possible parameters depending on particular function overloading (for example, an iterator for output the signature).
Once executed, the function's result is a signed message.

The supplied private key should be of type `private_key<Scheme>`, so specialization of `private_key` template for
intended `Scheme` should be defined (details about `private_key` see below).

The resulted signature is of type `private_key<Scheme>::signature_type` (equivalently `ProcessingMode::result_type`).

### verify.hpp

The algorithm is responsible for verifying signatures.

Verify is a validation algorithm that outputs true if the signature is a valid for the supplied public key, message and
signature, and false otherwise.

The supplied public key should be of type `public_key<Scheme>`, so specialization of `public_key` template for
intended `Scheme` should be defined (details about `public_key` see below).

The signature should be supplied in the correct form, namely defined as `public_key<Scheme>::signature_type`.

### aggregate.hpp

The algorithm for a given list of signatures for a some list of messages and public keys generates one signature that
authenticates the same list of messages and public keys.

All signatures should be of type `public_key<Scheme>::signature_type`.

## Pubkey Policies {#pubkey_policies}

Pubkey policies architecturally are completely stateless. Pubkey policies are required to be compliant
with [`pubkey` concept](@ref pubkey_concept). Thus, a policy has to contain all the data corresponding to the `pubkey`
and defined in the [`pubkey` concept](@ref pubkey_concept).

## Accumulators {#pubkey_accumulators}

Encryption contains an accumulation step, which is implemented with
[Boost.Accumulators](https://boost.org/libs/accumulators) library.

All the concepts are held.

Pubkey contain pre-defined [`block::accumulator_set`](@ref accumulator_set), which is a `boost::accumulator_set` with
pre-filled
[`pubkey` accumulator](@ref accumulators::hash).

Pubkey accumulator can accepts one either `block_type::value_type` or `block_type`
at insert. Verified accumulator can accepts verified signature.

Accumulator is implemented as a caching one. This means there is an input cache sized as same as
particular `Pubkey::block_type`, which accumulates unprocessed data. After it gets `filled`, data gets encrypted, then
it gets moved to the main accumulator storage, then cache gets emptied.

[`pubkey` accumulator](@ref accumulators::hash) internally uses
[`bit_count` accumulator](@ref accumulators::bit_count) and designed to be combined with other accumulators available
for
[Boost.Accumulators](https://boost.org/libs/accumulators).

Example. Let's assume there is an accumulator set, which intention is to encrypt all the incoming data
with [`bls<128, 128>` cipher](@ref block::rijndael)
and to compute a [`sha2<256>` hashes](@ref hashes::sha2) of all the incoming data as well.

This means there will be an accumulator set defined as follows:

```cpp
using namespace boost::accumulators;
using namespace nil::crypto3;

boost::accumulator_set<
    accumulators::block<block::rijndael<128, 128>>,
    accumulators::hashes<hashes::sha2<256>>> acc;
```

Extraction is supposed to be defined as follows:

```cpp
std::string hashes = extract::hash<hashes::sha2<256>>(acc);
std::string ciphertext = extract::block<block::rijndael<128, 128>>(acc);
```


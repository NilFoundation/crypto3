# Implementation {#pubkey_impl}


@tableofcontents

Pubkey is responsible for asymmetric cryptography.
Asymmetric public key encryption is based on the following principles:

1. It is possible to generate a pair of very large numbers (public key and private key) so that knowing the public key, the private key cannot be computed in a reasonable amount of time. Moreover, the generation mechanism is generally known.
2. Strong encryption methods are available to encrypt a message with a public key so that only the private key can decrypt it. The encryption mechanism is well known.
3. The owner of two keys does not disclose the private key to anyone, but transfers the public key to counterparties or makes it publicly known.

## Architecture Overview {#pubkey_arch}

Pubkey library architecture consists of several parts listed below:

1. Algorithms
2. Stream Processors
3. Generating a signature
4. Signature verification
5. Accumulators
6. Aggregation of signatures

@dot digraph hash_arch { color="#222222"; rankdir="TB"
node [shape="box"]

a [label="Algorithms" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref hashes_algorithms"];
b [label="Stream Processors" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref hashes_stream"];
c [label="Data Type Conversion" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref hashes_data"];
d [label="Hash Policies" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref hashes_policies"];
e [label="Constructions and Compressors" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref hashes_constructions_compressors"]
; f [label="Accumulators" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref hashes_accumulators"];
g [label="Value Processors" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref hashes_value"];

a -> b; b -> c; c -> d; d -> e; e -> f; f -> g; } @enddot

## Algorithms {#pubkey_algorithms}

Implementation of a library is considered to be highly compliant with STL. So the crucial point is to have hashes to be
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




Algorithms are no more than an internal structures initializer wrapper. In this particular case algorithm would
initialize stream processor fed with accumulator set with accumulator we [`need` ](@ref accumulators::hash) inside
initialized with `pubkey`.

## Stream Data Processing {#pubkey_stream}

Pubkey are usually defined for processing `Integral` value typed byte 
sequences of specific size packed in blocks (e.g. `rijndael` is defined for 
blocks of words which are actually plain `n`-sized arrays of `uint32_t` ). 
Input data in the implementation proposed is supposed to be a various-length 
input stream, which length could be not even to block size.
  
This requires an introduction of stream processor specified with particular 
parameter set unique for each [`pubkey`](@ref pubkey_concept) type, 
which takes input data stream and gets it split to blocks filled with converted 
to appropriate size integers (words in the cryptography meaning, not machine words).
  
Example. Lets assume input data stream consists of 16 bytes as follows.

@dot
digraph bytes {
bgcolor="#222222";
node [shape=record color="#F5F2F1" fontcolor="#F5F2F1"];

struct1 [label="0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x10 | 0x11 | 0x12 | 0x13
 | 0x14 | 0x15"];
  
}
@enddot

Lets assume the selected cipher to be used is Rijndael with 32 bit word size, 
128 bit block size and 128 bit key size. This means input data stream needs to 
be converted to 32 bit words and merged to 128 bit blocks as follows:
  
@dot
digraph bytes_to_words {
bgcolor="#222222";
node [shape=record color="#F5F2F1" fontcolor="#F5F2F1"];

struct1 [label="<b0> 0x00 |<b1> 0x01 |<b2> 0x02 |<b3> 0x03 |<b4> 0x04 |<b5> 0x05 |<b6> 0x06 |<b7> 0x07 |<b8> 0x08 |<b9> 0x09 |<b10> 0x10 |<b11> 0x11 |<b12> 0x12 |<b13> 0x13 |<b14> 0x14 |<b15> 0x15"];

struct2 [label="<w0> 0x00 0x01 0x02 0x03 |<w1> 0x04 0x05 0x06 0x07 |<w2> 0x08 0x09 0x10 0x11 |<w3> 0x12 0x13 0x14 0x15"];

struct3 [label="<bl0> 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x10 0x11 0x12 0x13 0x14
 0x15"];

struct1:b0 -> struct2:w0
struct1:b1 -> struct2:w0
struct1:b2 -> struct2:w0
struct1:b3 -> struct2:w0

struct1:b4 -> struct2:w1
struct1:b5 -> struct2:w1
struct1:b6 -> struct2:w1
struct1:b7 -> struct2:w1

struct1:b8 -> struct2:w2
struct1:b9 -> struct2:w2
struct1:b10 -> struct2:w2
struct1:b11 -> struct2:w2

struct1:b12 -> struct2:w3
struct1:b13 -> struct2:w3
struct1:b14 -> struct2:w3
struct1:b15 -> struct2:w3

struct2:w0 -> struct3:bl0
struct2:w1 -> struct3:bl0
struct2:w2 -> struct3:bl0
struct2:w3 -> struct3:bl0
}

@enddot

Now with this a [`pubkey`](@ref pubkey_concept) instance of 
[`rijndael`](@ref pubkey:rijndael) can be fed.

This mechanism is handled with `stream_processor` template class specified for 
each particular cipher with parameters required. Pubkey suppose only 
one type of stream processor exist - the one which split the data to blocks, 
converts them and passes to `AccumulatorSet` reference as cipher input of 
format required. The rest of data not even to block size gets converted too and 
fed value by value to the same `AccumulatorSet` reference.

## Data Type Conversion {#pubkey_data}

Since pubkey algorithms are usually defined for `Integral` types or byte sequences of unique format for each hash, its
function being generic requirement should be handled with particular hash-specific input data format converter.

For example `bls`  is defined over blocks of 8 bit words, which could be represented with `uint32_t`. This means
all the input data should be in some way converted to 4 byte sized `Integral` type. In case of
`InputIterator` is defined over some range of `Integral` value type, this is is handled with plain byte repack as shown
in previous section. This is a case with both input stream and required data format are satisfy the same concept.

The more case with input data being presented by sequence of various type `T`
requires for the `T` to has conversion operator `operator Integral()` to the type required by particular `pubkey` policy.

Example. Let us assume the following class is presented:

```cpp
class A {
public:
    std::size_t vals;
    std::uint16_t val16;
    std::char valc;
};
```

Now let us assume there exists an initialized and filled with random values
`SequenceContainer` of value type `A`:

```cpp
std::vector<A> a;
```

To feed the `pubkey` with the data presented, it is required to convert `A` to `Integral` type which is only available
if `A` has conversion operator in some way as follows:

```cpp
class A {
public:
    operator uint128_t() {
        return (vals << (3U * CHAR_BIT)) & (val16 << 16) & valc 
    }

    std::size_t vals;
    std::uint16_t val16;
    std::char valc;
};
``` 

This part is handled internally with `stream_processor` configured for each particular pubkey.

## Pubkey Algorithms ## {#Pubkey_policies}

The pubkey algorithm is as follows:

Sign.hpp is responsible for creating a signature.
```cpp
template<typename Scheme, typename InputIterator, typename OutputIterator>
        OutputIterator sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key,
                            OutputIterator out)
```

The function sign takes as input parameters - a message to be signed, a private key for signing and an iterator for output the message. Once executed, the function's result is a signed message.

Verify.hpp is responsible for verifying signatures.
```cpp
template<typename Scheme, typename InputIterator, typename OutputIterator>
        OutputIterator sign(InputIterator first, InputIterator last, const pubkey::private_key<Scheme> &key,
                            OutputIterator out)
```
Verify is a validation algorithm that outputs true if the signature is a valid public key message signature, and false otherwise.

aggregate
Given a list of signatures for a list of messages and public keys, an aggregation algorithm generates one signature that authenticates the same list of messages and public keys.

```cpp
template<typename Scheme, typename InputIterator, typename OutputIterator>
        typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
              OutputIterator>::type
            aggregate(InputIterator first, InputIterator last, OutputIterator out)
```

## Pubkey Policies {#pubkey_policies}

Pubkey policies architecturally are completely stateless. Pubkey policies are required to be compliant
with [`pubkey` concept](@ref pubkey_concept). Thus, a policy has to contain all the data corresponding to the `pubkey` and
defined in the [`pubkey` concept](@ref pubkey_concept).





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
particular `Pubkey::block_type`, which accumulates unprocessed data. After it gets `filled`, data gets encrypted, then it
gets moved to the main accumulator storage, then cache gets emptied.

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


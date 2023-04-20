# implementation



Hashes usage is usually split into three stages:

1. Initialization. Implicit stage with the creation of accumulator to be used.
2. Accumulation. Performed one or more times. Calling an update several times is equivalent to calling it once with all of the arguments concatenated.
3. Finalization. Accumulated hash data is required to be finalized, padded and prepared to be retrieved by the user.

## Architecture Overview <a href="#hashes_arch" id="hashes_arch"></a>

Hashes library architecture consists of several parts listed below:

1. Algorithms
2. Stream Processors
3. Hash Policies
4. Constructions and Compressors
5. Accumulators
6. Value Processors

@dot digraph hash\_arch { bgcolor="#151515" rankdir="TB" node \[shape="box"]

a \[label="Algorithms" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica" URL="@ref hashes\_algorithms"]; b \[label="Stream Processors" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica" URL="@ref hashes\_stream"]; c \[label="Data Type Conversion" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica" URL="@ref hashes\_data"]; d \[label="Hash Policies" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica" URL="@ref hashes\_policies"]; e \[label="Constructions and Compressors" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica" URL="@ref hashes\_constructions\_compressors"]; f \[label="Accumulators" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica" URL="@ref hashes\_accumulators"]; g \[label="Value Processors" color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica" URL="@ref hashes\_value"];

a -> b; b -> c; c -> d; d -> e; e -> f; f -> g;

} @enddot

## Algorithms <a href="#hashes_algorithms" id="hashes_algorithms"></a>

Implementation of a library is considered to be highly compliant with STL. So the crucial point is to have hashes to be usable in the same way as STL algorithms do.

STL algorithms library mostly consists of generic iterators and since C++20 range-based algorithms over generic concept-compliant types. Great example is `std::transform` algorithm:

```cpp
template<typename InputIterator, typename OutputIterator, typename UnaryOperation>
OutputIterator transform(InputIterator first, InputIterator last, OutputIterator out, UnaryOperation unary_op);
```

Input values of type `InputIterator` operate over any iterable range, no matter which particular type is supposed to be processed. While `OutputIterator` provides a type-independent output place for the algorithm to put results no matter which particular range this `OutputIterator` represents.

Since C++20, this algorithm got it analogous inside the Ranges library as follows:

```cpp
template<typename InputRange, typename OutputRange, typename UnaryOperation>
OutputRange transform(InputRange rng, OutputRange out, UnaryOperation unary_op);
```

This particular modification makes no difference if `InputRange` is a `Container` or something else. The algorithm is generic, just as data representation types are.

As much as such algorithms are implemented as generic ones, hash algorithms should follow that too:

```cpp
template<typename Hash, typename InputIterator, typename OutputIterator>
OutputIterator hash(InputIterator first, InputIterator last, OutputIterator out);
```

`Hash` is a policy type which represents the particular hash that will be used. `InputIterator` represents the input data coming to be hashed. `OutputIterator` It is exactly the same as in `std::transform` algorithm - it handles all the output storage operations.

The most obvious difference between `std::transform` is a representation of a policy defining the particular behaviour of an algorithm. `std::transform` proposes to pass it as a reference to `Functor`, which is also possible in the case of `Hash` the policy used in function already pre-scheduled:

```cpp
template<typename Hash, typename InputIterator, typename OutputIterator>
OutputIterator hash(InputIterator first, InputIterator last, OutputIterator out);
```

Algorithms are no more than an internal structures initializer wrapper. In this particular case, algorithm would initialize a stream processor fed with an accumulator set with \[`hash` accumulator]\(@ref accumulators::hash) inside initialized with `Hash`.

## Stream Data Processing <a href="#hashes_stream" id="hashes_stream"></a>

Hashes are usually defined as processing `Integral` value typed byte sequences of specific size packed in blocks ( e.g. \[`SHA2`]\(@ref hashes::sha2) is defined for blocks of words which are actually plain `n`-sized arrays of `uint32_t` ). Input data in the implementation proposed is supposed to be a various-length input stream, which length could not be even to block size.

This requires the introduction of a stream processor specified with a particular parameter set unique for each \[`Hash`]\(@ref hashes\_concept) type, which takes input data stream and gets it split to blocks filled with converted to appropriate size integers (words in the cryptography meaning, not machine words).

Example. Let's assume the input data stream consists of 16 bytes as follows.

@dot digraph bytes { bgcolor="#151515" node \[shape=record color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica"];

struct1 \[label="0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15"] ;

} @enddot

Let's assume the selected hash to be used is SHA2 with a 32-bit word size and 512-bit block size. This means the input data stream needs to be converted to 32-bit words and merged into 512-bit blocks as follows:

@dot digraph bytes\_to\_words { bgcolor="#151515" node \[shape=record color="#f5f2f1" fontcolor="#f5f2f1" fontname="helvetica"];

struct1 \[label=" 0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x10 | 0x11 | 0x12 | 0x13 | 0x14 | 0x15"] ;

struct2 \[label=" 0x00 0x01 0x02 0x03 | 0x04 0x05 0x06 0x07 | 0x08 0x09 0x10 0x11 | 0x12 0x13 0x14 0x15"] ;

struct3 \[label=" 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x10 0x11 0x12 0x13 0x14 0x15"];

struct1:b0 -> struct2:w0 struct1:b1 -> struct2:w0 struct1:b2 -> struct2:w0 struct1:b3 -> struct2:w0

struct1:b4 -> struct2:w1 struct1:b5 -> struct2:w1 struct1:b6 -> struct2:w1 struct1:b7 -> struct2:w1

struct1:b8 -> struct2:w2 struct1:b9 -> struct2:w2 struct1:b10 -> struct2:w2 struct1:b11 -> struct2:w2

struct1:b12 -> struct2:w3 struct1:b13 -> struct2:w3 struct1:b14 -> struct2:w3 struct1:b15 -> struct2:w3

struct2:w0 -> struct3:bl0 struct2:w1 -> struct3:bl0 struct2:w2 -> struct3:bl0 struct2:w3 -> struct3:bl0 }

@enddot

Now with this a \[`Hash`]\(@ref hashes\_concept) instance of \[`SHA2`]\(@ref hashes::sha2) can be fed.

This mechanism is handled with `stream_processor` template class specified for each particular hash with parameters required. Hashes suppose only one type of stream processor exists - the one which split the data into blocks, converts them, and passes them to `AccumulatorSet` reference as hash input of format required. The rest of the data, not even to block size, gets converted too and fed value by value to the same `AccumulatorSet` reference.

## Data Type Conversion <a href="#hashes_data" id="hashes_data"></a>

Since hash algorithms are usually defined for `Integral` types or byte sequences of unique format for each hash, its function being a generic requirement, should be handled with a particular hash-specific input data format converter.

For example `SHA2` hash is defined over blocks of 32-bit words, which could be represented with `uint32_t`. This means all the input data should be in some way converted to a 4-byte-sized `Integral` type. In case of `InputIterator` is defined over some range of `Integral` value type, this is handled with plain byte repack, as shown in the previous section. This is a case with both the input stream and required data format satisfying the same concept.

The more case with input data being presented by a sequence of various type `T` requires for the `T` to have a conversion operator `operator Integral()` to the type required by particular `Hash` policy.

Example. Let us assume the following class is presented:

```cpp
class A {
public:
    std::size_t vals;
    std::uint16_t val16;
    std::char valc;
};
```

Now let us assume there exists an initialized and filled with random values `SequenceContainer` of value type `A`:

```cpp
std::vector<A> a;
```

To feed the `Hash` with the data presented, it is required to convert `A` to `Integral` the type which is only available if `A` has conversion operator in some way as follows:

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

This part is handled internally with `stream_processor` configured for each particular hash.

## Hash Policies <a href="#hashes_policies" id="hashes_policies"></a>

Hash policies architecturally are completely stateless. Hash policies are required to be compliant with \[`Hash` concept]\(@ref hash\_concept). Thus, a policy has to contain all the data corresponding to the `Hash` and defined in the \[`Hash` concept]\(@ref hash\_concept).

Among other things, a hash policy should contain information about its compressor and construction. For example, for `SHA2` there are Merkle-Damgard Construction and Davies-Meyer compressor.

## Constructions and Compressors <a href="#hashes_constructions_compressors" id="hashes_constructions_compressors"></a>

Constructions and Compressors used by a `Hash` should be defined in its \[`policy`]\(@ref hashes\_policies). Construction defines how the message should be padded if its size is not multiple of `block_bits` and how the hashed message should be finalized. Construction also calls the compressor inside itself while processing a message block.

For example, \[`sha2` hashes]\(@ref hashes::sha2) has Merkle-Damgard construction with default Merkle-Damgard padding and Davies-Meyer compressor. It means each message block is being processed by Davies-Meyer compressor. The last message block is padded before processing using Merkle-Damgard padding. After processing, the last block message is finalised by appending the length of the input message to the end of the result.

## Accumulators <a href="#hashes_accumulators" id="hashes_accumulators"></a>

The Hashing contains an accumulation step, which is implemented with [Boost.Accumulators](https://boost.org/libs/accumulators) library.

All the concepts are held.

Hash contains pre-defined \[`block::accumulator_set`]\(@ref accumulator\_set), which is a `boost::accumulator_set` with pre-filled \[`hash` accumulator]\(@ref accumulators::hash).

Hash accumulator accepts only one either `block_type::value_type` or `block_type` at insert.

Accumulator is implemented as a caching one. This means there is an input cache sized as same as particular `Hash::block_type`, which accumulates unprocessed data. After it gets `filled`, data gets hashed, then it gets moved to the main accumulator storage, and then the cache gets emptied.

\[`hash` accumulator]\(@ref accumulators::hash) internally uses \[`bit_count` accumulator]\(@ref accumulators::bit\_count) and designed to be combined with other accumulators available for [Boost.Accumulators](https://boost.org/libs/accumulators).

Example. Let's assume there is an accumulator set which intention is to encrypt all the incoming data with \[`rijndael<128, 128>` cipher]\(@ref block::rijndael) and to compute a \[`sha2<256>` hashes]\(@ref hashes::sha2) of all the incoming data as well.

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

## Value Postprocessors <a href="#hashes_value" id="hashes_value"></a>

Since the accumulator output type is strictly tied to \[`digest_type`]\(@ref hashes::digest\_type) of particular \[`Hash`]\(@ref hash\_concept) policy, the output format in generic is closely tied to the digest type too. Digest type is usually defined as a fixed or variable length byte array, which is not always the format of the container or ranges the user likes to store the output in. It could easily be a `std::vector<uint32_t>` or a `std::string`, so there is a \[`hash_value`]\(@ref hash\_value) state holder, which is made to be implicitly convertible to various container and range types with internal data repacking implemented.

Such a state holder is split into a couple of types:

1. Value holder. Intended to have an internal output data storage. Actually stores the `AccumulatorSet` digest data.
2. Reference holder. Intended to store a reference to external `AccumulatorSet`, which is usable in case of data gets appended to the existing accumulator.

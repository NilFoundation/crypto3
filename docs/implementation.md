# Implementation {#modes_impl}

@tableofcontents

Cipher modes usage is usually split to three stages:

1. Initialization. Implicit stage with creation of accumulator to be used.
2. Accumulation. Performed one or more times. Calling update several times is 
equivalent to calling it once with all of the arguments concatenated.
3. Finalization. Accumulated hash data is required to be finalized, padded and 
prepared to be retrieved by user.  

## Architecture Overview {#modes_arch}

Hashes library architecture consists of several parts listed below:

1. Algorithms
2. Stream Processors
3. Constructions and Compressors
4. Accumulators
5. Value Processors

@dot
digraph modes_arch {
color="#222222";
rankdir="TB"
node [shape="box"]

  a [label="Algorithms" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref modes_algorithms"];
  b [label="Stream Processors" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref modes_stream"];
  c [label="Constructions and Compressors" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref modes_pol"];
  d [label="Accumulators" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref modes_acc"];
  e [label="Value Processors" color="#F5F2F1" fontcolor="#F5F2F1" URL="@ref modes_val"];
  
  a -> b;
  b -> c;
  c -> d;
  d -> e;
}
@enddot

## Algorithms {#modes_algorithms}

Implementation of a library is considered to be highly
compliant with STL. So the crucial point is to have
ciphers to be usable in the same way as STL algorithms
do.

STL algorithms library mostly consists of generic iterator and since C++20 
range-based algorithms over generic concept-compliant types. Great example is 
`std::transform` algorithm:
 
```cpp
template<typename InputIterator, typename OutputIterator, typename UnaryOperation>
OutputIterator transform(InputIterator first, InputIterator last, OutputIterator out, UnaryOperation unary_op);
```

Input values of type `InputIterator` operate over any iterable range, no matter 
which particular type is supposed to be processed. 
While `OutputIterator` provides a type-independent output place for the 
algorithm to put results no matter which particular range this `OutputIterator` 
represents.
 
Since C++20 this algorithm got it analogous inside Ranges library as follows:
 
```cpp
template<typename InputRange, typename OutputRange, typename UnaryOperation>
OutputRange transform(InputRange rng, OutputRange out, UnaryOperation unary_op);
```

This particular modification takes no difference if `InputRange` is a 
`Container` or something else. The algorithm is generic just as data 
representation types are.
 
As much as such algorithms are implemented as generic ones, hash algorithms 
should follow that too:
 
```cpp
template<typename Hash, typename InputIterator, typename OutputIterator>
OutputIterator hash(InputIterator first, InputIterator last, OutputIterator out);
```

`Hash` is a policy type which represents the particular hash will be used.
`InputIterator` represents the input data coming to be hashed.
`OutputIterator` is exactly the same as it was in `std::transform` algorithm - 
it handles all the output storage operations.
 
The most obvious difference between `std::transform` is a representation of a 
policy defining the particular behaviour of an algorithm. `std::transform` 
proposes to pass it as a reference to `Functor`, which is also possible in case 
of `Hash` policy used in function already pre-scheduled:
   
```cpp
template<typename Hash, typename InputIterator, typename OutputIterator>
OutputIterator hash(InputIterator first, InputIterator last, OutputIterator out);
```

Algorithms are no more than an internal structures initializer wrapper. In this 
particular case algorithm would initialize stream processor fed with accumulator 
set with [`hash` accumulator](@ref accumulators::hash) inside initialized with `Hash`.

## Stream Data Processing {#modes_stream}

Hashes are usually defined for processing `Integral` value typed byte sequences 
of specific size packed in blocks (e.g. [sha2](@ref nil::crypto3::hashes::sha2) is defined for 
blocks of words which are actually plain `n`-sized arrays of `uint32_t` ). 
Input data in the implementation proposed is supposed to be a various-length 
input stream, which length could be not even to block size.
  
This requires an introduction of stream processor specified with particular 
parameter set unique for each [`Hash`](@ref modes_concept) type, which takes 
input data stream and gets it split to blocks filled with converted to 
appropriate size integers (words in the cryptography meaning, not machine words).
  
Example. Lets assume input data stream consists of 16 bytes as follows.

@dot
digraph bytes {
bgcolor="#222222";
node [shape=record color="#F5F2F1" fontcolor="#F5F2F1"];

struct1 [label="0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x10 | 0x11 | 0x12 | 0x13
 | 0x14 | 0x15"];
  
}
@enddot

Lets assume the selected cipher to be used is Rijndael with 32 bit word size, 128 bit block size and 128
 bit key size. This means input data stream needs to be converted to 32 bit words and merged to 128 bit
  blocks as follows:
  
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

Now with this a [`Hash`](@ref modes_concept) instance of [sha2](@ref nil::crypto3::hashes::sha2) 
can be fed.

This mechanism is handled with `stream_processor` template class specified for 
each particular cipher with parameters required. Hashes suppose only one type 
of stream processor exist - the one which split the data to blocks, converts 
them and passes to `AccumulatorSet` reference as cipher input of format required. 
The rest of data not even to block size gets converted too and fed value by 
value to the same `AccumulatorSet` reference.

## Data Type Conversion {#modes_data}
 
Since block cipher algorithms are usually defined for `Integral` types or 
byte sequences of unique format for each cipher, encryption function being 
generic requirement should be handled with particular cipher-specific input data 
format converter.
  
For example `Rijndael` cipher is defined over blocks of 32 bit words, which 
could be represented with `uint32_t`. This means all the input data should be 
in some way converted to 4 byte sized `Integral` type. In case of 
`InputIterator` is defined over some range of `Integral` value type, this is is 
handled with plain byte repack as shown in previous section. This is a case with 
both input stream and required data format are satisfy the same concept.
    
The more case with input data being presented by sequence of various type `T` 
requires for the `T` to has conversion operator `operator Integral()` to the 
type required by particular `BlockCipher` policy.   
 
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
```SequenceContainer``` of value type ```A```:

```cpp
std::vector<A> a;
```

To feed the ```BlockCipher``` with the data presented, it is required to convert ```A``` to ```Integral``` type which
 is only available if ```A``` has conversion operator in some way as follows:
 
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

This part is handled internally with ```stream_processor``` configured for each particular cipher. 
   
## Hash Algorithms {#modes_pol}

## Accumulators {#modes_acc}

## Value Postprocessors {#modes_val}
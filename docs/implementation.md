# Implementation {#block_ciphers_impl}

Block ciphers usage is usually split to three stages:

1. Initialization (key scheduling)
2. Accumulation (data processing/preprocessing)
3. Encryption

This separation defines the implementation architecture.

Some particular cases merge accumulation step with
encryption step. This means block gets encrypted as
far as it is found filled with enough data.  

## Architecture Overview {#block_ciphers_arch}

Block cipher library architecture consists of several parts listed below:

1. Algorithms
2. Stream Processors
3. Cipher Algorithms
4. Accumulators
5. Value Processors

@dot
digraph block_cipher_arch {
color="#222222";
rankdir="TB"
node [shape="box"]

  a [label="Algorithms" color="#F5F2F1" URL="@ref block_cipher_algs"];
  b [label="Stream Processors" color="#F5F2F1" URL="@ref block_cipher_stream"];
  c [label="Cipher Algorithms" color="#F5F2F1" URL="@ref block_cipher_pol"];
  d [label="Accumulators" color="#F5F2F1" URL="@ref block_cipher_acc"];
  e [label="Value Processors" color="#F5F2F1" URL="@ref block_cipher_val"];
  
  a -> b;
  b -> c;
  c -> d;
  d -> e;
}
@enddot

## Algorithms {#block_cipher_algs}

Implementation of a library is considered to be highly
 compliant with STL. So the crucial point is to have
 ciphers to be usable in the same way as STL
 algorithms do.

STL algorithms library mostly consists of generic
iterator and since C++20 range-based algorithms over
generic concept-compliant types. Great example 
is ```std::transform``` algorithm:
 
```cpp
template<typename InputIterator, typename OutputIterator, typename UnaryOperation>
OutputIterator transform(InputIterator first, InputIterator last, OutputIterator out, UnaryOperation unary_op);
```

Input values of type ```InputIterator``` operate over
any iterable range, no matter which particular type is
supposed to be processed. 
While ```OutputIterator``` provides a type-independent
output place for the algorithm to put results no
matter which particular range this 
```OutputIterator``` represents.
 
Since C++20 this algorithm got it analogous inside
Ranges library as follows:
 
```cpp
template<typename InputRange, typename OutputRange, typename UnaryOperation>
OutputRange transform(InputRange rng, OutputRange out, UnaryOperation unary_op);
```

This particular modification takes no difference if
```InputRange``` is a ```Container``` or something
else. The algorithm is generic just as data
representation types are.
 
As much as such algorithms are implemented as generic
ones, block cipher algorithms should follow that too:
 
```cpp
template<typename BlockCipher, typename InputIterator, typename KeyIterator, typename OutputIterator>
OutputIterator encrypt(InputIterator first, InputIterator last, KeyIterator kfirst, KeyIterator klast, OutputIterator out);
```

```BlockCipher``` represents the particular block
cipher will be used. ```InputIterator``` represents
the input data coming to be encrypted. Since block
ciphers rely on secret key ```KeyIterator```
represents the key data, and ```OutputIterator``` is
exactly the same as it was in ```std::transform```
algorithm - it handles all the output storage
operations.
 
The most obvious difference between 
```std::transform``` is a representation 
of a policy defining the particular behaviour of an
algorithm. ```std::transform``` proposes to pass it 
as a reference to ```Functor```, which is also
possible in case of ```BlockCipher``` policy used in
function already pre-scheduled:
   
```cpp
template<typename BlockCipher, typename InputIterator, typename KeyIterator, typename OutputIterator>
OutputIterator encrypt(InputIterator first, InputIterator last, KeyIterator kfirst, KeyIterator klast, OutputIterator out);
```

Algorithms are no more than an internal structures
initializer wrapper. In this particular case algorithm
would initialize stream processor fed with
accumulator set with 
```[block](@ref accumulators::block)``` accumulator
inside initialized with ```BlockCipher``` initialized
with ```KeyType``` retrieved from input 
```KeyIterator``` instances.

## Stream Data Processing {#block_cipher_stream}

Block ciphers are usually defined for processing
```Integral``` value typed byte sequences of specific
size packed in blocks (e.g. ```Rijndael``` is
defined for blocks of words which are actually plain
```n```-sized arrays of ```uint32_t ``` ). Input data
in the implementation proposed is supposed to
be a various-length input stream, which length could
be not even to block size.
  
This requires an introduction of stream processor
specified with particular parameter set unique for
each ```BlockCipher``` type, which takes input data 
stream and gets it split to blocks filled with 
converted to appropriate size integers (words in the
cryptography meaning, not machine words).
  
Example. Lets assume input data stream consists of 16
bytes as follows.

@dot
digraph bytes {
color="#222222";
node [shape=record color="#F5F2F1"];

struct1 [label="0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07 | 0x08 | 0x09 | 0x10 | 0x11 | 0x12 | 0x13
 | 0x14 | 0x15"];
  
}
@enddot

Lets assume the selected cipher to be used is Rijndael
with 32 bit word size, 128 bit block size and 128 bit
key size. This means input data stream needs to 
be converted to 32 bit words and merged to 128 bit
blocks as follows:
  
@dot
digraph bytes_to_words {
color="#222222";
node [shape=record color="#F5F2F1"];

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

Now with this a ```BlockCipher``` instance of 
```Rijndael``` can be fed.

This mechanism is handled with ```stream_processor```
template class specified for each particular cipher
with parameters required. Block ciphers suppose only 
one type of stream processor exist - the one which 
split the data to blocks, converts them and passes to
```AccumulatorSet``` reference as cipher input of 
format required. The rest of data not even to block
size gets converted too and fed value by value to the
same ```AccumulatorSet``` reference.

## Data Type Conversion {#block_cipher_data}
 
Since block cipher algorithms are usually defined for ```Integral``` types or byte sequences of unique format for
 each cipher, encryption function being generic requirement should be handled with particular
  cipher-specific input data format converter.
  
For example ```Rijndael``` cipher is defined over blocks of 32 bit words, which could be represented
 with ```uint32_t```. This means all the input data should be in some way converted to 4 byte sized
  ```Integral``` type. In case of ```InputIterator``` is defined over some range of ```Integral``` value
   type, this is is handled with plain byte repack as shown in previous section. This is a case with both
 input stream and required data format are satisfy the same concept.
    
The more case with input data being presented by sequence of various type ```T``` requires for the ```T``` to has
 conversion operator ```operator Integral()``` to the type required by particular ```BlockCipher``` policy.   
 
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

This part is handled internally with
```stream_processor``` configured for 
each particular cipher. 
   
## Block Cipher Algorithms {#block_cipher_pol}

Block cipher algorithms architecturally are stateful 
policies, which structural contents are regulated by
concepts and runtime content is a scheduled key data. 
Block cipher policies are required to be compliant
with [```BlockCipher``` concept](@ref block_ciphers_concepts).

```BlockCipher``` policies are required to be 
constructed with particular policy-compliant strictly-typed key data, usually represented by 
```BlockCipher::key_type```. This means construction
of such a policy is quite a heavy task, so this 
should be handled with care. The result of 
a ```BlockCipher``` construction is filled and strictly-typed key schedule data member. 

Once initialized with particular key, ```BlockCipher``` policy is not meant to be
reinitialized, but only destructed. Destruction of a ```BlockCipher``` instance should zeroize key schedule data.

Usually such a ```BlockCipher``` policy would contain
```constexpr static const std::size_t```-typed
numerical cipher parameters, such as block bits, 
word bits, block words or cipher rounds.

Coming to typedefs contained in policy - they meant to
be mostly a fixed-length arrays (usually 
```std::array```), which guarantees type-safety and no
occasional input data length issues.

Functions contained in policy are meant to process 
one block of strictly-typed data (usually it is
represented by ```block_type``` typedef) per call. 
Such functions are stateful with respect to key
schedule data represented by ```key_schedule_type``` and generated while block cipher constructor call.

## Accumulators {#block_cipher_acc}

Encryption contains an accumulation step, which is
implemented with [Boost.Accumulators](https://boost.org/libs/accumulators) library.

All the concepts are held.

Block ciphers contains pre-defined [block_accumulator_set](@ref block_accumulator_set), which is a 
```boost::accumulator_set``` with pre-filled
[```block``` accumulator](@ref accumulators::block).

Block accumulator accepts only one either 
```block_type::value_type``` or ```block_type``` 
at insert.

Accumulator is implemented as a caching one. This means there is an input cache sized as same as particular
 ```BlockCipher::block_type```, which accumulates
 unprocessed data. After it gets filled, data gets
 encrypted, then it gets moved to the main accumulator
 storage, then cache gets emptied. 

## Value Postprocessors {#block_cipher_val}
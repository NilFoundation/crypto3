## Block Cipher Concepts

### HashAlgorithm Concept
 
Models of the ```HashAlgorithm``` concept are policies to be provided as template arguments to other
templates. They provide access to the set of types needed to generically compute and store digests with
a particular algorithm. (For example, the ```hash``` algorithm templates are parametrized by a
HashAlgorithm, as would a future HMAC-computing function template.)

A type ```T``` modelling the ```HashAlgorithm``` concept must support the following:

- ```T::stream_hash<ValueBits>::type``` 
must model the ```StreamCipher<ValueBits>``` concept.
Not all possible values of ```ValueBits``` need be accepted. Typically, small powers of 2 (1, 2, 4, 8, 16, 32, 64) are accepted.

- ```T::digest_type```
an instantiation of the static_digest class template.
must match the ```digest_type``` of the ```StreamCipher<ValueBits>``` policies mentioned above for any allowed choice
of ```ValueBits```

### StreamCipher<ValueBits> Concept

A type ```T``` modelling the ```StreamCipher<ValueBits>``` concept must be:
 - Default-Constructible
 - Copy-Constructible
 - Copy-Assignable
 
 and must support the following:

- ```T::digest_type``` 
an instantiation of the static_digest class template.

- ```T::value_type```
an unsigned fundamental integral type that can hold least ```ValueBits``` bits

- ```T h; h.reset();``` (equivalent to ```T h = T();```)

- ```T h; T::digest_type d = h.end_message();```
returns the static_digest of all input provided since the last reset, then resets
(equivalent to ```digest_type d = h.static_digest(); h.reset();```, though typically more efficient if the hash involves 
padding or finalization)

- ```const T hc; T::digest_type d = hc.static_digest();```
returns the static_digest of all input provided since the last reset
(equivalent to ```digest_type d = T(hc).end_message();```, though typically more efficient if the hash
involves neither padding nor finalization)

- ```value_type x; h.update_one(x);```
Feeds the low ```ValueBits``` bits of x as input to the hash algorithm

- ```InputIterator1 b, e; h.update(b, e);``` Equivalent to:

      for (InputIterator1 i = b; i != e; ++i) {
          h.update_one(i);
      }

- ```InputIterator1 b; size_t n; h.update_n(b, n);``` Equivalent to:

      InputIterator1 i = b; 
      for (size_t j = 0; j != n; ++j) {
          h.update_one(i++);
      }

Each ```HashAlgorithm``` model provides access to all its associated ```StreamCipher``` models; Those ```StreamCipher```
models are generally not accessible in other ways.
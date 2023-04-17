---
description: Multi exponentiation helpers
---

# multi-exponentiation

Multi-exponentiation can be performed in two forms

* standard
* mixed addition

Each of the above forms takes a policy which can be one of the following :

* Naive: simple multiplication & summation of the result
* Bos-Coster
* [Pippenger (Special case)](https://eprint.iacr.org/2012/549.pdf)

Each of the above functions takes ranges to vectors/scalars as inputs.

## Usage

multi-exponentiation algorithms are defined under the namespace `nil::crypto3::algebra` and header need to be included ex: `algebra/multiexp/multiexp.hpp`

TODO - Chunks!?

```cpp
template<typename MultiexpMethod, typename InputBaseIterator, typename InputFieldIterator>
typename std::iterator_traits<InputBaseIterator>::value_type
	multiexp(InputBaseIterator vec_start, InputBaseIterator vec_end, InputFieldIterator scalar_start,
			 InputFieldIterator scalar_end, const std::size_t chunks_count)
```

Policy

```cpp
struct multiexp_method_naive_plain {
	template<typename InputBaseIterator, typename InputFieldIterator>
	static inline typename std::iterator_traits<InputBaseIterator>::value_type
		process(InputBaseIterator vec_start,
				InputBaseIterator vec_end,
				InputFieldIterator scalar_start,
				InputFieldIterator scalar_end) {..}
```

### Example#1

```cpp
multiexp<policies::multiexp_method_BDLO12>(group_elements.cbegin(), group_elements.cend(),scalars.cbegin(), scalars.cend(), 1)
```

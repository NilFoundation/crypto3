# pairings

Bi-linear pairing groups are predefined for a set of curves.

Pairings for the following curves are implemented

1. mnt4 & mnt6
2. bls12 & jubjub
3. altbn128 & baby jubjub

## Usage

Pairings are defined under the namespaces `nil::crypto3::algebra::pairing`

Below we define some types used as inputs in algorithms:

1. `g1_type::value_type` conforms to the traits of a `curve_element` a type representing an element from the group `G1`
2. `g2_type::value_type` conforms to the traits of a `curve_element` a type representing an element from the group `G2`
3. `gt_type::value_type` is an extended field type. This differs from curve to curve.

### Pair

<pre class="language-cpp"><code class="lang-cpp">template&#x3C;typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy&#x3C;PairingCurveType>>
<strong>typename PairingCurveType::gt_type::value_type pair(const typename PairingCurveType::template g1_type&#x3C;>::value_type &#x26;v1,
</strong>                     const typename PairingCurveType::template g2_type&#x3C;>::value_type &#x26;v2)
</code></pre>

TODO : Add description

###

### Pair Reduced

```cpp
template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
typename PairingCurveType::gt_type::value_type
	pair_reduced(const typename PairingCurveType::template g1_type<>::value_type &v1,
				 const typename PairingCurveType::template g2_type<>::value_type &v2)
```

TODO : Add description

### Miller Loop

```cpp
template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
typename PairingCurveType::gt_type::value_type
	miller_loop(const typename PairingPolicy::g1_precomputed_type &prec_P,
		    const typename PairingPolicy::g2_precomputed_type &prec_Q)
```

TODO : Add description

### Double Miller Loop

```cpp
template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
typename PairingCurveType::gt_type::value_type
	double_miller_loop(const typename PairingPolicy::g1_precomputed_type &prec_P1,
	                   const typename PairingPolicy::g2_precomputed_type &prec_Q1,
			   const typename PairingPolicy::g1_precomputed_type &prec_P2,
			   const typename PairingPolicy::g2_precomputed_type &prec_Q2)
```

TODO : Add description

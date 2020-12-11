//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_POLICY_FIXED_HPP
#define BOOST_MULTIPRECISION_MODULAR_POLICY_FIXED_HPP

#include <boost/multiprecision/cpp_int.hpp>

#include <boost/utility/enable_if.hpp>

namespace boost {
namespace multiprecision {
namespace backends {

// TODO: replace cpp_int_backend on this type everywhere in fixed modular_adaptor
template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
using modular_fixed_cpp_int_backend = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;

template <typename Backend>
class modular_policy;

template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
struct modular_policy<modular_fixed_cpp_int_backend<MinBits, SignType, Checked> >
{
   typedef modular_fixed_cpp_int_backend<MinBits, SignType, Checked> Backend;

   static_assert(MinBits, "number of bits should be defined");
   static_assert(is_fixed_precision<Backend>::value, "fixed precision backend should be used");
   static_assert(!is_unsigned_number<Backend>::value, "number should be signed");
   static_assert(is_non_throwing_cpp_int<Backend>::value, "backend should be unchecked");

   constexpr static auto limbs_count = is_trivial_cpp_int<Backend>::value
                                           ? 1u
                                           : Backend::internal_limb_count;
   constexpr static auto limb_bits   = is_trivial_cpp_int<Backend>::value
                                           ? sizeof(typename trivial_limb_type<MinBits>::type) * CHAR_BIT
                                           : Backend::limb_bits;

   /// real limb_type depending on is_trivial_cpp_int property
   /// such logic is necessary due to local_limb_type could be uint128
   typedef typename mpl::if_c<is_trivial_cpp_int<Backend>::value,
                              typename trivial_limb_type<MinBits>::type,
                              limb_type>::type        internal_limb_type;
   typedef typename mpl::if_c<is_trivial_cpp_int<Backend>::value,
                              number<cpp_int_backend<2u * limb_bits,
                                                     2u * limb_bits,
                                                     cpp_integer_type::unsigned_magnitude,
                                                     cpp_int_check_type::unchecked, void> >,
                              double_limb_type>::type internal_double_limb_type;

   constexpr static auto BitsCount_doubled              = 2u * MinBits;
   constexpr static auto BitsCount_doubled_1            = BitsCount_doubled + 1;
   constexpr static auto BitsCount_quadruple_1          = 2u * BitsCount_doubled + 1;
   constexpr static auto BitsCount_padded_limbs         = limbs_count * limb_bits + limb_bits;
   constexpr static auto BitsCount_doubled_limbs        = 2u * limbs_count * limb_bits;
   constexpr static auto BitsCount_doubled_padded_limbs = BitsCount_doubled_limbs + limb_bits;

   typedef modular_fixed_cpp_int_backend<BitsCount_doubled, SignType, Checked>              Backend_doubled;
   typedef modular_fixed_cpp_int_backend<BitsCount_doubled_1, SignType, Checked>            Backend_doubled_1;
   typedef modular_fixed_cpp_int_backend<BitsCount_quadruple_1, SignType, Checked>          Backend_quadruple_1;
   typedef modular_fixed_cpp_int_backend<BitsCount_padded_limbs, SignType, Checked>         Backend_padded_limbs;
   typedef modular_fixed_cpp_int_backend<BitsCount_doubled_limbs, SignType, Checked>        Backend_doubled_limbs;
   typedef modular_fixed_cpp_int_backend<BitsCount_doubled_padded_limbs, SignType, Checked> Backend_doubled_padded_limbs;

   typedef number<Backend>               number_type;
   typedef number<Backend_doubled>       dbl_number_type;
   typedef number<Backend_doubled_limbs> dbl_lmb_number_type;
};

}
}
} // namespace boost::multiprecision::backends

#endif // BOOST_MULTIPRECISION_MODULAR_POLICY_FIXED_HPP

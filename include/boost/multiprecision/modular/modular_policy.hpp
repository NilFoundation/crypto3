//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MODULAR_POLICY_HPP
#define BOOST_MULTIPRECISION_MODULAR_POLICY_HPP

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/mpl/if.hpp>
#include <boost/utility/enable_if.hpp>

namespace boost {
namespace multiprecision {
namespace backends {

/// the function works correctly only with consistent backend objects,
/// i.e. their limbs should not be manipulated directly
/// as it breaks backend logic of size determination
/// (or real size of such objects should be adjusted then)
template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr typename mpl::if_c<
    is_trivial_cpp_int<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>::value,
    typename trivial_limb_type<MinBits>::type,
    limb_type>::type
get_limb_value(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &b, const std::size_t i) {
   if (i < b.size()) {
      return b.limbs()[i];
   }
   return 0;
}

template <typename Backend>
class modular_policy;

template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
struct modular_policy<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
{
   /// to take into account bit for a sign
   constexpr static auto InternalBitsCount = MinBits + 1u;

   typedef cpp_int_backend<InternalBitsCount, InternalBitsCount, SignType, Checked, void> Backend;

   static_assert(MinBits, "number of bits should be defined");
   static_assert(is_fixed_precision<Backend>::value, "fixed precision backend should be used");
   static_assert(!is_unsigned_number<Backend>::value, "number should be signed");
   static_assert(is_non_throwing_cpp_int<Backend>::value, "backend should be unchecked");

   constexpr static auto limbs_count = is_trivial_cpp_int<Backend>::value
                                       ? 1u
                                       : Backend::internal_limb_count;
   constexpr static auto limb_bits = is_trivial_cpp_int<Backend>::value
                                     ? sizeof(typename trivial_limb_type<MinBits>::type) * CHAR_BIT
                                     : Backend::limb_bits;

   /// real limb_type depending on is_trivial_cpp_int property
   /// such logic is necessary due to local_limb_type could be uint128
   typedef typename mpl::if_c<is_trivial_cpp_int<Backend>::value,
                              typename trivial_limb_type<MinBits>::type,
                              limb_type>::type internal_limb_type;
   typedef typename mpl::if_c<is_trivial_cpp_int<Backend>::value,
                              number<cpp_int_backend<2u * limb_bits,
                                                     2u * limb_bits,
                                                     cpp_integer_type::unsigned_magnitude,
                                                     cpp_int_check_type::unchecked, void>>,
                              double_limb_type>::type internal_double_limb_type;

   /// to take into account bit for a sign
   constexpr static auto InternalBitsCount_doubled = 2u * MinBits + 1u;
   constexpr static auto InternalBitsCount_padded_limbs = limbs_count * limb_bits + limb_bits;
   constexpr static auto InternalBitsCount_doubled_limbs = 2u * limbs_count * limb_bits;
   constexpr static auto InternalBitsCount_doubled_padded_limbs = 2u * limbs_count * limb_bits + limb_bits;

   typedef cpp_int_backend<InternalBitsCount_doubled, InternalBitsCount_doubled,
                           SignType, Checked, void> Backend_doubled;
   typedef cpp_int_backend<InternalBitsCount_padded_limbs, InternalBitsCount_padded_limbs,
                           SignType, Checked, void> Backend_padded_limbs;
   typedef cpp_int_backend<InternalBitsCount_doubled_limbs, InternalBitsCount_doubled_limbs,
                           SignType, Checked, void> Backend_doubled_limbs;
   typedef cpp_int_backend<InternalBitsCount_doubled_padded_limbs, InternalBitsCount_doubled_padded_limbs,
                           SignType, Checked, void> Backend_doubled_padded_limbs;

   typedef number<Backend> number_type;
   typedef number<Backend_doubled> dbl_number_type;
   typedef number<Backend_doubled_limbs> dbl_lmb_number_type;
};

}
}
} // namespace boost::multiprecision::backends

#endif // BOOST_MULTIPRECISION_MODULAR_POLICY_HPP

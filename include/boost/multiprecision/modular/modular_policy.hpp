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

namespace boost {
namespace multiprecision {
namespace backends {

template <typename Backend>
class modular_policy;

template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
class modular_policy<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
{
 protected:
   /// to take into account bit for sign
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
                                     ? sizeof(typename trivial_limb_type<InternalBitsCount>::type) * CHAR_BIT
                                     : Backend::limb_bits;

   typedef cpp_int_backend<2u * MinBits, 2u * MinBits,
                           SignType, Checked, void> Backend_doubled;
   typedef cpp_int_backend<limbs_count * limb_bits + limb_bits,
                           limbs_count * limb_bits + limb_bits,
                           SignType, Checked, void> Backend_padded_limbs;
   typedef cpp_int_backend<2u * limbs_count * limb_bits,
                           2u * limbs_count * limb_bits,
                           SignType, Checked, void> Backend_doubled_limbs;
   typedef cpp_int_backend<2u * limbs_count * limb_bits + limb_bits,
                           2u * limbs_count * limb_bits + limb_bits,
                           SignType, Checked, void> Backend_doubled_padded_limbs;

   typedef number<Backend> number_type;
   typedef number<Backend_doubled> dbl_number_type;
   typedef number<Backend_doubled_limbs> dbl_lmb_number_type;
};

}
}
} // namespace boost::multiprecision::backends

#endif // BOOST_MULTIPRECISION_MODULAR_POLICY_HPP

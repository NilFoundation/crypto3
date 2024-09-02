//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MULTIPRECISION_MODULAR_POLICY_FIXED_HPP
#define CRYPTO3_MULTIPRECISION_MODULAR_POLICY_FIXED_HPP

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

#include <boost/utility/enable_if.hpp>

namespace boost {   
    namespace multiprecision {
        namespace backends {

            template<typename Backend>
            BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if_c<is_trivial_cpp_int_modular<Backend>::value, std::size_t>::type
                get_limbs_count() {
                return 1u;
            }

            template<typename Backend>
            BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if_c<!is_trivial_cpp_int_modular<Backend>::value, std::size_t>::type
                get_limbs_count() {
                return Backend::internal_limb_count;
            }

            template<typename Backend>
            BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if_c<is_trivial_cpp_int_modular<Backend>::value, std::size_t>::type
                get_limb_bits() {
                return sizeof(typename trivial_limb_type<boost::multiprecision::backends::max_precision<Backend>::value>::type) * CHAR_BIT;
            }

            template<typename Backend>
            BOOST_MP_CXX14_CONSTEXPR typename boost::enable_if_c<!is_trivial_cpp_int_modular<Backend>::value, std::size_t>::type
                get_limb_bits() {
                return Backend::limb_bits;
            }

            template<typename Backend>
            struct modular_policy;

            template<unsigned Bits>
            struct modular_policy<cpp_int_modular_backend<Bits>> {
                typedef cpp_int_modular_backend<Bits> Backend;

                BOOST_MP_CXX14_CONSTEXPR static auto limbs_count = get_limbs_count<Backend>();
                BOOST_MP_CXX14_CONSTEXPR static auto limb_bits = get_limb_bits<Backend>();

                /// real limb_type depending on is_trivial_cpp_int_modular property
                /// such logic is necessary due to local_limb_type could be uint128
                typedef typename std::conditional<is_trivial_cpp_int_modular<Backend>::value,
                                                  typename trivial_limb_type<Bits>::type,
                                                  limb_type>::type
                    internal_limb_type;

                typedef typename std::conditional<is_trivial_cpp_int_modular<Backend>::value,
                                                  typename trivial_limb_type<2u * limb_bits>::type,
                                                  double_limb_type>::type
                    internal_double_limb_type;

                // Delete this if everything works.
                //typedef typename std::conditional<
                //    is_trivial_cpp_int_modular<Backend>::value,
                //    boost::multiprecision::number<cpp_int_modular_backend<2u * limb_bits>>,
                //    double_limb_type>::type internal_double_limb_type;

                BOOST_MP_CXX14_CONSTEXPR static auto BitsCount_doubled = 2u * Bits;
                BOOST_MP_CXX14_CONSTEXPR static auto BitsCount_doubled_1 = BitsCount_doubled + 1;
                BOOST_MP_CXX14_CONSTEXPR static auto BitsCount_quadruple_1 = 2u * BitsCount_doubled + 1;
                BOOST_MP_CXX14_CONSTEXPR static auto BitsCount_padded_limbs = limbs_count * limb_bits + limb_bits;
                BOOST_MP_CXX14_CONSTEXPR static auto BitsCount_doubled_limbs = 2u * limbs_count * limb_bits;
                BOOST_MP_CXX14_CONSTEXPR static auto BitsCount_doubled_padded_limbs = BitsCount_doubled_limbs + limb_bits;

                typedef cpp_int_modular_backend<BitsCount_doubled> Backend_doubled;
                typedef cpp_int_modular_backend<BitsCount_doubled_1> Backend_doubled_1;
                typedef cpp_int_modular_backend<BitsCount_quadruple_1> Backend_quadruple_1;
                typedef cpp_int_modular_backend<BitsCount_padded_limbs> Backend_padded_limbs;
                typedef cpp_int_modular_backend<BitsCount_doubled_limbs> Backend_doubled_limbs;
                typedef cpp_int_modular_backend<BitsCount_doubled_padded_limbs> Backend_doubled_padded_limbs;

                // Modular adaptor must not know about the existance of class boost::mp::number.
                //typedef boost::multiprecision::number<Backend> number_type;
                //typedef boost::multiprecision::number<Backend_doubled> dbl_number_type;
                //typedef boost::multiprecision::number<Backend_doubled_limbs> dbl_lmb_number_type;
            };
        }    // namespace backends
    }   // namespace multiprecision
}   // namespace boost

#endif    // CRYPTO3_MULTIPRECISION_MODULAR_POLICY_FIXED_HPP

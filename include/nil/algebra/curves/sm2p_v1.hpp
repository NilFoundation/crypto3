//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_SM2P_V1_HPP
#define ALGEBRA_CURVES_SM2P_V1_HPP

#include <nil/algebra/fields/sm2p_v1/fq.hpp>
#include <nil/algebra/fields/sm2p_v1/fr.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            template<std::size_t PBits>
            struct sm2p_v1 { };

            template<>
            struct sm2p_v1<256> {
                constexpr static const std::size_t base_field_bits = 256;
                typedef fields::sm2p_v1_fq<base_field_bits, CHAR_BIT> base_field_type;
                typedef typename base_field_type::modulus_type number_type;
                constexpr static const number_type base_field_modulus = base_field_type::modulus;

                constexpr static const std::size_t scalar_field_bits = 256;
                typedef fields::sm2p_v1_fr<scalar_field_bits, CHAR_BIT> scalar_field_type;
                constexpr static const number_type scalar_field_modulus = scalar_field_type::modulus;

                constexpr static const number_type p = base_field_modulus;
                constexpr static const number_type q = scalar_field_modulus;

                constexpr static const number_type a =
                    0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC_cppui256;
                constexpr static const number_type b =
                    0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93_cppui256;
                constexpr static const number_type x =
                    0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7_cppui256;
                constexpr static const number_type y =
                    0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0_cppui256;
            };

            typedef sm2p_v1<256> sm2p256v1;
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_SM2P_V1_HPP

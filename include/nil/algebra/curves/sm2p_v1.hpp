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

#include <nil/crypto3/pubkey/ec_group/curve_weierstrass.hpp>
#include <nil/crypto3/algebra/curves/detail/element/sm2p_v1.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)
            

            template<std::size_t PBits>
            struct sm2p_v1 : public curve_weierstrass<PBits> {};

            template<>
            struct sm2p_v1<256> : public curve_weierstrass<256> {
                typedef typename curve_weierstrass<256>::number_type number_type;

                constexpr static const number_type p =
                    0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF_cppui256;
                constexpr static const number_type a =
                    0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC_cppui256;
                constexpr static const number_type b =
                    0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93_cppui256;
                constexpr static const number_type x =
                    0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7_cppui256;
                constexpr static const number_type y =
                    0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0_cppui256;
                constexpr static const number_type order =
                    0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123_cppui256;

            };

            typedef sm2p_v1<256> sm2p256v1;
        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_SM2P_V1_HPP

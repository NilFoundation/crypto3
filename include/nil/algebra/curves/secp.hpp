//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_CURVE_SECP_HPP
#define CRYPTO3_PUBKEY_CURVE_SECP_HPP

#include <memory>

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_gfp.hpp>

namespace nil {
    namespace crypto3 {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(160)
        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(192)
        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(224)
        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)
    
    
        template<std::size_t PBits>
        struct secp_k1 : public ec_group_info<PBits> {};

        template<std::size_t PBits>
        struct secp_r1 : public ec_group_info<PBits> {};

        template<std::size_t PBits>
        struct secp_r2 : public ec_group_info<PBits> {};

        template<>
        struct secp_k1<160> : public ec_group_info<160> {
            typedef typename ec_group_info<160>::number_type number_type;

            constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73_cppui160;
            constexpr static const number_type a = 0x0_cppui160;
            constexpr static const number_type b = 0x7_cppui160;
            constexpr static const number_type x = 0x3B4C382CE37AA192A4019E763036F4F5DD4D7EBB_cppui160;
            constexpr static const number_type y = 0x938CF935318FDCED6BC28286531733C3F03C4FEE_cppui160;
            constexpr static const number_type order = 0x100000000000000000001B8FA16DFAB9ACA16B6B3_cppui160;

        };

        typedef secp_k1<160> secp160k1;

        template<>
        struct secp_r1<160> : public ec_group_info<160> {
            typedef typename ec_group_info<160>::number_type number_type;

            constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF_cppui160;
            constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC_cppui160;
            constexpr static const number_type b = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45_cppui160;
            constexpr static const number_type x = 0x4A96B5688EF573284664698968C38BB913CBFC82_cppui160;
            constexpr static const number_type y = 0x23A628553168947D59DCC912042351377AC5FB32_cppui160;
            constexpr static const number_type order = 0x100000000000000000001F4C8F927AED3CA752257_cppui160;

        };

        typedef secp_r1<160> secp160r1;

        template<>
        struct secp_r2<160> : public ec_group_info<160> {
            typedef typename ec_group_info<160>::number_type number_type;

            constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73_cppui160;
            constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70_cppui160;
            constexpr static const number_type b = 0xB4E134D3FB59EB8BAB57274904664D5AF50388BA_cppui160;
            constexpr static const number_type x = 0x52DCB034293A117E1F4FF11B30F7199D3144CE6D_cppui160;
            constexpr static const number_type y = 0xFEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E_cppui160;
            constexpr static const number_type order = 0x100000000000000000000351EE786A818F3A1A16B_cppui160;

        };

        typedef secp_r2<160> secp160r2;

        template<>
        struct secp_k1<192> : public ec_group_info<192> {
            typedef typename ec_group_info<192>::number_type number_type;

            constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37_cppui192;
            constexpr static const number_type a = 0x0_cppui192;
            constexpr static const number_type b = 0x3_cppui192;
            constexpr static const number_type x = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D_cppui192;
            constexpr static const number_type y = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D_cppui192;
            constexpr static const number_type order = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D_cppui192;

        };

        typedef secp_k1<192> secp192k1;

        template<>
        struct secp_r1<192> : public ec_group_info<192> {
            typedef typename ec_group_info<192>::number_type number_type;

            constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37_cppui192;
            constexpr static const number_type a = 0x0_cppui192;
            constexpr static const number_type b = 0x3_cppui192;
            constexpr static const number_type x = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D_cppui192;
            constexpr static const number_type y = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D_cppui192;
            constexpr static const number_type order = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D_cppui192;

        };

        typedef secp_r1<192> secp192r1;

        template<>
        struct secp_k1<224> : public ec_group_info<224> {
            typedef typename ec_group_info<224>::number_type number_type;

            constexpr static const number_type p =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D_cppui224;
            constexpr static const number_type a = 0x0_cppui224;
            constexpr static const number_type b = 0x5_cppui224;
            constexpr static const number_type x =
                0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C_cppui224;
            constexpr static const number_type y =
                0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5_cppui224;
            constexpr static const number_type order =
                0x10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7_cppui224;

        };

        typedef secp_k1<224> secp224k1;

        template<>
        struct secp_r1<224> : public ec_group_info<224> {
            typedef typename ec_group_info<224>::number_type number_type;

            constexpr static const number_type p =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001_cppui224;
            constexpr static const number_type a =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE_cppui224;
            constexpr static const number_type b =
                0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4_cppui224;
            constexpr static const number_type x =
                0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21_cppui224;
            constexpr static const number_type y =
                0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34_cppui224;
            constexpr static const number_type order =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D_cppui224;

        };

        typedef secp_r1<256> secp256r1;

        template<>
        struct secp_k1<256> : public ec_group_info<256> {
            typedef typename ec_group_info<256>::number_type number_type;

            constexpr static const number_type p =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F_cppui256;
            constexpr static const number_type a = 0x0_cppui256;
            constexpr static const number_type b = 0x7_cppui256;
            constexpr static const number_type x =
                0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798_cppui256;
            constexpr static const number_type y =
                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8_cppui256;
            constexpr static const number_type order =
                0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_cppui256;

        };

        typedef secp_k1<256> secp256k1;
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_CURVE_SECP_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_CURVE_X962_P_HPP
#define CRYPTO3_PUBKEY_CURVE_X962_P_HPP

#include <memory>

#include <boost/multiprecision/cpp_bin_float.hpp>
#include <boost/multiprecision/mask_bits.hpp>
#include <boost/multiprecision/reduce_below.hpp>

#include <nil/crypto3/pubkey/ec_group/curve_gfp.hpp>

namespace nil {
    namespace crypto3 {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(192)
        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(239)
        
        template<std::size_t PBits>
        struct x962_p_v1 : public ec_group_info<PBits> {};

        template<std::size_t PBits>
        struct x962_p_v2 : public ec_group_info<PBits> {};

        template<std::size_t PBits>
        struct x962_p_v3 : public ec_group_info<PBits> {};

        template<>
        struct x962_p_v2<192> : public ec_group_info<192> {
            typedef typename ec_group_info<192>::number_type number_type;

            constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF_cppui192;
            constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC_cppui192;
            constexpr static const number_type b = 0xCC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953_cppui192;
            constexpr static const number_type x = 0xEEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A_cppui192;
            constexpr static const number_type y = 0x6574D11D69B6EC7A672BB82A083DF2F2B0847DE970B2DE15_cppui192;
            constexpr static const number_type order = 0xFFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31_cppui192;

        };

        typedef x962_p_v3<192> x962_p192v2;

        template<>
        struct x962_p_v3<192> : public ec_group_info<192> {
            typedef typename ec_group_info<192>::number_type number_type;

            constexpr static const number_type p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF_cppui192;
            constexpr static const number_type a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC_cppui192;
            constexpr static const number_type b = 0x22123DC2395A05CAA7423DAECCC94760A7D462256BD56916_cppui192;
            constexpr static const number_type x = 0x7D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896_cppui192;
            constexpr static const number_type y = 0x38A90F22637337334B49DCB66A6DC8F9978ACA7648A943B0_cppui192;
            constexpr static const number_type order = 0xFFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13_cppui192;

        };

        typedef x962_p_v3<192> x962_p192v3;

        template<>
        struct x962_p_v1<239> : public ec_group_info<239> {
            typedef typename ec_group_info<239>::number_type number_type;

            constexpr static const number_type p =
                0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF_cppui239;
            constexpr static const number_type a =
                0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC_cppui239;
            constexpr static const number_type b =
                0x6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A_cppui239;
            constexpr static const number_type x =
                0xFFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF_cppui239;
            constexpr static const number_type y =
                0x7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE_cppui239;
            constexpr static const number_type order =
                0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B_cppui239;

        };

        typedef x962_p_v3<239> x962_p239v1;

        template<>
        struct x962_p_v2<239> : public ec_group_info<239> {
            typedef typename ec_group_info<239>::number_type number_type;

            constexpr static const number_type p =
                0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF_cppui239;
            constexpr static const number_type a =
                0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC_cppui239;
            constexpr static const number_type b =
                0x617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C_cppui239;
            constexpr static const number_type x =
                0x38AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7_cppui239;
            constexpr static const number_type y =
                0x5B0125E4DBEA0EC7206DA0FC01D9B081329FB555DE6EF460237DFF8BE4BA_cppui239;
            constexpr static const number_type order =
                0x7FFFFFFFFFFFFFFFFFFFFFFF800000CFA7E8594377D414C03821BC582063_cppui239;

        };

        typedef x962_p_v3<239> x962_p239v2;

        template<>
        struct x962_p_v3<239> : public ec_group_info<239> {
            typedef typename ec_group_info<239>::number_type number_type;

            constexpr static const number_type p =
                0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF_cppui239;
            constexpr static const number_type a =
                0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC_cppui239;
            constexpr static const number_type b =
                0x255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E_cppui239;
            constexpr static const number_type x =
                0x6768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A_cppui239;
            constexpr static const number_type y =
                0x1607E6898F390C06BC1D552BAD226F3B6FCFE48B6E818499AF18E3ED6CF3_cppui239;
            constexpr static const number_type order =
                0x7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF975DEB41B3A6057C3C432146526551_cppui239;

        };

        typedef x962_p_v3<239> x962_p239v3;
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_CURVE_X962_P_HPP

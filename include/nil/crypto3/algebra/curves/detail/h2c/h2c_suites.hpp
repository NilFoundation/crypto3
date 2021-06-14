//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_SUITES_HPP
#define CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_SUITES_HPP

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

//#include <nil/crypto3/algebra/curves/detail/h2c/h2c_utils.hpp>
//#include <nil/crypto3/algebra/curves/detail/h2c/h2c_iso_map.hpp>

#include <cstdint>
#include <vector>

#include <boost/predef.h>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    template<typename GroupType>
                    struct h2c_suite;

                    template<>
                    struct h2c_suite<typename bls12_381::g1_type> {
                        typedef bls12_381 curve_type;
                        typedef typename bls12_381::g1_type group_type;
                        typedef hashes::sha2<256> hash_type;

                        typedef typename group_type::value_type group_value_type;
                        typedef typename curve_type::number_type number_type;
                        typedef typename group_type::underlying_field_type::number_type modular_type;
                        typedef typename group_type::underlying_field_type::value_type field_value_type;

                        // BLS12381G1_XMD:SHA-256_SSWU_RO_
                        constexpr static std::array<std::uint8_t, 31> suite_id = {
                            66, 76, 83, 49, 50, 51, 56, 49, 71, 49, 95, 88, 77, 68, 58, 83,
                            72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85, 95, 82, 79, 95};
                        constexpr static number_type p = curve_type::p;
                        constexpr static std::size_t m = 1;
                        constexpr static std::size_t k = 128;
                        constexpr static std::size_t L = 64;

                        constexpr static inline const field_value_type Ai = field_value_type(
                            0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d_cppui381);
                        constexpr static inline const field_value_type Bi = field_value_type(
                            0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0_cppui381);
                        constexpr static inline const field_value_type Z = field_value_type(11);
                        constexpr static number_type h_eff = 0xd201000000010001_cppui381;
                    };

                    template<>
                    struct h2c_suite<typename bls12_381::g2_type> {
                        typedef bls12_381 curve_type;
                        typedef typename bls12_381::g2_type group_type;
                        typedef hashes::sha2<256> hash_type;

                        typedef typename group_type::value_type group_value_type;
                        typedef typename curve_type::number_type number_type;
                        typedef typename group_type::underlying_field_type::number_type modular_type;
                        typedef typename group_type::underlying_field_type::value_type field_value_type;

                        // BLS12381G2_XMD:SHA-256_SSWU_RO_
                        constexpr static std::array<std::uint8_t, 31> suite_id = {
                            0x42, 0x4c, 0x53, 0x31, 0x32, 0x33, 0x38, 0x31, 0x47, 0x32, 0x5f,
                            0x58, 0x4d, 0x44, 0x3a, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36,
                            0x5f, 0x53, 0x53, 0x57, 0x55, 0x5f, 0x52, 0x4f, 0x5f};
                        constexpr static number_type p = curve_type::p;
                        constexpr static std::size_t m = 2;
                        constexpr static std::size_t k = 128;
                        constexpr static std::size_t L = 64;

                        constexpr static inline field_value_type Ai = field_value_type(0, 240);
                        constexpr static inline field_value_type Bi = field_value_type(1012, 1012);
#if BOOST_COMP_GNUC
                        constexpr static inline field_value_type Z = []() { return -field_value_type(2, 1); }();
#else
                        constexpr static inline field_value_type Z = -field_value_type(2, 1);
#endif
                        constexpr static inline auto h_eff =
                            0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551_cppui636;
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_SUITES_HPP

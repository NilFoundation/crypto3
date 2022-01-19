//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_HASH_H2C_SUITES_HPP
#define CRYPTO3_HASH_H2C_SUITES_HPP

#include <cstdint>
#include <array>
#include <vector>
#include <type_traits>

#include <boost/predef.h>

#include <nil/crypto3/algebra/curves/bls12.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<typename Group>
            struct h2c_suite;

            template<typename Coordinates, typename Form>
            struct h2c_suite<typename algebra::curves::bls12_381::g1_type<Coordinates, Form>> {
                typedef algebra::curves::bls12_381 curve_type;
                typedef typename algebra::curves::bls12_381::g1_type<Coordinates, Form> group_type;

                typedef typename group_type::value_type group_value_type;
                typedef typename group_type::field_type::integral_type integral_type;
                typedef typename group_type::field_type::modular_type modular_type;
                typedef typename group_type::field_type field_type;
                typedef typename field_type::value_type field_value_type;

                constexpr static inline const field_value_type Ai = field_value_type(
                    0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d_cppui381);
                constexpr static inline const field_value_type Bi = field_value_type(
                    0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0_cppui381);
                constexpr static inline const field_value_type Z = field_value_type(11);
                constexpr static integral_type h_eff = 0xd201000000010001_cppui381;
            };

            template<typename Coordinates, typename Form>
            struct h2c_suite<typename algebra::curves::bls12_381::g2_type<Coordinates, Form>> {
                typedef algebra::curves::bls12_381 curve_type;
                typedef typename algebra::curves::bls12_381::g2_type<Coordinates, Form> group_type;

                typedef typename group_type::value_type group_value_type;
                typedef typename group_type::field_type::integral_type integral_type;
                typedef typename group_type::field_type::modular_type modular_type;
                typedef typename group_type::field_type field_type;
                typedef typename field_type::value_type field_value_type;

                constexpr static inline field_value_type Ai = field_value_type(0, 240);
                constexpr static inline field_value_type Bi = field_value_type(1012, 1012);
                constexpr static inline field_value_type Z = []() { return -field_value_type(2, 1); }();
                constexpr static inline auto h_eff =
                    0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551_cppui636;
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_H2C_SUITES_HPP

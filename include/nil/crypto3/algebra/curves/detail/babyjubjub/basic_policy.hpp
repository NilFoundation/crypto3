//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/fields/babyjubjub/base_field.hpp>
#include <nil/crypto3/algebra/fields/babyjubjub/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    using namespace algebra;
                    
                    /** @brief A struct representing details about base and scalar fields of the size 183 bits and 181
                     * bits respectively. Corresponds to [BabyJubJub](https://eips.ethereum.org/EIPS/eip-2494)
                     * twisted Edwards elliptic curve defined over alt_bn128 scalar field and described by equation ax^2 + y^2 = 1 + dx^2y^2
                     *
                     */
                    struct babyjubjub_basic_policy {
                        constexpr static const std::size_t version = 254;    ///< size of the base field in bits
                        typedef fields::babyjubjub_fq<version> g1_field_type;
                        typedef g1_field_type base_field_type;

                        typedef typename base_field_type::modulus_type number_type;
                        typedef typename base_field_type::extended_modulus_type extended_number_type;

                        constexpr static const number_type base_field_modulus =
                            base_field_type::modulus;    ///< characteristic of the base field

                        typedef fields::babyjubjub_fr<version> scalar_field_type;
                        constexpr static const number_type scalar_field_modulus =
                            scalar_field_type::modulus;    ///< characteristic of the scalar field (order of the group
                                                           ///< of points)

                        constexpr static const number_type p =
                            base_field_modulus;    ///< characteristic of the base field
                        constexpr static const number_type q =
                            scalar_field_modulus;    ///< characteristic of the scalar field (order of the group of
                                                     ///< points)

                        // Edwards representation constants a and d
                        constexpr static const number_type a =              ///< twisted Edwards elliptic curve 
                            0x292FC_cppui18;                                ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                        constexpr static const number_type d =
                            0x292F8_cppui18;                                ///< twisted Edwards elliptic curve 
                                                                            ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                        // Montgomery representation constants A and scale
                        constexpr static const number_type A = 
                            0x292FA_cppui18;
                        constexpr static const number_type scale = 
                            0x01;

                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_zero_fill = {
                            g1_field_type::value_type::zero(), g1_field_type::value_type::one(),
                            g1_field_type::value_type::zero()};

                        // constexpr static const std::array<typename g1_field_type::value_type, 3> g1_one_fill = {
                        //     typename g1_field_type::value_type(0x23343E3445B673D38BCBA38F25645ADB494B1255B1162BB40F41A59F4D4B45E_cppui250),
                        //     typename g1_field_type::value_type(0xC19139CB84C680A6E14116DA06056174A0CFA121E6E5C2450F87D64FC000001_cppui252),
                        //     g1_field_type::value_type::one()};
                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_one_fill = {
                            typename g1_field_type::value_type(0xBB77A6AD63E739B4EACB2E09D6277C12AB8D8010534E0B62893F3F6BB957051_cppui252),
                            typename g1_field_type::value_type(0x25797203F7A0B24925572E1CD16BF9EDFCE0051FB9E133774B3C257A872D7D8B_cppui254),
                            g1_field_type::value_type::one()};
                    };

                    constexpr typename babyjubjub_basic_policy::number_type const
                        babyjubjub_basic_policy::base_field_modulus;

                    constexpr typename babyjubjub_basic_policy::number_type const
                        babyjubjub_basic_policy::scalar_field_modulus;

                    constexpr typename babyjubjub_basic_policy::number_type const babyjubjub_basic_policy::a;
                    constexpr typename babyjubjub_basic_policy::number_type const babyjubjub_basic_policy::d;

                    constexpr typename babyjubjub_basic_policy::number_type const babyjubjub_basic_policy::A;
                    constexpr typename babyjubjub_basic_policy::number_type const babyjubjub_basic_policy::scale;

                    constexpr typename babyjubjub_basic_policy::number_type const babyjubjub_basic_policy::p;
                    constexpr typename babyjubjub_basic_policy::number_type const babyjubjub_basic_policy::q;

                    constexpr std::array<typename babyjubjub_basic_policy::g1_field_type::value_type, 3> const
                        babyjubjub_basic_policy::g1_zero_fill;
                    constexpr std::array<typename babyjubjub_basic_policy::g1_field_type::value_type, 3> const
                        babyjubjub_basic_policy::g1_one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_BASIC_POLICY_HPP

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

// #include <nil/crypto3/algebra/fields/fp3.hpp>
// #include <nil/crypto3/algebra/fields/fp6_2over3.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    using namespace algebra;
                    /** @brief A struct representing details about base and scalar fields.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct edwards_basic_policy;
                    /** @brief A struct representing details about base and scalar fields of the size 183 bits and 181
                     * bits respectively. Corresponds to [BabyJubJub](https://eips.ethereum.org/EIPS/eip-2494)
                     * twisted Edwards elliptic curve defined over alt_bn128 scalar field and described by equation ax^2 + y^2 = 1 + dx^2y^2
                     *
                     */
                    template<>
                    struct edwards_basic_policy<254> {
                        constexpr static const std::size_t version = 254;    ///< size of the base field in bits
                        typedef fields::babyjubjub_fq<version> g1_field_type;
                        typedef g1_field_type base_field_type;
                        // typedef typename fields::fp3<base_field_type> g2_field_type;
                        // typedef typename fields::fp6_2over3<base_field_type> gt_field_type;

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

                        constexpr static const number_type a =              ///< twisted Edwards elliptic curve 
                            0x292FC_cppui18;                                ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                        constexpr static const number_type d =
                            0x292F8_cppui18;                                ///< twisted Edwards elliptic curve 
                                                                            ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
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

                        // constexpr static const std::array<typename g2_field_type::value_type, 3> g2_zero_fill = {
                        //     g2_field_type::value_type::zero(), g2_field_type::value_type::one(),                            // Temporary value for compiling testing
                        //     g2_field_type::value_type::zero()};                                                             // Temporary value for compiling testing

                        // constexpr static const std::array<typename g2_field_type::value_type, 3> g2_one_fill = {
                        //     typename g2_field_type::value_type(0x2F501F9482C0D0D6E80AC55A79FD4D4594CAF187952660_cppui182,   // Temporary value for compiling testing
                        //                                 0x37BF8F1B1CDA11A81E8BB8F41B5FF462C9A13DC7DE1578_cppui182,          // Temporary value for compiling testing
                        //                                 0x2962F0DA0C7928B2CFBBACE3D0354652B6922A764C12D8_cppui182),         // Temporary value for compiling testing
                        //     typename g2_field_type::value_type(0x3CE954C85AD30F53B1BB4C4F87029780F4141927FEB19_cppui178,    // Temporary value for compiling testing
                        //                                 0x2214EB976DE3A4D9DF9C8D5F7AEDFEC337E03A20B32FFF_cppui182,          // Temporary value for compiling testing
                        //                                 0x249774AB0EDC7FE2E665DDBFE08594F3071E0B3AC994C3_cppui182),         // Temporary value for compiling testing
                        //     g2_field_type::value_type::zero()};    //< Third value is not correct!
                    };

                    constexpr typename edwards_basic_policy<254>::number_type const
                        edwards_basic_policy<254>::base_field_modulus;

                    constexpr typename edwards_basic_policy<254>::number_type const
                        edwards_basic_policy<254>::scalar_field_modulus;

                    constexpr typename edwards_basic_policy<254>::number_type const edwards_basic_policy<254>::a;
                    constexpr typename edwards_basic_policy<254>::number_type const edwards_basic_policy<254>::d;

                    constexpr typename edwards_basic_policy<254>::number_type const edwards_basic_policy<254>::p;
                    constexpr typename edwards_basic_policy<254>::number_type const edwards_basic_policy<254>::q;

                    constexpr std::array<typename edwards_basic_policy<254>::g1_field_type::value_type, 3> const
                        edwards_basic_policy<254>::g1_zero_fill;
                    constexpr std::array<typename edwards_basic_policy<254>::g1_field_type::value_type, 3> const
                        edwards_basic_policy<254>::g1_one_fill;
                    // constexpr std::array<typename edwards_basic_policy<254>::g2_field_type::value_type, 3> const
                    //     edwards_basic_policy<254>::g2_zero_fill;
                    // constexpr std::array<typename edwards_basic_policy<254>::g2_field_type::value_type, 3> const
                    //     edwards_basic_policy<254>::g2_one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_BASIC_POLICY_HPP

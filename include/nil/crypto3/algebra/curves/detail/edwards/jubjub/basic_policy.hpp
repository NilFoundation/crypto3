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

#ifndef CRYPTO3_ALGEBRA_CURVES_JUBJUB_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_CURVES_JUBJUB_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/fields/jubjub/base_field.hpp>
#include <nil/crypto3/algebra/fields/jubjub/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/fp3.hpp>
#include <nil/crypto3/algebra/fields/fp6_2over3.hpp>

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
                     * bits respectively. Corresponds to [JubJub](https://raw.githubusercontent.com/zcash/zips/master/protocol/protocol.pdf#jubjub)
                     * twisted Edwards elliptic curve defined over Bls12-381 scalar field and described by equation ax^2 + y^2 = 1 + dx^2y^2
                     *
                     */
                    template<>
                    struct edwards_basic_policy<255> {
                        constexpr static const std::size_t version = 255;    ///< size of the base field in bits
                        typedef fields::jubjub_fq<version> g1_field_type;
                        typedef g1_field_type base_field_type;
                        typedef typename fields::fp3<base_field_type> g2_field_type;
                        typedef typename fields::fp6_2over3<base_field_type> gt_field_type;

                        typedef typename base_field_type::modulus_type number_type;
                        typedef typename base_field_type::extended_modulus_type extended_number_type;

                        constexpr static const number_type base_field_modulus =
                            base_field_type::modulus;    ///< characteristic of the base field

                        typedef fields::jubjub_fr<version> scalar_field_type;
                        constexpr static const number_type scalar_field_modulus =
                            scalar_field_type::modulus;    ///< characteristic of the scalar field (order of the group
                                                           ///< of points)

                        constexpr static const number_type p =
                            base_field_modulus;    ///< characteristic of the base field
                        constexpr static const number_type q =
                            scalar_field_modulus;    ///< characteristic of the scalar field (order of the group of
                                                     ///< points)

                        constexpr static const number_type a =                                              ///< twisted Edwards elliptic curve 
                            0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000_cppui255;    ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                        constexpr static const number_type d =                                              ///< twisted Edwards elliptic curve 
                            0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1_cppui254;    ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                        
                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_zero_fill = {
                            g1_field_type::value_type::zero(), g1_field_type::value_type::one(),
                            g1_field_type::value_type::zero()};

                        // according to https://neuromancer.sk/std/other/JubJub
                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_one_fill = {
                            typename g1_field_type::value_type(0x11dafe5d23e1218086a365b99fbf3d3be72f6afd7d1f72623e6b071492d1122b_cppui253),
                            typename g1_field_type::value_type(0x1d523cf1ddab1a1793132e78c866c0c33e26ba5cc220fed7cc3f870e59d292aa_cppui253),
                            g1_field_type::value_type::one()};    //< Third value is not correct!
                    };

                    constexpr typename edwards_basic_policy<255>::number_type const
                        edwards_basic_policy<255>::base_field_modulus;

                    constexpr typename edwards_basic_policy<255>::number_type const
                        edwards_basic_policy<255>::scalar_field_modulus;

                    constexpr typename edwards_basic_policy<255>::number_type const edwards_basic_policy<255>::a;
                    constexpr typename edwards_basic_policy<255>::number_type const edwards_basic_policy<255>::d;

                    constexpr typename edwards_basic_policy<255>::number_type const edwards_basic_policy<255>::p;
                    constexpr typename edwards_basic_policy<255>::number_type const edwards_basic_policy<255>::q;

                    constexpr std::array<typename edwards_basic_policy<255>::g1_field_type::value_type, 3> const
                        edwards_basic_policy<255>::g1_zero_fill;
                    constexpr std::array<typename edwards_basic_policy<255>::g1_field_type::value_type, 3> const
                        edwards_basic_policy<255>::g1_one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_JUBJUB_BASIC_POLICY_HPP

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

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_377_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_377_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp12_2over3over2.hpp>

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
                    struct bls12_basic_policy;

                    /** @brief A struct representing details about base and scalar fields of the size 377 bits and 253
                     * bits respectively.
                     *
                     */
                    template<>
                    struct bls12_basic_policy<377> {
                        constexpr static const std::size_t version = 377;
                        typedef fields::bls12_fq<version> g1_field_type;
                        using base_field_type = g1_field_type;
                        typedef typename fields::fp2<base_field_type> g2_field_type;
                        typedef typename fields::fp12_2over3over2<base_field_type> gt_field_type;

                        typedef typename base_field_type::modulus_type number_type;
                        constexpr static const number_type base_field_modulus =
                            base_field_type::modulus;    ///< characteristic of the base field
                        typedef typename base_field_type::extended_modulus_type extended_number_type;

                        typedef fields::bls12_fr<version> scalar_field_type;
                        constexpr static const number_type scalar_field_modulus =
                            scalar_field_type::modulus;    ///< characteristic of the scalar field (order of the group
                                                           ///< of points)

                        constexpr static const number_type p =
                            base_field_modulus;    ///< characteristic of the base field
                        constexpr static const number_type q =
                            scalar_field_modulus;    ///< characteristic of the scalar field (order of the group of
                                                     ///< points)

                        constexpr static const number_type a =
                            number_type(0x00);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const number_type b =
                            number_type(0x01);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$

                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_zero_fill = {
                            g1_field_type::value_type::zero(), g1_field_type::value_type::one(),
                            g1_field_type::value_type::zero()};

                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_one_fill = {
                            typename g1_field_type::value_type(
                                0x8848DEFE740A67C8FC6225BF87FF5485951E2CAA9D41BB188282C8BD37CB5CD5481512FFCD394EEAB9B16EB21BE9EF_cppui376),
                            typename g1_field_type::value_type(
                                0x1914A69C5102EFF1F674F5D30AFEEC4BD7FB348CA3E52D96D182AD44FB82305C2FE3D3634A9591AFD82DE55559C8EA6_cppui377),
                            g1_field_type::value_type::one()};

                        constexpr static const std::array<typename g2_field_type::value_type, 3> g2_zero_fill = {
                            g2_field_type::value_type::zero(), g2_field_type::value_type::one(),
                            g2_field_type::value_type::zero()};

                        constexpr static const std::array<typename g2_field_type::value_type, 3> g2_one_fill = {
                            typename g2_field_type::value_type(
                                0xB997FEF930828FE1B9E6A1707B8AA508A3DBFD7FE2246499C709226A0A6FEF49F85B3A375363F4F8F6EA3FBD159F8A_cppui376,
                                0xD6AC33B84947D9845F81A57A136BFA326E915FABC8CD6A57FF133B42D00F62E4E1AF460228CD5184DEAE976FA62596_cppui376),
                            typename g2_field_type::value_type(
                                0x118DD509B2E9A13744A507D515A595DBB7E3B63DF568866473790184BDF83636C94DF2B7A962CB2AF4337F07CB7E622_cppui377,
                                0x185067C6CA76D992F064A432BD9F9BE832B0CAC2D824D0518F77D39E76C3E146AFB825F2092218D038867D7F337A010_cppui377),
                            g2_field_type::value_type::one()};
                    };

                    constexpr typename bls12_basic_policy<377>::number_type const bls12_basic_policy<377>::a;
                    constexpr typename bls12_basic_policy<377>::number_type const bls12_basic_policy<377>::b;

                    constexpr typename bls12_basic_policy<377>::number_type const bls12_basic_policy<377>::p;
                    constexpr typename bls12_basic_policy<377>::number_type const bls12_basic_policy<377>::q;

                    constexpr std::array<typename bls12_basic_policy<377>::g1_field_type::value_type, 3> const
                        bls12_basic_policy<377>::g1_zero_fill;
                    constexpr std::array<typename bls12_basic_policy<377>::g1_field_type::value_type, 3> const
                        bls12_basic_policy<377>::g1_one_fill;
                    constexpr std::array<typename bls12_basic_policy<377>::g2_field_type::value_type, 3> const
                        bls12_basic_policy<377>::g2_zero_fill;
                    constexpr std::array<typename bls12_basic_policy<377>::g2_field_type::value_type, 3> const
                        bls12_basic_policy<377>::g2_one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_BLS12_377_BASIC_POLICY_HPP

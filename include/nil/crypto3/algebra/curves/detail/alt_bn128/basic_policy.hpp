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

#ifndef CRYPTO3_ALGEBRA_CURVES_ALT_BN128_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_CURVES_ALT_BN128_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/fields/alt_bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>

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
                    template<std::size_t Version = 254>
                    struct alt_bn128_basic_policy { };

                    /** @brief A struct representing details about base and scalar fields of the size 254 bits.
                     *
                     */
                    template<>
                    struct alt_bn128_basic_policy<254> {
                        constexpr static const std::size_t version = 254;    ///< curve version

                        typedef fields::alt_bn128_fq<version> g1_field_type;
                        typedef g1_field_type base_field_type;
                        typedef typename fields::fp2<base_field_type> g2_field_type;
                        typedef typename fields::fp12_2over3over2<base_field_type> gt_field_type;

                        typedef typename base_field_type::modulus_type number_type;
                        typedef typename base_field_type::extended_modulus_type extended_number_type;

                        constexpr static const number_type base_field_modulus =
                            base_field_type::modulus;    ///< characteristic of the base field

                        typedef fields::alt_bn128_fr<version> scalar_field_type;
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
                            number_type(0x03);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$

                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_zero_fill = {
                            g1_field_type::value_type::zero(), g1_field_type::value_type::one(),
                            g1_field_type::value_type::zero()};

                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_one_fill = {
                            typename g1_field_type::value_type(
                                0x01),
                            typename g1_field_type::value_type(
                                0x02),
                            typename g1_field_type::value_type(
                                0x01)};
                            
                        constexpr static const std::array<typename g2_field_type::value_type, 3> g2_zero_fill = {
                            g2_field_type::value_type::zero(), g2_field_type::value_type::one(),
                            g2_field_type::value_type::zero()};

                        constexpr static const std::array<typename g2_field_type::value_type, 3> g2_one_fill = {
                            typename g2_field_type::value_type(
                                0x1800DEEF121F1E76426A00665E5C4479674322D4F75EDADD46DEBD5CD992F6ED_cppui254,
                                0x198E9393920D483A7260BFB731FB5D25F1AA493335A9E71297E485B7AEF312C2_cppui254),
                            typename g2_field_type::value_type(
                                0x12C85EA5DB8C6DEB4AAB71808DCB408FE3D1E7690C43D37B4CE6CC0166FA7DAA_cppui254,
                                0x90689D0585FF075EC9E99AD690C3395BC4B313370B38EF355ACDADCD122975B_cppui254),
                            g2_field_type::value_type::one()};
                    };

                    constexpr typename alt_bn128_basic_policy<254>::number_type const alt_bn128_basic_policy<254>::a;
                    constexpr typename alt_bn128_basic_policy<254>::number_type const alt_bn128_basic_policy<254>::b;

                    constexpr typename alt_bn128_basic_policy<254>::number_type const alt_bn128_basic_policy<254>::p;
                    constexpr typename alt_bn128_basic_policy<254>::number_type const alt_bn128_basic_policy<254>::q;

                    constexpr std::array<typename alt_bn128_basic_policy<254>::g1_field_type::value_type, 3> const
                        alt_bn128_basic_policy<254>::g1_zero_fill;
                    constexpr std::array<typename alt_bn128_basic_policy<254>::g1_field_type::value_type, 3> const
                        alt_bn128_basic_policy<254>::g1_one_fill;
                    constexpr std::array<typename alt_bn128_basic_policy<254>::g2_field_type::value_type, 3> const
                        alt_bn128_basic_policy<254>::g2_zero_fill;
                    constexpr std::array<typename alt_bn128_basic_policy<254>::g2_field_type::value_type, 3> const
                        alt_bn128_basic_policy<254>::g2_one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_ALT_BN128_BASIC_POLICY_HPP

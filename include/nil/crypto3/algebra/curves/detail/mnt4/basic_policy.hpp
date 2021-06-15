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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT4_BASIC_POLICY_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT4_BASIC_POLICY_HPP

#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>

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
                    template<std::size_t Version = 298>
                    struct mnt4_basic_policy { };

                    /** @brief A struct representing details about base and scalar fields of the size 298 bits.
                     *
                     */
                    template<>
                    struct mnt4_basic_policy<298> {
                        constexpr static const std::size_t version = 298;    ///< size of the base field in bits
                        typedef fields::mnt4_fq<version> g1_field_type;
                        using base_field_type = g1_field_type;
                        typedef typename fields::fp2<base_field_type> g2_field_type;
                        typedef typename fields::fp4<base_field_type> gt_field_type;

                        typedef typename base_field_type::modulus_type number_type;
                        typedef typename base_field_type::extended_modulus_type extended_number_type;

                        constexpr static const number_type base_field_modulus =
                            base_field_type::modulus;    ///< characteristic of the base field

                        typedef fields::mnt4_scalar_field<version> scalar_field_type;
                        constexpr static const number_type scalar_field_modulus =
                            scalar_field_type::modulus;    ///< characteristic of the scalar field (order of the group
                                                           ///< of points)

                        constexpr static const number_type p =
                            base_field_modulus;    ///< characteristic of the base field
                        constexpr static const number_type q =
                            scalar_field_modulus;    ///< characteristic of the scalar field (order of the group of
                                                     ///< points)

                        constexpr static const number_type a =
                            number_type(0x02);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const number_type b = number_type(
                            0x3545A27639415585EA4D523234FC3EDD2A2070A085C7B980F4E9CD21A515D4B0EF528EC0FD5_cppui298);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$

                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_zero_fill = {
                            g1_field_type::value_type::zero(), g1_field_type::value_type::one(),
                            g1_field_type::value_type::zero()};

                        constexpr static const std::array<typename g1_field_type::value_type, 3> g1_one_fill = {
                            typename g1_field_type::value_type(
                                0x7A2CAF82A1BA85213FE6CA3875AEE86ABA8F73D69060C4079492B948DEA216B5B9C8D2AF46_cppui295),
                            typename g1_field_type::value_type(
                                0x2DB619461CC82672F7F159FEC2E89D0148DCC9862D36778C1AFD96A71E29CBA48E710A48AB2_cppui298),
                            g1_field_type::value_type::one()};
                            
                        constexpr static const std::array<typename g2_field_type::value_type, 3> g2_zero_fill = {
                            g2_field_type::value_type::zero(), g2_field_type::value_type::one(),
                            g2_field_type::value_type::zero()};

                        constexpr static const std::array<typename g2_field_type::value_type, 3> g2_one_fill = {
                            typename g2_field_type::value_type(
                                0x371780491C5660571FF542F2EF89001F205151E12A72CB14F01A931E72DBA7903DF6C09A9A4_cppui298,
                                0x4BA59A3F72DA165DEF838081AF697C851F002F576303302BB6C02C712C968BE32C0AE0A989_cppui295),
                            typename g2_field_type::value_type(
                                0x4B471F33FFAAD868A1C47D6605D31E5C4B3B2E0B60EC98F0F610A5AAFD0D9522BCA4E79F22_cppui295,
                                0x355D05A1C69A5031F3F81A5C100CB7D982F78EC9CFC3B5168ED8D75C7C484FB61A3CBF0E0F1_cppui298),
                            g2_field_type::value_type::one()};
                    };

                    constexpr typename mnt4_basic_policy<298>::number_type const mnt4_basic_policy<298>::a;
                    constexpr typename mnt4_basic_policy<298>::number_type const mnt4_basic_policy<298>::b;

                    constexpr typename mnt4_basic_policy<298>::number_type const mnt4_basic_policy<298>::p;
                    constexpr typename mnt4_basic_policy<298>::number_type const mnt4_basic_policy<298>::q;

                    constexpr std::array<typename mnt4_basic_policy<298>::g1_field_type::value_type, 3> const
                        mnt4_basic_policy<298>::g1_zero_fill;
                    constexpr std::array<typename mnt4_basic_policy<298>::g1_field_type::value_type, 3> const
                        mnt4_basic_policy<298>::g1_one_fill;
                    constexpr std::array<typename mnt4_basic_policy<298>::g2_field_type::value_type, 3> const
                        mnt4_basic_policy<298>::g2_zero_fill;
                    constexpr std::array<typename mnt4_basic_policy<298>::g2_field_type::value_type, 3> const
                        mnt4_basic_policy<298>::g2_one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_MNT4_BASIC_POLICY_HPP

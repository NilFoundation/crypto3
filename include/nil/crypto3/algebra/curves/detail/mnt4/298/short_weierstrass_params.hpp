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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT4_298_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT4_298_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt4/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<>
                    struct mnt4_params<298, forms::short_weierstrass> {

                        using base_field_type = typename mnt4_types<298>::base_field_type;
                        using scalar_field_type = typename mnt4_types<298>::scalar_field_type;

                        constexpr static const typename mnt4_types<298>::integral_type a =
                            typename mnt4_types<298>::integral_type(
                                0x02);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename mnt4_types<298>::integral_type b =
                            typename mnt4_types<298>::integral_type(
                                0x3545A27639415585EA4D523234FC3EDD2A2070A085C7B980F4E9CD21A515D4B0EF528EC0FD5_cppui298);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct mnt4_g1_params<298, forms::short_weierstrass>
                        : public mnt4_params<298, forms::short_weierstrass> {

                        using field_type = typename mnt4_types<298>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = mnt4_types<298>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x7A2CAF82A1BA85213FE6CA3875AEE86ABA8F73D69060C4079492B948DEA216B5B9C8D2AF46_cppui295),
                            typename field_type::value_type(
                                0x2DB619461CC82672F7F159FEC2E89D0148DCC9862D36778C1AFD96A71E29CBA48E710A48AB2_cppui298)};
                    };

                    template<>
                    struct mnt4_g2_params<298, forms::short_weierstrass>
                        : public mnt4_params<298, forms::short_weierstrass> {

                        using field_type = typename mnt4_types<298>::g2_field_type;
                        // using group_type = mnt4_g2<298, forms::short_weierstrass>;

                    private:
                        using g1_field_type = typename mnt4_types<298>::g1_field_type;

                        constexpr static const typename g1_field_type::value_type g1_a = g1_field_type::value_type(a);
                        constexpr static const typename g1_field_type::value_type g1_b = g1_field_type::value_type(b);

                    public:
                        constexpr static const typename field_type::value_type a =
                            typename field_type::value_type(g1_a * field_type::value_type::non_residue,
                                                            g1_field_type::value_type::zero());

                        constexpr static const typename field_type::value_type b =
                            typename field_type::value_type(g1_field_type::value_type::zero(),
                                                            g1_b *field_type::value_type::non_residue);

                        template<typename Coordinates>
                        using group_type = mnt4_types<298>::g2_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x371780491C5660571FF542F2EF89001F205151E12A72CB14F01A931E72DBA7903DF6C09A9A4_cppui298,
                                0x4BA59A3F72DA165DEF838081AF697C851F002F576303302BB6C02C712C968BE32C0AE0A989_cppui295),
                            typename field_type::value_type(
                                0x4B471F33FFAAD868A1C47D6605D31E5C4B3B2E0B60EC98F0F610A5AAFD0D9522BCA4E79F22_cppui295,
                                0x355D05A1C69A5031F3F81A5C100CB7D982F78EC9CFC3B5168ED8D75C7C484FB61A3CBF0E0F1_cppui298)};
                    };

                    constexpr
                        typename mnt4_types<298>::integral_type const mnt4_params<298, forms::short_weierstrass>::a;
                    constexpr
                        typename mnt4_types<298>::integral_type const mnt4_params<298, forms::short_weierstrass>::b;

                    constexpr typename mnt4_g2_params<298, forms::short_weierstrass>::field_type::value_type const
                        mnt4_g2_params<298, forms::short_weierstrass>::a;
                    constexpr typename mnt4_g2_params<298, forms::short_weierstrass>::field_type::value_type const
                        mnt4_g2_params<298, forms::short_weierstrass>::b;

                    constexpr std::array<typename mnt4_g1_params<298, forms::short_weierstrass>::field_type::value_type,
                                         2> const mnt4_g1_params<298, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<typename mnt4_g1_params<298, forms::short_weierstrass>::field_type::value_type,
                                         2> const mnt4_g1_params<298, forms::short_weierstrass>::one_fill;

                    constexpr std::array<typename mnt4_g2_params<298, forms::short_weierstrass>::field_type::value_type,
                                         2> const mnt4_g2_params<298, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<typename mnt4_g2_params<298, forms::short_weierstrass>::field_type::value_type,
                                         2> const mnt4_g2_params<298, forms::short_weierstrass>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_MNT4_298_PARAMS_HPP

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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT6_298_SHORT_WEIERSTRASS_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT6_298_SHORT_WEIERSTRASS_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt6/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<>
                    struct mnt6_params<298, forms::short_weierstrass> {

                        using base_field_type = typename mnt6_types<298>::base_field_type;
                        using scalar_field_type = typename mnt6_types<298>::scalar_field_type;

                        constexpr static const typename mnt6_types<298>::integral_type a =
                            typename mnt6_types<298>::integral_type(
                                0x0B);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename mnt6_types<298>::integral_type b =
                            typename mnt6_types<298>::integral_type(
                                0xD68C7B1DC5DD042E957B71C44D3D6C24E683FC09B420B1A2D263FDE47DDBA59463D0C65282_cppui296);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct mnt6_g1_params<298, forms::short_weierstrass>
                        : public mnt6_params<298, forms::short_weierstrass> {

                        using field_type = typename mnt6_types<298>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = mnt6_types<298>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(
                                0x2A4FEEE24FD2C69D1D90471B2BA61ED56F9BAD79B57E0B4C671392584BDADEBC01ABBC0447D_cppui298),
                            typename field_type::value_type(
                                0x32986C245F6DB2F82F4E037BF7AFD69CBFCBFF07FC25D71E9C75E1B97208A333D73D91D3028_cppui298)};
                    };

                    template<>
                    struct mnt6_g2_params<298, forms::short_weierstrass>
                        : public mnt6_params<298, forms::short_weierstrass> {

                        using field_type = typename mnt6_types<298>::g2_field_type;

                        template<typename Coordinates>
                        using group_type = mnt6_types<298>::g2_type<forms::short_weierstrass, Coordinates>;

                    private:
                        using g1_field_type = typename mnt6_types<298>::g1_field_type;

                        constexpr static const typename g1_field_type::value_type g1_a = g1_field_type::value_type(a);
                        constexpr static const typename g1_field_type::value_type g1_b = g1_field_type::value_type(b);

                    public:
                        constexpr static const typename field_type::value_type a =
                            typename field_type::value_type(g1_field_type::value_type::zero(),
                                                            g1_field_type::value_type::zero(),
                                                            g1_a);

                        constexpr static const typename field_type::value_type b =
                            typename field_type::value_type(g1_b * field_type::value_type::non_residue,
                                                            g1_field_type::value_type::zero(),
                                                            g1_field_type::value_type::zero());

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(
                                0x34F7320A12B56CE532BCCB3B44902CBAA723CD60035ADA7404B743AD2E644AD76257E4C6813_cppui298,
                                0xCF41620BAA52EEC50E61A70AB5B45F681952E0109340FEC84F1B2890ABA9B15CAC5A0C80FA_cppui296,
                                0x11F99170E10E326433CCCB8032FB48007CA3C4E105CF31B056AC767E2CB01258391BD4917CE_cppui297),
                            typename field_type::value_type(
                                0x3A65968F03CC64D62AD05C79C415E07EBD38B363EC48309487C0B83E1717A582C1B60FECC91_cppui298,
                                0xCA5E8427E5DB1506C1A24CEFC2451AB3ACCAEA5DB82DCB0C7117CC74402FAA5B2C37685C6E_cppui296,
                                0xF75D2DD88302C9A4EF941307629A1B3E197277D83ABB715F647C2E55A27BAF782F5C60E7F7_cppui296)};
                    };

                    constexpr
                        typename mnt6_types<298>::integral_type const mnt6_params<298, forms::short_weierstrass>::a;
                    constexpr
                        typename mnt6_types<298>::integral_type const mnt6_params<298, forms::short_weierstrass>::b;

                    constexpr typename mnt6_g2_params<298, forms::short_weierstrass>::field_type::value_type const
                        mnt6_g2_params<298, forms::short_weierstrass>::a;
                    constexpr typename mnt6_g2_params<298, forms::short_weierstrass>::field_type::value_type const
                        mnt6_g2_params<298, forms::short_weierstrass>::b;

                    constexpr std::array<typename mnt6_g1_params<298, forms::short_weierstrass>::field_type::value_type,
                                         3> const mnt6_g1_params<298, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<typename mnt6_g1_params<298, forms::short_weierstrass>::field_type::value_type,
                                         3> const mnt6_g1_params<298, forms::short_weierstrass>::one_fill;

                    constexpr std::array<typename mnt6_g2_params<298, forms::short_weierstrass>::field_type::value_type,
                                         3> const mnt6_g2_params<298, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<typename mnt6_g2_params<298, forms::short_weierstrass>::field_type::value_type,
                                         3> const mnt6_g2_params<298, forms::short_weierstrass>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_MNT6_298_SHORT_WEIERSTRASS_PARAMS_HPP

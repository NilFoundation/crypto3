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

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_381_SHORT_WEIERSTRASS_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_381_SHORT_WEIERSTRASS_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/bls12/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<>
                    struct bls12_params<381, forms::short_weierstrass> {

                        using base_field_type = typename bls12_types<381>::base_field_type;
                        using scalar_field_type = typename bls12_types<381>::scalar_field_type;

                        constexpr static const typename bls12_types<381>::integral_type a =
                            typename bls12_types<381>::integral_type(
                                0x00);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                        constexpr static const typename bls12_types<381>::integral_type b =
                            typename bls12_types<381>::integral_type(
                                0x04);    ///< coefficient of short Weierstrass curve $y^2=x^3+a*x+b$
                    };

                    template<>
                    struct bls12_g1_params<381, forms::short_weierstrass>
                        : public bls12_params<381, forms::short_weierstrass> {

                        using field_type = typename bls12_types<381>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = bls12_types<381>::g1_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB_cppui381),
                            typename field_type::value_type(
                                0x8B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1_cppui380)};
                    };

                    template<>
                    struct bls12_g2_params<381, forms::short_weierstrass>
                        : public bls12_params<381, forms::short_weierstrass> {

                        using field_type = typename bls12_types<381>::g2_field_type;

                        constexpr static const typename field_type::value_type twist =
                            typename field_type::value_type(field_type::value_type::underlying_type::one(),
                                                            field_type::value_type::underlying_type::one());
                        constexpr static const typename field_type::value_type::underlying_type g1_b =
                            typename field_type::value_type::underlying_type(b);
                        constexpr static const typename field_type::value_type b = g1_b * twist;

                        template<typename Coordinates>
                        using group_type = bls12_types<381>::g2_type<forms::short_weierstrass, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x24AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8_cppui378,
                                0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E_cppui381),
                            typename field_type::value_type(
                                0xCE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801_cppui380,
                                0x606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE_cppui379)};
                    };

                    constexpr
                        typename bls12_types<381>::integral_type const bls12_params<381, forms::short_weierstrass>::a;
                    constexpr
                        typename bls12_types<381>::integral_type const bls12_params<381, forms::short_weierstrass>::b;

                    constexpr typename bls12_g2_params<381, forms::short_weierstrass>::field_type::value_type const
                        bls12_g2_params<381, forms::short_weierstrass>::b;

                    constexpr std::array<
                        typename bls12_g1_params<381, forms::short_weierstrass>::field_type::value_type,
                        2> const bls12_g1_params<381, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename bls12_g1_params<381, forms::short_weierstrass>::field_type::value_type,
                        2> const bls12_g1_params<381, forms::short_weierstrass>::one_fill;

                    constexpr std::array<
                        typename bls12_g2_params<381, forms::short_weierstrass>::field_type::value_type,
                        2> const bls12_g2_params<381, forms::short_weierstrass>::zero_fill;
                    constexpr std::array<
                        typename bls12_g2_params<381, forms::short_weierstrass>::field_type::value_type,
                        2> const bls12_g2_params<381, forms::short_weierstrass>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BLS12_381_SHORT_WEIERSTRASS_PARAMS_HPP

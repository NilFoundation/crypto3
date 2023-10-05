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

#ifndef CRYPTO3_ALGEBRA_CURVES_CURVE25519_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_CURVE25519_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/curve25519/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    /**
                     * @brief https://neuromancer.sk/std/other/Curve25519#
                     */
                    template<>
                    class curve25519_params<forms::montgomery> {
                    public:
                        using base_field_type = typename curve25519_types::base_field_type;
                        using scalar_field_type = typename curve25519_types::scalar_field_type;

                        constexpr static typename curve25519_types::integral_type a =
                            typename curve25519_types::integral_type(
                                0x76d06);    ///< coefficient of Montgomery curve $b*y^2=x^3+a*x^2+x$
                        constexpr static typename curve25519_types::integral_type b =
                            typename curve25519_types::integral_type(
                                0x01);    ///< coefficient of Montgomery curve $b*y^2=x^3+a*x^2+x$
                    };

                    template<>
                    class curve25519_g1_params<forms::montgomery> : public curve25519_params<forms::montgomery> {
                    public:
                        using field_type = typename curve25519_types::g1_field_type;

                        template<typename Coordinates>
                        using group_type = curve25519_types::g1_type<forms::montgomery, Coordinates>;
#ifdef __ZKLLVM__
#else
                        constexpr static std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(0x09),
                            typename field_type::value_type(
                                0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9_cppui254)};
#endif
                    };

                    /**
                     * @brief https://neuromancer.sk/std/other/Ed25519#
                     */
                    template<>
                    class curve25519_params<forms::twisted_edwards> {
                    public:
                        using base_field_type = typename curve25519_types::base_field_type;
                        using scalar_field_type = typename curve25519_types::scalar_field_type;
#ifdef __ZKLLVM__
#else
                        constexpr static typename curve25519_types::integral_type a = typename curve25519_types::integral_type(
                            0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec_cppui255);    ///< coefficient
                                                                                                             ///< of
                                                                                                             ///< Twisted
                                                                                                             ///< Edwards
                                                                                                             ///< curves
                                                                                                             ///< $a*x^2+y^2=1+d*x^2*y^2$
                        constexpr static typename curve25519_types::integral_type d = typename curve25519_types::integral_type(
                            0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3_cppui255);    ///< coefficient
                                                                                                             ///< of
                                                                                                             ///< Twisted
                                                                                                             ///< Edwards
                                                                                                             ///< curves
                                                                                                             ///< $a*x^2+y^2=1+d*x^2*y^2$
#endif
                    };

                    template<>
                    class curve25519_g1_params<forms::twisted_edwards>
                        : public curve25519_params<forms::twisted_edwards> {
                    public:
                        using field_type = typename curve25519_types::g1_field_type;

                        template<typename Coordinates>
                        using group_type = curve25519_types::g1_type<forms::twisted_edwards, Coordinates>;
#ifdef __ZKLLVM__
#else
                        constexpr static std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A_cppui254),
                            typename field_type::value_type(
                                0x6666666666666666666666666666666666666666666666666666666666666658_cppui255)};
#endif
                    };
#ifdef __ZKLLVM__
#else
                    constexpr typename curve25519_types::integral_type curve25519_params<forms::montgomery>::a;
                    constexpr typename curve25519_types::integral_type curve25519_params<forms::montgomery>::b;

                    constexpr std::array<typename curve25519_g1_params<forms::montgomery>::field_type::value_type, 2>
                        curve25519_g1_params<forms::montgomery>::zero_fill;
                    constexpr std::array<typename curve25519_g1_params<forms::montgomery>::field_type::value_type, 2>
                        curve25519_g1_params<forms::montgomery>::one_fill;

                    constexpr typename curve25519_types::integral_type curve25519_params<forms::twisted_edwards>::a;
                    constexpr typename curve25519_types::integral_type curve25519_params<forms::twisted_edwards>::d;

                    constexpr std::array<typename curve25519_g1_params<forms::twisted_edwards>::field_type::value_type,
                                         2>
                        curve25519_g1_params<forms::twisted_edwards>::zero_fill;
                    constexpr std::array<typename curve25519_g1_params<forms::twisted_edwards>::field_type::value_type,
                                         2>
                        curve25519_g1_params<forms::twisted_edwards>::one_fill;
#endif
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_CURVE25519_PARAMS_HPP

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

#ifndef CRYPTO3_ALGEBRA_CURVES_JUBJUB_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_JUBJUB_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/jubjub/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    template<>
                    struct jubjub_params<forms::twisted_edwards> {
                        using base_field_type = typename jubjub_types::base_field_type;
                        using scalar_field_type = typename jubjub_types::scalar_field_type;

                        // Edwards representation constants a and d
                        constexpr static const typename jubjub_types::integral_type
                            a =    ///< twisted Edwards elliptic curve
                            0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000_cppui255;    ///< described
                                                                                                            ///< by
                                                                                                            ///< equation
                                                                                                            ///< ax^2 +
                                                                                                            ///< y^2 = 1
                                                                                                            ///< +
                                                                                                            ///< dx^2y^2
                        constexpr static const typename jubjub_types::integral_type
                            d =    ///< twisted Edwards elliptic curve
                            0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1_cppui254;    ///< described
                                                                                                            ///< by
                                                                                                            ///< equation
                                                                                                            ///< ax^2 +
                                                                                                            ///< y^2 = 1
                                                                                                            ///< +
                                                                                                            ///< dx^2y^2
                        static constexpr std::size_t cofactor = 8;
                    };

                    constexpr typename jubjub_types::integral_type const jubjub_params<forms::twisted_edwards>::a;
                    constexpr typename jubjub_types::integral_type const jubjub_params<forms::twisted_edwards>::d;

                    template<>
                    struct jubjub_params<forms::montgomery> {
                        using base_field_type = typename jubjub_types::base_field_type;
                        using scalar_field_type = typename jubjub_types::scalar_field_type;

                        // Montgomery representation constants A and B
                        constexpr static const typename jubjub_types::integral_type
                            A =                ///< Montgomery elliptic curve
                            0xA002_cppui16;    ///< described by equation b*y^2 = x^3 + a*x^2 + x
                        constexpr static const typename jubjub_types::integral_type
                            B =      ///< Montgomery elliptic curve
                            0x01;    ///< described by equation b*y^2 = x^3 + a*x^2 + x
                        static constexpr std::size_t cofactor = 8;
                    };

                    constexpr typename jubjub_types::integral_type const jubjub_params<forms::montgomery>::A;
                    constexpr typename jubjub_types::integral_type const jubjub_params<forms::montgomery>::B;

                    template<>
                    struct jubjub_g1_params<forms::twisted_edwards> : public jubjub_params<forms::twisted_edwards> {
                        using field_type = typename jubjub_params<forms::twisted_edwards>::base_field_type;

                        template<typename Coordinates>
                        using group_type = jubjub_types::g1_type<forms::twisted_edwards, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        // according to https://neuromancer.sk/std/other/JubJub
                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x11dafe5d23e1218086a365b99fbf3d3be72f6afd7d1f72623e6b071492d1122b_cppui253),
                            typename field_type::value_type(
                                0x1d523cf1ddab1a1793132e78c866c0c33e26ba5cc220fed7cc3f870e59d292aa_cppui253)};
                    };

                    constexpr std::array<typename jubjub_g1_params<forms::twisted_edwards>::base_field_type::value_type,
                                         2> const jubjub_g1_params<forms::twisted_edwards>::zero_fill;
                    constexpr std::array<typename jubjub_g1_params<forms::twisted_edwards>::base_field_type::value_type,
                                         2> const jubjub_g1_params<forms::twisted_edwards>::one_fill;

                    template<>
                    struct jubjub_g1_params<forms::montgomery> : public jubjub_params<forms::montgomery> {
                        using field_type = typename jubjub_params<forms::twisted_edwards>::base_field_type;

                        template<typename Coordinates>
                        using group_type = jubjub_types::g1_type<forms::montgomery, Coordinates>;

                        // TODO: check correctness of the base point coordinates
                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(
                                0x52a47af6ec47deb77d663b6a45b148d1ccdaa4e2299ecfbd5504c409b3ea62c0_cppui255),
                            typename field_type::value_type(
                                0x399b020832f6a499ba9d5334ca932dc9faaeea860e9a49a8f8854f55f3b676d4_cppui254)};
                    };

                    constexpr std::array<typename jubjub_g1_params<forms::montgomery>::base_field_type::value_type,
                                         2> const jubjub_g1_params<forms::montgomery>::one_fill;
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_JUBJUB_PARAMS_HPP

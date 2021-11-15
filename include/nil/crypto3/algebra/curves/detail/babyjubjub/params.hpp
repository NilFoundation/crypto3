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

#ifndef CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/babyjubjub/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    template<>
                    struct babyjubjub_params<forms::twisted_edwards> {
                        using base_field_type = typename babyjubjub_types::base_field_type;
                        using scalar_field_type = typename babyjubjub_types::scalar_field_type;

                        // Edwards representation constants a and d
                        constexpr static const typename babyjubjub_types::integral_type
                            a =                 ///< twisted Edwards elliptic curve
                            0x292FC_cppui18;    ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                        constexpr static const typename babyjubjub_types::integral_type
                            d =                 ///< twisted Edwards elliptic curve
                            0x292F8_cppui18;    ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                    };

                    constexpr
                        typename babyjubjub_types::integral_type const babyjubjub_params<forms::twisted_edwards>::a;
                    constexpr
                        typename babyjubjub_types::integral_type const babyjubjub_params<forms::twisted_edwards>::d;

                    template<>
                    struct babyjubjub_params<forms::montgomery> {
                        using base_field_type = typename babyjubjub_types::base_field_type;
                        using scalar_field_type = typename babyjubjub_types::scalar_field_type;

                        // Montgomery representation constants A and B
                        constexpr static const typename babyjubjub_types::integral_type
                            A =                 ///< Montgomery elliptic curve
                            0x292FA_cppui18;    ///< described by equation b*y^2 = x^3 + a*x^2 + x
                        constexpr static const typename babyjubjub_types::integral_type
                            B =      ///< Montgomery elliptic curve
                            0x01;    ///< described by equation b*y^2 = x^3 + a*x^2 + x
                    };

                    constexpr typename babyjubjub_types::integral_type const babyjubjub_params<forms::montgomery>::A;
                    constexpr typename babyjubjub_types::integral_type const babyjubjub_params<forms::montgomery>::B;

                    template<>
                    struct babyjubjub_g1_params<forms::twisted_edwards>
                        : public babyjubjub_params<forms::twisted_edwards> {
                        using field_type = typename babyjubjub_params<forms::twisted_edwards>::base_field_type;

                        template<typename Coordinates>
                        using group_type = babyjubjub_types::g1_type<forms::twisted_edwards, Coordinates>;

                        constexpr static const std::array<typename base_field_type::value_type, 2> zero_fill = {
                            base_field_type::value_type::zero(), base_field_type::value_type::one()};

                        constexpr static const std::array<typename base_field_type::value_type, 2> one_fill = {
                            typename base_field_type::value_type(
                                0xBB77A6AD63E739B4EACB2E09D6277C12AB8D8010534E0B62893F3F6BB957051_cppui252),
                            typename base_field_type::value_type(
                                0x25797203F7A0B24925572E1CD16BF9EDFCE0051FB9E133774B3C257A872D7D8B_cppui254)};
                    };

                    constexpr std::array<
                        typename babyjubjub_g1_params<forms::twisted_edwards>::base_field_type::value_type, 2> const
                        babyjubjub_g1_params<forms::twisted_edwards>::zero_fill;
                    constexpr std::array<
                        typename babyjubjub_g1_params<forms::twisted_edwards>::base_field_type::value_type, 2> const
                        babyjubjub_g1_params<forms::twisted_edwards>::one_fill;

                    template<>
                    struct babyjubjub_g1_params<forms::montgomery> : public babyjubjub_params<forms::montgomery> {
                        using field_type = typename babyjubjub_params<forms::montgomery>::base_field_type;

                        template<typename Coordinates>
                        using group_type = babyjubjub_types::g1_type<forms::montgomery, Coordinates>;

                        constexpr static const std::array<typename base_field_type::value_type, 2> one_fill = {
                            typename base_field_type::value_type(
                                0xfbc9ac10c16d45d4eacdd6489fa006480b17a811cdba46922896085f89faaf6_cppui252),
                            typename base_field_type::value_type(
                                0x203a710160811d5c07ebaeb8fe1d9ce201c66b970d66f18d0d2b264c195309aa_cppui254)};
                    };

                    constexpr std::array<typename babyjubjub_g1_params<forms::montgomery>::base_field_type::value_type,
                                         2> const babyjubjub_g1_params<forms::montgomery>::one_fill;
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_PARAMS_HPP

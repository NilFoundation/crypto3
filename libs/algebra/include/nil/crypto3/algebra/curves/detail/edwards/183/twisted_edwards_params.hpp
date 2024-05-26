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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_TWISTED_EDWARDS_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_TWISTED_EDWARDS_PARAMS_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/183/edwards_params.hpp>
#include <nil/crypto3/algebra/curves/forms.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<>
                    struct edwards_params<183, forms::twisted_edwards> {

                        using base_field_type = typename edwards_types<183>::base_field_type;
                        using scalar_field_type = typename edwards_types<183>::scalar_field_type;

                        constexpr static const typename edwards_types<183>::integral_type a =
                            typename edwards_types<183>::integral_type(0x01);
                        constexpr static const typename edwards_types<183>::integral_type d =
                            edwards_params<183, forms::edwards>::d;
                    };

                    template<>
                    struct edwards_g1_params<183, forms::twisted_edwards>
                        : public edwards_params<183, forms::twisted_edwards> {

                        using field_type = typename edwards_types<183>::g1_field_type;

                        template<typename Coordinates>
                        using group_type = edwards_types<183>::g1_type<forms::twisted_edwards, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill =
                            edwards_g1_params<183, forms::edwards>::zero_fill;

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill =
                            edwards_g1_params<183, forms::edwards>::one_fill;
                    };

                    template<>
                    struct edwards_g2_params<183, forms::twisted_edwards>
                        : public edwards_params<183, forms::twisted_edwards> {

                        using field_type = typename edwards_types<183>::g2_field_type;

                        template<typename Coordinates>
                        using group_type = edwards_types<183>::g2_type<forms::twisted_edwards, Coordinates>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill =
                            edwards_g2_params<183, forms::edwards>::zero_fill;

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill =
                            edwards_g2_params<183, forms::edwards>::one_fill;
                    };

                    constexpr typename edwards_params<183, forms::twisted_edwards>::base_field_type::integral_type const
                        edwards_params<183, forms::twisted_edwards>::a;
                    constexpr typename edwards_params<183, forms::twisted_edwards>::base_field_type::integral_type const
                        edwards_params<183, forms::twisted_edwards>::d;

                    constexpr std::array<
                        typename edwards_g1_params<183, forms::twisted_edwards>::field_type::value_type, 2> const
                        edwards_g1_params<183, forms::twisted_edwards>::zero_fill;
                    constexpr std::array<
                        typename edwards_g1_params<183, forms::twisted_edwards>::field_type::value_type, 2> const
                        edwards_g1_params<183, forms::twisted_edwards>::one_fill;

                    constexpr std::array<
                        typename edwards_g2_params<183, forms::twisted_edwards>::field_type::value_type, 2> const
                        edwards_g2_params<183, forms::twisted_edwards>::zero_fill;
                    constexpr std::array<
                        typename edwards_g2_params<183, forms::twisted_edwards>::field_type::value_type, 2> const
                        edwards_g2_params<183, forms::twisted_edwards>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_TWISTED_EDWARDS_PARAMS_HPP

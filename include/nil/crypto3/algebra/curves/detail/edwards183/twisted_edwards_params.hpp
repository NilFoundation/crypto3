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

#include <nil/crypto3/algebra/curves/detail/edwards183/edwards_params.hpp>

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<std::size_t Version, 
                             typename Form>
                    struct edwards_params;

                    template<std::size_t Version, 
                             typename Form, 
                             typename Coordinates>
                    struct edwards_g1_params;

                    template<std::size_t Version, 
                             typename Form, 
                             typename Coordinates>
                    struct edwards_g2_params;

                    template<>
                    struct edwards_params<183, forms::twisted_edwards> : public edwards_basic_params<183> {

                        using base_field_type = typename edwards_basic_params<183>::base_field_type;
                        using scalar_field_type = typename edwards_basic_params<183>::scalar_field_type;

                        constexpr static const typename base_field_type::modulus_type a =
                            typename base_field_type::modulus_type(0x01);
                        constexpr static const typename base_field_type::modulus_type d = 
                            edwards_params<183, forms::edwards>::d;
                    };

                    template<>
                    struct edwards_g1_params<183, forms::twisted_edwards, 
                        coordinates::inverted> : 
                        public edwards_params<183, forms::twisted_edwards> {

                        using field_type = typename edwards_basic_params<183>::g1_field_type;
                        using group_type = edwards_g1<183, forms::twisted_edwards,  
                            coordinates::inverted>;

                        using affine_params = edwards_g1_params<183, 
                            forms::twisted_edwards, 
                            coordinates::affine>;

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = 
                            edwards_g1_params<183, forms::edwards, coordinates::inverted>::zero_fill;

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = 
                            edwards_g1_params<183, forms::edwards, coordinates::inverted>::one_fill;
                    };

                    template<>
                    struct edwards_g1_params<183, 
                        forms::twisted_edwards, 
                        coordinates::affine> : 
                            public edwards_params<183, forms::twisted_edwards> {

                        using field_type = typename edwards_basic_params<183>::g1_field_type;
                        using group_type = edwards_g1<183, forms::twisted_edwards,  
                            coordinates::inverted>;

                        using inverted_params = edwards_g1_params<183, 
                            forms::twisted_edwards, 
                            coordinates::inverted>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            inverted_params::zero_fill[2]/inverted_params::zero_fill[0], 
                            inverted_params::zero_fill[2]/inverted_params::zero_fill[1]};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            inverted_params::one_fill[2]/inverted_params::one_fill[0], 
                            inverted_params::one_fill[2]/inverted_params::one_fill[1]};
                    };

                    template<>
                    struct edwards_g2_params<183, forms::twisted_edwards, 
                        coordinates::inverted> : 
                        public edwards_params<183, forms::twisted_edwards> {

                        using field_type = typename edwards_basic_params<183>::g2_field_type;
                        using group_type = edwards_g2<183, forms::twisted_edwards,  
                            coordinates::inverted>;

                        using affine_params = edwards_g2_params<183, 
                            forms::twisted_edwards, 
                            coordinates::affine>;

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = 
                            edwards_g2_params<183, forms::edwards, coordinates::inverted>::zero_fill;

                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = 
                            edwards_g2_params<183, forms::edwards, coordinates::inverted>::one_fill;
                    };

                    template<>
                    struct edwards_g2_params<183, 
                        forms::twisted_edwards, 
                        coordinates::affine> : 
                            public edwards_params<183, forms::twisted_edwards> {

                        using field_type = typename edwards_basic_params<183>::g2_field_type;
                        using group_type = edwards_g2<183, forms::twisted_edwards,  
                            coordinates::inverted>;

                        using inverted_params = edwards_g2_params<183, 
                            forms::twisted_edwards, 
                            coordinates::inverted>;

                        constexpr static const std::array<typename field_type::value_type, 2> zero_fill = {
                            inverted_params::zero_fill[2]*inverted_params::zero_fill[0].inversed(), 
                            inverted_params::zero_fill[2]*inverted_params::zero_fill[1].inversed()};

                        constexpr static const std::array<typename field_type::value_type, 2> one_fill = {
                            inverted_params::one_fill[2]*inverted_params::one_fill[0].inversed(), 
                            inverted_params::one_fill[2]*inverted_params::one_fill[1].inversed()};
                    };

                    constexpr typename edwards_params<183, forms::twisted_edwards>::base_field_type::modulus_type const edwards_params<183, forms::twisted_edwards>::a;
                    constexpr typename edwards_params<183, forms::twisted_edwards>::base_field_type::modulus_type const edwards_params<183, forms::twisted_edwards>::d;

                    constexpr std::array<typename edwards_g1_params<183, forms::twisted_edwards, 
                        coordinates::inverted>::field_type::value_type, 3> const
                        edwards_g1_params<183, forms::twisted_edwards, 
                            coordinates::inverted>::zero_fill;
                    constexpr std::array<typename edwards_g1_params<183, forms::twisted_edwards, 
                        coordinates::inverted>::field_type::value_type, 3> const
                        edwards_g1_params<183, forms::twisted_edwards, 
                            coordinates::inverted>::one_fill;

                    constexpr std::array<typename edwards_g1_params<183, forms::twisted_edwards, 
                        coordinates::affine>::field_type::value_type, 2> const
                        edwards_g1_params<183, forms::twisted_edwards, 
                            coordinates::affine>::zero_fill;
                    constexpr std::array<typename edwards_g1_params<183, forms::twisted_edwards, 
                        coordinates::affine>::field_type::value_type, 2> const
                        edwards_g1_params<183, forms::twisted_edwards, 
                            coordinates::affine>::one_fill;

                    constexpr std::array<typename edwards_g2_params<183, forms::twisted_edwards, 
                        coordinates::inverted>::field_type::value_type, 3> const
                        edwards_g2_params<183, forms::twisted_edwards, 
                            coordinates::inverted>::zero_fill;
                    constexpr std::array<typename edwards_g2_params<183, forms::twisted_edwards, 
                        coordinates::inverted>::field_type::value_type, 3> const
                        edwards_g2_params<183, forms::twisted_edwards, 
                            coordinates::inverted>::one_fill;

                    constexpr std::array<typename edwards_g2_params<183, forms::twisted_edwards, 
                        coordinates::affine>::field_type::value_type, 2> const
                        edwards_g2_params<183, forms::twisted_edwards, 
                            coordinates::affine>::zero_fill;
                    constexpr std::array<typename edwards_g2_params<183, forms::twisted_edwards, 
                        coordinates::affine>::field_type::value_type, 2> const
                        edwards_g2_params<183, forms::twisted_edwards, 
                            coordinates::affine>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_183_TWISTED_EDWARDS_PARAMS_HPP

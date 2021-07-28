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

#include <nil/crypto3/algebra/fields/jubjub/base_field.hpp>
#include <nil/crypto3/algebra/fields/jubjub/scalar_field.hpp>

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<typename Form, 
                             typename Coordinates>
                    struct jubjub_g1;

                    template <typename Form>
                    struct jubjub_params;

                    template <typename Form, 
                              typename Coordinates>
                    struct jubjub_g1_params;

                    using namespace algebra;
                    /** @brief A struct representing details about base and scalar fields of the corresponding size 183 bits and 181
                     * bits respectively. Corresponds to [JubJub](https://raw.githubusercontent.com/zcash/zips/master/protocol/protocol.pdf#jubjub)
                     * twisted Edwards elliptic curve defined over Bls12-381 scalar field and described by equation ax^2 + y^2 = 1 + dx^2y^2
                     *
                     */
                    struct jubjub_basic_params {
                        using base_field_type = fields::jubjub_fq;
                        using scalar_field_type = fields::jubjub_fr;
                    };

                    template <>
                    struct jubjub_params<forms::twisted_edwards> : public jubjub_basic_params {

                        using base_field_type = typename jubjub_basic_params::base_field_type;
                        using scalar_field_type = typename jubjub_basic_params::scalar_field_type;

                        // Edwards representation constants a and d
                        constexpr static const typename base_field_type::modulus_type a =                                              ///< twisted Edwards elliptic curve 
                            0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000_cppui255;    ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                        constexpr static const typename base_field_type::modulus_type d =                                              ///< twisted Edwards elliptic curve 
                            0x2A9318E74BFA2B48F5FD9207E6BD7FD4292D7F6D37579D2601065FD6D6343EB1_cppui254;    ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                    };

                    template <>
                    struct jubjub_params<forms::montgomery> : public jubjub_basic_params {

                        using base_field_type = typename jubjub_basic_params::base_field_type;
                        using scalar_field_type = typename jubjub_basic_params::scalar_field_type;

                        // Montgomery representation constants A and scale
                        constexpr static const typename base_field_type::modulus_type A = 
                            0xA002_cppui16;
                        constexpr static const typename base_field_type::modulus_type scale = 
                            0x01;
                    };

                    template <>
                    struct jubjub_g1_params<
                        forms::twisted_edwards, 
                        coordinates::affine> : 
                            public jubjub_params<forms::twisted_edwards> {

                        using field_type = typename jubjub_params<forms::twisted_edwards>::base_field_type;
                        using group_type = jubjub_g1<forms::twisted_edwards, 
                            coordinates::affine>;

                        constexpr static const std::array<typename field_type::value_type, 3> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one(),
                            field_type::value_type::zero()};

                        // according to https://neuromancer.sk/std/other/JubJub
                        constexpr static const std::array<typename field_type::value_type, 3> one_fill = {
                            typename field_type::value_type(0x11dafe5d23e1218086a365b99fbf3d3be72f6afd7d1f72623e6b071492d1122b_cppui253),
                            typename field_type::value_type(0x1d523cf1ddab1a1793132e78c866c0c33e26ba5cc220fed7cc3f870e59d292aa_cppui253),
                            field_type::value_type::one()};    //< Third value is not correct!
                    };

                    constexpr typename jubjub_params<forms::twisted_edwards>::base_field_type::modulus_type const jubjub_params<forms::twisted_edwards>::a;
                    constexpr typename jubjub_params<forms::twisted_edwards>::base_field_type::modulus_type const jubjub_params<forms::twisted_edwards>::d;

                    constexpr typename jubjub_params<forms::montgomery>::base_field_type::modulus_type const jubjub_params<forms::montgomery>::A;
                    constexpr typename jubjub_params<forms::montgomery>::base_field_type::modulus_type const jubjub_params<forms::montgomery>::scale;

                    constexpr std::array<typename jubjub_g1_params<forms::twisted_edwards, 
                        coordinates::affine>::base_field_type::value_type, 3> const
                        jubjub_g1_params<forms::twisted_edwards, 
                            coordinates::affine>::zero_fill;
                    constexpr std::array<typename jubjub_g1_params<forms::twisted_edwards, 
                        coordinates::affine>::base_field_type::value_type, 3> const
                        jubjub_g1_params<forms::twisted_edwards, 
                            coordinates::affine>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_JUBJUB_PARAMS_HPP

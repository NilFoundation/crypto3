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

#include <nil/crypto3/algebra/fields/babyjubjub/base_field.hpp>
#include <nil/crypto3/algebra/fields/babyjubjub/scalar_field.hpp>

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
                    struct babyjubjub_g1;

                    template <typename Form>
                    struct babyjubjub_params;

                    template<typename Form, 
                             typename Coordinates>
                    struct babyjubjub_g1_params;

                    using namespace algebra;
                    
                    /** @brief A struct representing details about base and scalar fields of the size 183 bits and 181
                     * bits respectively. Corresponds to [BabyJubJub](https://eips.ethereum.org/EIPS/eip-2494)
                     * twisted Edwards elliptic curve defined over alt_bn128 scalar field and described by equation ax^2 + y^2 = 1 + dx^2y^2
                     *
                     */
                    struct babyjubjub_basic_params {
                        using base_field_type = fields::babyjubjub_fq;
                        using scalar_field_type = fields::babyjubjub_fr;
                    };

                    template <>
                    struct babyjubjub_params<forms::twisted_edwards> : 
                        public babyjubjub_basic_params {

                        using base_field_type = typename babyjubjub_basic_params::base_field_type;
                        using scalar_field_type = typename babyjubjub_basic_params::scalar_field_type;

                        // Edwards representation constants a and d
                        constexpr static const typename base_field_type::modulus_type a =              ///< twisted Edwards elliptic curve 
                            0x292FC_cppui18;                                ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                        constexpr static const typename base_field_type::modulus_type d =
                            0x292F8_cppui18;                                ///< twisted Edwards elliptic curve 
                                                                            ///< described by equation ax^2 + y^2 = 1 + dx^2y^2
                    };

                    template <>
                    struct babyjubjub_params<forms::montgomery> : 
                        public babyjubjub_basic_params {

                        using base_field_type = typename babyjubjub_basic_params::base_field_type;
                        using scalar_field_type = typename babyjubjub_basic_params::scalar_field_type;

                        // Montgomery representation constants A and scale
                        constexpr static const typename base_field_type::modulus_type A = 
                            0x292FA_cppui18;
                        constexpr static const typename base_field_type::modulus_type scale = 
                            0x01;
                    };

                    template <>
                    struct babyjubjub_g1_params<
                        forms::twisted_edwards, 
                        coordinates::affine> : 
                            public babyjubjub_params<forms::twisted_edwards> {

                        using field_type = typename babyjubjub_params<forms::twisted_edwards>::base_field_type;
                        using group_type = babyjubjub_g1<forms::twisted_edwards, 
                            coordinates::affine>;

                        constexpr static const std::array<typename base_field_type::value_type, 3> zero_fill = {
                            base_field_type::value_type::zero(), base_field_type::value_type::one()};

                        // constexpr static const std::array<typename base_field_type::value_type, 3> one_fill = {
                        //     typename base_field_type::value_type(0x23343E3445B673D38BCBA38F25645ADB494B1255B1162BB40F41A59F4D4B45E_cppui250),
                        //     typename base_field_type::value_type(0xC19139CB84C680A6E14116DA06056174A0CFA121E6E5C2450F87D64FC000001_cppui252)};
                        constexpr static const std::array<typename base_field_type::value_type, 3> one_fill = {
                            typename base_field_type::value_type(0xBB77A6AD63E739B4EACB2E09D6277C12AB8D8010534E0B62893F3F6BB957051_cppui252),
                            typename base_field_type::value_type(0x25797203F7A0B24925572E1CD16BF9EDFCE0051FB9E133774B3C257A872D7D8B_cppui254)};
                    };

                    constexpr typename babyjubjub_params<forms::twisted_edwards>::base_field_type::modulus_type const babyjubjub_params<forms::twisted_edwards>::a;
                    constexpr typename babyjubjub_params<forms::twisted_edwards>::base_field_type::modulus_type const babyjubjub_params<forms::twisted_edwards>::d;

                    constexpr typename babyjubjub_params<forms::montgomery>::base_field_type::modulus_type const babyjubjub_params<forms::montgomery>::A;
                    constexpr typename babyjubjub_params<forms::montgomery>::base_field_type::modulus_type const babyjubjub_params<forms::montgomery>::scale;

                    constexpr std::array<typename babyjubjub_g1_params<forms::twisted_edwards, 
                        coordinates::affine>::base_field_type::value_type, 3> const
                        babyjubjub_g1_params<forms::twisted_edwards, 
                            coordinates::affine>::zero_fill;
                    constexpr std::array<typename babyjubjub_g1_params<forms::twisted_edwards, 
                        coordinates::affine>::base_field_type::value_type, 3> const
                        babyjubjub_g1_params<forms::twisted_edwards, 
                            coordinates::affine>::one_fill;

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_PARAMS_HPP

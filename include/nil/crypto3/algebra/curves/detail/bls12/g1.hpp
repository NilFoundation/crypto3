//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_G1_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_G1_HPP

#ifndef __ZKLLVM__
#include <nil/crypto3/algebra/curves/detail/bls12/377/short_weierstrass_params.hpp>
#include <nil/crypto3/algebra/curves/detail/bls12/381/short_weierstrass_params.hpp>
#endif

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/jacobian_with_a4_0/element_g1.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/element_g1_affine.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<std::size_t Version>
                class bls12;

                namespace detail {

                    /** @brief A struct representing a group G1 of BLS12 curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version, typename Form, typename Coordinates>
                    struct bls12_g1 {

#ifdef __ZKLLVM__
                        typedef __zkllvm_curve_bls12381 value_type;
                        typedef __zkllvm_field_bls12381_base base_field_value_type;

                        static_assert(Version == 381 && "zkllvm works with 381 version");

                        static value_type make_value(
                            base_field_value_type affine_one_X,
                            base_field_value_type affine_one_Y) {
                            return __builtin_assigner_bls12381_curve_init(affine_one_X, affine_one_Y);
                        }

                        static value_type one () {
                            return make_value(
                                0x17F1D3A73197D7942695638C4FA9AC0FC3688C4F9774B905A14E3A3F171BAC586C55E83FF97A1AEFFB3AF00ADB22C6BB_cppui381,
                                0x8B3F481E3AAA0F1A09E30ED741D8AE4FCF5E095D5D00AF600DB18CB2C04B3EDD03CC744A2888AE40CAA232946C5E7E1_cppui380
                                );
                        }

                        static value_type zero () {
                            return make_value(
                                0,
                                1
                                );
                        }

#else
                        using params_type = bls12_g1_params<Version, Form>;

                        using curve_type = bls12<Version>;

                        using field_type = typename params_type::field_type;


                        constexpr static const std::size_t value_bits =
                            field_type::value_bits + 1;    ///< size of the base field in bits

                        using value_type = curve_element<params_type, Form, Coordinates>;
#endif
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_BLS12_G1_HPP

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

#ifndef CRYPTO3_ALGEBRA_CURVES_CURVE25519_G1_HPP
#define CRYPTO3_ALGEBRA_CURVES_CURVE25519_G1_HPP

#include <nil/crypto3/algebra/curves/detail/curve25519/params.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>
#ifdef __ZKLLVM__
#else
// #include <nil/crypto3/algebra/curves/detail/forms/montgomery/xz/element_g1.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/extended_with_a_minus_1/element_g1.hpp>
#endif

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                class curve25519;
                class ed25519;

                namespace detail {
                    /** @brief A struct representing a group G1 of curve25519 curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<typename Form, typename Coordinates>
                    class curve25519_g1 {
                    public:
                        using params_type = curve25519_g1_params<Form>;

                        using curve_type = typename std::conditional<std::is_same<Form, forms::twisted_edwards>::value,
                                                                     ed25519, curve25519>::type;

                        using field_type = typename params_type::field_type;

                        constexpr static const std::size_t value_bits =
                            field_type::value_bits + 1;    ///< size of the base field in bits

#ifdef __ZKLLVM__
                        using value_type = __zkllvm_curve_curve25519;

                        static value_type make_value(
                            typename field_type::value_type affine_one_X,
                            typename field_type::value_type affine_one_Y) {
                            return __builtin_assigner_curve25519_curve_init(affine_one_X, affine_one_Y);
                        }

                        static value_type one () {
                            return make_value(
                                0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a_cppui256,
                                0x6666666666666666666666666666666666666666666666666666666666666658_cppui256
                                );
                        }

                        static value_type zero () {
                            return make_value(0, 1);
                        }

#else
                        using value_type = curve_element<params_type, Form, Coordinates>;
#endif
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_CURVE25519_G1_HPP

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

#ifndef CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_TYPES_HPP
#define CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_TYPES_HPP

#include <nil/crypto3/algebra/fields/babyjubjub/base_field.hpp>
#include <nil/crypto3/algebra/fields/babyjubjub/scalar_field.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<typename Form, typename Coordinates>
                    struct babyjubjub_g1;

                    template<typename Form>
                    struct babyjubjub_params;

                    template<typename Form>
                    struct babyjubjub_g1_params;

                    /** @brief A struct representing details about base and scalar fields of the size 183 bits and 181
                     * bits respectively. Corresponds to [BabyJubJub](https://eips.ethereum.org/EIPS/eip-2494)
                     * twisted Edwards elliptic curve defined over alt_bn128 scalar field and described by equation ax^2
                     * + y^2 = 1 + dx^2y^2
                     *
                     */
                    struct babyjubjub_types {
                        using base_field_type = fields::babyjubjub_base_field;
                        using scalar_field_type = fields::babyjubjub_scalar_field;

                        using g1_field_type = base_field_type;

                        using integral_type = typename base_field_type::integral_type;

                        template<typename Form, typename Coordinates>
                        using g1_type = babyjubjub_g1<Form, Coordinates>;
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_TYPES_HPP

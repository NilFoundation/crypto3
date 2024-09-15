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

#ifndef CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_G1_HPP
#define CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_G1_HPP

#include <nil/crypto3/algebra/curves/detail/babyjubjub/params.hpp>

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/element_g1_affine.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                class babyjubjub;

                namespace detail {
                    /** @brief A struct representing a group G1 of BabyJubJub curve.
                     */
                    template<typename Form, typename Coordinates>
                    struct babyjubjub_g1 {
                        using params_type = babyjubjub_g1_params<Form>;

                        using curve_type = babyjubjub;

                        using field_type = typename params_type::field_type;

                        constexpr static const std::size_t value_bits =
                            field_type::value_bits + 1;    ///< size of the base field in bits

                        using value_type = curve_element<params_type, Form, Coordinates>;
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_G1_HPP

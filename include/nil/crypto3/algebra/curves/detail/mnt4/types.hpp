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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT4_TYPES_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT4_TYPES_HPP

#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp4.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {

                    template<std::size_t Version, typename Form, typename Coordinates>
                    struct mnt4_g1;

                    template<std::size_t Version, typename Form, typename Coordinates>
                    struct mnt4_g2;

                    template<std::size_t Version, typename Form>
                    struct mnt4_params;

                    template<std::size_t Version, typename Form>
                    struct mnt4_g1_params;

                    template<std::size_t Version, typename Form>
                    struct mnt4_g2_params;

                    /** @brief A struct representing details about base and scalar fields.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version>
                    struct mnt4_types {
                        using base_field_type = fields::mnt4_base_field<Version>;
                        using scalar_field_type = fields::mnt4_scalar_field<Version>;

                        using g1_field_type = base_field_type;
                        using g2_field_type = typename fields::fp2<base_field_type>;
                        using gt_field_type = typename fields::fp4<base_field_type>;

                        using integral_type = typename base_field_type::integral_type;

                        template<typename Form, typename Coordinates>
                        using g1_type = mnt4_g1<Version, Form, Coordinates>;

                        template<typename Form, typename Coordinates>
                        using g2_type = mnt4_g2<Version, Form, Coordinates>;
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_MNT4_TYPES_HPP

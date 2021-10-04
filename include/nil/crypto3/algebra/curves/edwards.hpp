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

#ifndef CRYPTO3_ALGEBRA_CURVES_EDWARDS_HPP
#define CRYPTO3_ALGEBRA_CURVES_EDWARDS_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/types.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/g2.hpp>

// #include <nil/crypto3/algebra/curves/detail/forms/edwards/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>

// #include <nil/crypto3/algebra/pairing/edwards.hpp>
// #include <nil/crypto3/algebra/pairing/detail/edwards/functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                /** @brief A struct representing a Edwards curve, providing 128 bits of security.
                 *    @tparam Version version of the curve
                 *
                 */
                template<std::size_t Version>
                class edwards {

                    typedef detail::edwards_types<Version> policy_type;

                public:
                    typedef typename policy_type::base_field_type base_field_type;
                    typedef typename policy_type::scalar_field_type scalar_field_type;

                    template<typename Coordinates = coordinates::inverted, typename Form = forms::twisted_edwards>
                    using g1_type = typename detail::edwards_g1<Version, Form, Coordinates>;

                    template<typename Coordinates = coordinates::inverted, typename Form = forms::twisted_edwards>
                    using g2_type = typename detail::edwards_g2<Version, Form, Coordinates>;

                    // typedef typename pairing::pairing_policy<edwards<Version>,
                    //                                          pairing::detail::edwards_pairing_functions<Version>>
                    //     pairing;

                    typedef typename policy_type::gt_field_type gt_type;

                    constexpr static const bool has_affine_pairing = false;
                };

                typedef edwards<183> edwards_183;

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_EDWARDS_HPP

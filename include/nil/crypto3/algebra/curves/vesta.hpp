//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_VESTA_HPP
#define CRYPTO3_ALGEBRA_CURVES_VESTA_HPP

#include <nil/crypto3/algebra/curves/detail/vesta/types.hpp>
#include <nil/crypto3/algebra/curves/detail/vesta/g1.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                /**
                 * @brief A struct representing a vesta curve.
                 * https://zips.z.cash/protocol/protocol.pdf#pallasandvesta
                 */
                class vesta {

                    typedef detail::vesta_types policy_type;

                public:
                    typedef typename policy_type::base_field_type base_field_type;
                    typedef typename policy_type::scalar_field_type scalar_field_type;

                    template<typename Coordinates = coordinates::jacobian_with_a4_0,
                             typename Form = forms::short_weierstrass>
                    using g1_type = typename detail::vesta_g1<Form, Coordinates>;
                };
            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_VESTA_HPP
 

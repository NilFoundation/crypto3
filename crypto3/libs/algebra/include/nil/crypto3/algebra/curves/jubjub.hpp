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

#ifndef CRYPTO3_ALGEBRA_CURVES_JUBJUB_HPP
#define CRYPTO3_ALGEBRA_CURVES_JUBJUB_HPP

// #include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/detail/jubjub/types.hpp>
#include <nil/crypto3/algebra/curves/detail/jubjub/g1.hpp>

// #include <nil/crypto3/algebra/pairing/edwards.hpp>
// #include <nil/crypto3/algebra/pairing/detail/edwards/functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                /**
                 * @brief A struct representing a
                 * [JubJub](https://raw.githubusercontent.com/zcash/zips/master/protocol/protocol.pdf#jubjub) twisted
                 * Edwards elliptic curve defined over Bls12-381 scalar field and described by equation ax^2 + y^2 = 1 +
                 * dx^2y^2.
                 *    @tparam Version version of the curve
                 *
                 */
                class jubjub {

                    typedef detail::jubjub_types policy_type;

                public:
                    typedef typename policy_type::base_field_type base_field_type;
                    typedef typename policy_type::scalar_field_type scalar_field_type;

                    template<typename Coordinates = coordinates::affine, typename Form = forms::twisted_edwards>
                    using g1_type = typename detail::jubjub_g1<Form, Coordinates>;

                    // typedef typename curves::bls12<381> chained_on_curve_type;

                    // typedef typename pairing::pairing_policy<edwards<version>,
                    //                                          pairing::detail::edwards_pairing_functions<Version>>
                    //     pairing;

                    // constexpr static const bool has_affine_pairing = false;
                };
            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_JUBJUB_HPP

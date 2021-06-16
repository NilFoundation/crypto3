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

#ifndef CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_HPP
#define CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_HPP

#include <nil/crypto3/algebra/curves/detail/edwards/babyjubjub/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/edwards/g1.hpp>

// #include <nil/crypto3/algebra/pairing/edwards.hpp>
// #include <nil/crypto3/algebra/pairing/detail/edwards/functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                /** @brief A struct representing a [BabyJubJub](https://eips.ethereum.org/EIPS/eip-2494) 
                 * twisted Edwards elliptic curve defined over alt_bn128 scalar field and described by equation ax^2 + y^2 = 1 + dx^2y^2
                 *  @tparam Version version of the curve
                 *
                 */
                struct babyjubjub {
                    constexpr static const std::size_t version = 254;

                    using policy_type = detail::edwards_basic_policy<version>;

                    typedef typename policy_type::base_field_type base_field_type;
                    typedef typename policy_type::scalar_field_type scalar_field_type;
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::extended_number_type extended_number_type;

                    constexpr static const number_type p = policy_type::p;    ///< base field characteristic

                    constexpr static const number_type q =
                        policy_type::q;    ///< scalar field characteristic (order of the group of points)

                    typedef typename detail::edwards_g1<version> g1_type;

                    typedef typename curves::alt_bn128<254> chained_on_curve_type;

                    // typedef typename pairing::pairing_policy<edwards<version>,
                    //                                          pairing::detail::edwards_pairing_functions<Version>>
                    //     pairing;

                    // constexpr static const bool has_affine_pairing = false;
                };

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BABYJUBJUB_HPP

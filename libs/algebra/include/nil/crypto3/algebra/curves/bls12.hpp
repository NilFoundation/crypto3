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

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_HPP

#include <nil/crypto3/algebra/curves/detail/bls12/types.hpp>

#include <nil/crypto3/algebra/curves/detail/bls12/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/bls12/g2.hpp>

// #include <nil/crypto3/algebra/pairing/bls12.hpp>
// #include <nil/crypto3/algebra/pairing/detail/bls12/functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                /** @brief A struct representing a BLS12-381 and BLS12-377 curve.
                 *  @tparam Version version of the curve
                 *
                 *  The basic equation of the curve is y^2 = x^3 + 4.
                 */
                template<std::size_t Version>
                class bls12 {

                    typedef detail::bls12_types<Version> policy_type;

                public:
                    typedef typename policy_type::base_field_type base_field_type;
                    typedef typename policy_type::scalar_field_type scalar_field_type;

                    template<typename Coordinates = coordinates::jacobian_with_a4_0,
                             typename Form = forms::short_weierstrass>
                    using g1_type = typename detail::bls12_g1<Version, Form, Coordinates>;

                    template<typename Coordinates = coordinates::jacobian_with_a4_0,
                             typename Form = forms::short_weierstrass>
                    using g2_type = typename detail::bls12_g2<Version, Form, Coordinates>;
#ifndef __ZKLLVM__

                    constexpr static const bool has_affine_pairing = false;

                    // typedef typename pairing::pairing_policy<bls12<Version>,
                    //                                          pairing::detail::bls12_pairing_functions<Version>>
                    //     pairing;

#endif
                    typedef typename policy_type::gt_field_type gt_type;
                };

                typedef bls12<381> bls12_381;
                typedef bls12<377> bls12_377;
            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_BLS12_381_HPP

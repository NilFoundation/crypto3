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

#ifndef CRYPTO3_ALGEBRA_CURVES_MNT4_HPP
#define CRYPTO3_ALGEBRA_CURVES_MNT4_HPP

#include <nil/crypto3/algebra/curves/detail/mnt4/types.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt4/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/mnt4/g2.hpp>

// #include <nil/crypto3/algebra/pairing/mnt4.hpp>
// #include <nil/crypto3/algebra/pairing/detail/mnt4/functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                /** @brief A struct representing a mnt4 curve.
                 *    @tparam Version version of the curve
                 *
                 */
                template<std::size_t Version>
                class mnt4 {

                    typedef detail::mnt4_types<Version> policy_type;

                public:
                    typedef typename policy_type::base_field_type base_field_type;
                    typedef typename policy_type::scalar_field_type scalar_field_type;

                    template<typename Coordinates = coordinates::projective, typename Form = forms::short_weierstrass>
                    using g1_type = typename detail::mnt4_g1<Version, Form, Coordinates>;

                    template<typename Coordinates = coordinates::projective, typename Form = forms::short_weierstrass>
                    using g2_type = typename detail::mnt4_g2<Version, Form, Coordinates>;

                    // typedef typename pairing::pairing_policy<mnt4<Version>,
                    //                                          pairing::detail::mnt4_pairing_functions<Version>>
                    //     pairing;

                    // typedef typename pairing::pair_curve_type chained_on_curve_type;

                    typedef typename policy_type::gt_field_type gt_type;

                    constexpr static const bool has_affine_pairing = true;
                };

                typedef mnt4<298> mnt4_298;
            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_MNT4_HPP

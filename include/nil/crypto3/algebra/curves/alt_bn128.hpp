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

#ifndef CRYPTO3_ALGEBRA_CURVES_ALT_BN128_HPP
#define CRYPTO3_ALGEBRA_CURVES_ALT_BN128_HPP

#include <nil/crypto3/algebra/curves/detail/alt_bn128/basic_policy.hpp>
#include <nil/crypto3/algebra/curves/detail/alt_bn128/g1.hpp>
#include <nil/crypto3/algebra/curves/detail/alt_bn128/g2.hpp>

//#include <nil/crypto3/algebra/pairing/alt_bn128.hpp>
//#include <nil/crypto3/algebra/pairing/detail/alt_bn128/functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                /** @brief A struct representing a Barreto-Naehrig curve.
                 *  @tparam Version version of the curve
                 *
                 *  An alternative to `bn128`, somewhat slower but avoids dynamic code generation.
                 */
                template<std::size_t Version>
                struct alt_bn128 {

                    using policy_type = detail::alt_bn128_basic_policy<Version>;

                    typedef typename policy_type::base_field_type base_field_type;
                    typedef typename policy_type::scalar_field_type scalar_field_type;
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::extended_number_type extended_number_type;

                    constexpr static const number_type p = policy_type::p;    ///< base field characteristic
                    constexpr static const number_type q = policy_type::q;    ///< scalar field characteristic (order of the group of points)

                    typedef typename detail::alt_bn128_g1<Version> g1_type;
                    typedef typename detail::alt_bn128_g2<Version> g2_type;

                    // typedef typename pairing::pairing_policy<alt_bn128<Version>,
                    //    pairing::detail::alt_bn128_pairing_functions<Version>> pairing_policy;

                    typedef typename policy_type::gt_field_type gt_type;
                };

                typedef alt_bn128<254> alt_bn128_254;

            }    // namespace curves
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_ALT_BN128_HPP

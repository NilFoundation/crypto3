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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_POLICY_HPP

#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/params.hpp>
#include <nil/crypto3/algebra/pairing/edwards/183/ate_double_miller_loop.hpp>
#include <nil/crypto3/algebra/pairing/edwards/183/ate_miller_loop.hpp>
#include <nil/crypto3/algebra/pairing/edwards/183/ate_precompute_g1.hpp>
#include <nil/crypto3/algebra/pairing/edwards/183/ate_precompute_g2.hpp>
#include <nil/crypto3/algebra/pairing/edwards/183/final_exponentiation.hpp>
#include <nil/crypto3/algebra/pairing/pairing_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<>
                struct pairing_policy<curves::edwards<183>> {
                    using curve_type = curves::edwards<183>;

                    using precompute_g1 = pairing::edwards_ate_precompute_g1<183>;
                    using precompute_g2 = pairing::edwards_ate_precompute_g2<183>;
                    using miller_loop = pairing::edwards_ate_miller_loop<183>;
                    using double_miller_loop = pairing::edwards_ate_double_miller_loop<183>;
                    using final_exponentiation = pairing::edwards_final_exponentiation<183>;

                    using g1_precomputed_type = typename precompute_g1::g1_precomputed_type;
                    using g2_precomputed_type = typename precompute_g2::g2_precomputed_type;
                };

            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_POLICY_HPP

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

#ifndef CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_PAIR_HPP
#define CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_PAIR_HPP

#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/edwards/183/types.hpp>
#include <nil/crypto3/algebra/pairing/edwards/183/ate_precompute_g1.hpp>
#include <nil/crypto3/algebra/pairing/edwards/183/ate_precompute_g2.hpp>
#include <nil/crypto3/algebra/pairing/edwards/183/ate_miller_loop.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 183, 
                         typename PrecomputeG1 = ate_precompute_g1<Version>, 
                         typename PrecomputeG2 = ate_precompute_g2<Version>, 
                         typename MillerLoop = ate_miller_loop<Version>>
                class edwards_pair {
                    using curve_type = curves::edwards<183>;

                    using params_type = detail::params_type<curve_type>;
                    using types_policy = detail::types_policy<curve_type>;

                    using gt_type = typename curve_type::gt_type;
                public:

                    static typename gt_type::value_type process(
                        const typename g1_type::value_type &P, 
                        const typename g2_type::value_type &Q) {

                        typename PrecomputeG1::g1_precomputed_type prec_P = 
                            PrecomputeG1::process(P);
                        typename PrecomputeG2::g2_precomputed_type prec_Q = 
                            PrecomputeG2::process(Q);
                        typename gt_type::value_type result = 
                            MillerLoop::process(prec_P, prec_Q);
                        return result;
                    }
                };
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_EDWARDS_183_PAIR_HPP

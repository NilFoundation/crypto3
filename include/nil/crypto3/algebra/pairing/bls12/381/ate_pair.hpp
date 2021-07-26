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

#ifndef CRYPTO3_ALGEBRA_PAIRING_BLS12_ATE_PAIR_HPP
#define CRYPTO3_ALGEBRA_PAIRING_BLS12_ATE_PAIR_HPP

#include <nil/crypto3/algebra/pairing/detail/bls12/381/params.hpp>
#include <nil/crypto3/algebra/pairing/detail/bls12/381/types.hpp>
#include <nil/crypto3/algebra/pairing/bls12/381/ate_precompute_g1.hpp>
#include <nil/crypto3/algebra/pairing/bls12/381/ate_precompute_g2.hpp>
#include <nil/crypto3/algebra/pairing/bls12/381/ate_miller_loop.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<std::size_t Version = 381, 
                         typename AtePrecomputeG1 = ate_precompute_g1<Version>, 
                         typename AtePrecomputeG2 = ate_precompute_g2<Version>, 
                         typename AteMillerLoop = ate_miller_loop<Version>>
                class bls12_ate_pair;

                template<typename AtePrecomputeG1, 
                         typename AtePrecomputeG2, 
                         typename AteMillerLoop>
                class bls12_ate_pair<381, AtePrecomputeG1, AtePrecomputeG2, AteMillerLoop> {
                    using curve_type = curves::bls12<381>;

                    using params_type = detail::params_type<curve_type>;
                    using types_policy = detail::types_policy<curve_type>;

                    using gt_type = typename curve_type::gt_type;
                public:

                    static typename gt_type::value_type process(
                        const typename g1_type::value_type &P, 
                        const typename g2_type::value_type &Q) {

                        typename types_policy::ate_g1_precomp prec_P = 
                            AtePrecomputeG1::process(P);
                        typename types_policy::ate_g2_precomp prec_Q = 
                            AtePrecomputeG2::process(Q);
                        typename gt_type::value_type result = 
                            AteMillerLoop::process(prec_P, prec_Q);
                        return result;
                    }
                };
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_BLS12_ATE_PAIR_HPP

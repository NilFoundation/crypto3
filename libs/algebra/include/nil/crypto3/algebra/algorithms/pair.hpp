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

#ifndef CRYPTO3_ALGEBRA_PAIRING_ALGORITHM_HPP
#define CRYPTO3_ALGEBRA_PAIRING_ALGORITHM_HPP

#include <nil/crypto3/algebra/pairing/pairing_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {

            // template<typename PairingCurveType>
            // typename PairingCurveType::pairing::affine_ate_g1_precomp
            //     affine_ate_precompute_g1(const typename PairingCurveType::pairing::g1_type::value_type &P) {

            //     return PairingCurveType::pairing::affine_ate_precompute_g1(P);
            // }

            // template<typename PairingCurveType>
            // typename PairingCurveType::pairing::affine_ate_g2_precomp
            //     affine_ate_precompute_g2(const typename PairingCurveType::pairing::g2_type::value_type &P) {

            //     return PairingCurveType::pairing::affine_ate_precompute_g2(P);
            // }

            // template<typename PairingCurveType>
            // typename PairingCurveType::pairing::gt_type::value_type
            //     affine_ate_miller_loop(const typename PairingCurveType::pairing::affine_ate_g1_precomp &prec_P,
            //                            const typename PairingCurveType::pairing::affine_ate_g2_precomp &prec_Q) {

            //     return PairingCurveType::pairing::affine_ate_miller_loop(prec_P, prec_Q);
            // }

            template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
            typename PairingPolicy::g1_precomputed_type
                precompute_g1(const typename PairingCurveType::template g1_type<>::value_type &P) {

                return PairingPolicy::precompute_g1::process(P);
            }

            template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
            typename PairingPolicy::g2_precomputed_type
                precompute_g2(const typename PairingCurveType::template g2_type<>::value_type &P) {

                return PairingPolicy::precompute_g2::process(P);
            }

#ifdef __ZKLLVM__
            template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
            typename PairingCurveType::gt_type::value_type
                pair(const typename PairingCurveType::template g1_type<>::value_type v1,
                     const typename PairingCurveType::template g2_type<>::value_type v2) {
                return __builtin_assigner_bls12_optimal_ate_pairing(v1, v2);
            }

#else
            template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
            typename PairingCurveType::gt_type::value_type
                pair(const typename PairingCurveType::template g1_type<>::value_type &v1,
                     const typename PairingCurveType::template g2_type<>::value_type &v2) {
                typename PairingPolicy::g1_precomputed_type prec_P = PairingPolicy::precompute_g1::process(v1);
                typename PairingPolicy::g2_precomputed_type prec_Q = PairingPolicy::precompute_g2::process(v2);

                return PairingPolicy::miller_loop::process(prec_P, prec_Q);
            }
#endif

            template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
            typename PairingCurveType::gt_type::value_type
                pair_reduced(const typename PairingCurveType::template g1_type<>::value_type &v1,
                             const typename PairingCurveType::template g2_type<>::value_type &v2) {

                typename PairingPolicy::g1_precomputed_type prec_P = PairingPolicy::precompute_g1::process(v1);
                typename PairingPolicy::g2_precomputed_type prec_Q = PairingPolicy::precompute_g2::process(v2);

                typename PairingCurveType::gt_type::value_type f = PairingPolicy::miller_loop::process(prec_P, prec_Q);
                return PairingPolicy::final_exponentiation::process(f);
            }

            template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
            typename PairingCurveType::gt_type::value_type
                double_miller_loop(const typename PairingPolicy::g1_precomputed_type &prec_P1,
                                   const typename PairingPolicy::g2_precomputed_type &prec_Q1,
                                   const typename PairingPolicy::g1_precomputed_type &prec_P2,
                                   const typename PairingPolicy::g2_precomputed_type &prec_Q2) {

                return PairingPolicy::double_miller_loop::process(prec_P1, prec_Q1, prec_P2, prec_Q2);
            }

            template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
            typename PairingCurveType::gt_type::value_type
                final_exponentiation(const typename PairingCurveType::gt_type::value_type &elt) {

                return PairingPolicy::final_exponentiation::process(elt);
            }

            template<typename PairingCurveType, typename PairingPolicy = pairing::pairing_policy<PairingCurveType>>
            typename PairingCurveType::gt_type::value_type
                miller_loop(const typename PairingPolicy::g1_precomputed_type &prec_P,
                            const typename PairingPolicy::g2_precomputed_type &prec_Q) {

                return PairingPolicy::miller_loop::process(prec_P, prec_Q);
            }
        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_ALGORITHM_HPP

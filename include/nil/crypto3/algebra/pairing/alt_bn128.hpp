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

#ifndef CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_POLICY_HPP
#define CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_POLICY_HPP

#include <numeric>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<std::size_t Version>
                struct alt_bn128;

                struct babyjubjub;

            }    // namespace curves
            namespace pairing {

                template<typename PairingCurveType, typename PairingFunctions>
                struct pairing_policy;

                template<std::size_t Version, typename PairingFunctions>
                class pairing_policy<curves::alt_bn128<Version>, PairingFunctions> {

                    using policy_type = PairingFunctions;

                public:
                    using chained_curve_type = curves::babyjubjub;

                    typedef typename policy_type::number_type number_type;

                    constexpr static const typename policy_type::number_type pairing_loop_count =
                        policy_type::ate_loop_count;

                    using fp_type = typename policy_type::fp_type;
                    using fq_type = typename policy_type::fq_type;
                    using fqe_type = typename policy_type::fqe_type;
                    using fqk_type = typename policy_type::fqk_type;

                    using g1_type = typename policy_type::g1_type;
                    using g2_type = typename policy_type::g2_type;
                    using gt_type = typename policy_type::gt_type;

                    using g1_precomp = typename policy_type::g1_precomp;
                    using g2_precomp = typename policy_type::g2_precomp;

                    constexpr static const typename g2_type::underlying_field_type::value_type twist =
                        policy_type::twist;

                    static inline g1_precomp precompute_g1(const typename g1_type::value_type &P) {
                        return policy_type::precompute_g1(P);
                    }

                    static inline g2_precomp precompute_g2(const typename g2_type::value_type &Q) {
                        return policy_type::precompute_g2(Q);
                    }

                    static inline typename gt_type::value_type pair(const typename g1_type::value_type &P,
                                                                    const typename g2_type::value_type &Q) {
                        return policy_type::pair(P, Q);
                    }

                    static inline typename gt_type::value_type pair_reduced(const typename g1_type::value_type &P,
                                                                            const typename g2_type::value_type &Q) {
                        return policy_type::pair_reduced(P, Q);
                    }

                    static inline typename gt_type::value_type double_miller_loop(const g1_precomp &prec_P1,
                                                                                  const g2_precomp &prec_Q1,
                                                                                  const g1_precomp &prec_P2,
                                                                                  const g2_precomp &prec_Q2) {
                        return policy_type::double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
                    }

                    static inline typename gt_type::value_type
                        final_exponentiation(const typename gt_type::value_type &elt) {
                        return policy_type::final_exponentiation(elt);
                    }

                    static inline typename gt_type::value_type miller_loop(const g1_precomp &prec_P,
                                                                           const g2_precomp &prec_Q) {
                        return policy_type::miller_loop(prec_P, prec_Q);
                    }
                };

                template<std::size_t Version, typename PairingFunctions>
                constexpr typename pairing_policy<curves::alt_bn128<Version>, PairingFunctions>::number_type const
                    pairing_policy<curves::alt_bn128<Version>, PairingFunctions>::pairing_loop_count;
            }    // namespace pairing
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_PAIRING_ALT_BN128_POLICY_HPP

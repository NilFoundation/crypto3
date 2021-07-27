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

#ifndef CRYPTO3_ALGEBRA_PAIRING_PAIR_HPP
#define CRYPTO3_ALGEBRA_PAIRING_PAIR_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {

                template<typename PairingCurveType>
                struct ate_precompute_g1;

                template<typename PairingCurveType>
                struct ate_precompute_g2;

                template<typename PairingCurveType>
                struct ate_miller_loop;

                template<typename PairingCurveType, 
                         typename PrecomputeG1 = ate_precompute_g1<PairingCurveType>, 
                         typename PrecomputeG2 = ate_precompute_g2<PairingCurveType>, 
                         typename MillerLoop = ate_miller_loop<PairingCurveType>>
                class pair {
                    using curve_type = PairingCurveType;

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
#endif    // CRYPTO3_ALGEBRA_PAIRING_PAIR_HPP

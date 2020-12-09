//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_PAIRING_ALGORITM_HPP
#define CRYPTO3_ALGEBRA_PAIRING_ALGORITM_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {

            template<typename PairingCurveType>
            typename PairingCurveType::pairing_policy::affine_ate_G1_precomp affine_ate_precompute_G1(
                const typename PairingCurveType::pairing_policy::G1_type &P) {

                return PairingCurveType::pairing_policy::affine_ate_precompute_g1(P);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::pairing_policy::affine_ate_G2_precomp affine_ate_precompute_G2(
                const typename PairingCurveType::pairing_policy::G2_type &P) {

                return PairingCurveType::pairing_policy::affine_ate_precompute_g2(P);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::pairing_policy::G1_precomp precompute_g1(
                const typename PairingCurveType::pairing_policy::G1_type &P) {

                return PairingCurveType::pairing_policy::precompute_g1(P);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::pairing_policy::G2_precomp precompute_g2(
                const typename PairingCurveType::pairing_policy::G2_type &P) {

                return PairingCurveType::pairing_policy::precompute_g2(P);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::pairing_policy::GT_type pairing(const typename PairingCurveType::pairing_policy::G1_type &v1,
                                                                    const typename PairingCurveType::pairing_policy::G2_type &v2) {
                return PairingCurveType::pairing_policy::pairing(v1, v2);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::pairing_policy::GT_type reduced_pairing(
                const typename PairingCurveType::pairing_policy::G1_type &v1,
                const typename PairingCurveType::pairing_policy::G2_type &v2) {

                return PairingCurveType::pairing_policy::reduced_pairing(v1, v2);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::pairing_policy::GT_type double_miller_loop(
                const typename PairingCurveType::pairing_policy::G1_precomp &prec_P1,
                const typename PairingCurveType::pairing_policy::G2_precomp &prec_Q1,
                const typename PairingCurveType::pairing_policy::G1_precomp &prec_P2,
                const typename PairingCurveType::pairing_policy::G2_precomp &prec_Q2) {

                return PairingCurveType::pairing_policy::double_miller_loop(prec_P1, prec_Q1, prec_P2, prec_Q2);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::pairing_policy::GT_type final_exponentiation(
                const typename PairingCurveType::pairing_policy::GT_type &elt) {

                return PairingCurveType::pairing_policy::final_exponentiation(elt);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::pairing_policy::GT_type miller_loop(
                const typename PairingCurveType::pairing_policy::G1_precomp &prec_P,
                const typename PairingCurveType::pairing_policy::G2_precomp &prec_Q) {

                return PairingCurveType::pairing_policy::miller_loop(P, Q);
            }

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_PAIRING_ALGORITHM_HPP

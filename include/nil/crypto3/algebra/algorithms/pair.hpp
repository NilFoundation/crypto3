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

#ifndef CRYPTO3_ALGEBRA_PAIR_HPP
#define CRYPTO3_ALGEBRA_PAIR_HPP

#include <nil/crypto3/algebra/pairing/policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            template<typename PairingCurveType>
            typename PairingCurveType::gt_type pair(typename PairingCurveType::g1_type &v1,
                                                    typename PairingCurveType::g2_type &v2) {
                return pairing::pairing_policy<PairingCurveType>::pairing(v1, v2);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::gt_type reduced_pair(typename PairingCurveType::g1_type &v1,
                                                            typename PairingCurveType::g2_type &v2) {
                return pairing::pairing_policy<PairingCurveType>::reduced_pairing(v1, v2);
            }

            template<typename PairingCurveType>
            typename PairingCurveType::gt_type final_exp(typename PairingCurveType::gt_type &elt) {
                return pairing::pairing_policy<PairingCurveType>::final_exponentiation(elt);
            }

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PAIR_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2022 Noam Y <@NoamDev>
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

#ifndef CRYPTO3_ZK_POWERS_OF_TAU_PUBLIC_KEY_HPP
#define CRYPTO3_ZK_POWERS_OF_TAU_PUBLIC_KEY_HPP

#include <nil/crypto3/zk/commitments/detail/polynomial/element_proof_of_knowledge.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {
                    template<typename CurveType>
                    struct powers_of_tau_public_key {
                        typedef CurveType curve_type;

                        typedef commitments::detail::element_pok<curve_type> pok_type;

                        pok_type tau_pok;
                        pok_type alpha_pok;
                        pok_type beta_pok;

                        powers_of_tau_public_key(pok_type tau_pok, pok_type alpha_pok, pok_type beta_pok) :
                                tau_pok(tau_pok), alpha_pok(alpha_pok), beta_pok(beta_pok) {
                        }
                    };
                }    // namespace detail
            }        // namespace commitments
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_POWERS_OF_TAU_PUBLIC_KEY_HPP

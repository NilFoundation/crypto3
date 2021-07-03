//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_VERIFICATION_KEY_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_VERIFICATION_KEY_HPP

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/verification_key.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct r1cs_gg_ppzksnark_aggregate_verification_key {
                    typedef CurveType curve_type;

                    typename curve_type::g1_type::value_type alpha_g1;
                    typename curve_type::g2_type::value_type beta_g2;
                    typename curve_type::g2_type::value_type gamma_g2;
                    typename curve_type::g2_type::value_type delta_g2;

                    accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1;

                    r1cs_gg_ppzksnark_aggregate_verification_key() = default;
                    r1cs_gg_ppzksnark_aggregate_verification_key(
                        const typename curve_type::g1_type::value_type &alpha_g1,
                        const typename curve_type::g2_type::value_type &beta_g2,
                        const typename curve_type::g2_type::value_type &gamma_g2,
                        const typename curve_type::g2_type::value_type &delta_g2,
                        const accumulation_vector<typename curve_type::g1_type> &gamma_ABC_g1) :
                        alpha_g1(alpha_g1),
                        beta_g2(beta_g2), gamma_g2(gamma_g2), delta_g2(delta_g2), gamma_ABC_g1(gamma_ABC_g1) {
                    }

                    bool operator==(const r1cs_gg_ppzksnark_aggregate_verification_key &other) const {
                        return (this->alpha_g1 == other.alpha_g1 && this->beta_g2 == other.beta_g2 &&
                                this->gamma_g2 == other.gamma_g2 && this->delta_g2 == other.delta_g2 &&
                                this->gamma_ABC_g1 == other.gamma_ABC_g1);
                    }

                    operator r1cs_gg_ppzksnark_verification_key<curve_type>() const {
                        return r1cs_gg_ppzksnark_verification_key<curve_type>(
                            algebra::pair_reduced<curve_type>(alpha_g1, beta_g2, gamma_g2, delta_g2, gamma_ABC_g1));
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_IPP2_VERIFICATION_KEY_HPP

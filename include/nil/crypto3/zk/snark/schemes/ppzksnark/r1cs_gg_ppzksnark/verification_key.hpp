//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_VERIFICATION_KEY_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_VERIFICATION_KEY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct r1cs_gg_ppzksnark_verification_key {
                    typedef CurveType curve_type;

                    typename CurveType::gt_type::value_type alpha_g1_beta_g2;
                    typename CurveType::g2_type::value_type gamma_g2;
                    typename CurveType::g2_type::value_type delta_g2;

                    accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1;

                    r1cs_gg_ppzksnark_verification_key() = default;
                    r1cs_gg_ppzksnark_verification_key(
                        const typename CurveType::gt_type::value_type &alpha_g1_beta_g2,
                        const typename CurveType::g2_type::value_type &gamma_g2,
                        const typename CurveType::g2_type::value_type &delta_g2,
                        const accumulation_vector<typename CurveType::g1_type> &gamma_ABC_g1) :
                        alpha_g1_beta_g2(alpha_g1_beta_g2),
                        gamma_g2(gamma_g2), delta_g2(delta_g2), gamma_ABC_g1(gamma_ABC_g1) {
                    }

                    std::size_t G1_size() const {
                        return gamma_ABC_g1.size();
                    }

                    std::size_t G2_size() const {
                        return 2;
                    }

                    std::size_t GT_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        // TODO: include GT size
                        return (gamma_ABC_g1.size_in_bits() + 2 * CurveType::g2_type::value_bits);
                    }

                    bool operator==(const r1cs_gg_ppzksnark_verification_key &other) const {
                        return (this->alpha_g1_beta_g2 == other.alpha_g1_beta_g2 && this->gamma_g2 == other.gamma_g2 &&
                                this->delta_g2 == other.delta_g2 && this->gamma_ABC_g1 == other.gamma_ABC_g1);
                    }
                };

                template<typename CurveType>
                struct r1cs_gg_ppzksnark_processed_verification_key {
                    typedef CurveType curve_type;
                    typedef typename CurveType::pairing pairing_policy;

                    typename CurveType::gt_type::value_type vk_alpha_g1_beta_g2;
                    typename pairing_policy::g2_precomp vk_gamma_g2_precomp;
                    typename pairing_policy::g2_precomp vk_delta_g2_precomp;

                    accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1;

                    bool operator==(const r1cs_gg_ppzksnark_processed_verification_key &other) const {
                        return (this->vk_alpha_g1_beta_g2 == other.vk_alpha_g1_beta_g2 &&
                                this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
                                this->vk_delta_g2_precomp == other.vk_delta_g2_precomp &&
                                this->gamma_ABC_g1 == other.gamma_ABC_g1);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP

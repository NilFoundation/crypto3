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

#include <nil/crypto3/algebra/algorithms/pair.hpp>

#include <nil/crypto3/container/accumulation_vector.hpp>
#include <nil/crypto3/zk/commitments/polynomial/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>
#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                struct r1cs_gg_ppzksnark_processed_verification_key;

                template<typename CurveType>
                struct r1cs_gg_ppzksnark_verification_key {
                    typedef CurveType curve_type;

                    typename CurveType::gt_type::value_type alpha_g1_beta_g2;
                    typename CurveType::template g2_type<>::value_type gamma_g2;
                    typename CurveType::template g2_type<>::value_type delta_g2;

                    container::accumulation_vector<typename CurveType::template g1_type<>> gamma_ABC_g1;

                    r1cs_gg_ppzksnark_verification_key() = default;
                    r1cs_gg_ppzksnark_verification_key(
                        const typename CurveType::gt_type::value_type &alpha_g1_beta_g2,
                        const typename CurveType::template g2_type<>::value_type &gamma_g2,
                        const typename CurveType::template g2_type<>::value_type &delta_g2,
                        const container::accumulation_vector<typename CurveType::template g1_type<>> &gamma_ABC_g1) :
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
                        using g2_type = typename CurveType::template g2_type<>;

                        // TODO: include GT size
                        return (gamma_ABC_g1.size_in_bits() + 2 * g2_type::value_bits);
                    }

                    bool operator==(const r1cs_gg_ppzksnark_verification_key &other) const {
                        return (this->alpha_g1_beta_g2 == other.alpha_g1_beta_g2 && this->gamma_g2 == other.gamma_g2 &&
                                this->delta_g2 == other.delta_g2 && this->gamma_ABC_g1 == other.gamma_ABC_g1);
                    }

                    explicit operator r1cs_gg_ppzksnark_processed_verification_key<CurveType>() const {
                        r1cs_gg_ppzksnark_processed_verification_key<CurveType> processed_verification_key;
                        processed_verification_key.vk_alpha_g1_beta_g2 = alpha_g1_beta_g2;
                        processed_verification_key.vk_gamma_g2_precomp = precompute_g2<CurveType>(gamma_g2);
                        processed_verification_key.vk_delta_g2_precomp = precompute_g2<CurveType>(delta_g2);
                        processed_verification_key.gamma_ABC_g1 = gamma_ABC_g1;

                        return processed_verification_key;
                    }
                };

                template<typename CurveType>
                struct r1cs_gg_ppzksnark_processed_verification_key {
                    typedef CurveType curve_type;
                    typedef typename algebra::pairing::pairing_policy<CurveType> pairing_policy;

                    typename CurveType::gt_type::value_type vk_alpha_g1_beta_g2;
                    typename pairing_policy::g2_precomputed_type vk_gamma_g2_precomp;
                    typename pairing_policy::g2_precomputed_type vk_delta_g2_precomp;

                    container::accumulation_vector<typename CurveType::template g1_type<>> gamma_ABC_g1;

                    bool operator==(const r1cs_gg_ppzksnark_processed_verification_key &other) const {
                        return (this->vk_alpha_g1_beta_g2 == other.vk_alpha_g1_beta_g2 &&
                                this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
                                this->vk_delta_g2_precomp == other.vk_delta_g2_precomp &&
                                this->gamma_ABC_g1 == other.gamma_ABC_g1);
                    }
                };

                template<typename CurveType>
                struct r1cs_gg_ppzksnark_extended_verification_key {
                    typedef CurveType curve_type;

                    typedef typename CurveType::template g1_type<> g1_type;
                    typedef typename CurveType::template g2_type<> g2_type;
                    typedef typename CurveType::gt_type gt_type;

                    typename gt_type::value_type alpha_g1_beta_g2;
                    typename g2_type::value_type gamma_g2;
                    typename g2_type::value_type delta_g2;
                    typename g1_type::value_type delta_g1;
                    container::accumulation_vector<g1_type> gamma_ABC_g1;
                    typename g1_type::value_type gamma_g1;

                    r1cs_gg_ppzksnark_extended_verification_key() = default;
                    r1cs_gg_ppzksnark_extended_verification_key(
                        const typename gt_type::value_type &alpha_g1_beta_g2,
                        const typename g2_type::value_type &gamma_g2,
                        const typename g2_type::value_type &delta_g2,
                        const typename g1_type::value_type &delta_g1,
                        const container::accumulation_vector<g1_type> &gamma_ABC_g1,
                        const typename g1_type::value_type &gamma_g1) :
                        alpha_g1_beta_g2(alpha_g1_beta_g2),
                        gamma_g2(gamma_g2), delta_g2(delta_g2), delta_g1(delta_g1), gamma_ABC_g1(gamma_ABC_g1),
                        gamma_g1(gamma_g1) {
                    }

                    std::size_t G1_size() const {
                        return gamma_ABC_g1.size() + 2;
                    }

                    std::size_t G2_size() const {
                        return 2;
                    }

                    std::size_t GT_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        // TODO: include GT size
                        return (gamma_ABC_g1.size_in_bits() + 2 * g2_type::value_bits + 2 * g1_type::value_bits);
                    }

                    bool operator==(const r1cs_gg_ppzksnark_extended_verification_key &other) const {
                        return alpha_g1_beta_g2 == other.alpha_g1_beta_g2 && gamma_g2 == other.gamma_g2 &&
                               delta_g2 == other.delta_g2 && delta_g1 == other.delta_g1 &&
                               gamma_ABC_g1 == other.gamma_ABC_g1;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP

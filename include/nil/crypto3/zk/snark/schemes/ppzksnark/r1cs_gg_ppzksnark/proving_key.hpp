//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_PROVING_KEY_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_PROVING_KEY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType,
                         typename ConstraintSystem = r1cs_constraint_system<typename CurveType::scalar_field_type>>
                struct r1cs_gg_ppzksnark_proving_key {
                    typedef CurveType curve_type;
                    typedef ConstraintSystem constraint_system_type;

                    typename CurveType::g1_type::value_type alpha_g1;
                    typename CurveType::g1_type::value_type beta_g1;
                    typename CurveType::g2_type::value_type beta_g2;
                    typename CurveType::g1_type::value_type delta_g1;
                    typename CurveType::g2_type::value_type delta_g2;

                    std::vector<typename CurveType::g1_type::value_type>
                        A_query;    // this could be a sparse vector if we had multiexp for those
                    knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> B_query;
                    std::vector<typename CurveType::g1_type::value_type> H_query;
                    std::vector<typename CurveType::g1_type::value_type> L_query;

                    constraint_system_type constraint_system;

                    r1cs_gg_ppzksnark_proving_key() {};
                    r1cs_gg_ppzksnark_proving_key &operator=(const r1cs_gg_ppzksnark_proving_key &other) = default;
                    r1cs_gg_ppzksnark_proving_key(const r1cs_gg_ppzksnark_proving_key &other) = default;
                    r1cs_gg_ppzksnark_proving_key(r1cs_gg_ppzksnark_proving_key &&other) = default;

                    r1cs_gg_ppzksnark_proving_key(
                        typename CurveType::g1_type::value_type &&alpha_g1,
                        typename CurveType::g1_type::value_type &&beta_g1,
                        typename CurveType::g2_type::value_type &&beta_g2,
                        typename CurveType::g1_type::value_type &&delta_g1,
                        typename CurveType::g2_type::value_type &&delta_g2,
                        std::vector<typename CurveType::g1_type::value_type> &&A_query,
                        knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> &&B_query,
                        std::vector<typename CurveType::g1_type::value_type> &&H_query,
                        std::vector<typename CurveType::g1_type::value_type> &&L_query,
                        constraint_system_type &&constraint_system) :
                        alpha_g1(std::move(alpha_g1)),
                        beta_g1(std::move(beta_g1)), beta_g2(std::move(beta_g2)), delta_g1(std::move(delta_g1)),
                        delta_g2(std::move(delta_g2)), A_query(std::move(A_query)), B_query(std::move(B_query)),
                        H_query(std::move(H_query)), L_query(std::move(L_query)), constraint_system(std::move(constraint_system)) {};

                    std::size_t G1_size() const {
                        return 1 + A_query.size() + B_query.domain_size() + H_query.size() + L_query.size();
                    }

                    std::size_t G2_size() const {
                        return 1 + B_query.domain_size();
                    }

                    std::size_t G1_sparse_size() const {
                        return 1 + A_query.size() + B_query.size() + H_query.size() + L_query.size();
                    }

                    std::size_t G2_sparse_size() const {
                        return 1 + B_query.size();
                    }

                    std::size_t size_in_bits() const {
                        return A_query.size() * CurveType::g1_type::value_bits + B_query.size_in_bits() +
                               H_query.size() * CurveType::g1_type::value_bits +
                               L_query.size() * CurveType::g1_type::value_bits + 1 * CurveType::g1_type::value_bits +
                               1 * CurveType::g2_type::value_bits;
                    }

                    bool operator==(const r1cs_gg_ppzksnark_proving_key &other) const {
                        return (this->alpha_g1 == other.alpha_g1 && this->beta_g1 == other.beta_g1 &&
                                this->beta_g2 == other.beta_g2 && this->delta_g1 == other.delta_g1 &&
                                this->delta_g2 == other.delta_g2 && this->A_query == other.A_query &&
                                this->B_query == other.B_query && this->H_query == other.H_query &&
                                this->L_query == other.L_query && this->constraint_system == other.constraint_system);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP

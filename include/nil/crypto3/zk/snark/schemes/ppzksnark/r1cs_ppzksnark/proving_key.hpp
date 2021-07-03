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

#ifndef CRYPTO3_R1CS_PPZKSNARK_PROVING_KEY_HPP
#define CRYPTO3_R1CS_PPZKSNARK_PROVING_KEY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/commitments/knowledge_commitment_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A proving key for the R1CS ppzkSNARK.
                 */
                template<typename CurveType, typename ConstraintSystemType>
                class r1cs_ppzksnark_proving_key {
                    using g1_type = typename CurveType::g1_type;
                    using g2_type = typename CurveType::g2_type;
                    using g1_value_type = typename g1_type::value_type;
                    using g2_value_type = typename g2_type::value_type;

                public:
                    typedef CurveType curve_type;
                    typedef ConstraintSystemType constraint_system_type;

                    knowledge_commitment_vector<g1_type, g1_type> A_query;
                    knowledge_commitment_vector<g2_type, g1_type> B_query;
                    knowledge_commitment_vector<g1_type, g1_type> C_query;
                    std::vector<g1_value_type> H_query;
                    std::vector<g1_value_type> K_query;

                    constraint_system_type constraint_system;

                    r1cs_ppzksnark_proving_key() {};
                    r1cs_ppzksnark_proving_key &operator=(const r1cs_ppzksnark_proving_key &other) = default;
                    r1cs_ppzksnark_proving_key(const r1cs_ppzksnark_proving_key &other) = default;
                    r1cs_ppzksnark_proving_key(r1cs_ppzksnark_proving_key &&other) = default;
                    r1cs_ppzksnark_proving_key(knowledge_commitment_vector<g1_type, g1_type> &&A_query,
                                               knowledge_commitment_vector<g2_type, g1_type> &&B_query,
                                               knowledge_commitment_vector<g1_type, g1_type> &&C_query,
                                               typename std::vector<g1_value_type> &&H_query,
                                               typename std::vector<g1_value_type> &&K_query,
                                               constraint_system_type &&constraint_system) :
                        A_query(std::move(A_query)),
                        B_query(std::move(B_query)), C_query(std::move(C_query)), H_query(std::move(H_query)),
                        K_query(std::move(K_query)), constraint_system(std::move(constraint_system)) {};

                    std::size_t G1_size() const {
                        return 2 * (A_query.domain_size() + C_query.domain_size()) + B_query.domain_size() +
                               H_query.size() + K_query.size();
                    }

                    std::size_t G2_size() const {
                        return B_query.domain_size();
                    }

                    std::size_t G1_sparse_size() const {
                        return 2 * (A_query.size() + C_query.size()) + B_query.size() + H_query.size() + K_query.size();
                    }

                    std::size_t G2_sparse_size() const {
                        return B_query.size();
                    }

                    std::size_t size_in_bits() const {
                        return A_query.size_in_bits() + B_query.size_in_bits() + C_query.size_in_bits() +
                               H_query.size() * CurveType::g1_type::value_bits +
                               K_query.size() * CurveType::g1_type::value_bits;
                    }

                    bool operator==(const r1cs_ppzksnark_proving_key &other) const {
                        return (this->A_query == other.A_query && this->B_query == other.B_query &&
                                this->C_query == other.C_query && this->H_query == other.H_query &&
                                this->K_query == other.K_query && this->constraint_system == other.constraint_system);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_PROVER_HPP

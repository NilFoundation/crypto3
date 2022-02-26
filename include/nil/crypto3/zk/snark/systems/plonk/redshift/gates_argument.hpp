//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_GATES_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_GATES_ARGUMENT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/merkle/tree.hpp>

#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType,
                         typename RedshiftParams,
                         std::size_t ArgumentSize = 1>
                struct redshift_gates_argument;

                template<typename FieldType,
                         typename RedshiftParams>
                struct redshift_gates_argument<FieldType, RedshiftParams, 1> {

                    using transcript_hash_type = typename RedshiftParams::transcript_hash_type;

                    using types_policy = detail::redshift_types_policy<FieldType, RedshiftParams>;

                    constexpr static const std::size_t argument_size = 1;

                    static inline std::array<math::polynomial<typename FieldType::value_type>, argument_size>
                        prove_eval(typename types_policy::constraint_system_type &constraint_system,
                                    const std::vector<math::polynomial<typename FieldType::value_type>> &column_polynomials,
                                   fiat_shamir_heuristic_updated<transcript_hash_type> &transcript) {

                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<math::polynomial<typename FieldType::value_type>,
                                             argument_size> F;

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        std::vector<plonk_gate<FieldType>> &gates = constraint_system.gates;

                        for (std::size_t i = 0; i < gates.size(); i++) {
                            math::polynomial<typename FieldType::value_type> gate_result = {0};

                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                gate_result = gate_result + gates[i].constraints[j].evaluate(column_polynomials) * theta_acc;
                                theta_acc *= theta;
                            }

                            gate_result = gate_result * gates[i].selector;

                            F[0] = F[0] + gate_result;
                        }

                        return F;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size> 
                        verify_eval(const std::vector<plonk_gate<FieldType>> &gates,
                            typename plonk_constraint<FieldType>::evaluation_map &evaluations,
                            typename FieldType::value_type challenge,
                            fiat_shamir_heuristic_updated<transcript_hash_type> &transcript) {
                        typename FieldType::value_type theta = transcript.template challenge<FieldType>();

                        std::array<typename FieldType::value_type, argument_size> F;

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        for (std::size_t i = 0; i < gates.size(); i++) {
                            typename FieldType::value_type gate_result = {0};

                            for (std::size_t j = 0; j < gates[i].constraints.size(); j++) {
                                gate_result = gate_result + gates[i].constraints[j].evaluate(evaluations) * theta_acc;
                                theta_acc *= theta;
                            }

                            gate_result = gate_result * gates[i].selector.evaluate(challenge);

                            F[0] = F[0] + gate_result;
                        }

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_GATES_ARGUMENT_HPP
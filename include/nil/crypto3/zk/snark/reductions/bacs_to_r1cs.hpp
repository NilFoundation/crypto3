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
// @file Declaration of interfaces for a BACS-to-R1CS reduction, that is, constructing
// a R1CS ("Rank-1 Constraint System") from a BACS ("Bilinear Arithmetic Circuit Satisfiability").
//
// The reduction is straightforward: each bilinear gate gives rises to a
// corresponding R1CS constraint that enforces correct computation of the gate;
// also, each output gives rise to a corresponding R1CS constraint that enforces
// that the output is zero.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BACS_TO_R1CS_BASIC_POLICY_HPP
#define CRYPTO3_ZK_BACS_TO_R1CS_BASIC_POLICY_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace reductions {

                    template<typename FieldType>
                    struct bacs_to_r1cs {
                        typedef FieldType field_type;

                        /**
                         * Instance map for the BACS-to-R1CS reduction.
                         */
                        static r1cs_constraint_system<FieldType> instance_map(const bacs_circuit<FieldType> &circuit) {
                            assert(circuit.is_valid());
                            r1cs_constraint_system<FieldType> result;

                            result.primary_input_size = circuit.primary_input_size;
                            result.auxiliary_input_size = circuit.auxiliary_input_size + circuit.gates.size();

                            for (auto &g : circuit.gates) {
                                result.constraints.emplace_back(r1cs_constraint<FieldType>(g.lhs, g.rhs, g.output));
                            }

                            for (auto &g : circuit.gates) {
                                if (g.is_circuit_output) {
                                    result.constraints.emplace_back(r1cs_constraint<FieldType>(1, g.output, 0));
                                }
                            }

                            return result;
                        }

                        /**
                         * Witness map for the BACS-to-R1CS reduction.
                         */
                        static r1cs_variable_assignment<FieldType>
                            witness_map(const bacs_circuit<FieldType> &circuit,
                                        const bacs_primary_input<FieldType> &primary_input,
                                        const bacs_auxiliary_input<FieldType> &auxiliary_input) {
                            const r1cs_variable_assignment<FieldType> result =
                                circuit.get_all_wires(primary_input, auxiliary_input);
                            return result;
                        }
                    };
                }    // namespace reductions
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_TO_R1CS_BASIC_POLICY_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a BACS-to-R1CS reduction, that is, constructing
// a R1CS ("Rank-1 Constraint System") from a BACS ("Bilinear Arithmetic Circuit Satisfiability").
//
// The reduction is straightforward: each bilinear gate gives rises to a
// corresponding R1CS constraint that enforces correct computation of the gate;
// also, each output gives rise to a corresponding R1CS constraint that enforces
// that the output is zero.
//---------------------------------------------------------------------------//

#ifndef BACS_TO_R1CS_HPP_
#define BACS_TO_R1CS_HPP_

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/bacs.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Instance map for the BACS-to-R1CS reduction.
                 */
                template<typename FieldType>
                r1cs_constraint_system<FieldType> bacs_to_r1cs_instance_map(const bacs_circuit<FieldType> &circuit);

                /**
                 * Witness map for the BACS-to-R1CS reduction.
                 */
                template<typename FieldType>
                r1cs_variable_assignment<FieldType>
                    bacs_to_r1cs_witness_map(const bacs_circuit<FieldType> &circuit,
                                             const bacs_primary_input<FieldType> &primary_input,
                                             const bacs_auxiliary_input<FieldType> &auxiliary_input);

                template<typename FieldType>
                r1cs_constraint_system<FieldType> bacs_to_r1cs_instance_map(const bacs_circuit<FieldType> &circuit) {
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

                template<typename FieldType>
                r1cs_variable_assignment<FieldType>
                    bacs_to_r1cs_witness_map(const bacs_circuit<FieldType> &circuit,
                                             const bacs_primary_input<FieldType> &primary_input,
                                             const bacs_auxiliary_input<FieldType> &auxiliary_input) {
                    const r1cs_variable_assignment<FieldType> result =
                        circuit.get_all_wires(primary_input, auxiliary_input);
                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // BACS_TO_R1CS_HPP_

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a TBCS example, as well as functions to sample
// TBCS examples with prescribed parameters (according to some distribution).
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TBCS_EXAMPLES_HPP_
#define CRYPTO3_ZK_TBCS_EXAMPLES_HPP_

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A TBCS example comprises a TBCS circuit, TBCS primary input, and TBCS auxiliary input.
                 */
                struct tbcs_example {

                    tbcs_circuit circuit;
                    tbcs_primary_input primary_input;
                    tbcs_auxiliary_input auxiliary_input;

                    tbcs_example() = default;
                    tbcs_example(const tbcs_example &other) = default;
                    tbcs_example(const tbcs_circuit &circuit,
                                 const tbcs_primary_input &primary_input,
                                 const tbcs_auxiliary_input &auxiliary_input) :
                        circuit(circuit),
                        primary_input(primary_input), auxiliary_input(auxiliary_input) {
                    }

                    tbcs_example(tbcs_circuit &&circuit,
                                 tbcs_primary_input &&primary_input,
                                 tbcs_auxiliary_input &&auxiliary_input) :
                        circuit(std::move(circuit)),
                        primary_input(std::move(primary_input)), auxiliary_input(std::move(auxiliary_input)) {
                    }
                };

                /**
                 * Generate a TBCS example such that:
                 * - the primary input has size primary_input_size;
                 * - the auxiliary input has size auxiliary_input_size;
                 * - the circuit has num_gates gates;
                 * - the circuit has num_outputs (<= num_gates) output gates.
                 *
                 * This is done by first selecting primary and auxiliary inputs uniformly at random, and then for each
                 * gate:
                 * - selecting random left and right wires from primary inputs, auxiliary inputs, and outputs of
                 * previous gates,
                 * - selecting a gate type at random (subject to the constraint "output = 0" if this is an output gate).
                 */
                tbcs_example generate_tbcs_example(std::size_t primary_input_size,
                                                   std::size_t auxiliary_input_size,
                                                   std::size_t num_gates,
                                                   std::size_t num_outputs) {
                    tbcs_example example;
                    for (std::size_t i = 0; i < primary_input_size; ++i) {
                        example.primary_input.push_back(std::rand() % 2 == 0 ? false : true);
                    }

                    for (std::size_t i = 0; i < auxiliary_input_size; ++i) {
                        example.auxiliary_input.push_back(std::rand() % 2 == 0 ? false : true);
                    }

                    example.circuit.primary_input_size = primary_input_size;
                    example.circuit.auxiliary_input_size = auxiliary_input_size;

                    tbcs_variable_assignment all_vals;
                    all_vals.insert(all_vals.end(), example.primary_input.begin(), example.primary_input.end());
                    all_vals.insert(all_vals.end(), example.auxiliary_input.begin(), example.auxiliary_input.end());

                    for (std::size_t i = 0; i < num_gates; ++i) {
                        const std::size_t num_variables = primary_input_size + auxiliary_input_size + i;
                        tbcs_gate gate;
                        gate.left_wire = std::rand() % (num_variables + 1);
                        gate.right_wire = std::rand() % (num_variables + 1);
                        gate.output = num_variables + 1;

                        if (i >= num_gates - num_outputs) {
                            /* make gate a circuit output and fix */
                            do {
                                gate.type = (tbcs_gate_type)(std::rand() % num_tbcs_gate_types);
                            } while (gate.evaluate(all_vals));

                            gate.is_circuit_output = true;
                        } else {
                            gate.type = (tbcs_gate_type)(std::rand() % num_tbcs_gate_types);
                            gate.is_circuit_output = false;
                        }

                        example.circuit.add_gate(gate);
                        all_vals.push_back(gate.evaluate(all_vals));
                    }

                    BOOST_CHECK(example.circuit.is_satisfied(example.primary_input, example.auxiliary_input));

                    return example;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // TBCS_EXAMPLES_HPP_

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a BACS example, as well as functions to sample
// BACS examples with prescribed parameters (according to some distribution).
//---------------------------------------------------------------------------//

#ifndef BACS_EXAMPLES_HPP_
#define BACS_EXAMPLES_HPP_

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/bacs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A BACS example comprises a BACS circuit, BACS primary input, and BACS auxiliary input.
                 */
                template<typename FieldType>
                struct bacs_example {

                    bacs_circuit<FieldType> circuit;
                    bacs_primary_input<FieldType> primary_input;
                    bacs_auxiliary_input<FieldType> auxiliary_input;

                    bacs_example<FieldType>() = default;
                    bacs_example<FieldType>(const bacs_example<FieldType> &other) = default;
                    bacs_example<FieldType>(const bacs_circuit<FieldType> &circuit,
                                         const bacs_primary_input<FieldType> &primary_input,
                                         const bacs_auxiliary_input<FieldType> &auxiliary_input) :
                        circuit(circuit),
                        primary_input(primary_input), auxiliary_input(auxiliary_input) {
                    }

                    bacs_example<FieldType>(bacs_circuit<FieldType> &&circuit,
                                         bacs_primary_input<FieldType> &&primary_input,
                                         bacs_auxiliary_input<FieldType> &&auxiliary_input) :
                        circuit(std::move(circuit)),
                        primary_input(std::move(primary_input)), auxiliary_input(std::move(auxiliary_input)) {
                    }
                };

                template<typename FieldType>
                linear_combination<FieldType> random_linear_combination(const std::size_t num_variables) {
                    const std::size_t terms = 1 + (std::rand() % 3);
                    linear_combination<FieldType> result;

                    for (std::size_t i = 0; i < terms; ++i) {
                        const FieldType coeff = FieldType(
                            std::rand());    // TODO: replace with FieldType::random_element(), when it becomes faster...
                        result = result + coeff * variable<FieldType>(std::rand() % (num_variables + 1));
                    }

                    return result;
                }

                /**
                 * Generate a BACS example such that:
                 * - the primary input has size primary_input_size;
                 * - the auxiliary input has size auxiliary_input_size;
                 * - the circuit has num_gates gates;
                 * - the circuit has num_outputs (<= num_gates) output gates.
                 *
                 * This is done by first selecting primary and auxiliary inputs uniformly at random, and then for each
                 * gate:
                 * - selecting random left and right wires from primary inputs, auxiliary inputs, and outputs of
                 * previous gates,
                 * - selecting random linear combinations for left and right wires, consisting of 1, 2, 3 or 4 terms
                 * each, with random coefficients,
                 * - if the gate is an output gate, then adding a random non-output wire to either left or right linear
                 * combination, with appropriate coefficient, so that the linear combination evaluates to 0.
                 */
                template<typename FieldType>
                bacs_example<FieldType> generate_bacs_example(std::size_t primary_input_size,
                                                           std::size_t auxiliary_input_size,
                                                           std::size_t num_gates,
                                                           std::size_t num_outputs) {
                    bacs_example<FieldType> example;
                    for (std::size_t i = 0; i < primary_input_size; ++i) {
                        example.primary_input.emplace_back(FieldType::random_element());
                    }

                    for (std::size_t i = 0; i < auxiliary_input_size; ++i) {
                        example.auxiliary_input.emplace_back(FieldType::random_element());
                    }

                    example.circuit.primary_input_size = primary_input_size;
                    example.circuit.auxiliary_input_size = auxiliary_input_size;

                    bacs_variable_assignment<FieldType> all_vals;
                    all_vals.insert(all_vals.end(), example.primary_input.begin(), example.primary_input.end());
                    all_vals.insert(all_vals.end(), example.auxiliary_input.begin(), example.auxiliary_input.end());

                    for (std::size_t i = 0; i < num_gates; ++i) {
                        const std::size_t num_variables = primary_input_size + auxiliary_input_size + i;
                        bacs_gate<FieldType> gate;
                        gate.lhs = random_linear_combination<FieldType>(num_variables);
                        gate.rhs = random_linear_combination<FieldType>(num_variables);
                        gate.output = variable<FieldType>(num_variables + 1);

                        if (i >= num_gates - num_outputs) {
                            /* make gate a circuit output and fix */
                            gate.is_circuit_output = true;
                            const var_index_t var_idx =
                                std::rand() % (1 + primary_input_size + std::min(num_gates - num_outputs, i));
                            const FieldType var_val = (var_idx == 0 ? FieldType::one() : all_vals[var_idx - 1]);

                            if (std::rand() % 2 == 0) {
                                const FieldType lhs_val = gate.lhs.evaluate(all_vals);
                                const FieldType coeff = -(lhs_val * var_val.inverse());
                                gate.lhs = gate.lhs + coeff * variable<FieldType>(var_idx);
                            } else {
                                const FieldType rhs_val = gate.rhs.evaluate(all_vals);
                                const FieldType coeff = -(rhs_val * var_val.inverse());
                                gate.rhs = gate.rhs + coeff * variable<FieldType>(var_idx);
                            }

                            assert(gate.evaluate(all_vals).is_zero());
                        } else {
                            gate.is_circuit_output = false;
                        }

                        example.circuit.add_gate(gate);
                        all_vals.emplace_back(gate.evaluate(all_vals));
                    }

                    assert(example.circuit.is_satisfied(example.primary_input, example.auxiliary_input));

                    return example;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // BACS_EXAMPLES_HPP_

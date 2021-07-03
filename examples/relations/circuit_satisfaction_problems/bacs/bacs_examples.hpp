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

#ifndef CRYPTO3_BACS_EXAMPLES_HPP
#define CRYPTO3_BACS_EXAMPLES_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

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
                                                              std::size_t num_outputs);

                template<typename FieldType>
                linear_combination<FieldType> random_linear_combination(const std::size_t num_variables) {

                    using policy_type = FieldType;
                    using field_value_type = policy_type::value_type;

                    const std::size_t terms = 1 + (std::rand() % 3);
                    linear_combination<FieldType> result;

                    for (std::size_t i = 0; i < terms; ++i) {
                        const field_value_type coeff = algebra::random_element<FieldType>();
                        result = result + coeff * variable<FieldType>(std::rand() % (num_variables + 1));
                    }

                    return result;
                }

                template<typename FieldType>
                bacs_example<FieldType> generate_bacs_example(std::size_t primary_input_size,
                                                              std::size_t auxiliary_input_size,
                                                              std::size_t num_gates,
                                                              std::size_t num_outputs) {

                    using policy_type = FieldType;
                    using field_value_type = policy_type::value_type;

                    bacs_example<FieldType> example;
                    for (std::size_t i = 0; i < primary_input_size; ++i) {
                        example.primary_input.emplace_back(algebra::random_element<FieldType>());
                    }

                    for (std::size_t i = 0; i < auxiliary_input_size; ++i) {
                        example.auxiliary_input.emplace_back(algebra::random_element<FieldType>());
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
                            const field_value_type var_val =
                                (var_idx == 0 ? field_value_type::one() : all_vals[var_idx - 1]);

                            if (std::rand() % 2 == 0) {
                                const field_value_type lhs_val = gate.lhs.evaluate(all_vals);
                                const field_value_type coeff = -(lhs_val * var_val.inversed());
                                gate.lhs = gate.lhs + coeff * variable<FieldType>(var_idx);
                            } else {
                                const field_value_type rhs_val = gate.rhs.evaluate(all_vals);
                                const field_value_type coeff = -(rhs_val * var_val.inversed());
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

#endif    // CRYPTO3_BACS_EXAMPLES_HPP

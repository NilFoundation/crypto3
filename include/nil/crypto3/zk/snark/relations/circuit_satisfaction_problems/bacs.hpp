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
// @file Declaration of interfaces for:
// - a BACS variable assignment,
// - a BACS gate,
// - a BACS primary input,
// - a BACS auxiliary input,
// - a BACS circuit.
//
// Above, BACS stands for "Bilinear Arithmetic Circuit Satisfiability".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BACS_HPP
#define CRYPTO3_ZK_BACS_HPP

#include <vector>

#include <nil/crypto3/zk/snark/relations/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /*********************** BACS variable assignment ****************************/

                /**
                 * A BACS variable assignment is a vector of field elements.
                 */
                template<typename FieldType>
                using bacs_variable_assignment = std::vector<typename FieldType::value_type>;

                /**************************** BACS gate **************************************/

                /**
                 * A BACS gate is a formal expression of the form lhs * rhs = output ,
                 * where lhs and rhs are linear combinations (of variables) and output is a variable.
                 *
                 * In other words, a BACS gate is an arithmetic gate that is bilinear.
                 */
                template<typename FieldType>
                struct bacs_gate {
                    typedef FieldType field_type;

                    linear_combination<FieldType> lhs;
                    linear_combination<FieldType> rhs;

                    variable<FieldType> output;
                    bool is_circuit_output;

                    typename FieldType::value_type evaluate(const bacs_variable_assignment<FieldType> &input) const {
                        return lhs.evaluate(input) * rhs.evaluate(input);
                    }

                    bool operator==(const bacs_gate<FieldType> &other) const {
                        return (this->lhs == other.lhs && this->rhs == other.rhs && this->output == other.output &&
                                this->is_circuit_output == other.is_circuit_output);
                    }
                };

                /****************************** BACS inputs **********************************/

                /**
                 * A BACS primary input is a BACS variable assignment.
                 */
                template<typename FieldType>
                using bacs_primary_input = bacs_variable_assignment<FieldType>;

                /**
                 * A BACS auxiliary input is a BACS variable assigment.
                 */
                template<typename FieldType>
                using bacs_auxiliary_input = bacs_variable_assignment<FieldType>;

                /************************** BACS circuit *************************************/

                /**
                 * A BACS circuit is an arithmetic circuit in which every gate is a BACS gate.
                 *
                 * Given a BACS primary input and a BACS auxiliary input, the circuit can be evaluated.
                 * If every output evaluates to zero, then the circuit is satisfied.
                 *
                 * NOTE:
                 * The 0-th variable (i.e., "x_{0}") always represents the constant 1.
                 * Thus, the 0-th variable is not included in num_variables.
                 */
                template<typename FieldType>
                struct bacs_circuit {
                    typedef FieldType field_type;

                    std::size_t primary_input_size;
                    std::size_t auxiliary_input_size;
                    std::vector<bacs_gate<FieldType>> gates;

                    bacs_circuit() : primary_input_size(0), auxiliary_input_size(0) {
                    }

                    std::size_t num_inputs() const {
                        return primary_input_size + auxiliary_input_size;
                    }

                    std::size_t num_gates() const {
                        return gates.size();
                    }

                    std::size_t num_wires() const {
                        return num_inputs() + num_gates();
                    }

                    std::vector<std::size_t> wire_depths() const {
                        std::vector<std::size_t> depths;
                        depths.emplace_back(0);
                        depths.resize(num_inputs() + 1, 1);

                        for (auto &g : gates) {
                            std::size_t max_depth = 0;
                            for (auto &t : g.lhs) {
                                max_depth = std::max(max_depth, depths[t.index]);
                            }

                            for (auto &t : g.rhs) {
                                max_depth = std::max(max_depth, depths[t.index]);
                            }

                            depths.emplace_back(max_depth + 1);
                        }

                        return depths;
                    }

                    std::size_t depth() const {
                        std::vector<std::size_t> all_depths = this->wire_depths();
                        return *(std::max_element(all_depths.begin(), all_depths.end()));
                    }

                    bool is_valid() const {
                        for (std::size_t i = 0; i < num_gates(); ++i) {
                            /**
                             * The output wire of gates[i] must have index 1+num_inputs+i.
                             * (The '1+' accounts for the the index of the constant wire.)
                             */
                            if (gates[i].output.index != 1 + num_inputs() + i) {
                                return false;
                            }

                            /**
                             * Gates must be topologically sorted.
                             */
                            if (!gates[i].lhs.is_valid(gates[i].output.index) ||
                                !gates[i].rhs.is_valid(gates[i].output.index)) {
                                return false;
                            }
                        }

                        return true;
                    }

                    bool is_satisfied(const bacs_primary_input<FieldType> &primary_input,
                                      const bacs_auxiliary_input<FieldType> &auxiliary_input) const {
                        const bacs_variable_assignment<FieldType> all_outputs =
                            get_all_outputs(primary_input, auxiliary_input);

                        for (std::size_t i = 0; i < all_outputs.size(); ++i) {
                            if (!all_outputs[i].is_zero()) {
                                return false;
                            }
                        }

                        return true;
                    }

                    bacs_variable_assignment<FieldType>
                        get_all_outputs(const bacs_primary_input<FieldType> &primary_input,
                                        const bacs_auxiliary_input<FieldType> &auxiliary_input) const {
                        const bacs_variable_assignment<FieldType> all_wires =
                            get_all_wires(primary_input, auxiliary_input);

                        bacs_variable_assignment<FieldType> all_outputs;

                        for (auto &g : gates) {
                            if (g.is_circuit_output) {
                                all_outputs.emplace_back(all_wires[g.output.index - 1]);
                            }
                        }

                        return all_outputs;
                    }

                    bacs_variable_assignment<FieldType>
                        get_all_wires(const bacs_primary_input<FieldType> &primary_input,
                                      const bacs_auxiliary_input<FieldType> &auxiliary_input) const {
                        assert(primary_input.size() == primary_input_size);
                        assert(auxiliary_input.size() == auxiliary_input_size);

                        bacs_variable_assignment<FieldType> result;
                        result.insert(result.end(), primary_input.begin(), primary_input.end());
                        result.insert(result.end(), auxiliary_input.begin(), auxiliary_input.end());

                        assert(result.size() == num_inputs());

                        for (auto &g : gates) {
                            const typename FieldType::value_type gate_output = g.evaluate(result);
                            result.emplace_back(gate_output);
                        }

                        return result;
                    }

                    void add_gate(const bacs_gate<FieldType> &g) {
                        assert(g.output.index == num_wires() + 1);
                        gates.emplace_back(g);
                    }

                    void add_gate(const bacs_gate<FieldType> &g, const std::string &annotation) {
                        assert(g.output.index == num_wires() + 1);
                        gates.emplace_back(g);
                    }

                    bool operator==(const bacs_circuit<FieldType> &other) const {
                        return (this->primary_input_size == other.primary_input_size &&
                                this->auxiliary_input_size == other.auxiliary_input_size && this->gates == other.gates);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BACS_HPP

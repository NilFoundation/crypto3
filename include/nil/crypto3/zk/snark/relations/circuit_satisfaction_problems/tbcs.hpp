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
// - a TBCS gate,
// - a TBCS variable assignment, and
// - a TBCS circuit.
//
// Above, TBCS stands for "Two-input Boolean Circuit Satisfiability".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TBCS_HPP
#define CRYPTO3_ZK_TBCS_HPP

#include <nil/crypto3/zk/snark/relations/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /*********************** BACS variable assignment ****************************/

                /**
                 * A TBCS variable assignment is a vector of bools.
                 */
                typedef std::vector<bool> tbcs_variable_assignment;

                /**************************** TBCS gate **************************************/

                typedef std::size_t tbcs_wire_t;

                /**
                 * Types of TBCS gates (2-input boolean gates).
                 *
                 * The order and names used below is taken from page 4 of [1].
                 *
                 * Note that each gate's truth table is encoded in its 4-bit opcode. Namely,
                 * if g(X,Y) denotes the output of gate g with inputs X and Y, then
                 *            OPCODE(g) = (g(0,0),g(0,1),g(1,0),g(1,1))
                 * For example, if g is of type IF_X_THEN_Y, which has opcode 13, then the
                 * truth table of g is 1101 (13 in binary).
                 *
                 * (Note that MSB above is g(0,0) and LSB is g(1,1))
                 *
                 * References:
                 *
                 * [1] = https://mitpress.mit.edu/sites/default/files/titles/content/9780262640688_sch_0001.pdf
                 */
                enum tbcs_gate_type {
                    TBCS_GATE_CONSTANT_0 = 0,
                    TBCS_GATE_AND = 1,
                    TBCS_GATE_X_AND_NOT_Y = 2,
                    TBCS_GATE_X = 3,
                    TBCS_GATE_NOT_X_AND_Y = 4,
                    TBCS_GATE_Y = 5,
                    TBCS_GATE_XOR = 6,
                    TBCS_GATE_OR = 7,
                    TBCS_GATE_NOR = 8,
                    TBCS_GATE_EQUIVALENCE = 9,
                    TBCS_GATE_NOT_Y = 10,
                    TBCS_GATE_IF_Y_THEN_X = 11,
                    TBCS_GATE_NOT_X = 12,
                    TBCS_GATE_IF_X_THEN_Y = 13,
                    TBCS_GATE_NAND = 14,
                    TBCS_GATE_CONSTANT_1 = 15
                };

                static const int num_tbcs_gate_types = 16;

                /**
                 * A TBCS gate is a formal expression of the form
                 *
                 *                g(left_wire,right_wire) = output ,
                 *
                 * where 'left_wire' and 'right_wire' are the two input wires, and 'output' is
                 * the output wire. In other words, a TBCS gate is a 2-input boolean gate;
                 * there are 16 possible such gates (see tbcs_gate_type above).
                 *
                 * A TBCS gate is used to construct a TBCS circuit (see below).
                 */
                struct tbcs_gate {

                    tbcs_wire_t left_wire;
                    tbcs_wire_t right_wire;

                    tbcs_gate_type type;

                    tbcs_wire_t output;

                    bool is_circuit_output;

                    bool evaluate(const tbcs_variable_assignment &input) const {
                        /**
                         * This function is very tricky.
                         * See comment in tbcs.hpp .
                         */

                        const bool X = (left_wire == 0 ? true : input[left_wire - 1]);
                        const bool Y = (right_wire == 0 ? true : input[right_wire - 1]);

                        const std::size_t pos = 3 - ((X ? 2 : 0) + (Y ? 1 : 0)); /* 3 - ... inverts position */

                        return (((int)type) & (1u << pos));
                    }

                    bool operator==(const tbcs_gate &other) const {
                        return (this->left_wire == other.left_wire && this->right_wire == other.right_wire &&
                                this->type == other.type && this->output == other.output &&
                                this->is_circuit_output == other.is_circuit_output);
                    }
                };

                /****************************** TBCS inputs **********************************/

                /**
                 * A TBCS primary input is a TBCS variable assignment.
                 */
                typedef tbcs_variable_assignment tbcs_primary_input;

                /**
                 * A TBCS auxiliary input is a TBCS variable assignment.
                 */
                typedef tbcs_variable_assignment tbcs_auxiliary_input;

                /************************** TBCS circuit *************************************/

                /**
                 * A TBCS circuit is a boolean circuit in which every gate has 2 inputs.
                 *
                 * A TBCS circuit is satisfied by a TBCS variable assignment if every output
                 * evaluates to zero.
                 *
                 * NOTE:
                 * The 0-th variable (i.e., "x_{0}") always represents the constant 1.
                 * Thus, the 0-th variable is not included in num_variables.
                 */
                struct tbcs_circuit {

                    std::size_t primary_input_size;
                    std::size_t auxiliary_input_size;
                    std::vector<tbcs_gate> gates;

                    tbcs_circuit() : primary_input_size(0), auxiliary_input_size(0) {
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
                        std::vector<std::size_t> depths(num_inputs(), 1);

                        for (auto &g : gates) {
                            depths.emplace_back(std::max(depths[g.left_wire], depths[g.right_wire]) + 1);
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
                             * (The '1+' accounts for the index of the constant wire.)
                             */
                            if (gates[i].output != num_inputs() + i + 1) {
                                return false;
                            }

                            /**
                             * Gates must be topologically sorted.
                             */
                            if (gates[i].left_wire >= gates[i].output || gates[i].right_wire >= gates[i].output) {
                                return false;
                            }
                        }

                        return true;
                    }

                    bool is_satisfied(const tbcs_primary_input &primary_input,
                                      const tbcs_auxiliary_input &auxiliary_input) const {
                        const tbcs_variable_assignment all_outputs = get_all_outputs(primary_input, auxiliary_input);
                        for (size_t i = 0; i < all_outputs.size(); ++i) {
                            if (all_outputs[i]) {
                                return false;
                            }
                        }

                        return true;
                    }

                    tbcs_variable_assignment get_all_wires(const tbcs_primary_input &primary_input,
                                                           const tbcs_auxiliary_input &auxiliary_input) const {
                        assert(primary_input.size() == primary_input_size);
                        assert(auxiliary_input.size() == auxiliary_input_size);

                        tbcs_variable_assignment result;
                        result.insert(result.end(), primary_input.begin(), primary_input.end());
                        result.insert(result.end(), auxiliary_input.begin(), auxiliary_input.end());

                        assert(result.size() == num_inputs());

                        for (auto &g : gates) {
                            const bool gate_output = g.evaluate(result);
                            result.push_back(gate_output);
                        }

                        return result;
                    }

                    tbcs_variable_assignment get_all_outputs(const tbcs_primary_input &primary_input,
                                                             const tbcs_auxiliary_input &auxiliary_input) const {
                        const tbcs_variable_assignment all_wires = get_all_wires(primary_input, auxiliary_input);
                        tbcs_variable_assignment all_outputs;

                        for (auto &g : gates) {
                            if (g.is_circuit_output) {
                                all_outputs.push_back(all_wires[g.output - 1]);
                            }
                        }

                        return all_outputs;
                    }

                    void add_gate(const tbcs_gate &g) {
                        assert(g.output == num_wires() + 1);
                        gates.emplace_back(g);
                    }

                    bool operator==(const tbcs_circuit &other) const {
                        return (this->primary_input_size == other.primary_input_size &&
                                this->auxiliary_input_size == other.auxiliary_input_size && this->gates == other.gates);
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TBCS_HPP

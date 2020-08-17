//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

#ifndef BACS_HPP_
#define BACS_HPP_

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
                using bacs_variable_assignment = std::vector<FieldType>;

                /**************************** BACS gate **************************************/

                template<typename FieldType>
                struct bacs_gate;

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const bacs_gate<FieldType> &g);

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, bacs_gate<FieldType> &g);

                /**
                 * A BACS gate is a formal expression of the form lhs * rhs = output ,
                 * where lhs and rhs are linear combinations (of variables) and output is a variable.
                 *
                 * In other words, a BACS gate is an arithmetic gate that is bilinear.
                 */
                template<typename FieldType>
                struct bacs_gate {

                    linear_combination<FieldType> lhs;
                    linear_combination<FieldType> rhs;

                    variable<FieldType> output;
                    bool is_circuit_output;

                    FieldType evaluate(const bacs_variable_assignment<FieldType> &input) const;
                    void print(const std::map<size_t, std::string> &variable_annotations =
                                   std::map<size_t, std::string>()) const;

                    bool operator==(const bacs_gate<FieldType> &other) const;

                    friend std::ostream &operator<<<FieldType>(std::ostream &out, const bacs_gate<FieldType> &g);
                    friend std::istream &operator>><FieldType>(std::istream &in, bacs_gate<FieldType> &g);
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

                template<typename FieldType>
                class bacs_circuit;

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const bacs_circuit<FieldType> &circuit);

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, bacs_circuit<FieldType> &circuit);

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
                class bacs_circuit {
                public:
                    size_t primary_input_size;
                    size_t auxiliary_input_size;
                    std::vector<bacs_gate<FieldType>> gates;

                    bacs_circuit() : primary_input_size(0), auxiliary_input_size(0) {
                    }

                    size_t num_inputs() const;
                    size_t num_gates() const;
                    size_t num_wires() const;

                    std::vector<size_t> wire_depths() const;
                    size_t depth() const;

                    bool is_valid() const;
                    bool is_satisfied(const bacs_primary_input<FieldType> &primary_input,
                                      const bacs_auxiliary_input<FieldType> &auxiliary_input) const;

                    bacs_variable_assignment<FieldType>
                        get_all_outputs(const bacs_primary_input<FieldType> &primary_input,
                                        const bacs_auxiliary_input<FieldType> &auxiliary_input) const;
                    bacs_variable_assignment<FieldType>
                        get_all_wires(const bacs_primary_input<FieldType> &primary_input,
                                      const bacs_auxiliary_input<FieldType> &auxiliary_input) const;

                    void add_gate(const bacs_gate<FieldType> &g);
                    void add_gate(const bacs_gate<FieldType> &g, const std::string &annotation);

                    bool operator==(const bacs_circuit<FieldType> &other) const;

                    void print() const;
                    void print_info() const;

                    friend std::ostream &operator<<<FieldType>(std::ostream &out,
                                                               const bacs_circuit<FieldType> &circuit);
                    friend std::istream &operator>><FieldType>(std::istream &in, bacs_circuit<FieldType> &circuit);
                };

                template<typename FieldType>
                FieldType bacs_gate<FieldType>::evaluate(const bacs_variable_assignment<FieldType> &input) const {
                    return lhs.evaluate(input) * rhs.evaluate(input);
                }

                template<typename FieldType>
                void bacs_gate<FieldType>::print(const std::map<size_t, std::string> &variable_annotations) const {
                    printf("(\n");
                    lhs.print(variable_annotations);
                    printf(")\n *\n(\n");
                    rhs.print(variable_annotations);
                    printf(")\n -> \n");
                    auto it = variable_annotations.find(output.index);
                    printf("    x_%zu (%s) (%s)\n",
                           output.index,
                           (it == variable_annotations.end() ? "no annotation" : it->second.c_str()),
                           (is_circuit_output ? "circuit output" : "internal wire"));
                }

                template<typename FieldType>
                bool bacs_gate<FieldType>::operator==(const bacs_gate<FieldType> &other) const {
                    return (this->lhs == other.lhs && this->rhs == other.rhs && this->output == other.output &&
                            this->is_circuit_output == other.is_circuit_output);
                }

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const bacs_gate<FieldType> &g) {
                    out << (g.is_circuit_output ? 1 : 0) << "\n";
                    out << g.lhs << OUTPUT_NEWLINE;
                    out << g.rhs << OUTPUT_NEWLINE;
                    out << g.output.index << "\n";

                    return out;
                }

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, bacs_gate<FieldType> &g) {
                    size_t tmp;
                    in >> tmp;
                    algebra::consume_newline(in);
                    g.is_circuit_output = (tmp != 0 ? true : false);
                    in >> g.lhs;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> g.rhs;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> g.output.index;
                    algebra::consume_newline(in);

                    return in;
                }

                template<typename FieldType>
                size_t bacs_circuit<FieldType>::num_inputs() const {
                    return primary_input_size + auxiliary_input_size;
                }

                template<typename FieldType>
                size_t bacs_circuit<FieldType>::num_gates() const {
                    return gates.size();
                }

                template<typename FieldType>
                size_t bacs_circuit<FieldType>::num_wires() const {
                    return num_inputs() + num_gates();
                }

                template<typename FieldType>
                std::vector<size_t> bacs_circuit<FieldType>::wire_depths() const {
                    std::vector<size_t> depths;
                    depths.emplace_back(0);
                    depths.resize(num_inputs() + 1, 1);

                    for (auto &g : gates) {
                        size_t max_depth = 0;
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

                template<typename FieldType>
                size_t bacs_circuit<FieldType>::depth() const {
                    std::vector<size_t> all_depths = this->wire_depths();
                    return *(std::max_element(all_depths.begin(), all_depths.end()));
                }

                template<typename FieldType>
                bool bacs_circuit<FieldType>::is_valid() const {
                    for (size_t i = 0; i < num_gates(); ++i) {
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

                template<typename FieldType>
                bacs_variable_assignment<FieldType> bacs_circuit<FieldType>::get_all_wires(
                    const bacs_primary_input<FieldType> &primary_input,
                    const bacs_auxiliary_input<FieldType> &auxiliary_input) const {
                    assert(primary_input.size() == primary_input_size);
                    assert(auxiliary_input.size() == auxiliary_input_size);

                    bacs_variable_assignment<FieldType> result;
                    result.insert(result.end(), primary_input.begin(), primary_input.end());
                    result.insert(result.end(), auxiliary_input.begin(), auxiliary_input.end());

                    assert(result.size() == num_inputs());

                    for (auto &g : gates) {
                        const FieldType gate_output = g.evaluate(result);
                        result.emplace_back(gate_output);
                    }

                    return result;
                }

                template<typename FieldType>
                bacs_variable_assignment<FieldType> bacs_circuit<FieldType>::get_all_outputs(
                    const bacs_primary_input<FieldType> &primary_input,
                    const bacs_auxiliary_input<FieldType> &auxiliary_input) const {
                    const bacs_variable_assignment<FieldType> all_wires = get_all_wires(primary_input, auxiliary_input);

                    bacs_variable_assignment<FieldType> all_outputs;

                    for (auto &g : gates) {
                        if (g.is_circuit_output) {
                            all_outputs.emplace_back(all_wires[g.output.index - 1]);
                        }
                    }

                    return all_outputs;
                }

                template<typename FieldType>
                bool bacs_circuit<FieldType>::is_satisfied(
                    const bacs_primary_input<FieldType> &primary_input,
                    const bacs_auxiliary_input<FieldType> &auxiliary_input) const {
                    const bacs_variable_assignment<FieldType> all_outputs =
                        get_all_outputs(primary_input, auxiliary_input);

                    for (size_t i = 0; i < all_outputs.size(); ++i) {
                        if (!all_outputs[i].is_zero()) {
                            return false;
                        }
                    }

                    return true;
                }

                template<typename FieldType>
                void bacs_circuit<FieldType>::add_gate(const bacs_gate<FieldType> &g) {
                    assert(g.output.index == num_wires() + 1);
                    gates.emplace_back(g);
                }

                template<typename FieldType>
                void bacs_circuit<FieldType>::add_gate(const bacs_gate<FieldType> &g, const std::string &annotation) {
                    assert(g.output.index == num_wires() + 1);
                    gates.emplace_back(g);
                }

                template<typename FieldType>
                bool bacs_circuit<FieldType>::operator==(const bacs_circuit<FieldType> &other) const {
                    return (this->primary_input_size == other.primary_input_size &&
                            this->auxiliary_input_size == other.auxiliary_input_size && this->gates == other.gates);
                }

                template<typename FieldType>
                std::ostream &operator<<(std::ostream &out, const bacs_circuit<FieldType> &circuit) {
                    out << circuit.primary_input_size << "\n";
                    out << circuit.auxiliary_input_size << "\n";
                    algebra::operator<<(out, circuit.gates);
                    out << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename FieldType>
                std::istream &operator>>(std::istream &in, bacs_circuit<FieldType> &circuit) {
                    in >> circuit.primary_input_size;
                    algebra::consume_newline(in);
                    in >> circuit.auxiliary_input_size;
                    algebra::consume_newline(in);
                    algebra::operator>>(in, circuit.gates);
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename FieldType>
                void bacs_circuit<FieldType>::print() const {
                    algebra::print_indent();
                    printf("General information about the circuit:\n");
                    this->print_info();
                    algebra::print_indent();
                    printf("All gates:\n");
                    for (size_t i = 0; i < gates.size(); ++i) {
                        std::string annotation = "no annotation";
#ifdef DEBUG
                        auto it = gate_annotations.find(i);
                        if (it != gate_annotations.end()) {
                            annotation = it->second;
                        }
#endif
                        printf("Gate %zu (%s):\n", i, annotation.c_str());
#ifdef DEBUG
                        gates[i].print(variable_annotations);
#else
                        gates[i].print();
#endif
                    }
                }

                template<typename FieldType>
                void bacs_circuit<FieldType>::print_info() const {
                    algebra::print_indent();
                    printf("* Number of inputs: %zu\n", this->num_inputs());
                    algebra::print_indent();
                    printf("* Number of gates: %zu\n", this->num_gates());
                    algebra::print_indent();
                    printf("* Number of wires: %zu\n", this->num_wires());
                    algebra::print_indent();
                    printf("* Depth: %zu\n", this->depth());
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // BACS_HPP_

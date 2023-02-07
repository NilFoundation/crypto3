//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2023 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022-2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MINIMIZED_PROFILING_PLONK_CIRCUIT_HPP
#define CRYPTO3_MINIMIZED_PROFILING_PLONK_CIRCUIT_HPP

#include <fstream>
#include <sstream>
#include <filesystem>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/blueprint/transpiler/gate_argument_template.hpp>

#include <boost/assert.hpp>
#include <boost/algorithm/string.hpp> 

namespace nil {
    namespace blueprint {
        template<typename FieldType, typename ArithmetizationParams>
        struct minimized_profiling_plonk_circuit {
            using columns_rotations_type = std::array<std::vector<int>, ArithmetizationParams::total_columns>;
            using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
            using TableDescriptionType = nil::crypto3::zk::snark::plonk_table_description<FieldType, ArithmetizationParams>;
            using GateType = nil::crypto3::zk::snark::plonk_gate<FieldType, nil::crypto3::zk::snark::plonk_constraint<FieldType>>;

            static inline columns_rotations_type columns_rotations(ArithmetizationType &constraint_system,
                                                                   const TableDescriptionType &table_description) {
                columns_rotations_type result;

                std::vector<nil::crypto3::zk::snark::plonk_gate<FieldType, nil::crypto3::zk::snark::plonk_constraint<FieldType>>> gates =
                    constraint_system.gates();

                for (std::size_t g_index = 0; g_index < gates.size(); g_index++) {

                    for (std::size_t c_index = 0; c_index < gates[g_index].constraints.size(); c_index++) {

                        for (std::size_t t_index = 0; t_index < gates[g_index].constraints[c_index].terms.size();
                             t_index++) {
                            for (std::size_t v_index = 0;
                                 v_index < gates[g_index].constraints[c_index].terms[t_index].vars.size();
                                 v_index++) {

                                if (gates[g_index].constraints[c_index].terms[t_index].vars[v_index].relative) {
                                    std::size_t column_index = table_description.global_index(
                                        gates[g_index].constraints[c_index].terms[t_index].vars[v_index]);

                                    int rotation =
                                        gates[g_index].constraints[c_index].terms[t_index].vars[v_index].rotation;

                                    if (std::find(result[column_index].begin(), result[column_index].end(), rotation) ==
                                        result[column_index].end()) {
                                        result[column_index].push_back(rotation);
                                    }
                                }
                            }
                        }
                    }
                }

                std::vector<nil::crypto3::zk::snark::plonk_gate<FieldType, nil::crypto3::zk::snark::plonk_lookup_constraint<FieldType>>>
                    lookup_gates = constraint_system.lookup_gates();

                for (std::size_t g_index = 0; g_index < lookup_gates.size(); g_index++) {

                    for (std::size_t c_index = 0; c_index < lookup_gates[g_index].constraints.size(); c_index++) {

                        for (std::size_t v_index = 0;
                             v_index < lookup_gates[g_index].constraints[c_index].lookup_input.size();
                             v_index++) {

                            if (lookup_gates[g_index].constraints[c_index].lookup_input[v_index].vars[0].relative) {
                                std::size_t column_index = table_description.global_index(
                                    lookup_gates[g_index].constraints[c_index].lookup_input[v_index].vars[0]);

                                int rotation =
                                    lookup_gates[g_index].constraints[c_index].lookup_input[v_index].vars[0].rotation;

                                if (std::find(result[column_index].begin(), result[column_index].end(), rotation) ==
                                    result[column_index].end()) {
                                    result[column_index].push_back(rotation);
                                }
                            }
                        }
                    }
                }

                for (std::size_t i = 0; i < ArithmetizationParams::total_columns; i++) {
                    if (std::find(result[i].begin(), result[i].end(), 0) == result[i].end()) {
                        result[i].push_back(0);
                    }
                }

                return result;
            }

            template<typename Container, typename ContainerIt>
            static bool is_last_element(const Container &c, ContainerIt it) {
                return it == (std::cend(c) - 1);
            }

            static std::string generate_variable(const nil::crypto3::zk::snark::plonk_variable<FieldType> &var,
                                       columns_rotations_type &columns_rotations) {
                using variable_type = const nil::crypto3::zk::snark::plonk_variable<FieldType>;

                std::stringstream res;
                std::size_t index = var.index;
                std::size_t global_index;

                // Define global index in columns_rotations 
                if (var.type == variable_type::witness) {
                    global_index = var.index;
                }
                if (var.type == variable_type::public_input) {
                    global_index = var.index + ArithmetizationParams::witness_columns;
                }
                if (var.type == variable_type::constant) {
                    global_index = var.index + ArithmetizationParams::witness_columns +
                                   ArithmetizationParams::public_input_columns;
                }
                if (var.type == variable_type::selector) {
                    global_index = var.index + ArithmetizationParams::witness_columns +
                                   ArithmetizationParams::public_input_columns +
                                   ArithmetizationParams::constant_columns;
                }

                // Find out rotation_idx
                std::size_t rotation_idx = std::find(
                    std::cbegin(columns_rotations.at(global_index)),
                    std::cend(columns_rotations.at(global_index)),
                    var.rotation
                ) - std::begin(columns_rotations.at(global_index));

                if (var.type == variable_type::witness) {
                    res << "get_witness_i_by_rotation_idx("<< index << "," << rotation_idx << ", gate_params)";
                }
                if (var.type == variable_type::public_input) {
                    BOOST_ASSERT(rotation_idx == 0);
                    res << "get_public_input_i("<< index << ","<< rotation_idx << ", gate_params)";
                }
                if (var.type == variable_type::constant) {
                    BOOST_ASSERT(rotation_idx == 0);
                    res << "get_constant_i_by_rotation_idx("<< index << ", " << rotation_idx << ", gate_params)";
                }
                if (var.type == variable_type::selector) {
                    BOOST_ASSERT(rotation_idx == 0);
                    res << "get_selector_i("<< index << ", gate_params)";
                }
                return res.str();
            }

            template<typename Vars>
            static std::string generate_term(const Vars &vars, columns_rotations_type &columns_rotations ) {
                std::stringstream res;
                for( auto it = std::cbegin(vars); it != std::end(vars); it++){
                    res << "\t\t\tterms:=mulmod(terms, ";
                    res << generate_variable(*it, columns_rotations);
                    res << ", modulus)" << std::endl;
                }
                return res.str();
            }

            template<typename Terms, typename TermsIt>
            static std::string generate_terms(
                    const Terms &terms,
                    TermsIt it,
                    columns_rotations_type &columns_rotations
            ) {
                std::stringstream res;
                for( auto it = std::cbegin(terms); it != std::cend(terms); it++ ){
                    res << "\t\t\tterms:=0x" << std::hex << it->coeff.data << std::dec << std::endl;
                    res << generate_term(it->vars, columns_rotations);
                    res << "\t\t\tmstore("
                          "add(gate_params, CONSTRAINT_EVAL_OFFSET),"
                          "addmod("
                          "mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),";
                    res << "terms";
                    res << ",modulus))" << std::endl;
                }
                return res.str();
            }


            static std::string generate_constraint(
                const typename nil::crypto3::zk::snark::plonk_constraint<FieldType> &constraint,
                columns_rotations_type &columns_rotations
            ) {
                std::stringstream res;
                res << "\t\t\tmstore(add(gate_params, CONSTRAINT_EVAL_OFFSET), 0)" << std::endl;
                res << generate_terms(constraint.terms, std::cbegin(constraint.terms), columns_rotations);
                return res.str();
            }

            static std::string generate_gate_evaluation() {
                return "\t\t\tmstore("
                      "add(gate_params, GATE_EVAL_OFFSET),"
                      "addmod("
                      "mload(add(gate_params, GATE_EVAL_OFFSET)),"
                      "mulmod("
                      "mload(add(gate_params, CONSTRAINT_EVAL_OFFSET)),"
                      "theta_acc,"
                      "modulus"
                      "),"
                      "modulus"
                      ")"
                      ")\n";
            }

            static std::string generate_theta_acc() {
                return "\t\t\ttheta_acc := mulmod("
                      "theta_acc,"
                      "mload(add(gate_params, THETA_OFFSET)),"
                      "modulus"
                      ")\n";
            }

            static std::string generate_selector(
                const nil::crypto3::zk::snark::plonk_gate<
                FieldType, nil::crypto3::zk::snark::plonk_constraint<FieldType>> &gate
            ) {
                std::stringstream res; 

                res << "\t\t\tmstore("
                      "add(gate_params, GATE_EVAL_OFFSET),"
                      "mulmod("
                      "mload(add(gate_params, GATE_EVAL_OFFSET)),"
                      "get_selector_i("
                   << gate.selector_index
                   << ","
                      "gate_params"
                      "),"
                      "modulus"
                      ")"
                      ")"
                   << std::endl;
                return res.str();
            }

            static std::string generate_gate_argument_evaluation() {
                return "\t\t\tgates_evaluation := addmod("
                    "gates_evaluation,"
                    "mload(add(gate_params, GATE_EVAL_OFFSET)),"
                    "modulus"
                    ")\n";
            }

            static std::string generate_gate_assembly_code(int gate_ind, const GateType &gate, columns_rotations_type &columns_rotations){
                std::stringstream res;
                res << "\t\t\t//Gate" << gate_ind << std::endl;
                res << "\t\t\tmstore(add(gate_params, GATE_EVAL_OFFSET), 0)" << std::endl;
                std::size_t i = 0;
                for (auto &constraint : gate.constraints) {
                    res << generate_constraint(constraint, columns_rotations);
                    res << generate_gate_evaluation();
                    res << generate_theta_acc();
                    i++;
                }
                res << generate_selector(gate);
                res << generate_gate_argument_evaluation();
                return res.str();
            }

            static void print_gate_file(int gate_ind, std::ostream &gate_out, std::string gate_sol_file_template, const GateType &gate,
                                        columns_rotations_type &columns_rotations) {
                std::string result = gate_sol_file_template;

                boost::replace_all(result, "$CONTRACT_NUMBER$", std::to_string(gate_ind));
                boost::replace_all(result, "$GATES_ASSEMBLY_CODE$", generate_gate_assembly_code(gate_ind, gate, columns_rotations));
                gate_out << result;
            }

            static void print_main_file(
                std::ostream &out, 
                std::string main_file_template, 
                std::string includes,
                std::size_t gates_number,
                std::string executions
            ) {
                std::string result = main_file_template;
                boost::replace_all(result, "$GATES_IMPORTS$", includes );
                boost::replace_all(result, "$GATES_NUMBER$", std::to_string(gates_number));
                boost::replace_all(result, "$GATES_EXECUTION$", executions);
                out << result;
            }

            static void print_linked_libraries_list(std::ostream &out, std::size_t lib_num) {
                bool first = true;
                out << "[";
                for (size_t i = 0; i < lib_num; i++) {
                    if (first)
                        first = false;
                    else
                        out << "," << std::endl;
                    out << "\"gate" << i << "\"";
                }
                out << std::endl << "]" << std::endl;
            }

            static void process_split(
                std::string main_file_template,
                std::string gate_file_template,
                ArithmetizationType &bp,
                columns_rotations_type &columns_rotations,
                std::string out_folder_path = "."
            ) {
                std::ofstream json_out;
                json_out.open(out_folder_path + "/linked_libs_list.json");
                print_linked_libraries_list(json_out, bp.gates().size());
                json_out.close();

                size_t i = 0;

                std::stringstream imports;
                std::stringstream executions;

                for (const auto &gate : bp.gates()) {
                    imports << "import \"./gate" << i << ".sol\";" << std::endl;
                    executions << "\t\t(gate_params.gates_evaluation, gate_params.theta_acc) = gate"<< i <<".evaluate_gate_be(gate_params);" << std::endl;
                    std::ofstream gate_out;
                    gate_out.open(out_folder_path + "/gate" + std::to_string(i) + ".sol");
                    print_gate_file(i, gate_out, gate_file_template, gate, columns_rotations);
                    gate_out.close();
                    i++;
                }
                
                std::ofstream gate_argument_out;
                gate_argument_out.open(out_folder_path + "/gate_argument.sol");
                print_main_file(
                    gate_argument_out, 
                    main_file_template,
                    imports.str(),
                    bp.gates().size(),
                    executions.str()
                );
                gate_argument_out.close();
            }
        };
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_MINIMIZED_PROFILING_PLONK_CIRCUIT_HPP

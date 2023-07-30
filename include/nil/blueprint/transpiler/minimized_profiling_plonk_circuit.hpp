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

#include <nil/crypto3/zk/math/expression_visitors.hpp>
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
            static const std::size_t MAX_LINES = 1200;
            static const std::size_t ONE_FILE_GATES_MAX_LINES = 1000;

            using columns_rotations_type = std::array<std::set<int>, ArithmetizationParams::total_columns>;
            using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
            using TableDescriptionType = nil::crypto3::zk::snark::plonk_table_description<FieldType, ArithmetizationParams>;
            using GateType = nil::crypto3::zk::snark::plonk_gate<FieldType, nil::crypto3::zk::snark::plonk_constraint<FieldType>>;

            struct profiling_params_type {
                bool optimize_gates;

                bool need_witness;
                bool need_public_input;
                bool need_constant;
                bool need_selector;

                bool rotated_witness;
                bool rotated_constant;
                bool rotated_public_input;
                bool rotated_selector;

                std::size_t offset_witness;
                std::size_t offset_public_input;
                std::size_t offset_constant;
                std::size_t offset_selector;

                bool one_file_gates;
                std::vector<std::size_t> gates_lines;
                std::vector<std::size_t> gates_first;
                std::vector<std::size_t> gates_num;

                std::string evaluation_fields;
                std::string load_evaluation_fields;
                std::string evals_offsets;
                std::string get_evals_functions;

                profiling_params_type(
                    ArithmetizationType &bp,
                    bool optimize_gates = true
                ){
                    auto gates = bp.gates();

                    this->optimize_gates = optimize_gates;
                    this->need_witness = false;
                    this->need_public_input = false;
                    this->need_constant = false;
                    this->need_selector = true;
                    this->rotated_witness = false;
                    this->rotated_public_input = false;
                    this->rotated_constant = false;
                    this->rotated_selector = false;

                    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;
                    std::size_t offset = 0x80;
                    
                    // compute needed and rotated vars
                    for (const auto& gate: gates) {
                        // constraint
                        // gate_evaluation
                        // theta_acc
                        for (const auto& constraint: gate.constraints) {
		                    crypto3::math::expression_for_each_variable_visitor<variable_type> visitor(
                                [this](const variable_type& var){
                                    if (var.type == variable_type::witness) {
                                        this->need_witness = true;
                                        if( var.rotation != 0){ this->rotated_witness = true; }
                                    }
                                    if (var.type == variable_type::public_input) {
                                        this->need_public_input = true;
                                        if( var.rotation != 0){ this->rotated_public_input = true; }
                                    }
                                    if (var.type == variable_type::constant) {
                                        this->need_constant = true;
                                        if( var.rotation != 0) { this->rotated_constant = true; }
                                    }
                                    if (var.type == variable_type::selector) {
                                        if( var.rotation != 0) { this->rotated_selector = true; }
                                    }
                                });
			                visitor.visit(constraint);
                        }
                    }

                    for (const auto& gate: gates) {
                        std::size_t gate_lines = 2;
                        for (const auto& constraint: gate.constraints) {
                            gate_lines += 2;
            			    // Convert constraint expression to non_linear_combination.
 	                        crypto3::math::expression_to_non_linear_combination_visitor<variable_type> visitor;
                            auto comb = visitor.convert(constraint);

                            for (std::size_t t_index = 0; t_index < comb.terms.size(); t_index++) {
                                if (!comb.terms[t_index].get_coeff().is_one())
                                    gate_lines += 1;
                                gate_lines += comb.terms[t_index].get_vars().size();
                                gate_lines += 1;
                            }
                            gate_lines += 1;
                        }
                        gate_lines += 2;
                        this->gates_lines.push_back(gate_lines);
                    }

                    std::size_t sum = 0;
                    std::size_t total = 0;
                    std::size_t cur = 0;
                    this->gates_num.push_back(0);
                    this->gates_first.push_back(0);
                    for( std::size_t i =0; i < this->gates_lines.size(); i++ ){
                        BOOST_ASSERT( this->gates_lines[i] < MAX_LINES );
                        if( sum + this->gates_lines[i] < MAX_LINES ){
                            sum += this->gates_lines[i];
                            total += this->gates_lines[i];
                            this->gates_num[cur]++;
                            continue;
                        }
                        cur++;
                        this->gates_num.push_back(1);
                        sum = this->gates_lines[i];
                        this->gates_first.push_back(i);
                    }
                    this->one_file_gates = (total < ONE_FILE_GATES_MAX_LINES);

                    if( this->need_witness ){
                        this->offset_witness = offset;
                        offset += 0x20;
                    }
                    if( this->need_public_input ){
                        this->offset_public_input = offset;
                        offset += 0x20;
                    }
                    if( this->need_constant ){
                        this->offset_constant = offset;
                        offset += 0x20;
                    }
                    if( this->need_selector ){
                        this->offset_selector = offset;
                        offset += 0x20;
                    }
                    this->process();
                }

                void process(){
                    std::stringstream evaluation_fields_str;
                    std::stringstream load_evaluation_fields_str;
                    std::stringstream evals_offsets_str;
                    std::stringstream get_evals_functions_str;

                    if( this->need_witness ){
                        evals_offsets_str << "\tuint256 constant WITNESS_EVALUATIONS_OFFSET = 0x" << std::hex 
                            << this->offset_witness << std::dec << ";" << std::endl;
                        evaluation_fields_str << "\t\t//0x"  << std::hex << this->offset_witness << std::dec << std::endl;
                        if(this->rotated_witness){
                            get_evals_functions_str << get_rotated_witness;
                            evaluation_fields_str << field_rotated_witness_evaluations;
                            load_evaluation_fields_str << load_rotated_witness_evaluations;
                        } else {
                            evaluation_fields_str << field_witness_evaluations;
                            load_evaluation_fields_str << load_witness_evaluations;
                            get_evals_functions_str << get_witness;
                        }
                    }

                    if( this->need_public_input ){
                        evaluation_fields_str << "\t\t//0x"  << std::hex << this->offset_public_input << std::dec << std::endl;
                        evals_offsets_str << "\tuint256 constant PUBLIC_INPUT_EVALUATIONS_OFFSET = 0x" << std::hex 
                            << this->offset_public_input << std::dec << ";" << std::endl;
                        if(this->rotated_public_input){
                            get_evals_functions_str << get_rotated_public_input;
                            evaluation_fields_str << field_rotated_public_input_evaluations;
                            load_evaluation_fields_str << load_rotated_public_input_evaluations;
                        } else {
                            evaluation_fields_str << field_public_input_evaluations;
                            load_evaluation_fields_str << load_public_input_evaluations;
                            get_evals_functions_str << get_public_input;
                        }
                    }

                    if( this->need_constant ){
                        evaluation_fields_str << "\t\t//"  << std::hex << this->offset_constant << std::dec << std::endl;
                        evals_offsets_str << "\tuint256 constant CONSTANT_EVALUATIONS_OFFSET = 0x" << std::hex 
                            << this->offset_constant << std::dec << ";" << std::endl;
                        if(this->rotated_constant){
                            evaluation_fields_str << field_rotated_constant_evaluations;
                            load_evaluation_fields_str << load_rotated_constant_evaluations;
                            get_evals_functions_str << get_rotated_constant;
                        } else {
                            get_evals_functions_str << get_constant;
                            evaluation_fields_str << field_constant_evaluations;
                            load_evaluation_fields_str << load_constant_evaluations;
                        }
                    }

                    if( this->need_selector ){
                        evaluation_fields_str << "\t\t//"  << std::hex << this->offset_selector << std::dec << std::endl;
                        evals_offsets_str << "\tuint256 constant SELECTOR_EVALUATIONS_OFFSET = 0x" << std::hex 
                            << this->offset_selector << std::dec << ";" << std::endl;
                        if(this->rotated_selector){
                            evaluation_fields_str << field_rotated_selector_evaluations;
                            load_evaluation_fields_str << load_rotated_selector_evaluations;
                            get_evals_functions_str << get_rotated_selector;
                        } else {
                            evaluation_fields_str << field_selector_evaluations;
                            load_evaluation_fields_str << load_selector_evaluations;
                            get_evals_functions_str << get_selector;
                        }
                    }

                    this->get_evals_functions = get_evals_functions_str.str();
                    this->evals_offsets = evals_offsets_str.str();
                    this->evaluation_fields = evaluation_fields_str.str();
                    this->load_evaluation_fields = load_evaluation_fields_str.str();
                }
            };

            static inline columns_rotations_type columns_rotations(
                ArithmetizationType &constraint_system,  const TableDescriptionType &table_description
            ) {
                using variable_type = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

                columns_rotations_type result;
                for (const auto& gate: constraint_system.gates()) {
                    for (const auto& constraint: gate.constraints) {
			            crypto3::math::expression_for_each_variable_visitor<variable_type> visitor(
                            [&table_description, &result](const variable_type& var) {
                                if (var.relative) {
                                    std::size_t column_index = table_description.global_index(var);
                                    result[column_index].insert(var.rotation);
                                }
                            });
			            visitor.visit(constraint);
                    }
                }

                for (const auto& gate: constraint_system.lookup_gates()) {
                    for (const auto& constraint: gate.constraints) {
                        for (const auto& lookup_input: constraint.lookup_input) {
                            const auto& var = lookup_input.get_vars()[0];
                            if (var.relative) {
                                std::size_t column_index = table_description.global_index(var);
                                result[column_index].insert(var.rotation);
                            }
                        }
                    }
                }

                for (std::size_t i = 0; i < ArithmetizationParams::total_columns; i++) {
                    result[i].insert(0);
                }

                return result;
            }

            template<typename Container, typename ContainerIt>
            static bool is_last_element(const Container &c, ContainerIt it) {
                return it == (std::cend(c) - 1);
            }

            static std::string generate_variable(
                const profiling_params_type &profiling_params,
                const nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type> &var,
                columns_rotations_type &columns_rotations
            ) {
                using variable_type = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

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
                std::size_t rotation_idx = std::distance(
                    columns_rotations.at(global_index).begin(),
                    columns_rotations.at(global_index).find(var.rotation)
                    );

                if (var.type == variable_type::witness) {
                    if( profiling_params.rotated_witness )
                        res << get_rotated_witness_call << "("<< index << "," << rotation_idx << ", local_vars)";
                    else
                        res << get_witness_call << "("<< index << ", local_vars)";
                }
                if (var.type == variable_type::public_input) {
                    if( profiling_params.rotated_public_input )
                        res << get_rotated_public_input_call << "("<< index << ","<< rotation_idx << ", local_vars)";
                    else 
                        res << get_public_input_call << "("<< index << ", local_vars)";
                }
                if (var.type == variable_type::constant) {
                    if( profiling_params.rotated_public_input )
                        res << get_rotated_constant_call << "("<< index << ","<< rotation_idx << ", local_vars)";
                    else 
                        res << get_constant_call << "("<< index << ", local_vars)";
                }
                if (var.type == variable_type::selector) {
                    if( profiling_params.rotated_selector )
                        res << get_rotated_selector_call << "("<< index << ","<< rotation_idx << ", local_vars)";
                    else 
                        res << get_selector_call << "("<< index << ", local_vars)";
                }
                return res.str();
            }

            template<typename Vars>
            static std::string generate_term(
                const profiling_params_type &profiling_params,
                const Vars &vars, 
                columns_rotations_type &columns_rotations,
                bool coeff_one = false
            ) {
                std::stringstream res;
                bool first = true;

                for( auto it = std::cbegin(vars); it != std::end(vars); it++){
                    if( first ){
                        first = false;
                        if(coeff_one){
                            res << "\t\t\tterms:=" << generate_variable(profiling_params, *it, columns_rotations) << std::endl;
                            continue;
                        }
                    }
                    res << "\t\t\tterms:=mulmod(terms, ";
                    res << generate_variable(profiling_params, *it, columns_rotations);
                    res << ", modulus)" << std::endl;
                }
                return res.str();
            }

            template<typename Terms>
            static std::string generate_terms(
                    const profiling_params_type &profiling_params,
                    const Terms &terms,
                    columns_rotations_type &columns_rotations
            ) {
                std::stringstream res;
                for( auto it = std::cbegin(terms); it != std::cend(terms); it++ ){
                    if(it->get_coeff().is_one())
                        res << generate_term(profiling_params, it->get_vars(), columns_rotations, true);
                    else {
                        res << "\t\t\tterms:=0x" << std::hex << it->get_coeff().data << std::dec << std::endl;
                        res << generate_term(profiling_params, it->get_vars(), columns_rotations, false);
                    }
                    res << "\t\t\tmstore("
                          "add(local_vars, CONSTRAINT_EVAL_OFFSET),"
                          "addmod("
                          "mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),";
                    res << "terms";
                    res << ",modulus))" << std::endl;
                }
                return res.str();
            }


            static std::string generate_constraint(
                const profiling_params_type &profiling_params,
                const typename nil::crypto3::zk::snark::plonk_constraint<FieldType> &constraint,
                columns_rotations_type &columns_rotations
            ) {
                using variable_type = nil::crypto3::zk::snark::plonk_variable<typename FieldType::value_type>;

                std::stringstream res;
                res << "\t\t\tmstore(add(local_vars, CONSTRAINT_EVAL_OFFSET), 0)" << std::endl;

		        // Convert constraint expression to non_linear_combination.
		        crypto3::math::expression_to_non_linear_combination_visitor<variable_type> visitor;
                auto comb = visitor.convert(constraint);
                res << generate_terms(profiling_params, comb.terms, columns_rotations);
                return res.str();
            }

            static std::string generate_gate_evaluation() {
                return "\t\t\tmstore("
                      "add(local_vars, GATE_EVAL_OFFSET),"
                      "addmod("
                      "mload(add(local_vars, GATE_EVAL_OFFSET)),"
                      "mulmod("
                      "mload(add(local_vars, CONSTRAINT_EVAL_OFFSET)),"
                      "theta_acc,"
                      "modulus"
                      "),"
                      "modulus"
                      ")"
                      ")\n";
            }

            static std::string generate_theta_acc() {
                return "\t\t\ttheta_acc := mulmod(theta_acc, theta, modulus)\n";
            }

            static std::string generate_selector(
                const nil::crypto3::zk::snark::plonk_gate<
                FieldType, nil::crypto3::zk::snark::plonk_constraint<FieldType>> &gate
            ) {
                std::stringstream res; 

                res << "\t\t\tmstore("
                      "add(local_vars, GATE_EVAL_OFFSET),"
                      "mulmod("
                      "mload(add(local_vars, GATE_EVAL_OFFSET)),"
                      "get_selector_i("
                   << gate.selector_index
                   << ","
                      "local_vars"
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
                    "mload(add(local_vars, GATE_EVAL_OFFSET)),"
                    "modulus"
                    ")\n";
            }

            static std::string generate_gate_assembly_code(
                const profiling_params_type &profiling_params, 
                int gate_ind, const GateType &gate, 
                columns_rotations_type &columns_rotations
            ) {
                std::stringstream res;
                res << "\t\t\t//Gate" << gate_ind << std::endl;
                res << "\t\t\tmstore(add(local_vars, GATE_EVAL_OFFSET), 0)" << std::endl;
                for (auto &constraint : gate.constraints) {
                    res << generate_constraint(profiling_params, constraint, columns_rotations);
                    res << generate_gate_evaluation();
                    res << generate_theta_acc();
                }
                res << generate_selector(gate);
                res << generate_gate_argument_evaluation();
                return res.str();
            }

            static void print_gate_file(
                int gate_ind, std::ostream &gate_out, 
                std::string id,
                const profiling_params_type &profiling_params,
                std::string gate_sol_file_template, 
                const GateType &gate,
                columns_rotations_type &columns_rotations
            ) {
                std::string result = gate_sol_file_template;

                boost::replace_all(result, "$TEST_ID$", id);
                boost::replace_all(result, "$GATE_ARGUMENT_LOCAL_VARS_OFFSETS$", profiling_params.evals_offsets);
                boost::replace_all(result, "$GATES_GET_EVALUATIONS_FUNCTIONS$", profiling_params.get_evals_functions);
                boost::replace_all(result, "$CONTRACT_NUMBER$", std::to_string(gate_ind));
                boost::replace_all(result, "$GATES_ASSEMBLY_CODE$", generate_gate_assembly_code(profiling_params, gate_ind, gate, columns_rotations));
                gate_out << result;
            }

            static void print_multiple_gates_file(
                int file_ind, std::ostream &gate_out, 
                std::string id,
                const profiling_params_type &profiling_params,
                std::string gate_sol_file_template, 
                const ArithmetizationType &bp,
                columns_rotations_type &columns_rotations
            ) {
                std::string assembly_code;
                for(std::size_t i = profiling_params.gates_first[file_ind]; 
                    i < profiling_params.gates_first[file_ind] + profiling_params.gates_num[file_ind];
                    i++
                ){
                    assembly_code += generate_gate_assembly_code(profiling_params, i, bp.gates()[i], columns_rotations);
                    assembly_code += "\n";
                }

                std::string result = gate_sol_file_template;

                boost::replace_all(result, "$TEST_ID$", id);
                boost::replace_all(result, "$GATE_ARGUMENT_LOCAL_VARS_OFFSETS$", profiling_params.evals_offsets);
                boost::replace_all(result, "$GATES_GET_EVALUATIONS_FUNCTIONS$", profiling_params.get_evals_functions);
                boost::replace_all(result, "$CONTRACT_NUMBER$", std::to_string(profiling_params.gates_first[file_ind]));
                boost::replace_all(result, "$GATES_ASSEMBLY_CODE$", assembly_code);
                gate_out << result;
            }

            static void print_main_file(
                std::ostream &out, 
                std::string id,
                profiling_params_type &profiling_params,
                std::string main_file_template, 
                std::string includes,
                std::size_t gates_number,
                std::string executions
            ) {
                std::string result = main_file_template;
                boost::replace_all(result, "$GATES_IMPORTS$", includes );
                boost::replace_all(result, "$GATES_NUMBER$", std::to_string(gates_number));
                boost::replace_all(result, "$GATES_EXECUTION$", executions);
                boost::replace_all(result, "$GATES_LOCAL_VARS_EVALUATION_FIELDS$", profiling_params.evaluation_fields);
                boost::replace_all(result, "$GATES_LOAD_EVALUATIONS$", profiling_params.load_evaluation_fields);
                boost::replace_all(result, "$TEST_ID$", id );
                out << result;
            }

            static void print_single_sol_file(
                std::ostream &out, 
                std::string id,
                profiling_params_type &profiling_params,
                columns_rotations_type columns_rotations,
                std::string single_file_template, 
                ArithmetizationType &bp
            ) {
                std::stringstream gates_execution_str;
                for(std::size_t i = 0; i < bp.gates().size(); i++){
                    gates_execution_str << generate_gate_assembly_code(
                        profiling_params, i, bp.gates()[i], columns_rotations
                    );
                    gates_execution_str << std::endl;
                }

                std::string result = single_file_template;
                boost::replace_all(result, "$TEST_ID$", id);
                boost::replace_all(result, "$GATES_NUMBER$", std::to_string(bp.gates().size()));
                boost::replace_all(result, "$GATES_LOCAL_VARS_EVALUATION_FIELDS$", profiling_params.evaluation_fields);
                boost::replace_all(result, "$GATES_LOAD_EVALUATIONS$", profiling_params.load_evaluation_fields);

                boost::replace_all(result, "$GATE_ARGUMENT_LOCAL_VARS_OFFSETS$", profiling_params.evals_offsets);
                boost::replace_all(result, "$GATES_GET_EVALUATIONS_FUNCTIONS$", profiling_params.get_evals_functions);
                boost::replace_all(result, "$GATES_EXECUTION$", gates_execution_str.str());
                out << result;
            }

            static void print_linked_libraries_list(std::ostream &out, std::string id, const profiling_params_type &profiling_params) {
                bool first = true;
                if(!profiling_params.optimize_gates){
                    out << "[" << std::endl;
                    for (size_t i = 0; i < profiling_params.gates_lines.size(); i++) {
                        if (first)
                            first = false;
                        else
                            out << "," << std::endl;
                        out << "\""<< id << "_gate" << i << "\"";
                    }
                    out << std::endl << "]" << std::endl;
                    return;
                }

                if(profiling_params.one_file_gates){
                    out << "[]" << std::endl;
                    return;
                }

                out << "[" << std::endl;
                for (size_t i = 0; i < profiling_params.gates_first.size(); i++) {
                    if (first)
                        first = false;
                    else
                        out << "," << std::endl;
                    out << "\""<< id << "_gate" << profiling_params.gates_first[i] << "\"";
                }
                out << std::endl << "]" << std::endl;
            }


            static void process_split(
                std::string main_file_template,
                std::string gate_file_template,
                ArithmetizationType &bp,
                columns_rotations_type &columns_rotations,
                std::string out_folder_path = ".",
                bool optimize_gates = false
            ) {
                auto id = out_folder_path.substr(out_folder_path.rfind("/") + 1);

                profiling_params_type profiling_params(bp, optimize_gates);

                if( profiling_params.optimize_gates && profiling_params.one_file_gates ){
                    std::ofstream json_out;
                    json_out.open(out_folder_path + "/linked_libs_list.json");
                    print_linked_libraries_list(json_out,id, profiling_params);
                    json_out.close();

                    std::ofstream gate_argument_out;
                    gate_argument_out.open(out_folder_path + "/gate_argument.sol");
                    print_single_sol_file(
                        gate_argument_out,
                        id, 
                        profiling_params,
                        columns_rotations,
                        single_sol_file_template,
                        bp
                    );
                    gate_argument_out.close();
                }else{
                    std::ofstream json_out;
                    json_out.open(out_folder_path + "/linked_libs_list.json");
                    print_linked_libraries_list(json_out, id, profiling_params);
                    json_out.close();

                    size_t i = 0;

                    std::stringstream imports;
                    std::stringstream executions;

                    if(!profiling_params.optimize_gates){
                        for (const auto &gate : bp.gates()) {
                            imports << "import \"./gate" << i << ".sol\";" << std::endl;
                            executions << "\t\t(local_vars.gates_evaluation, local_vars.theta_acc) = "<< id <<"_gate"<< i <<".evaluate_gate_be(gate_params, local_vars);" << std::endl;
                            std::ofstream gate_out;
                            gate_out.open(out_folder_path + "/gate" + std::to_string(i) + ".sol");
                            print_gate_file(i, gate_out, id, profiling_params, gate_file_template, gate, columns_rotations);
                            gate_out.close();
                            i++;
                        }
                    } else {
                        for (std::size_t i = 0; i < profiling_params.gates_first.size(); i++) {
                            imports << "import \"./gate" << profiling_params.gates_first[i] << ".sol\";" << std::endl;
                            executions << "\t\t(local_vars.gates_evaluation, local_vars.theta_acc) = " << id << "_gate"<< profiling_params.gates_first[i] <<".evaluate_gate_be(gate_params, local_vars);" << std::endl;
                            std::ofstream gate_out;
                            gate_out.open(out_folder_path + "/gate" + std::to_string(profiling_params.gates_first[i]) + ".sol");
                            print_multiple_gates_file(i, gate_out, id, profiling_params, gate_file_template, bp, columns_rotations);
                            gate_out.close();
                        }
                    }
                    
                    std::ofstream gate_argument_out;
                    gate_argument_out.open(out_folder_path + "/gate_argument.sol");
                    print_main_file(
                        gate_argument_out, 
                        id,
                        profiling_params,
                        main_file_template,
                        imports.str(),
                        bp.gates().size(),
                        executions.str()
                    );
                    gate_argument_out.close();
                }
            }
        };
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_MINIMIZED_PROFILING_PLONK_CIRCUIT_HPP

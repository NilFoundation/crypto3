//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
#ifndef __EVM_VERIFIER_GEN_HPP__
#define __EVM_VERIFIER_GEN_HPP__

#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>

#include <boost/algorithm/string.hpp> 
#include <nil/blueprint/transpiler/templates/modular_verifier.hpp>
#include <nil/blueprint/transpiler/templates/gate_argument.hpp>
#include <nil/blueprint/transpiler/templates/permutation_argument.hpp>
#include <nil/blueprint/transpiler/templates/lookup_argument.hpp>
#include <nil/blueprint/transpiler/templates/commitment_scheme.hpp>
#include <nil/blueprint/transpiler/templates/external_gate.hpp>
#include <nil/blueprint/transpiler/templates/external_lookup.hpp>
#include <nil/blueprint/transpiler/lpc_scheme_gen.hpp>
#include <nil/blueprint/transpiler/util.hpp>

namespace nil {
    namespace blueprint {
        template <typename PlaceholderParams>
        class evm_verifier_printer{
            using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<
                typename PlaceholderParams::field_type, 
                PlaceholderParams
            >::preprocessed_data_type::common_data_type;

            using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
            using constraint_type = nil::crypto3::zk::snark::plonk_constraint<typename PlaceholderParams::field_type>;
            using lookup_constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<typename PlaceholderParams::field_type>;
            using gate_type = nil::crypto3::zk::snark::plonk_gate<typename PlaceholderParams::field_type, constraint_type>;
            using lookup_gate_type = nil::crypto3::zk::snark::plonk_lookup_gate<typename PlaceholderParams::field_type, lookup_constraint_type>;
            using variable_indices_type = std::map<nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>, std::size_t>;
            using columns_rotations_type = std::array<std::set<int>, PlaceholderParams::total_columns>;

            variable_indices_type get_plonk_variable_indices(const columns_rotations_type &col_rotations){
                using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
                std::map<variable_type, std::size_t> result;
                std::size_t j = 0;
                for(std::size_t i = 0; i < PlaceholderParams::constant_columns; i++){
                    for(auto& rot: col_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::constant);
                        result[v] = j;
                        j++;
                    }
                    j++;
                }
                for(std::size_t i = 0; i < PlaceholderParams::selector_columns; i++){
                    for(auto& rot: col_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns + PlaceholderParams::constant_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::selector);
                        result[v] = j;
                        j++;
                    }
                    j++;
                }
                for(std::size_t i = 0; i < PlaceholderParams::witness_columns; i++){
                    for(auto& rot: col_rotations[i]){
                        variable_type v(i, rot, true, variable_type::column_type::witness);
                        result[v] = j;
                        j++;
                    }
                }
                for(std::size_t i = 0; i < PlaceholderParams::public_input_columns; i++){
                    for(auto& rot: col_rotations[i + PlaceholderParams::witness_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::public_input);
                        result[v] = j;
                        j++;
                    }
                }
                return result;
            }

            std::string zero_indices(columns_rotations_type col_rotations){
                std::vector<std::size_t> zero_indices;
                std::uint16_t fixed_values_points;
                std::stringstream result;

                for(std::size_t i= 0; i < PlaceholderParams::constant_columns + PlaceholderParams::selector_columns; i++){
                    fixed_values_points += col_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns].size() + 1;
                }

                for(std::size_t i= 0; i < PlaceholderParams::total_columns; i++){
                    std::size_t j = 0;
                    for(auto& rot: col_rotations[i]){
                        if(rot == 0){
                            zero_indices.push_back(j);
                            break;
                        }
                        j++;
                    }
                }
                std::uint16_t sum = fixed_values_points;
                std::size_t i = 0;
                for(; i < PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns; i++){
                    zero_indices[i] = (sum + zero_indices[i]) * 0x20;
                    sum += col_rotations[i].size();
                    result << std::hex << std::setfill('0') << std::setw(4) << zero_indices[i];
                }

                sum = 0;
                for(; i < PlaceholderParams::total_columns; i++){
                    zero_indices[i] = (sum + zero_indices[i]) * 0x20;
                    sum += col_rotations[i].size() + 1;
                    result << std::hex << std::setfill('0') << std::setw(4) << zero_indices[i];
                }
                return result.str();
            }

            std::string constraint_computation_code(
                variable_indices_type &_var_indices,
                const constraint_type &constraint
            ){
                using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
                std::stringstream result;

                crypto3::math::expression_to_non_linear_combination_visitor<variable_type> visitor;
                auto comb = visitor.convert(constraint);
                result << "\t\tsum = 0;" << std::endl;
                for( auto it = std::cbegin(comb); it != std::cend(comb); it++ ){
                    bool coeff_one = (it->get_coeff() == PlaceholderParams::field_type::value_type::one());
                    if(!coeff_one) result << "\t\tprod = " << it->get_coeff() << ";" << std::endl;
                    const auto &vars = it->get_vars();
                    for( auto it2 = std::cbegin(vars); it2 != std::cend(vars); it2++ ){
                        const variable_type &v = *it2;
                        if(coeff_one){
                            coeff_one = false;
                            result << "\t\tprod = basic_marshalling.get_uint256_be(blob, " << _var_indices.at(v) * 0x20 << ");" << std::endl;
                        } else{
                            result << "\t\tprod = mulmod(prod, basic_marshalling.get_uint256_be(blob, " << _var_indices.at(v) * 0x20 << "), modulus);" << std::endl;
                        }
                    }
                    result << "\t\tsum = addmod(sum, prod, modulus);" << std::endl;
                }
                return result.str();
            }
        public:
            evm_verifier_printer(                
                const typename PlaceholderParams::constraint_system_type &constraint_system,
                const common_data_type &common_data,
                const typename PlaceholderParams::commitment_scheme_type &lpc_scheme,
                std::size_t permutation_size,
                std::string folder_name
            ): 
            _constraint_system(constraint_system),
            _common_data(common_data),
            _lpc_scheme(lpc_scheme),
            _permutation_size(permutation_size),
            _folder_name(folder_name)    
            {
                std::size_t found = folder_name.rfind("/");
                if( found == std::string::npos ){
                    _test_name = folder_name;
                } else{
                    _test_name = folder_name.substr(found + 1);
                }
                _use_lookups = _constraint_system.lookup_gates().size() > 0;
                
                _z_offset = _use_lookups ? 0xc9 : 0xa1;
                _special_selectors_offset = _z_offset + _permutation_size * 0x80;
                _table_z_offset = _special_selectors_offset + 0xc0;
                _variable_values_offset = 0;

                for( std::size_t i = 0; i < PlaceholderParams::arithmetization_params::constant_columns + PlaceholderParams::arithmetization_params::selector_columns; i++){
                    _variable_values_offset += 0x20 * (_common_data.columns_rotations[i + PlaceholderParams::arithmetization_params::witness_columns + PlaceholderParams::arithmetization_params::public_input_columns].size()+1);
                }

                _permutation_offset = _variable_values_offset;
                for( std::size_t i = 0; i < PlaceholderParams::arithmetization_params::witness_columns + PlaceholderParams::arithmetization_params::public_input_columns; i++){
                    if(i == PlaceholderParams::arithmetization_params::witness_columns){
                        _public_input_offset = _permutation_offset;
                    }
                    _permutation_offset += 0x20 * (_common_data.columns_rotations[i].size());
                }

                _quotient_offset = _use_lookups? _permutation_offset + 0x80: _permutation_offset + 0x40;

                _var_indices = get_plonk_variable_indices(_common_data.columns_rotations);
            }

            void print_gate_file(std::string gate_computation_code, std::size_t gate_id){
                std::string result = modular_external_gate_library_template;
                boost::replace_all(result, "$TEST_NAME$", _test_name);
                boost::replace_all(result, "$GATE_LIB_ID$", to_string(gate_id));
                boost::replace_all(result, "$GATES_ASSEMBLY_CODE$", gate_computation_code);
                boost::replace_all(result, "$MODULUS$", to_string(PlaceholderParams::field_type::modulus));

                std::ofstream out;
                out.open(_folder_name + "/gate_" + to_string(gate_id) + ".sol");
                out <<result;
                out.close();
            }

            void print_lookup_file(std::string lookup_computation_code, std::size_t lookup_id){
                std::string result = modular_external_lookup_library_template;
                boost::replace_all(result, "$TEST_NAME$", _test_name);
                boost::replace_all(result, "$LOOKUP_LIB_ID$", to_string(lookup_id));
                boost::replace_all(result, "$LOOKUP_ASSEMBLY_CODE$", lookup_computation_code);
                boost::replace_all(result, "$MODULUS$", to_string(PlaceholderParams::field_type::modulus));

                std::ofstream out;
                out.open(_folder_name + "/lookup_" + to_string(lookup_id) + ".sol");
                out <<result;
                out.close();
            }

            std::string gate_computation_code(const gate_type& gate){
                std::stringstream out;

                out << "\t\tgate = 0;" << std::endl;
                for(const auto &constraint: gate.constraints){
                    out << constraint_computation_code(_var_indices, constraint);
                    out << "\t\tgate = addmod(gate, mulmod(theta_acc, sum, modulus), modulus);" << std::endl;
                    out << "\t\ttheta_acc = mulmod(theta_acc, theta, modulus);" << std::endl;
                }
                variable_type sel_var(gate.selector_index, 0, true, variable_type::column_type::selector);
                out << "\t\tgate = mulmod(gate, basic_marshalling.get_uint256_be(blob, " << _var_indices.at(sel_var) * 0x20 << "), modulus);" << std::endl;
                out << "\t\tF = addmod(F, gate, modulus);" <<std::endl;
                return out.str();
            }

            std::string lookup_computation_code(const lookup_gate_type& gate){
                std::stringstream out;

                variable_type sel_var(gate.tag_index, 0, true, variable_type::column_type::selector);
                out << "\t\tselector_value=basic_marshalling.get_uint256_be(blob, " << _var_indices.at(sel_var) * 0x20 << ");" << std::endl;
                out << "\t\tg = 1;" << std::endl;
                for( const auto &constraint: gate.constraints ){
                    variable_type sel_var(gate.tag_index, 0, true, variable_type::column_type::selector);
                    out << "\t\tl = mulmod( " << constraint.table_id << ",selector_value, modulus);" << std::endl;
                    out << "\t\ttheta_acc=theta;" << std::endl;
                    for( const auto &expression:constraint.lookup_input ){
                        out << constraint_computation_code(_var_indices, expression) << std::endl  << std::endl;
                        out << "\t\tl = addmod( l, mulmod( mulmod(theta_acc, selector_value, modulus), sum, modulus), modulus);" << std::endl;
                        out << "\t\ttheta_acc = mulmod(theta_acc, theta, modulus);" << std::endl;
                    }
                    out << "\t\tg = mulmod(g, mulmod(addmod(1, beta, modulus), addmod(l,gamma, modulus), modulus), modulus);" << std::endl;
                }

                return out.str();
            }

            void print_gate_libs_list(std::vector<std::size_t> gate_ids){
                std::ofstream out;
                out.open(_folder_name + "/gate_libs_list.json");
                out << "[" << std::endl;
                for(std::size_t i=0; i < gate_ids.size(); i++){
                    out << "\"" << "gate_" << _test_name << "_" << gate_ids[i] << "\"";
                    if(i < gate_ids.size() - 1){
                        out << ",";
                    }
                    out << std::endl;
                }
                out << "]" << std::endl;
                out.close();
            }

            void print_lookup_libs_list(std::vector<std::size_t> gate_ids){
                std::ofstream out;
                out.open(_folder_name + "/lookup_libs_list.json");
                out << "[" << std::endl;
                for(std::size_t i=0; i < gate_ids.size(); i++){
                    out << "\"" << "lookup_" << _test_name << "_" << gate_ids[i] << "\"";
                    if(i < gate_ids.size() - 1){
                        out << ",";
                    }
                    out << std::endl;
                }
                out << "]" << std::endl;
                out.close();
            }

            std::string print_gate_argument(){
                std::stringstream gate_argument_str;
                std::vector<std::string> gates_computation_code;
                std::size_t i = 0;
                std::vector<std::size_t> gate_ids;

                for(const auto &gate: _constraint_system.gates()){
                    std::string gate_eval_string = gate_call_template;
                    boost::replace_all(gate_eval_string, "$TEST_NAME$", _test_name);
                    boost::replace_all(gate_eval_string, "$GATE_LIB_ID$", to_string(i));
                    boost::replace_all(gate_eval_string, "$MODULUS$", to_string(PlaceholderParams::field_type::modulus));
                    gate_argument_str << gate_eval_string << std::endl;
                    _gate_includes += "import \"./gate_"  + to_string(i) + ".sol\"; \n";
                    gates_computation_code.push_back(gate_computation_code(gate));
                    print_gate_file(gates_computation_code[i], i);
                    gate_ids.push_back(i);
                    i++;
                }
                print_gate_libs_list(gate_ids);

                return gate_argument_str.str();
            }

            std::string print_lookup_argument(){
                std::stringstream lookup_str;
                std::size_t j = 0;
                std::size_t i = 0;
                std::size_t cur = 0;
                std::vector<std::string> lookups_computation_code;
                std::vector<std::size_t> lookup_ids;

                for(const auto &lookup_gate: _constraint_system.lookup_gates()){
                    std::string lookup_eval_string = lookup_call_template;
                    boost::replace_all(lookup_eval_string, "$TEST_NAME$", _test_name);
                    boost::replace_all(lookup_eval_string, "$LOOKUP_LIB_ID$", to_string(i));
                    boost::replace_all(lookup_eval_string, "$MODULUS$", to_string(PlaceholderParams::field_type::modulus));
                    lookup_str << lookup_eval_string;
                    lookup_ids.push_back(i);
                    _lookup_includes += "import \"./lookup_"  + to_string(i) + ".sol\"; \n";
                    lookups_computation_code.push_back(lookup_computation_code(lookup_gate));
                    print_lookup_file(lookups_computation_code[i], i);
                    i++;
                }
                if(_use_lookups) print_lookup_libs_list(lookup_ids);
                j = 0;
                std::size_t table_index = 1;
                for(const auto &table: _constraint_system.lookup_tables()){
                    variable_type sel_var(table.tag_index, 0, true, variable_type::column_type::selector);
                    variable_type shifted_sel_var(table.tag_index, 1, true, variable_type::column_type::selector);
                    lookup_str << "\t\tstate.selector_value=basic_marshalling.get_uint256_be(blob, " << _var_indices.at(sel_var) * 0x20 << ");" << std::endl;                    
                    lookup_str << "\t\tstate.shifted_selector_value=basic_marshalling.get_uint256_be(blob, " << _var_indices.at(shifted_sel_var) * 0x20 << ");" << std::endl;                    

                    for( const auto &option: table.lookup_options ){
                        lookup_str << 
                            "\t\t\tl= mulmod( " << table_index << ", state.selector_value, modulus);" << std::endl;
                        lookup_str << 
                            "\t\t\tstate.l_shifted = mulmod( " << table_index << ", state.shifted_selector_value, modulus);" << std::endl;
                        lookup_str << "\t\t\tstate.theta_acc=state.theta;" << std::endl;
                        for( const auto &var: option ){
                            lookup_str << 
                                "\t\t\tl= addmod( l, mulmod(state.selector_value,  mulmod( state.theta_acc, basic_marshalling.get_uint256_be(blob, " << _var_indices.at(var) * 0x20 << "), modulus), modulus), modulus);" << std::endl;
                            variable_type shifted_var = var;
                            shifted_var.rotation = 1;
                            lookup_str << 
                                "\t\t\tstate.l_shifted = addmod( state.l_shifted, mulmod(state.shifted_selector_value, mulmod( state.theta_acc, basic_marshalling.get_uint256_be(blob, " << _var_indices.at(shifted_var) * 0x20 << "), modulus), modulus), modulus);" << std::endl;
                            lookup_str << "\t\t\tstate.theta_acc = mulmod(state.theta_acc, state.theta, modulus);" << std::endl;
                        }
                        lookup_str << 
                            "\t\t\tl= mulmod( l, state.mask, modulus);" << std::endl;
                        lookup_str << 
                            "\t\t\tstate.l_shifted = mulmod( state.l_shifted, state.shifted_mask, modulus);" << std::endl;
                        lookup_str << "\t\t\t state.g = mulmod(state.g, addmod( state.factor, addmod(l, mulmod(state.beta, state.l_shifted, modulus), modulus), modulus), modulus);" << std::endl;
                        j++;
                    }
                    table_index++;
                }
                lookup_str << std::endl;
                
                return lookup_str.str();
            }
        
            void print(){
                std::filesystem::create_directory(_folder_name);
                std::cout << "Generating verifier " << _test_name << std::endl;

                std::string gate_argument = print_gate_argument();
                std::string lookup_argument = print_lookup_argument();

                std::string commitment_code = generate_commitment_scheme_code<PlaceholderParams>(_common_data, _lpc_scheme);

                // Prepare all necessary replacements
                transpiler_replacements reps;
                reps["$LOOKUP_LIBRARY_CALL$"] = _use_lookups ? lookup_library_call :"        //No lookups";
                reps["$TEST_NAME$"] = _test_name;
                reps["$MODULUS$"] = to_string(PlaceholderParams::field_type::modulus);
                reps["$VERIFICATION_KEY1$"] = "0x" + to_string(_common_data.vk.constraint_system_hash);
                reps["$VERIFICATION_KEY2$"] = "0x" + to_string(_common_data.vk.fixed_values_commitment);
                reps["$BATCHES_NUM$"] = _use_lookups ? "5" :"4";
                reps["$EVAL_PROOF_OFFSET$"] = _use_lookups ? "0xa1" :"0x79";
                reps["$SORTED_COLUMNS_NUMBER$"] = to_string(_constraint_system.sorted_lookup_columns_number());
                reps["$LOOKUP_OPTIONS_NUMBER$"] = to_string(_constraint_system.lookup_options_num());
                reps["$LOOKUP_CONSTRAINTS_NUMBER$"] = to_string(_constraint_system.lookup_constraints_num());
                reps["$Z_OFFSET$"] = _use_lookups ? "0xc9" :"0xa1";
                reps["$PERMUTATION_SIZE$"] = to_string(_permutation_size);
                reps["$SPECIAL_SELECTORS_OFFSET$"] = to_string(_special_selectors_offset);
                reps["$TABLE_Z_OFFSET$"] = to_string(_table_z_offset);
                reps["$PUBLIC_INPUT_OFFSET$"] = to_string(_public_input_offset);
                reps["$PERMUTATION_TABLE_OFFSET$"] = to_string(_permutation_offset);
                reps["$QUOTIENT_OFFSET$"] = to_string(_quotient_offset);
                reps["$ROWS_AMOUNT$"] = to_string(_common_data.rows_amount);
                reps["$OMEGA$"] = to_string(_common_data.basic_domain->get_domain_element(1));
                reps["$ZERO_INDICES$"] = zero_indices(_common_data.columns_rotations);
                reps["$GATE_ARGUMENT_COMPUTATION$"] = gate_argument;
                reps["$GATE_INCLUDES$"] = _gate_includes;
                reps["$LOOKUP_INCLUDES$"] = _lookup_includes;
                reps["$LOOKUP_ARGUMENT_COMPUTATION$"] = lookup_argument;
                reps["$COMMITMENT_CODE$"] = commitment_code;

                commitment_scheme_replaces<PlaceholderParams>(reps, _common_data, _lpc_scheme, _permutation_size, _use_lookups);

                replace_and_print(modular_verifier_template, reps, _folder_name + "/modular_verifier.sol");
                replace_and_print(modular_permutation_argument_library_template, reps, _folder_name + "/permutation_argument.sol");
                replace_and_print(modular_gate_argument_library_template, reps, _folder_name + "/gate_argument.sol");
                replace_and_print(modular_commitment_library_template, reps, _folder_name + "/commitment.sol");
                if(_use_lookups)
                    replace_and_print(modular_lookup_argument_library_template, reps, _folder_name + "/lookup_argument.sol");
                else
                    replace_and_print(modular_dummy_lookup_argument_library_template, reps, _folder_name + "/lookup_argument.sol");
            }

        private:
            const typename PlaceholderParams::constraint_system_type &_constraint_system;
            const common_data_type &_common_data;
            const typename PlaceholderParams::commitment_scheme_type &_lpc_scheme;
            std::size_t _permutation_size;
            std::string _folder_name;
            std::string _test_name;
            bool        _use_lookups;
            std::size_t _z_offset;
            std::size_t _special_selectors_offset;
            std::size_t _table_z_offset;
            std::size_t _variable_values_offset;
            std::size_t _permutation_offset;
            std::size_t _quotient_offset;
            std::size_t _public_input_offset;
            variable_indices_type _var_indices;

            std::string _gate_includes;
            std::string _lookup_includes;
        };
    }
}

#endif //__MODULAR_CONTRACTS_TEMPLATES_HPP__
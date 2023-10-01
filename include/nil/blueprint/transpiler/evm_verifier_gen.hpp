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
#include <nil/blueprint/transpiler/lpc_scheme_gen.hpp>
#include <nil/blueprint/transpiler/util.hpp>

namespace nil {
    namespace blueprint {
        void replace_and_print(std::string input, transpiler_replacements reps, std::string output_file_name){
            std::string code = input;

            for(const auto&[k,v]: reps){
                boost::replace_all(code, k, v);
            }
            std::ofstream out;
            out.open(output_file_name);
            out << code;
            out.close();
        }

        template <typename PlaceholderParams>
        using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<
            typename PlaceholderParams::field_type, 
            PlaceholderParams
        >::preprocessed_data_type::common_data_type;

        template <typename PlaceholderParams>
        std::string zero_indices(std::array<std::set<int>, PlaceholderParams::total_columns> col_rotations){
            std::vector<std::uint16_t> zero_indices;
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
                sum += col_rotations[i].size();
                result << std::hex << std::setfill('0') << std::setw(4) << zero_indices[i];
            }
            return result.str();
        }

        template <typename PlaceholderParams>
        std::map<nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>, std::size_t>
        get_plonk_variable_indices(std::array<std::set<int>, PlaceholderParams::total_columns> col_rotations){
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

        template <typename PlaceholderParams>
        std::string constraint_computation_code(
            const std::map<nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>, std::size_t> &var_indices,
            const typename nil::crypto3::zk::snark::plonk_constraint<typename PlaceholderParams::field_type> &constraint
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
                        result << "\t\tprod = basic_marshalling.get_uint256_be(blob, " << var_indices.at(v) * 0x20 << ");" << std::endl;
                    } else{
                        result << "\t\tprod = mulmod(prod, basic_marshalling.get_uint256_be(blob, " << var_indices.at(v) * 0x20 << "), modulus);" << std::endl;
                    }
                }
                result << "\t\tsum = addmod(sum, prod, modulus);" << std::endl;
            }
            return result.str();
        }

        template<typename PlaceholderParams> 
        void print_evm_verifier(
            const typename PlaceholderParams::constraint_system_type &constraint_system,
            const common_data_type<PlaceholderParams> &common_data,
            const typename PlaceholderParams::commitment_scheme_type &lpc_scheme,
            std::size_t permutation_size,
            std::string folder_name
        ){
            std::filesystem::create_directory(folder_name);
            std::string test_name;
            std::size_t found = folder_name.rfind("/");
            if( found == std::string::npos ){
                test_name = folder_name;
            } else{
                test_name = folder_name.substr(found + 1);
            }
            std::cout << "Generating verifier " << test_name << std::endl;

            bool use_lookups = constraint_system.lookup_gates().size() > 0;

            std::size_t z_offset = use_lookups ? 0xc9 : 0xa1;
            std::size_t special_selectors_offset = z_offset + permutation_size * 0x80;
            std::size_t table_z_offset = special_selectors_offset + 0xc0;
            std::size_t variable_values_offset = 0;

            for( std::size_t i = 0; i < PlaceholderParams::arithmetization_params::constant_columns + PlaceholderParams::arithmetization_params::selector_columns; i++){
                variable_values_offset += 0x20 * (common_data.columns_rotations[i + PlaceholderParams::arithmetization_params::witness_columns + PlaceholderParams::arithmetization_params::public_input_columns].size()+1);
            }

            std::size_t permutation_offset = variable_values_offset;
            for( std::size_t i = 0; i < PlaceholderParams::arithmetization_params::witness_columns + PlaceholderParams::arithmetization_params::public_input_columns; i++){
                permutation_offset += 0x20 * (common_data.columns_rotations[i].size());
            }

            std::size_t quotient_offset = use_lookups? permutation_offset + 0x80: permutation_offset + 0x40;

            auto var_indices = get_plonk_variable_indices<PlaceholderParams>(common_data.columns_rotations);

            using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
            std::stringstream gate_argument_code;    
            gate_argument_code << "\t\tuint256 sum;" << std::endl;
            gate_argument_code << "\t\tuint256 gate;" << std::endl;
            gate_argument_code << "\t\tuint256 prod;" << std::endl;
            gate_argument_code << "\t\tuint256 theta_acc=1;" << std::endl;
            for(const auto &gate: constraint_system.gates()){
                gate_argument_code << "\t\tgate = 0;" << std::endl;
                for(const auto &constraint: gate.constraints){
                    gate_argument_code << constraint_computation_code<PlaceholderParams>(var_indices, constraint);
                    gate_argument_code << "\t\tgate = addmod(gate, mulmod(theta_acc, sum, modulus), modulus);" << std::endl;
                    gate_argument_code << "\t\ttheta_acc = mulmod(theta_acc, theta, modulus);" << std::endl;
                }
                variable_type sel_var(gate.selector_index, 0, true, variable_type::column_type::selector);
                gate_argument_code << "\t\t\tgate = mulmod(gate, basic_marshalling.get_uint256_be(blob, " << var_indices.at(sel_var) * 0x20 << "), modulus);" << std::endl;
                gate_argument_code << "\t\t\tF = addmod(F, gate, modulus);" <<std::endl <<std::endl;
            }

            std::size_t j = 0;
            std::stringstream lookup_argument_code;
            lookup_argument_code << "\t\t\tuint256 sum;" << std::endl;
            lookup_argument_code << "\t\t\tuint256 prod;" << std::endl;

            for(const auto &gate: constraint_system.lookup_gates()){
                variable_type sel_var(gate.tag_index, 0, true, variable_type::column_type::selector);
                lookup_argument_code << "\t\t\tstate.selector_value=basic_marshalling.get_uint256_be(blob, " << var_indices.at(sel_var) * 0x20 << ");" << std::endl;
                for( const auto &constraint: gate.constraints ){
                    variable_type sel_var(gate.tag_index, 0, true, variable_type::column_type::selector);
                    lookup_argument_code << 
                        "\t\t\tl = mulmod( " << constraint.table_id << ",state.selector_value, modulus);" << std::endl;
                    lookup_argument_code << "\t\t\tstate.theta_acc=state.theta;" << std::endl;
                    for( const auto &expression:constraint.lookup_input ){
                        lookup_argument_code << constraint_computation_code<PlaceholderParams>(var_indices, expression) << std::endl  << std::endl;
                        lookup_argument_code << 
                            "\t\t\tl = addmod( l, mulmod( mulmod(state.theta_acc, state.selector_value, modulus), sum, modulus), modulus);" << std::endl;
                        lookup_argument_code << "\t\t\tstate.theta_acc = mulmod(state.theta_acc, state.theta, modulus);" << std::endl;
                    }
                    lookup_argument_code << "state.g = mulmod(state.g, mulmod(addmod(1, state.beta, modulus), addmod(l,state.gamma, modulus), modulus), modulus);" << std::endl;
                    j++;
                }
            }

            lookup_argument_code << std::endl;
            j = 0;
            std::size_t table_index = 1;
            for(const auto &table: constraint_system.lookup_tables()){
                variable_type sel_var(table.tag_index, 0, true, variable_type::column_type::selector);
                variable_type shifted_sel_var(table.tag_index, 1, true, variable_type::column_type::selector);
                lookup_argument_code << "\t\tstate.selector_value=basic_marshalling.get_uint256_be(blob, " << var_indices.at(sel_var) * 0x20 << ");" << std::endl;                    
                lookup_argument_code << "\t\tstate.shifted_selector_value=basic_marshalling.get_uint256_be(blob, " << var_indices.at(shifted_sel_var) * 0x20 << ");" << std::endl;                    

                for( const auto &option: table.lookup_options ){
                    lookup_argument_code << 
                        "\t\t\tl= mulmod( " << table_index << ", state.selector_value, modulus);" << std::endl;
                    lookup_argument_code << 
                        "\t\t\tstate.l_shifted = mulmod( " << table_index << ", state.shifted_selector_value, modulus);" << std::endl;
                    lookup_argument_code << "\t\t\tstate.theta_acc=state.theta;" << std::endl;
                    for( const auto &var: option ){
                        lookup_argument_code << 
                            "\t\t\tl= addmod( l, mulmod(state.selector_value,  mulmod( state.theta_acc, basic_marshalling.get_uint256_be(blob, " << var_indices.at(var) * 0x20 << "), modulus), modulus), modulus);" << std::endl;
                        variable_type shifted_var = var;
                        shifted_var.rotation = 1;
                        lookup_argument_code << 
                            "\t\t\tstate.l_shifted = addmod( state.l_shifted, mulmod(state.shifted_selector_value, mulmod( state.theta_acc, basic_marshalling.get_uint256_be(blob, " << var_indices.at(shifted_var) * 0x20 << "), modulus), modulus), modulus);" << std::endl;
                        lookup_argument_code << "\t\t\tstate.theta_acc = mulmod(state.theta_acc, state.theta, modulus);" << std::endl;
                    }
                    lookup_argument_code << 
                        "\t\t\tl= mulmod( l, state.mask, modulus);" << std::endl;
                    lookup_argument_code << 
                        "\t\t\tstate.l_shifted = mulmod( state.l_shifted, state.shifted_mask, modulus);" << std::endl;
                    lookup_argument_code << "\t\t\t state.g = mulmod(state.g, addmod( state.factor, addmod(l, mulmod(state.beta, state.l_shifted, modulus), modulus), modulus), modulus);" << std::endl;
                    j++;
                }
                table_index++;
            }
            lookup_argument_code << std::endl;

            std::string commitment_code = generate_commitment_scheme_code<PlaceholderParams>(common_data, lpc_scheme);

            // Prepare all necessary replacements
            transpiler_replacements reps;
            reps["$LOOKUP_LIBRARY_CALL$"] = use_lookups ? lookup_library_call :"        //No lookups";
            reps["$TEST_NAME$"] = test_name;
            reps["$MODULUS$"] = to_string(PlaceholderParams::field_type::modulus);
            reps["$VERIFICATION_KEY1$"] = "0x" + to_string(common_data.vk.constraint_system_hash);
            reps["$VERIFICATION_KEY2$"] = "0x" + to_string(common_data.vk.fixed_values_commitment);
            reps["$BATCHES_NUM$"] = use_lookups ? "5" :"4";
            reps["$EVAL_PROOF_OFFSET$"] = use_lookups ? "0xa1" :"0x79";
            reps["$SORTED_COLUMNS_NUMBER$"] = to_string(constraint_system.sorted_lookup_columns_number());
            reps["$LOOKUP_OPTIONS_NUMBER$"] = to_string(constraint_system.lookup_options_num());
            reps["$LOOKUP_CONSTRAINTS_NUMBER$"] = to_string(constraint_system.lookup_constraints_num());
            reps["$Z_OFFSET$"] = use_lookups ? "0xc9" :"0xa1";
            reps["$PERMUTATION_SIZE$"] = to_string(permutation_size);
            reps["$SPECIAL_SELECTORS_OFFSET$"] = to_string(special_selectors_offset);
            reps["$TABLE_Z_OFFSET$"] = to_string(table_z_offset);
            reps["$PERMUTATION_TABLE_OFFSET$"] = to_string(permutation_offset);
            reps["$QUOTIENT_OFFSET$"] = to_string(quotient_offset);
            reps["$ROWS_AMOUNT$"] = to_string(common_data.rows_amount);
            reps["$OMEGA$"] = to_string(common_data.basic_domain->get_domain_element(1));
            reps["$ZERO_INDICES$"] = zero_indices<PlaceholderParams>(common_data.columns_rotations);
            reps["$GATE_ARGUMENT_COMPUTATION$"] = gate_argument_code.str();
            reps["$LOOKUP_ARGUMENT_COMPUTATION$"] = lookup_argument_code.str();
            reps["$COMMITMENT_CODE$"] = commitment_code;

            commitment_scheme_replaces<PlaceholderParams>(reps, common_data, lpc_scheme, permutation_size, use_lookups);

            replace_and_print(modular_verifier_template, reps, folder_name + "/modular_verifier.sol");
            replace_and_print(modular_permutation_argument_library_template, reps, folder_name + "/permutation_argument.sol");
            replace_and_print(modular_gate_argument_library_template, reps, folder_name + "/gate_argument.sol");
            replace_and_print(modular_commitment_library_template, reps, folder_name + "/commitment.sol");
            if(use_lookups)
                replace_and_print(modular_lookup_argument_library_template, reps, folder_name + "/lookup_argument.sol");
            else
                replace_and_print(modular_dummy_lookup_argument_library_template, reps, folder_name + "/lookup_argument.sol");
        }
    }
}

#endif //__MODULAR_CONTRACTS_TEMPLATES_HPP__
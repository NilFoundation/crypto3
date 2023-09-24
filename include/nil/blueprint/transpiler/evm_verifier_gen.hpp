#ifndef __EVM_VERIFIER_GEN_HPP__
#define __EVM_VERIFIER_GEN_HPP__

#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>

#include <boost/algorithm/string.hpp> 

#include <nil/blueprint/transpiler/modular_contracts_templates.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>

namespace nil {
    namespace blueprint {
        using transpiler_replacements = std::map<std::string, std::string>;

        template<typename T> std::string to_string(T val) {
            std::stringstream strstr;
            strstr << val;
            return strstr.str();
        }

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

        template<typename PlaceholderParams> 
        void print_evm_verifier(
            const typename PlaceholderParams::constraint_system_type &constraint_system,
            const common_data_type<PlaceholderParams> &common_data,
            std::size_t permutation_size,
            std::string folder_name
        ){
            std::cout << "Generating verifier " << folder_name << std::endl;
            bool use_lookups = constraint_system.lookup_gates().size() > 0;

            std::size_t z_offset = use_lookups ? 0xc9 : 0xa1;
            std::size_t special_selectors_offset = z_offset + permutation_size * 0x80;
            std::size_t table_z_offset = special_selectors_offset + 0x80;
            std::size_t variable_values_offset = 0;

            for( std::size_t i = 0; i < PlaceholderParams::arithmetization_params::constant_columns + PlaceholderParams::arithmetization_params::selector_columns; i++){
                variable_values_offset += 0x20 * (common_data.columns_rotations[i + PlaceholderParams::arithmetization_params::witness_columns + PlaceholderParams::arithmetization_params::public_input_columns].size()+1);
            }

            std::size_t permutation_offset = variable_values_offset;
            for( std::size_t i = 0; i < PlaceholderParams::arithmetization_params::witness_columns + PlaceholderParams::arithmetization_params::public_input_columns; i++){
                permutation_offset += 0x20 * (common_data.columns_rotations[i].size());
            }

            std::size_t quotient_offset = use_lookups? permutation_offset + 0x80: permutation_offset + 0x40;

            // Prepare all necessary replacements
            transpiler_replacements reps;
            reps["$LOOKUP_LIBRARY_CALL$"] = use_lookups ? lookup_library_call :"        //No lookups";
            reps["$TEST_NAME$"] = folder_name;
            reps["$MODULUS$"] = to_string(PlaceholderParams::field_type::modulus);
            reps["$VERIFICATION_KEY1$"] = "0x" + to_string(common_data.vk.constraint_system_hash);
            reps["$VERIFICATION_KEY2$"] = "0x" + to_string(common_data.vk.fixed_values_commitment);
            reps["$BATCHES_NUM$"] = use_lookups ? "5" :"4";
            reps["$EVAL_PROOF_OFFSET$"] = use_lookups ? "0xa1" :"0x79";
            reps["$SORTED_COLUMNS_NUMBER$"] = to_string(constraint_system.sorted_lookup_columns_number());
            reps["$Z_OFFSET$"] = use_lookups ? "0xc9" :"0xa1";
            reps["$PERMUTATION_SIZE$"] = to_string(permutation_size);
            reps["$SPECIAL_SELECTORS_OFFSET$"] = to_string(special_selectors_offset);
            reps["$TABLE_Z_OFFSET$"] = to_string(table_z_offset);
            reps["$PERMUTATION_TABLE_OFFSET$"] = to_string(permutation_offset);
            reps["$QUOTIENT_OFFSET$"] = to_string(quotient_offset);
            reps["$ROWS_AMOUNT$"] = to_string(common_data.rows_amount);
            reps["$OMEGA$"] = to_string(common_data.basic_domain->get_domain_element(1));
            reps["$ZERO_INDICES$"] = zero_indices<PlaceholderParams>(common_data.columns_rotations);

            replace_and_print(modular_verifier_template, reps, folder_name + "/modular_verifier.sol");
            replace_and_print(modular_permutation_argument_library_template, reps, folder_name + "/permutation_argument.sol");
            replace_and_print(modular_lookup_argument_library_template, reps, folder_name + "/lookup_argument.sol");
            replace_and_print(modular_gate_argument_library_template, reps, folder_name + "/gate_argument.sol");
            replace_and_print(modular_commitment_library_template, reps, folder_name + "/commitment.sol");
        }
    }
}

#endif //__MODULAR_CONTRACTS_TEMPLATES_HPP__
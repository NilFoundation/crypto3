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

#ifndef CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP
#define CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP

#include <sstream>
#include <map>

#include <boost/algorithm/string/replace.hpp>
#include <nil/blueprint/transpiler/util.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include<nil/crypto3/hash/keccak.hpp>
#include<nil/crypto3/hash/sha2.hpp>

#include<nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>

#include <nil/blueprint/transpiler/templates/recursive_verifier.hpp>
#include <nil/blueprint/transpiler/util.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>

namespace nil {
    namespace blueprint {
        template<typename PlaceholderParams, typename ProofType, typename CommonDataType>
        struct recursive_verifier_generator{
            using field_type = typename PlaceholderParams::field_type;
            using proof_type = ProofType;
            using common_data_type = CommonDataType;
            using verification_key_type = typename common_data_type::verification_key_type;
            using commitment_scheme_type = typename PlaceholderParams::commitment_scheme_type;
            using constraint_system_type = typename PlaceholderParams::constraint_system_type;
            using columns_rotations_type = std::vector<std::set<int>>;
            using variable_type = typename constraint_system_type::variable_type;
            using variable_indices_type = std::map<variable_type, std::size_t>;
            using degree_visitor_type = typename constraint_system_type::degree_visitor_type;
            using expression_type = typename constraint_system_type::expression_type;
            using term_type = typename constraint_system_type::term_type;
            using binary_operation_type = typename constraint_system_type::binary_operation_type;
            using pow_operation_type = typename constraint_system_type::pow_operation_type;
            using assignment_table_type = typename PlaceholderParams::assignment_table_type;

            std::vector<std::size_t> zero_indices(const columns_rotations_type &col_rotations, std::size_t permutation_size){
                std::vector<std::size_t> zero_indices;
                std::uint16_t fixed_values_points = 0;
                std::stringstream result;

                for(std::size_t i= 0; i < desc.constant_columns + desc.selector_columns; i++){
                    fixed_values_points += col_rotations[i + desc.witness_columns + desc.public_input_columns].size();
                }

                for(std::size_t i= 0; i < desc.witness_columns + desc.public_input_columns + desc.constant_columns + desc.selector_columns; i++){
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
                for(; i < desc.witness_columns + desc.public_input_columns; i++){
                    zero_indices[i] = sum + zero_indices[i] + 2 * permutation_size + 4;
                    sum += col_rotations[i].size();
                }

                sum = 0;
                for(; i < desc.witness_columns + desc.public_input_columns + desc.constant_columns + desc.selector_columns; i++){
                    zero_indices[i] = sum + zero_indices[i] + 2 * permutation_size + 4;
                    sum += col_rotations[i].size();
                }

                return zero_indices;
            }

            static std::string generate_field_array2_from_64_hex_string(std::string str){
                BOOST_ASSERT_MSG(str.size() == 64, "input string must be 64 hex characters long");
                std::string first_half = str.substr(0, 32);
                std::string second_half = str.substr(32, 32);
                return  "{\"vector\": [{\"field\": \"0x" + first_half + "\"},{\"field\": \"0x" + second_half + "\"}]}";
            }

            template<typename HashType>
            static inline std::string generate_hash(typename HashType::digest_type hashed_data){
                if constexpr(std::is_same<HashType, nil::crypto3::hashes::sha2<256>>::value){
                    std::stringstream out;
                    out << hashed_data;
                    return generate_field_array2_from_64_hex_string(out.str());
                } else if constexpr(std::is_same<HashType, nil::crypto3::hashes::keccak_1600<256>>::value){
                    std::stringstream out;
                    out << hashed_data;
                    return generate_field_array2_from_64_hex_string(out.str());
                } else {
                    std::stringstream out;
                    out << "{\"field\": \"" <<  hashed_data <<  "\"}";
                    return out.str();
                }
                BOOST_ASSERT_MSG(false, "unsupported merkle hash type");
                return "unsupported merkle hash type";
            }

            template<typename CommitmentSchemeType>
            static inline std::string generate_commitment(typename CommitmentSchemeType::commitment_type commitment) {
                return generate_hash<typename CommitmentSchemeType::lpc::merkle_hash_type>(commitment);
            }

            static inline std::string generate_lookup_options_amount_list(
                const constraint_system_type &constraint_system
            ) {
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_tables().size(); i++){
                    if( i != 0 ) result += ", ";
                    result += to_string(constraint_system.lookup_tables()[i].lookup_options.size());
                }
                return result;
            }

            static inline std::string generate_lookup_columns_amount_list(
                const constraint_system_type &constraint_system
            ) {
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_tables().size(); i++){
                    if( i != 0 ) result += ", ";
                    result += to_string(constraint_system.lookup_tables()[i].lookup_options[0].size());
                }
                return result;
            }

            static inline std::string generate_lookup_constraints_amount_list(
                const constraint_system_type &constraint_system
            ) {
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_gates().size(); i++){
                    if( i != 0 ) result += ", ";
                    result += to_string(constraint_system.lookup_gates()[i].constraints.size());
                }
                return result;
            }

            static inline std::string generate_lookup_constraint_table_ids_list(
                const constraint_system_type &constraint_system
            ){
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_gates().size(); i++){
                    for(std::size_t j = 0; j < constraint_system.lookup_gates()[i].constraints.size(); j++){
                        if( i != 0 || j!=0 ) result += ", ";
                        result += to_string(constraint_system.lookup_gates()[i].constraints[j].table_id);
                    }
                }
                return result;
            }

            static inline std::string generate_lookup_expressions_amount_list(
                const constraint_system_type &constraint_system
            ) {
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_gates().size(); i++){
                    for(std::size_t j = 0; j < constraint_system.lookup_gates()[i].constraints.size(); j++){
                        if( i != 0 || j != 0) result += ", ";
                        result += to_string(constraint_system.lookup_gates()[i].constraints[j].lookup_input.size());
                    }
                }
                return result;
            }

            static inline std::string generate_lookup_expressions_computation(
                const constraint_system_type &constraint_system
            ){
                return "";
            }

            template<typename CommitmentSchemeType>
            static inline std::string generate_eval_proof(typename CommitmentSchemeType::proof_type eval_proof) {
                std::stringstream out;
                out << "\t\t{\"array\":[" << std::endl;
                auto batch_info = eval_proof.z.get_batch_info();
                std::size_t sum = 0;
                std::size_t poly_num = 0;
                for(const auto& [k, v]: batch_info){
                    for(std::size_t i = 0; i < v; i++){
                        poly_num++;
                        BOOST_ASSERT(eval_proof.z.get_poly_points_number(k, i) != 0);
                        for(std::size_t j = 0; j < eval_proof.z.get_poly_points_number(k, i); j++){
                            if( sum != 0 ) out << "," << std::endl;
                            out << "\t\t\t{\"field\":\"" << eval_proof.z.get(k, i, j) << "\"}";
                            sum++;
                        }
                    }
                }
                out << std::endl << "\t\t]}," << std::endl;
                out << "\t\t{\"array\": [" << std::endl;
                for( std::size_t i = 0; i < eval_proof.fri_proof.fri_roots.size(); i++){
                    if(i != 0) out << "," << std::endl;
                    out << "\t\t\t" << generate_commitment<CommitmentSchemeType>(
                        eval_proof.fri_proof.fri_roots[i]
                    );
                }
                out << std::endl << "\t\t]}," << std::endl;
                out << "\t\t{\"array\": [" << std::endl;
                for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                    if(i != 0) out << "," << std::endl;
                    out << "\t\t\t{\"array\":[" << std::endl;
                    std::size_t cur = 0;
                    for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                        for( std::size_t k = 0; k < initial_proof.values.size(); k++){
                            if(cur != 0) out << "," << std::endl;
                            BOOST_ASSERT_MSG(initial_proof.values[k].size() == 1, "Unsupported step_list[0] value");
                            out << "\t\t\t\t{\"field\":\"" << initial_proof.values[k][0][0] << "\"}," << std::endl;
                            out << "\t\t\t\t{\"field\":\"" << initial_proof.values[k][0][1] << "\"}";
                            cur++;
                            cur++;
                        }
                    }
                    out << "\n\t\t\t]}";
                }
                out << std::endl << "\n\t\t]}," << std::endl;
                out << "\t\t{\"array\": [" << std::endl;
                std::size_t cur = 0;
                for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                    if(i != 0) out << "," << std::endl;
                    out << "\t\t\t{\"array\": [" << std::endl;
                    cur = 0;
                    for( std::size_t j = 0; j < eval_proof.fri_proof.query_proofs[i].round_proofs.size(); j++){
                        const auto &round_proof = eval_proof.fri_proof.query_proofs[i].round_proofs[j];
                        if(cur != 0) out << "," << std::endl;
                        BOOST_ASSERT_MSG(round_proof.y.size() == 1, "Unsupported step_lis value");
                        out << "\t\t\t\t{\"field\":\"" << round_proof.y[0][0] << "\"}," << std::endl;
                        out << "\t\t\t\t{\"field\":\"" << round_proof.y[0][1] << "\"}";
                        cur++;
                        cur++;
                    }
                    out << std::endl << "\t\t\t]}";
                }
                out << std::endl << "\t\t]}," << std::endl;

                out << "\t\t{\"array\": [" << std::endl;
                for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                    if( i!= 0 ) out << "," << std::endl;
                    out << "\t\t\t{\"array\":[" << std::endl;
                    std::size_t cur = 0;
                    for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                        for( std::size_t k = 0; k < initial_proof.p.path().size(); k++){
                            if(cur != 0) out << "," << std::endl;
                            out << "\t\t\t\t{\"int\":" << initial_proof.p.path()[k][0].position() << "}";
                            cur ++;
                        }
                        break;
                    }
                    out << std::endl << "\t\t\t]}";
                }
                out << std::endl << "\t\t]}," << std::endl;

                out << "\t\t{\"array\": [" << std::endl;
                for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                    if( i!= 0 ) out << "," << std::endl;
                    out << "\t\t\t{\"array\":[" << std::endl;
                    std::size_t cur = 0;
                    for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                        for( std::size_t k = 0; k < initial_proof.p.path().size(); k++){
                            if(cur != 0) out << "," << std::endl;
                            out << "\t\t\t\t" << generate_hash<typename CommitmentSchemeType::lpc::merkle_hash_type>(
                                initial_proof.p.path()[k][0].hash()
                            );
                            cur ++;
                        }
                    }
                    out << std::endl << "\t\t\t]}";
                }
                out << std::endl << "\t\t]}," << std::endl;

                out << "\t\t{\"array\": [" << std::endl;
                for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                    if(i != 0) out << "," << std::endl;
                    out << "\t\t\t{\"array\": [" << std::endl;
                    cur = 0;
                    for( std::size_t j = 0; j < eval_proof.fri_proof.query_proofs[i].round_proofs.size(); j++){
                        const auto& p = eval_proof.fri_proof.query_proofs[i].round_proofs[j].p;
                        for( std::size_t k = 0; k < p.path().size(); k++){
                            if(cur != 0) out << "," << std::endl;
                            out << "\t\t\t\t{\"int\": " << p.path()[k][0].position() << "}";
                            cur++;
                        }
                    }
                    out << std::endl << "\t\t\t]}";
                }
                out << std::endl << "\t\t]}," << std::endl;

                out << "\t\t{\"array\": [" << std::endl;
                for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                    if(i != 0) out << "," << std::endl;
                    out << "\t\t\t{\"array\": [" << std::endl;
                    cur = 0;
                    for( std::size_t j = 0; j < eval_proof.fri_proof.query_proofs[i].round_proofs.size(); j++){
                        const auto& p = eval_proof.fri_proof.query_proofs[i].round_proofs[j].p;
                        for( std::size_t k = 0; k < p.path().size(); k++){
                            if(cur != 0) out << "," << std::endl;
                            out << "\t\t\t\t" << generate_hash<typename CommitmentSchemeType::lpc::merkle_hash_type>(
                                p.path()[k][0].hash()
                            );
                            cur++;
                        }
                    }
                    out << std::endl << "\t\t\t]}";
                }
                out << std::endl << "\t\t]}," << std::endl;

                cur = 0;
                out << "\t\t{\"array\": [" << std::endl;
                for( std::size_t i = 0; i < eval_proof.fri_proof.final_polynomial.size(); i++){
                    if(cur != 0) out << "," << std::endl;
                    out << "\t\t\t{\"field\": \"" << eval_proof.fri_proof.final_polynomial[i] << "\"}";
                    cur++;
                }
                out << std::endl << "\t\t]}";

                return out.str();
                BOOST_ASSERT_MSG(false, "unsupported commitment scheme type");
                return "unsupported commitment scheme type";
            }

            inline std::string generate_input(
                const typename assignment_table_type::public_input_container_type &public_inputs,
                const proof_type &proof,
                const std::vector<std::size_t> public_input_sizes
            ){
                BOOST_ASSERT(public_input_sizes.size() == desc.public_input_columns);
                std::stringstream out;
                out << "[" << std::endl;

                if(desc.public_input_columns != 0){
                    out << "\t{\"array\":[" << std::endl;
                    std::size_t cur = 0;
                    for(std::size_t i = 0; i < desc.public_input_columns; i++){
                        std::size_t max_non_zero = 0;
                        for(std::size_t j = 0; j < public_inputs[i].size(); j++){
                            if( public_inputs[i][j] != 0 ) max_non_zero = j;
                        }
                        if( max_non_zero + 1 > public_input_sizes[i] ) {
                            std::cout << "Public input size is larger than reserved. Real size = " << max_non_zero  + 1 << " reserved = " << public_input_sizes[i] << std::endl;
                            exit(1);
                        }
                        BOOST_ASSERT(max_non_zero <= public_input_sizes[i]);
                        for(std::size_t j = 0; j < public_input_sizes[i]; j++){
                            if(cur != 0) out << "," << std::endl;
                            if( j >= public_inputs[i].size() )
                                out << "\t\t{\"field\": \"" << typename field_type::value_type(0) << "\"}";
                            else
                                out << "\t\t{\"field\": \"" << public_inputs[i][j] << "\"}";
                            cur++;
                        }
                    }
                    out << std::endl << "\t]}," << std::endl;
                }

                out << "\t{\"struct\":[" << std::endl;
                out << "\t\t{\"array\":[" << std::endl;
                bool first = true;
                for( const auto &it: proof.commitments ){
                    if( !first ) out << "," << std::endl; else first = false;
                    out << "\t\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(proof.commitments.at(it.first));//(nil::crypto3::zk::snark::VARIABLE_VALUES_BATCH)
                }
                out << "\t\t]}," << std::endl;

                out << "\t\t{\"field\": \"" << proof.eval_proof.challenge << "\"}," << std::endl;
                out << generate_eval_proof<typename PlaceholderParams::commitment_scheme_type>(
                    proof.eval_proof.eval_proof
                ) << std::endl;
                out << "\t]}" << std::endl;

                out << "]" << std::endl;
                return out.str();
            }

            // TODO move logic to utils.hpp to prevent code duplication
            inline variable_indices_type get_plonk_variable_indices(const columns_rotations_type &col_rotations, std::size_t start_index){
                std::map<variable_type, std::size_t> result;
                std::size_t j = 0;
                for(std::size_t i = 0; i < desc.constant_columns; i++){
                    for(auto& rot: col_rotations[i + desc.witness_columns + desc.public_input_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::constant);
                        result[v] = j + start_index;
                        j++;
                    }
                }
                for(std::size_t i = 0; i < desc.selector_columns; i++){
                    for(auto& rot: col_rotations[i + desc.witness_columns + desc.public_input_columns + desc.constant_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::selector);
                        result[v] = j + start_index;
                        j++;
                    }
                }
                for(std::size_t i = 0; i < desc.witness_columns; i++){
                    for(auto& rot: col_rotations[i]){
                        variable_type v(i, rot, true, variable_type::column_type::witness);
                        result[v] = j + start_index;
                        j++;
                    }
                }
                for(std::size_t i = 0; i < desc.public_input_columns; i++){
                    for(auto& rot: col_rotations[i + desc.witness_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::public_input);
                        result[v] = j + start_index;
                        j++;
                    }
                }
                return result;
            }

            template<typename VariableType>
            class expression_gen_code_visitor : public boost::static_visitor<std::string> {
                const variable_indices_type &_indices;
            public:
                expression_gen_code_visitor(const variable_indices_type &var_indices) :_indices(var_indices){}

                std::string generate_expression(const expression_type& expr) {
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                std::string operator()(const term_type& term) {
                    std::string result;
                    std::vector <std::string> v;
                    if( term.get_coeff() != field_type::value_type::one() || term.get_vars().size() == 0)
                        v.push_back("pallas::base_field_type::value_type(0x" + to_hex_string(term.get_coeff()) + "_cppui255)");
                    for(auto& var: term.get_vars()){
                        v.push_back("z[" + to_string(_indices.at(var)) + "]");
                    }
                    for(std::size_t i = 0; i < v.size(); i++){
                        if(i != 0) result += " * ";
                        result += v[i];
                    }
                    return result;
                }

                std::string operator()(
                        const pow_operation_type& pow) {
                    std::string result = boost::apply_visitor(*this, pow.get_expr().get_expr());
                    return "pow" + to_string(pow.get_power()) + "(" + result +")";
                }

                std::string operator()(
                        const binary_operation_type& op) {
                    std::string left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    std::string right = boost::apply_visitor(*this, op.get_expr_right().get_expr());
                    switch (op.get_op()) {
                        case binary_operation_type::ArithmeticOperatorType::ADD:
                            return "(" + left + " + " + right + ")";
                        case binary_operation_type::ArithmeticOperatorType::SUB:
                            return "(" + left + " - " + right + ")";
                        case binary_operation_type::ArithmeticOperatorType::MULT:
                            return "(" + left + " * " + right + ")";
                    }
                    return "";
                }
            };

            static inline std::string rot_string (int j){
                if(j == 0) return "xi"; else
                if(j == 1 ) return "xi*omega"; else
                if(j == -1) return "xi/omega"; else
                if(j > 0) return "xi*pow<" + to_string(j) + ">(omega)"; else
                if(j < 0) return "xi/pow<" + to_string(-j) + ">(omega)";
                return "";
            }

            static inline std::vector<std::string> split_point_string(std::string point){
                std::vector<std::string> result;
                std::size_t found = point.find("& ");
                std::size_t j = 0;
                std::size_t prev = 0;
                while (found!=std::string::npos){
                    result.push_back(point.substr(prev, found-prev));
                    prev = found + 2;
                    found = point.find("& ",prev);
                    j++;
                }
                return result;
            }

            std::string generate_recursive_verifier(
                const constraint_system_type &constraint_system,
                const common_data_type &common_data,
                const std::vector<std::size_t> public_input_sizes
            ){
                auto placeholder_info = nil::crypto3::zk::snark::prepare_placeholder_info<PlaceholderParams>(
                    constraint_system,
                    common_data
                );

                std::size_t permutation_size = common_data.permuted_columns.size();
                const auto &desc = common_data.desc;
                BOOST_ASSERT(desc.public_input_columns == public_input_sizes.size());
                std::string result = nil::blueprint::recursive_verifier_template;
                bool use_lookups = constraint_system.lookup_gates().size() > 0;
                transpiler_replacements lookup_reps;
                transpiler_replacements reps;

                auto fri_params = common_data.commitment_params;
                std::size_t batches_num = placeholder_info.batches_num;
                auto lambda = fri_params.lambda;

                std::size_t round_proof_layers_num = 0;
                for(std::size_t i = 0; i < fri_params.r; i++ ){
                    round_proof_layers_num += log2(fri_params.D[i]->m) -1;
                }

                std::size_t lookup_degree = constraint_system.lookup_poly_degree_bound();

                std::size_t rows_amount = desc.rows_amount;
                std::size_t quotient_polys = placeholder_info.quotient_size;

                std::size_t poly_num = placeholder_info.poly_num;

                std::size_t points_num = placeholder_info.points_num;
                std::size_t table_values_num = placeholder_info.table_values_num;

                std::size_t constraints_amount = 0;
                std::string gates_sizes = "";
                std::stringstream constraints_body;
                std::size_t cur = 0;
                auto verifier_indices = get_plonk_variable_indices(common_data.columns_rotations, 2*permutation_size + 4);

                expression_gen_code_visitor<variable_type> visitor(verifier_indices);
                for(std::size_t i = 0; i < constraint_system.gates().size(); i++){
                    constraints_amount += constraint_system.gates()[i].constraints.size();
                    if( i != 0) gates_sizes += ", ";
                    gates_sizes += to_string(constraint_system.gates()[i].constraints.size());
                    for(std::size_t j = 0; j < constraint_system.gates()[i].constraints.size(); j++, cur++){
                        constraints_body << "\tconstraints[" << cur << "] = " << visitor.generate_expression(constraint_system.gates()[i].constraints[j]) << ";" << std::endl;
                    }
                }

                std::stringstream lookup_expressions_body;
                cur = 0;
                for(const auto &lookup_gate: constraint_system.lookup_gates()){
                    for(const auto &lookup_constraint: lookup_gate.constraints){
                        for( const auto &expr: lookup_constraint.lookup_input){
                            lookup_expressions_body << "\texpressions[" << cur << "] = " << visitor.generate_expression(expr) << ";" << std::endl;
                            cur++;
                        }
                    }
                }

                std::stringstream lookup_gate_selectors_list;
                cur = 0;
                for(const auto &lookup_gate: constraint_system.lookup_gates()){
                    variable_type var(lookup_gate.tag_index, 0, true, variable_type::column_type::selector);
                    lookup_gate_selectors_list << "\t\tlookup_gate_selectors[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                    cur++;
                }

                std::stringstream lookup_table_selectors_list;
                cur = 0;
                for(const auto &lookup_table: constraint_system.lookup_tables()){
                    variable_type var(lookup_table.tag_index, 0, true, variable_type::column_type::selector);
                    lookup_table_selectors_list << "\t\tlookup_table_selectors[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                    cur++;
                }

                std::stringstream lookup_shifted_table_selectors_list;
                cur = 0;
                for(const auto &lookup_table: constraint_system.lookup_tables()){
                    variable_type var(lookup_table.tag_index, 1, true, variable_type::column_type::selector);
                    lookup_shifted_table_selectors_list << "\t\tshifted_lookup_table_selectors[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                    cur++;
                }

                std::stringstream lookup_options_list;
                cur = 0;
                for(const auto &lookup_table: constraint_system.lookup_tables()){
                    for(const auto &lookup_option: lookup_table.lookup_options){
                        for( const auto &column: lookup_option){
                            variable_type var(column.index, 0, true, variable_type::column_type::constant);
                            lookup_options_list << "\t\tlookup_table_lookup_options[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                            cur++;
                        }
                    }
                }

                std::stringstream lookup_shifted_options_list;
                cur = 0;
                for(const auto &lookup_table: constraint_system.lookup_tables()){
                    for(const auto &lookup_option: lookup_table.lookup_options){
                        for( const auto &column: lookup_option){
                            variable_type var(column.index, 1, true, variable_type::column_type::constant);
                            lookup_shifted_options_list << "\t\tshifted_lookup_table_lookup_options[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                            cur++;
                        }
                    }
                }

                std::stringstream gates_selectors_indices;
                cur = 0;
                for(const auto &gate: constraint_system.gates()){
                    if(cur != 0) gates_selectors_indices << ", ";
                    gates_selectors_indices << gate.selector_index;
                    cur++;
                }

                auto [z_points_indices, singles_strs, singles_map, poly_ids] = calculate_unique_points<PlaceholderParams, common_data_type>(
                    placeholder_info,
                    desc,
                    common_data, permutation_size, quotient_polys,
                    use_lookups?constraint_system.sorted_lookup_columns_number():0,
                    "recursive" // Generator mode
                );

                std::string singles_str = "";
                for(const auto &[k, v]: singles_map){
                    singles_str+= "\tsingles[" + to_string(v) + "] = " + k + ";\n";
                }

                std::string lpc_poly_ids_const_arrays = "";
                for(std::size_t i = 0; i < poly_ids.size(); i++){
                    lpc_poly_ids_const_arrays += "\tconstexpr std::array<std::size_t, " + to_string(poly_ids[i].size()) + "> lpc_poly_ids" + to_string(i) + " = {";
                    for(std::size_t j = 0; j < poly_ids[i].size(); j++){
                        if(j != 0) lpc_poly_ids_const_arrays += ", ";
                        lpc_poly_ids_const_arrays += to_string(poly_ids[i][j]);
                    }
                    lpc_poly_ids_const_arrays += "};\n";
                }

                std::stringstream prepare_U_V_str;
                prepare_U_V_str << "\tpallas::base_field_type::value_type theta_acc = pallas::base_field_type::value_type(1);\n\n";
                for(std::size_t i = 0; i < singles_strs.size();i++){
                    prepare_U_V_str << "\tU[" + to_string(i) << "] = pallas::base_field_type::value_type(0);\n";
                    for(std::size_t j = 0; j <z_points_indices.size(); j++){
                        if( z_points_indices[j] == i)
                            prepare_U_V_str << "\tU[" + to_string(i) << "] += theta_acc * proof.z[" << j << "]; theta_acc *= challenges.lpc_theta;\n";
                    }
                    prepare_U_V_str << "\n";
                }
                for( std::size_t j = 0; j < placeholder_info.batches_sizes[0]; j++){
                    prepare_U_V_str << "\tU[unique_points] += theta_acc * pallas::base_field_type::value_type(0x"<< std::hex << common_data.commitment_scheme_data.at(0)[j] << std::dec << "_cppui255); theta_acc *= challenges.lpc_theta;\n";
                }

                std::stringstream lpc_y_computation;
                for( std::size_t i = 0; i < singles_strs.size(); i++){
                    lpc_y_computation << "\t\tQ0 = pallas::base_field_type::value_type(0);" << std::endl;
                    lpc_y_computation << "\t\tQ1 = pallas::base_field_type::value_type(0);" << std::endl;
                    for( std::size_t j = 0; j < poly_ids[i].size(); j++){
                        lpc_y_computation << "\t\tQ0 += proof.initial_proof_values[i]["<< poly_ids[i][j]*2 <<"] * theta_acc;" << std::endl;
                        lpc_y_computation << "\t\tQ1 += proof.initial_proof_values[i]["<< poly_ids[i][j]*2 + 1 <<"] * theta_acc;" << std::endl;
                        lpc_y_computation << "\t\ttheta_acc *= challenges.lpc_theta;\n";
                    }
                    lpc_y_computation << "\t\tQ0 -= U["<< i << "];" << std::endl;
                    lpc_y_computation << "\t\tQ1 -= U["<< i << "];" << std::endl;
                    lpc_y_computation << "\t\tQ0 /= (x_2 - singles[" << i << "]);" << std::endl;
                    lpc_y_computation << "\t\tQ1 /= (-x_2 - singles[" << i << "]);" << std::endl;
                    lpc_y_computation << "\t\ty0 += Q0;" << std::endl;
                    lpc_y_computation << "\t\ty1 += Q1;" << std::endl;
                }
                lpc_y_computation << "\t\tQ0 = pallas::base_field_type::value_type(0);" << std::endl;
                lpc_y_computation << "\t\tQ1 = pallas::base_field_type::value_type(0);" << std::endl;
                for( std::size_t j = 0; j < placeholder_info.batches_sizes[0]; j++){
                    lpc_y_computation << "\t\tQ0 += proof.initial_proof_values[i]["<< j*2 <<"] * theta_acc;" << std::endl;
                    lpc_y_computation << "\t\tQ1 += proof.initial_proof_values[i]["<< j*2 + 1 <<"] * theta_acc;" << std::endl;
                    lpc_y_computation << "\t\ttheta_acc *= challenges.lpc_theta;\n";
                }
                lpc_y_computation << "\t\tQ0 -= U[unique_points];" << std::endl;
                lpc_y_computation << "\t\tQ1 -= U[unique_points];" << std::endl;
                lpc_y_computation << "\t\tQ0 /= (x_2 - challenges.eta);" << std::endl;
                lpc_y_computation << "\t\tQ1 /= (-x_2 - challenges.eta);" << std::endl;
                lpc_y_computation << "\t\ty0 += Q0;" << std::endl;
                lpc_y_computation << "\t\ty1 += Q1;" << std::endl;

                std::string initial_proof_check_str = "";
                const std::vector<std::size_t> &batches_sizes = placeholder_info.batches_sizes;

                std::size_t start_position = 0;
                std::size_t initial_merkle_proofs_position_num = (log2(fri_params.D[0]->m) - 1);
                cur = 0;
                for(std::size_t i = 0; i < batches_num; i++){
                    initial_proof_check_str += "\t\thash_state = calculate_leaf_hash<"+to_string(start_position*2)+"," + to_string(batches_sizes[i]) + ">(proof.initial_proof_values[i]);\n";
                    for(std::size_t j = 0; j < initial_merkle_proofs_position_num; j++){
                        initial_proof_check_str += "\t\tpos = pallas::base_field_type::value_type(proof.initial_proof_positions[i][" + to_string(j) + "]);";
                        initial_proof_check_str += " npos = pallas::base_field_type::value_type(1) - pos;\n";
                        initial_proof_check_str +=
                            "\t\thash_state = __builtin_assigner_poseidon_pallas_base({0, pos * hash_state + npos * proof.initial_proof_hashes[i]["
                                +to_string(cur)+
                            "], npos * hash_state + pos * proof.initial_proof_hashes[i]["
                                +to_string(cur)+
                            "]})[2];\n";
                        cur++;
                    }
                    start_position += batches_sizes[i];
                    if( i == 0 )
                        initial_proof_check_str += "\t\t__builtin_assigner_exit_check(hash_state == pallas::base_field_type::value_type(0x$VK1$_cppui255));\n\n";
                    else
                        initial_proof_check_str += "\t\t__builtin_assigner_exit_check(hash_state == proof.commitments[" + to_string(i-1) + "]);\n\n";
                }

                std::string placeholder_challenges_str = "\tchallenges.eta = state = __builtin_assigner_poseidon_pallas_base({0, vk0, vk1})[2];\n";
                if(placeholder_info.use_permutations){
                    placeholder_challenges_str += "\t// generate permutation argument challenges\n";
                    placeholder_challenges_str += "\tchallenges.perm_beta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[0], 0})[2];\n";
                    placeholder_challenges_str += "\tchallenges.perm_gamma = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];\n";
                    if( placeholder_info.permutation_poly_amount  > 1 ){
                        placeholder_challenges_str += "\tfor( std::size_t i = 0; i < " + to_string(placeholder_info.permutation_poly_amount - 1) + "; i++){\n";
                        placeholder_challenges_str += "\t\tchallenges.perm_chunk_alphas[i] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];\n";
                        placeholder_challenges_str += "\t}\n";
                    }
                }
                if(placeholder_info.use_lookups){
                    placeholder_challenges_str += "\t// generate permutation argument challenges\n";
                    if( placeholder_info.use_permutations ) {
                        placeholder_challenges_str += "\tchallenges.lookup_theta = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];\n";
                        placeholder_challenges_str += "\tchallenges.lookup_beta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[3], 0})[2];";
                    } else {
                        placeholder_challenges_str += "\tchallenges.lookup_theta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[0], 0})[2];\n";
                        placeholder_challenges_str += "\tchallenges.lookup_beta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[3], 0})[2];";
                    }
                    placeholder_challenges_str += "\tchallenges.lookup_gamma = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];\n";
                    if( placeholder_info.lookup_poly_amount  > 1 ){
                        placeholder_challenges_str += "\tfor( std::size_t i = 0; i < " + to_string(placeholder_info.lookup_poly_amount - 1) + "; i++){\n";
                        placeholder_challenges_str += "\t\tchallenges.lookup_chunk_alphas[i] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];\n";
                        placeholder_challenges_str += "\t}\n";
                    }
                    placeholder_challenges_str += "\tfor( std::size_t i = 0; i < " + to_string(placeholder_info.sorted_poly_amount -1) + "; i++){\n";
                    placeholder_challenges_str += "\t\tchallenges.lookup_alphas[i] = state =__builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];\n";
                    placeholder_challenges_str += "\t}\n";
                }
                if(placeholder_info.use_permutations || placeholder_info.use_lookups){
                    placeholder_challenges_str += "\tchallenges.gate_theta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[1], 0})[2];\n";
                } else {
                    placeholder_challenges_str += "\tchallenges.gate_theta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[0]})[2];\n";
                }

                for( std::size_t i = 0; i < 8; i++){
                    placeholder_challenges_str += "\tchallenges.alphas[" + to_string(i) + "] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];\n";
                }

                if( placeholder_info.use_permutations || placeholder_info.use_lookups )
                    placeholder_challenges_str += "\tchallenges.xi = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[2], 0})[2];\n";
                else
                    placeholder_challenges_str += "\tchallenges.xi = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[1], 0})[2];\n";

                if( placeholder_info.use_lookups ){
                    placeholder_challenges_str += "\tstate = __builtin_assigner_poseidon_pallas_base({state, vk1, proof.commitments[0]})[2];\n";
                    placeholder_challenges_str += "\tstate = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[1], proof.commitments[2]})[2];\n";
                    placeholder_challenges_str += "\tchallenges.lpc_theta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[3], 0})[2];\n";
                } else if (placeholder_info.use_permutations){
                    placeholder_challenges_str += "\tstate = __builtin_assigner_poseidon_pallas_base({state, vk1, proof.commitments[0]})[2];\n";
                    placeholder_challenges_str += "\tchallenges.lpc_theta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[1], proof.commitments[2]})[2];\n";
                } else {
                    placeholder_challenges_str += "\tstate = __builtin_assigner_poseidon_pallas_base({state, vk1, proof.commitments[0]})[2];\n";
                    placeholder_challenges_str += "\tchallenges.lpc_theta = state = __builtin_assigner_poseidon_pallas_base({state, proof.commitments[1], 0})[2];\n";
                }

                placeholder_challenges_str += "\tfor(std::size_t i = 0; i < fri_roots_num; i++){\n";
                placeholder_challenges_str += "\t\tchallenges.fri_alphas[i] = state = __builtin_assigner_poseidon_pallas_base({state, proof.fri_roots[i], 0})[2];\n";
                placeholder_challenges_str += "\t}\n";

                placeholder_challenges_str += "\tfor(std::size_t i = 0; i < lambda; i++){\n";
                placeholder_challenges_str += "\t\tchallenges.fri_x_indices[i] = state = __builtin_assigner_poseidon_pallas_base({state, 0, 0})[2];\n";
                placeholder_challenges_str += "\t}\n";

                std::string batches_size_list;
                for( std::size_t  i = 0; i < batches_num; i++){
                    if( i != 0) batches_size_list += ", ";
                    batches_size_list += to_string(batches_sizes[i]);
                }

                std::string round_proof_check_str = "";
                cur = 0;
                for( std::size_t i = 0; i < fri_params.r; i++){
                    round_proof_check_str += "\t\tpos = res[" + to_string(i) + "][2]; npos = pallas::base_field_type::value_type(1) - pos;\n";
                    if(i == 0)
                        round_proof_check_str += "\t\trhash = __builtin_assigner_poseidon_pallas_base({0, y0, y1})[2];\n";
                    else
                        round_proof_check_str += "\t\trhash = __builtin_assigner_poseidon_pallas_base({0, proof.round_proof_values[i]["+to_string(i*2-2)+"], proof.round_proof_values[i]["+to_string(i*2-1)+"]})[2];\n";
                    for ( std::size_t j = 0; j < log2(fri_params.D[0]->m) - i - 1; j++){
                        round_proof_check_str += "\t\tpos = pallas::base_field_type::value_type(proof.round_merkle_proof_positions[i][" + to_string(cur) + "]); npos = pallas::base_field_type::value_type(1) - pos;\n";
                        round_proof_check_str += "\t\trhash = __builtin_assigner_poseidon_pallas_base({0, pos * rhash + npos * proof.round_proof_hashes[i]["+to_string(cur)+"], npos * rhash + pos * proof.round_proof_hashes[i]["+to_string(cur)+"]})[2];\n";
                        cur++;
                    }
                    round_proof_check_str += "\t\t__builtin_assigner_exit_check(rhash == proof.fri_roots["+to_string(i)+"]);\n\n";
                }


                std::size_t domain_size_log = std::ceil(std::log2(fri_params.D[0]->size())) - 1;
                for(std::size_t i = 0; i < fri_params.r; i++){
                    if( i == 0){
                        round_proof_check_str += "\t\tinterpolant = __builtin_assigner_fri_lin_inter(x_2, y0, y1, challenges.fri_alphas["+to_string(i)+"]);\n";
                        round_proof_check_str += "\t\t__builtin_assigner_exit_check_eq_pallas(proof.initial_proof_positions[i][" + to_string(domain_size_log - 1) + "] * (interpolant - proof.round_proof_values[i]["+to_string(2*i)+"]),0);\n";
                        round_proof_check_str += "\t\t__builtin_assigner_exit_check_eq_pallas((1 - proof.initial_proof_positions[i][" + to_string(domain_size_log - 1) + "]) * (interpolant - proof.round_proof_values[i]["+to_string(2*i + 1)+"]),0);\n";
                        round_proof_check_str += "\t\t\n";
                    }
                    else{
                        round_proof_check_str += "\t\tinterpolant = __builtin_assigner_fri_lin_inter(2 * proof.initial_proof_positions[i][" + to_string(domain_size_log - i) + "] * x - x, y0, y1, challenges.fri_alphas["+to_string(i)+"]);\n";
                        round_proof_check_str += "\t\t__builtin_assigner_exit_check_eq_pallas(proof.initial_proof_positions[i][" + to_string(domain_size_log - i - 1) + "] * (interpolant - proof.round_proof_values[i]["+to_string(2*i)+"]),0);\n";
                        round_proof_check_str += "\t\t__builtin_assigner_exit_check_eq_pallas((1 - proof.initial_proof_positions[i][" + to_string(domain_size_log - i - 1) + "]) * (interpolant - proof.round_proof_values[i]["+to_string(2*i + 1)+"]),0);\n";
                        round_proof_check_str += "\t\t\n";
                    }
                    round_proof_check_str += "\t\ty0 = proof.round_proof_values[i]["+to_string(2*i)+"];\n";
                    round_proof_check_str += "\t\ty1 = proof.round_proof_values[i]["+to_string(2*i+1)+"];\n";
                    round_proof_check_str += "\t\tx = x * x;\n";
                }
                round_proof_check_str += "\t\tx = 2 * proof.initial_proof_positions[i][" + to_string(domain_size_log - fri_params.r) + "] * x - x;\n";

                std::vector<std::size_t> selectors_indices;
                for(const auto &gate: constraint_system.gates()){
                    selectors_indices.push_back(gate.selector_index);
                }

                auto zeroes = zero_indices(common_data.columns_rotations, permutation_size);
                std::string public_input_sizes_str = "";
                std::string public_input_indices_str = "";
                std::size_t full_public_input_size = 0;
                for(std::size_t i = 0; i < public_input_sizes.size(); i++){
                    if(i != 0) {
                        public_input_sizes_str += ", ";
                        public_input_indices_str += ", ";
                    }
                    public_input_sizes_str += to_string(public_input_sizes[i]);
                    public_input_indices_str += to_string(zeroes[desc.witness_columns + i]);
                    full_public_input_size += public_input_sizes[i];
                }

                cur = 0;
                std::string full_public_input_check_str = "";
                if( desc.public_input_columns != 0){
                    full_public_input_check_str += "\tstd::array<pallas::base_field_type::value_type, "+ to_string(full_public_input_size) + "> Omegas ;\n";
                    full_public_input_check_str += "\tOmegas[0] = pallas::base_field_type::value_type(1);\n";
                    full_public_input_check_str += "\tpallas::base_field_type::value_type result(0);\n";
                    for (std::size_t i = 0; i < desc.public_input_columns; i++){
                        full_public_input_check_str += "\t{\n";
                        full_public_input_check_str += "\tresult = pallas::base_field_type::value_type(0);\n";
                        for( std::size_t j = 0; j < public_input_sizes[i]; j++){
                            full_public_input_check_str += "\t\tresult += public_input[" + to_string(cur) + "] * Omegas["+to_string(j)+"] / (challenges.xi - Omegas["+to_string(j)+"]);";
                            if( j != public_input_sizes[i] - 1)
                                full_public_input_check_str += "  Omegas["+to_string(j+1)+"] = Omegas["+to_string(j)+"] * omega;\n";
                            cur++;
                        }
                        full_public_input_check_str += "\n\t\t__builtin_assigner_exit_check_eq_pallas(rows_amount * proof.z[public_input_indices[" + to_string(i) + " ]], precomputed_values.Z_at_xi * result);\n";
                        full_public_input_check_str += "\t}\n";
                    }
                }

                std::string perm_arg_str = "";
                if( placeholder_info.use_permutations){
                    cur = 0;
                    std::size_t chunk = 0;
                    for( std::size_t i = 0; i < permutation_size; i++ ){
                        perm_arg_str += "\t\ttmp = challenges.perm_gamma +  proof.z["+to_string(zeroes[common_data.permuted_columns[i]])+"];\n";
                        perm_arg_str += "\t\tg *= challenges.perm_beta *  proof.z["+to_string(i)+"] + tmp;\n";
                        perm_arg_str += "\t\th *= challenges.perm_beta *  proof.z["+to_string(permutation_size + i)+"] + tmp;\n";
                        cur++;
                        if(common_data.max_quotient_chunks != 0 && cur == common_data.max_quotient_chunks - 1){
                            perm_arg_str += "\t\tcurrent_value = proof.z["+to_string(2 * permutation_size + 4 + placeholder_info.table_values_num + 2 + chunk ) +"];\n";
                            perm_arg_str += "\t\tF[1] += challenges.perm_chunk_alphas["+to_string(chunk)+"] * (previous_value * g - current_value * h);\n";
                            perm_arg_str += "\t\tprevious_value = current_value;\n";
                            perm_arg_str += "\t\tg = pallas::base_field_type::value_type(1); h = pallas::base_field_type::value_type(1);\n";
                            chunk++;
                            cur = 0;
                        }
                    }
                }

                std::string gate_arg_prepare_str = "\t\tpallas::base_field_type::value_type theta_acc(1);\n";
                cur = 0;
                for( std::size_t i = 0; i < constraint_system.gates().size(); i++ ){
                    for( std::size_t j = 0; j < constraint_system.gates()[i].constraints.size(); j++, cur++){
                        gate_arg_prepare_str += "\t\tF[7] += proof.z["+to_string(zeroes[desc.witness_columns + desc.public_input_columns + desc.constant_columns + selectors_indices[i]]) + "] * constraints["+to_string(cur)+"] * theta_acc; theta_acc *= challenges.gate_theta;\n";
                    }
                    gate_arg_prepare_str += "\n";
                }

                std::string lookup_input_loop = "";
                cur = 0;
                std::size_t cur_e = 0;
                for(std::size_t i=0; i < constraint_system.lookup_gates().size(); i++){
                    for(std::size_t j = 0; j < constraint_system.lookup_gates()[i].constraints.size(); j++){
                        lookup_input_loop += "\t\tlookup_input["+to_string(cur) + "] = lookup_gate_constraints_table_ids["+to_string(cur)+"];\n";
                        lookup_input_loop += "\t\ttheta_acc = theta;\n";
                        for(std::size_t k = 0; k < constraint_system.lookup_gates()[i].constraints[j].lookup_input.size(); k++){
                            lookup_input_loop += "\t\tlookup_input["+to_string(cur)+"] += lookup_gate_constraints_lookup_inputs["+to_string(cur_e)+"] * theta_acc; theta_acc *= theta;\n";
                            cur_e++;
                        }
                        lookup_input_loop += "\t\tlookup_input["+to_string(cur) + "] *= lookup_gate_selectors["+to_string(i)+"];\n";
                        cur++;
                    }
                }

                std::string lookup_table_loop = "";
                cur = 0;
                std::size_t cur_o = 0;
                for(std::size_t i = 0; i < constraint_system.lookup_tables().size(); i++){
                    for(std::size_t j = 0; j < constraint_system.lookup_tables()[i].lookup_options.size(); j++){
                        lookup_table_loop += "\t\ttheta_acc = theta;\n";
                        lookup_table_loop += "\t\tlookup_value["+to_string(cur)+"] = lookup_table_selectors["+to_string(i)+"] * pallas::base_field_type::value_type("+to_string(i+1)+");\n";
                        lookup_table_loop += "\t\tlookup_shifted_value["+to_string(cur)+"] = shifted_lookup_table_selectors["+to_string(i)+"] * pallas::base_field_type::value_type("+to_string(i+1)+");\n";
                        for(std::size_t k = 0; k < constraint_system.lookup_tables()[i].lookup_options[j].size(); k++){
                            lookup_table_loop += "\t\tlookup_value["+to_string(cur)+"] += lookup_table_selectors["+to_string(i)+"] * lookup_table_lookup_options["+to_string(cur_o)+"] * theta_acc;\n";
                            lookup_table_loop += "\t\tlookup_shifted_value["+to_string(cur)+"] += shifted_lookup_table_selectors["+to_string(i)+"] * shifted_lookup_table_lookup_options["+to_string(cur_o)+"] * theta_acc;\n";
                            lookup_table_loop += "\t\ttheta_acc = theta_acc * theta;\n";
                            cur_o++;
                        }
                        lookup_table_loop += "\t\tlookup_value["+to_string(cur)+"] *= precomputed_values.mask;\n";
                        lookup_table_loop += "\t\tlookup_shifted_value["+to_string(cur)+"] *= precomputed_values.shifted_mask;\n";
                        cur++;
                    }
                }

                std::string lookup_chunking_code_str = "";
                if( placeholder_info.use_lookups ){
                    std::vector<std::size_t> lookup_parts = constraint_system.lookup_parts(common_data.max_quotient_chunks);
                    cur = 0;
                    std::size_t chunk = 0;
                    std::size_t v_l_start_index = placeholder_info.use_permutations? 2*permutation_size + 4 + placeholder_info.table_values_num + placeholder_info.permutation_poly_amount + 1:2*permutation_size + 4 + placeholder_info.table_values_num;
                    for( std::size_t i = 0; i < constraint_system.lookup_constraints_num(); i++ ){
                        lookup_chunking_code_str += "\t\tg = g *(pallas::base_field_type::value_type(1)+beta)*(gamma + lookup_input["+to_string(i)+"]);\n";
                        lookup_chunking_code_str += "\t\th = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted["+to_string(3*i)+"] + beta * sorted[" + to_string(3*i+1) + "]);\n";
                        cur++;
                        if( common_data.max_quotient_chunks > 0 && cur == lookup_parts[chunk]){
                            lookup_chunking_code_str += "\t\tcurrent_value = proof.z["+to_string(v_l_start_index + 2 + chunk)+"];\n";
                            lookup_chunking_code_str += "\t\tlookup_argument[2] += challenges.lookup_chunk_alphas[" + to_string(chunk) + "] * (previous_value * g - current_value * h);\n";
                            lookup_chunking_code_str += "\t\tprevious_value = current_value;\n";
                            lookup_chunking_code_str += "\t\tg = pallas::base_field_type::value_type(1); h = pallas::base_field_type::value_type(1);\n";
                            cur = 0;
                            chunk++;
                        }
                    }
                    for( std::size_t i = 0; i < constraint_system.lookup_options_num(); i++ ){
                        lookup_chunking_code_str += "\t\tg = g * ((pallas::base_field_type::value_type(1)+beta) * gamma + lookup_value["+to_string(i)+"] + beta * lookup_shifted_value["+to_string(i)+"]);\n";
                        lookup_chunking_code_str += "\t\th = h * ((pallas::base_field_type::value_type(1)+beta) * gamma + sorted["+to_string(3*(i+constraint_system.lookup_constraints_num()))+"] + beta * sorted[" + to_string(3*(i+constraint_system.lookup_constraints_num())+1) + "]);\n";
                        cur++;
                        if( common_data.max_quotient_chunks > 0 && cur ==  lookup_parts[chunk] && i != constraint_system.lookup_options_num() - 1 ){
                            lookup_chunking_code_str += "\t\tcurrent_value = proof.z["+to_string(v_l_start_index + 2 + chunk)+"];\n";
                            lookup_chunking_code_str += "\t\tlookup_argument[2] += challenges.lookup_chunk_alphas[" + to_string(chunk) + "] * (previous_value * g - current_value * h);\n";
                            lookup_chunking_code_str += "\t\tprevious_value = current_value;\n";
                            lookup_chunking_code_str += "\t\tg = pallas::base_field_type::value_type(1); h = pallas::base_field_type::value_type(1);\n";
                            cur = 0;
                            chunk++;
                        }
                    }
                }

                std::string x_challenge_pow_str = "\t\t";
                typename PlaceholderParams::field_type::integral_type x_power = (PlaceholderParams::field_type::modulus - 1)/fri_params.D[0]->size();
                typename PlaceholderParams::field_type::integral_type mask = 1;
                while( mask < x_power ){ mask <<= 1; }
                mask >>= 1;
                while( mask > 0 ){
                    x_challenge_pow_str += "x = x * x;";
                    if( mask & x_power ) x_challenge_pow_str += " x = x * x_challenge; ";
                    mask >>= 1;
                }
                x_challenge_pow_str += "\n";

//             for( uint64 j = 0; j < D0_log - 1; j++){
//                state.x_index += (uint64(1 - uint8(blob[state.initial_proof_offset + 0x47 + 0x38 * j])) << j );
//             }

                for( std::size_t i = 0; i < domain_size_log; i++){
                    x_challenge_pow_str += "\t\tx_2 = x_2 * x_2; x_2 *= (proof.initial_proof_positions[i]["+ to_string(domain_size_log - i - 1) + "] + (1 - proof.initial_proof_positions[i]["+ to_string(domain_size_log - i - 1) + "]) * D0_omega);\n";
                }

                lookup_reps["$LOOKUP_VARS$"] = use_lookups?lookup_vars:"";
                lookup_reps["$LOOKUP_EXPRESSIONS$"] = use_lookups?lookup_expressions:"";
                lookup_reps["$LOOKUP_CODE$"] = use_lookups?lookup_code:"";
                lookup_reps["$LOOKUP_INPUT_LOOP$"] = use_lookups?lookup_input_loop:"";
                lookup_reps["$LOOKUP_TABLE_LOOP$"] = use_lookups?lookup_table_loop:"";
                result = replace_all(result, lookup_reps);

                reps["$LOOKUP_CHUNKING_CODE$"] = use_lookups?lookup_chunking_code_str:"";
                reps["$USE_LOOKUPS$"] = use_lookups? "true" : "false";
                reps["$BATCHES_NUM$"] = to_string(batches_num);
                reps["$COMMITMENTS_NUM$"] = to_string(batches_num - 1);
                reps["$POINTS_NUM$"] = to_string(points_num);
                reps["$POLY_NUM$"] = to_string(poly_num);
                reps["$INITIAL_PROOF_POINTS_NUM$"] = to_string(poly_num * 2);
                reps["$ROUND_PROOF_POINTS_NUM$"] = to_string(fri_params.r * 2);
                reps["$FRI_ROOTS_NUM$"] = to_string(fri_params.r);
                reps["$INITIAL_MERKLE_PROOFS_NUM$"] = to_string(batches_num * lambda);
                reps["$INITIAL_MERKLE_PROOFS_POSITION_NUM$"] = to_string(initial_merkle_proofs_position_num);
                reps["$INITIAL_MERKLE_PROOFS_HASH_NUM$"] = to_string((log2(fri_params.D[0]->m) - 1) * batches_num);
                reps["$INITIAL_PROOF_CHECK$"] = to_string(initial_proof_check_str);
                reps["$ROUND_MERKLE_PROOFS_POSITION_NUM$"] = to_string(round_proof_layers_num);
                reps["$ROUND_MERKLE_PROOFS_HASH_NUM$"] = to_string(round_proof_layers_num);
                reps["$ROUND_PROOF_CHECK$"] = to_string(round_proof_check_str);
                reps["$FINAL_POLYNOMIAL_SIZE$"] = to_string(std::pow(2, std::log2(fri_params.max_degree + 1) - fri_params.r + 1) - 2);
                reps["$LAMBDA$"] = to_string(lambda);
                reps["$PERMUTATION_SIZE$"] = to_string(permutation_size);
                reps["$TOTAL_COLUMNS$"] = to_string(desc.table_width());
                reps["$ROWS_LOG$"] = to_string(log2(rows_amount));
                reps["$ROWS_AMOUNT$"] = to_string(rows_amount);
                reps["$TABLE_VALUES_NUM$"] = to_string(table_values_num);
                reps["$GATES_AMOUNT$"] = to_string(constraint_system.gates().size());
                reps["$CONSTRAINTS_AMOUNT$"] = to_string(constraints_amount);
                reps["$GATES_SIZES$"] = gates_sizes;
                reps["$GATES_SELECTOR_INDICES$"] = gates_selectors_indices.str();
                reps["$CONSTRAINTS_BODY$"] = constraints_body.str();
                reps["$WITNESS_COLUMNS_AMOUNT$"] = to_string(desc.witness_columns);
                reps["$PUBLIC_INPUT_COLUMNS_AMOUNT$"] = to_string(desc.public_input_columns);
                reps["$CONSTANT_COLUMNS_AMOUNT$"] = to_string(desc.constant_columns);
                reps["$SELECTOR_COLUMNS_AMOUNT$"] = to_string(desc.selector_columns);
                reps["$QUOTIENT_POLYS_START$"] = to_string(placeholder_info.quotient_poly_first_index);
                reps["$QUOTIENT_POLYS_AMOUNT$"] = to_string(quotient_polys);
                reps["$D0_SIZE$"] = to_string(fri_params.D[0]->m);
                reps["$D0_LOG$"] = to_string(log2(fri_params.D[0]->m));
                reps["$D0_OMEGA$"] = "pallas::base_field_type::value_type(0x" + to_hex_string(fri_params.D[0]->get_domain_element(1)) + "_cppui255)";
                reps["$OMEGA$"] = "pallas::base_field_type::value_type(0x" + to_hex_string(common_data.basic_domain->get_domain_element(1)) + "_cppui255)";
                reps["$FRI_ROUNDS$"] = to_string(fri_params.r);
                reps["$UNIQUE_POINTS$"] = to_string(singles_strs.size());
                reps["$SINGLES_AMOUNT$"] = to_string(singles_strs.size());
                reps["$SINGLES_COMPUTATION$"] = singles_str;
                reps["$PREPARE_U_AND_V$"] = prepare_U_V_str.str();
                reps["$SORTED_COLUMNS$"] = to_string(constraint_system.sorted_lookup_columns_number());
                reps["$SORTED_ALPHAS$"] = to_string(use_lookups? constraint_system.sorted_lookup_columns_number() - 1: 0);
                reps["$LOOKUP_TABLE_AMOUNT$"] = to_string(constraint_system.lookup_tables().size());
                reps["$LOOKUP_GATE_AMOUNT$"] = to_string(constraint_system.lookup_gates().size());
                reps["$LOOKUP_OPTIONS_AMOUNT$"] = to_string(constraint_system.lookup_options_num());
                reps["$LOOKUP_OPTIONS_AMOUNT_LIST$"] = generate_lookup_options_amount_list(constraint_system);
                reps["$LOOKUP_CONSTRAINTS_AMOUNT$"] = to_string(constraint_system.lookup_constraints_num());
                reps["$LOOKUP_CONSTRAINTS_AMOUNT_LIST$"] = generate_lookup_constraints_amount_list(constraint_system);
                reps["$LOOKUP_EXPRESSIONS_AMOUNT$"] = to_string(constraint_system.lookup_expressions_num());
                reps["$LOOKUP_EXPRESSIONS_AMOUNT_LIST$"] = generate_lookup_expressions_amount_list(constraint_system);
                reps["$LOOKUP_TABLES_COLUMNS_AMOUNT$"] = to_string(constraint_system.lookup_tables_columns_num());
                reps["$LOOKUP_TABLES_COLUMNS_AMOUNT_LIST$"] = generate_lookup_columns_amount_list(constraint_system);
                reps["$LOOKUP_EXPRESSIONS_BODY$"] = lookup_expressions_body.str();
                reps["$LOOKUP_CONSTRAINT_TABLE_IDS_LIST$"] = generate_lookup_constraint_table_ids_list(constraint_system);
                reps["$LOOKUP_GATE_SELECTORS_LIST$"] = lookup_gate_selectors_list.str();
                reps["$LOOKUP_TABLE_SELECTORS_LIST$"] = lookup_table_selectors_list.str();
                reps["$LOOKUP_SHIFTED_TABLE_SELECTORS_LIST$"] = lookup_shifted_table_selectors_list.str();
                reps["$LOOKUP_OPTIONS_LIST$"] = lookup_options_list.str();
                reps["$LOOKUP_SHIFTED_OPTIONS_LIST$"] = lookup_shifted_options_list.str();
                reps["$LOOKUP_SORTED_START$"] = to_string(2*permutation_size + 4 + table_values_num + (placeholder_info.use_permutations?placeholder_info.permutation_poly_amount+1:0)  + (placeholder_info.use_lookups?placeholder_info.lookup_poly_amount+1:0) + quotient_polys);
                reps["$BATCHES_AMOUNT_LIST$"] = batches_size_list;
                reps["$PUBLIC_INPUT_SIZES$"] = public_input_sizes_str;
                reps["$PUBLIC_INPUT_INDICES$"] = public_input_indices_str;
                reps["$FULL_PUBLIC_INPUT_SIZE$"] = to_string(full_public_input_size);
                reps["$LPC_POLY_IDS_CONSTANT_ARRAYS$"] = lpc_poly_ids_const_arrays;
                reps["$LPC_Y_COMPUTATION$"] = lpc_y_computation.str();
                reps["$PUBLIC_INPUT_CHECK$"] = desc.public_input_columns == 0 ? "" :full_public_input_check_str;
                reps["$PUBLIC_INPUT_INPUT$"] = desc.public_input_columns == 0 ? "" : public_input_input_str;
                reps["$VK0$"] = to_hex_string(common_data.vk.constraint_system_with_params_hash);
                reps["$VK1$"] = to_hex_string(common_data.vk.fixed_values_commitment);
                reps["$PERM_BODY$"] = placeholder_info.use_permutations? perm_arg_body:"";
                reps["$PERM_CODE$"] = placeholder_info.use_permutations? perm_arg_str: "";
                reps["$GATE_ARG_PREPARE$"] = gate_arg_prepare_str;
                reps["$PERMUTATION_CHUNK_ALPHAS$"] = to_string(placeholder_info.use_permutations? placeholder_info.permutation_poly_amount - 1: 0);
                reps["$LOOKUP_CHUNK_ALPHAS$"] = to_string(placeholder_info.use_lookups? placeholder_info.lookup_poly_amount - 1: 0);
                reps["$PLACEHOLDER_CHALLENGES_STR$"] = placeholder_challenges_str;
                reps["$V_P_INDEX$"] = placeholder_info.use_permutations? to_string(2*permutation_size + 4 + placeholder_info.table_values_num):"0";
                reps["$V_L_INDEX$"] = placeholder_info.use_permutations? to_string(2*permutation_size + 4 + placeholder_info.table_values_num + placeholder_info.permutation_poly_amount + 1):to_string(2*permutation_size + 4 + placeholder_info.table_values_num);
                reps["$X_CHALLENGE_POW$"] = x_challenge_pow_str;

                result = replace_all(result, reps);
                result = replace_all(result, reps);
                return result;
            }

        public:
            recursive_verifier_generator(
                zk::snark::plonk_table_description<typename PlaceholderParams::field_type> _desc) :
            desc(_desc) {}

        private:
            const zk::snark::plonk_table_description<typename PlaceholderParams::field_type> desc;
        };
    }
}

#endif   // CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP
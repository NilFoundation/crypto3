//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Object, that helps to transform placeholder proof to public input column for recursive circuit
//---------------------------------------------------------------------------//
#ifndef BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_PLACEHOLDER_PROOF_INPUT_TYPE_HPP
#define BLUEPRINT_COMPONENTS_FLEXIBLE_VERIFIER_PLACEHOLDER_PROOF_INPUT_TYPE_HPP

#include <map>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/proof.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail{
                template <typename PlaceholderParams>
                class placeholder_proof_input_type{
                public:
                    using field_type = typename PlaceholderParams::field_type;
                    using value_type = typename field_type::value_type;
                    using var = crypto3::zk::snark::plonk_variable<value_type>;

                    using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, typename PlaceholderParams::placeholder_params>;
                    using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, PlaceholderParams>::preprocessed_data_type::common_data_type;
                    using constraint_system_type = typename PlaceholderParams::constraint_system_type;
                    using placeholder_info_type = nil::crypto3::zk::snark::placeholder_info<PlaceholderParams>;

                    placeholder_proof_input_type(
                        const common_data_type& common_data,
                        const constraint_system_type& constraint_system,
                        const typename PlaceholderParams::commitment_scheme_params_type &fri_params,
                        std::size_t start_row_index = 0
                    ) : common_data(common_data), constraint_system(constraint_system), fri_params(fri_params)
                    {
                        placeholder_info = nil::crypto3::zk::snark::prepare_placeholder_info<PlaceholderParams>(
                            constraint_system,
                            common_data);

                        fill_vector();
                    }
                public:
                    std::vector<var> vector(){
                        return var_vector;
                    }
                    std::vector<var> commitments() const{
                        return _commitments;
                    }
                    std::vector<var> fri_roots() const{
                        return _fri_roots;
                    }
                    var challenge() const{
                        return _challenge;
                    }
                    const std::vector<std::vector<var>> &merkle_tree_positions() const{
                        return _merkle_tree_positions;
                    }
                    const std::vector<std::vector<var>> &initial_proof_values() const{
                        return _initial_proof_values;
                    }
                    const std::vector<std::vector<var>> &initial_proof_hashes() const{
                        return _initial_proof_hashes;
                    }
                    const std::vector<std::vector<var>> &round_proof_values() const{
                        return _round_proof_values;
                    }
                    const std::vector<std::vector<var>> &round_proof_hashes() const{
                        return _round_proof_hashes;
                    }
                protected:
                    std::vector<var> _commitments;
                    var _challenge;
                    std::vector<var> _fri_roots;
                    std::vector<std::vector<var>> _merkle_tree_positions;
                    std::vector<std::vector<var>> _initial_proof_values;
                    std::vector<std::vector<var>> _initial_proof_hashes;
                    std::vector<std::vector<var>> _round_proof_values;
                    std::vector<std::vector<var>> _round_proof_hashes;

                    void fill_vector() {
                        auto &desc = common_data.desc;

                        std::size_t cur = 0;
                        _commitments.push_back(var(0, cur++, false, var::column_type::public_input));
                        var_vector.push_back(_commitments[0]);
                        _commitments.push_back(var(0, cur++, false, var::column_type::public_input));
                        var_vector.push_back(_commitments[1]);
                        _commitments.push_back(var(0, cur++, false, var::column_type::public_input));
                        var_vector.push_back(_commitments[2]);

                        if( placeholder_info.use_lookups ){ //nil::crypto3::zk::snark::LOOKUP_BATCH
                            _commitments.push_back(var(0, cur++, false, var::column_type::public_input));
                            var_vector.push_back(_commitments[3]);
                        }

                        // Challenge
                        _challenge = var(0, cur++, false, var::column_type::public_input);
                        var_vector.push_back(_challenge);

                        // TODO: Commitment scheme may be different
                        // Z-s
                        // Fixed values batch.
                        // Permutation polynomials
                        std::cout << "placeholder_info.permutation_size = " << constraint_system.permuted_columns().size() << std::endl;
                        for(auto &column: constraint_system.permuted_columns()){
                            std::cout << "Permuted column " << column << std::endl;
                        }
                        std::size_t permutation_size = constraint_system.permuted_columns().size();
                        std::size_t points_num = 0;
                        for(std::size_t i = 0; i < permutation_size * 2; i++){
                            var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                            points_num++;
                        }
                        // Special selectors
                        var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                        var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                        var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                        var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                        points_num += 4;
                        //Constant columns
                        for( std::size_t i = 0; i < desc.constant_columns; i++){
                            for( std::size_t j = 0; j < common_data.columns_rotations[desc.witness_columns + desc.public_input_columns + i].size(); j++){
                                var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                                points_num++;
                            }
                        }
                        //Selector columns
                        for( std::size_t i = 0; i < desc.selector_columns; i++){
                            for( std::size_t j = 0; j < common_data.columns_rotations[desc.witness_columns + desc.public_input_columns + desc.public_input_columns + i].size(); j++){
                                var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                                points_num++;
                            }
                        }
                        //Variable values
                        //Witness columns
                        for( std::size_t i = 0; i < desc.witness_columns; i++){
                            for( std::size_t j = 0; j < common_data.columns_rotations[i].size(); j++){
                                var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                                points_num++;
                            }
                        }
                        //Public input columns
                        for( std::size_t i = 0; i < desc.public_input_columns; i++){
                            for( std::size_t j = 0; j < common_data.columns_rotations[i + desc.witness_columns].size(); j++){
                                var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                                points_num++;
                            }
                        }
                        std::cout << "Proof input points num = " << points_num << std::endl;
                        //Permutation Polynomials
                        var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                        var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                        if( placeholder_info.use_lookups ){ //lookup permutation polynomial
                            var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                            var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                        }
                        //Quotient batch
                        // TODO: place it to one single place to prevent code duplication
                        for(std::size_t i = 0; i < placeholder_info.quotient_size; i++){
                            var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                        }
                        // Lookup columns
                        if( placeholder_info.use_lookups ){ //lookup sorted columns
                            for(std::size_t i = 0; i < constraint_system.sorted_lookup_columns_number(); i++){
                                var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                                var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                                var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                            }
                        }
                        // FRI roots
                        for(std::size_t i = 0; i < fri_params.r; i++){
                            _fri_roots.push_back(var(0, cur++, false, var::column_type::public_input));
                            var_vector.push_back(_fri_roots[i]);
                        }

                        // Query proofs
                        _merkle_tree_positions.resize(fri_params.lambda);
                        _initial_proof_values.resize(fri_params.lambda);
                        _initial_proof_hashes.resize(fri_params.lambda);
                        _round_proof_values.resize(fri_params.lambda);
                        _round_proof_hashes.resize(fri_params.lambda);
                        std::cout << "Poly input num = " << placeholder_info.poly_num << std::endl;
                        for( std::size_t i = 0; i < fri_params.lambda; i++){
                            // Initial proof values
                            _initial_proof_values[i] = {};
                            for( std::size_t j = 0; j < placeholder_info.poly_num; j++ ){
                                auto val0 = var(0, cur++, false, var::column_type::public_input);
                                auto val1 = var(0, cur++, false, var::column_type::public_input);
                                _initial_proof_values[i].push_back(val0);
                                _initial_proof_values[i].push_back(val1);
                                var_vector.push_back(val0);
                                var_vector.push_back(val1);
                            }
                            // Initial proof positions
                            _merkle_tree_positions[i].resize(log2(fri_params.D[0]->m) - 1);
                            for( std::size_t j = 0; j < log2(fri_params.D[0]->m) - 1; j++ ){
                                var pos_var = var(0, cur++, false, var::column_type::public_input);
                                var_vector.push_back(pos_var);
                                _merkle_tree_positions[i][j] = pos_var;
                            }
                            // Initial proof hashes
                            for( std::size_t j = 0; j < placeholder_info.batches_num * (log2(fri_params.D[0]->m) - 1); j++ ){
                                var hash_var = var(0, cur++, false, var::column_type::public_input);
                                var_vector.push_back(hash_var);
                                _initial_proof_hashes[i].push_back(hash_var);
                            }
                            // Round proof values
                            for( std::size_t j = 0; j < fri_params.r; j++){
                                var y0_var = var(0, cur++, false, var::column_type::public_input);
                                var y1_var = var(0, cur++, false, var::column_type::public_input);
                                var_vector.push_back(y0_var);
                                var_vector.push_back(y1_var);
                                _round_proof_values[i].push_back(y0_var);
                                _round_proof_values[i].push_back(y1_var);
                            }
                            // Round proof hashes
                            for( std::size_t j = 0; j < placeholder_info.round_proof_layers_num; j++ ){
                                var hash_var = var(0, cur++, false, var::column_type::public_input);
                                var_vector.push_back(hash_var);
                                _round_proof_hashes[i].push_back(hash_var);
                            }
                        }
                        // Final polynomials
                        std::size_t final_polynomial_size = std::pow(2, std::log2(fri_params.max_degree + 1) - fri_params.r + 1) - 2;
                        for( std::size_t i = 0; i < final_polynomial_size; i++){
                            var_vector.push_back(var(0, cur++, false, var::column_type::public_input));
                        }
                    }
                private:
                    const common_data_type &common_data;
                    const constraint_system_type &constraint_system;
                    std::vector<var> var_vector;
                    const typename PlaceholderParams::commitment_scheme_params_type &fri_params;
                    placeholder_info_type placeholder_info;
                };
            }
        }
    }
}

#endif

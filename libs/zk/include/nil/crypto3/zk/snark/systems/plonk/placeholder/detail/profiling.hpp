//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PROFILING_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PROFILING_HPP

#include <algorithm>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/commitments/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                // We have a piece of logic that is may be easily computed from constraint system,
                // common data and commitment parameters,
                // but it is not convenient to place it inside any of these classes.
                //
                // This piece of code is used in different projects with verifiers, and it's not good ot repeat it.
                template <typename PlaceholderParams>
                struct placeholder_info{
                    using variable_indices_type = std::map<nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>, std::size_t>;

                    std::size_t batches_num;
                    std::vector<std::size_t> batches_sizes;
                    std::size_t poly_num;
                    std::size_t quotient_size;
                    std::size_t permutation_batch_size;
                    bool use_lookups;
                    bool use_permutations;
                    std::size_t points_num;
                    std::size_t table_values_num;

                    // Commitments order in placeholder proof
                    int  variable_value_batch_order;
                    int  permutation_batch_order;
                    int  quotient_batch_order;
                    int  lookup_batch_order;

                    // Polynomial_amount
                    std::size_t permutation_poly_amount;
                    std::size_t lookup_poly_amount;
                    std::size_t sorted_poly_amount;

                    std::size_t permutation_size;
                    std::size_t round_proof_layers_num;
                    std::size_t quotient_poly_first_index;

                    variable_indices_type var_indices;
                    std::vector<std::size_t> permuted_zero_indices;
                };


                template<typename PlaceholderParams, typename enable = void>
                placeholder_info<PlaceholderParams> prepare_placeholder_info();

                // TODO remove permutation size
                template<typename PlaceholderParams, std::enable_if_t<nil::crypto3::zk::is_lpc<typename PlaceholderParams::commitment_scheme_type>, bool> = true>
                placeholder_info<PlaceholderParams> prepare_placeholder_info(
                    const typename PlaceholderParams::constraint_system_type &constraint_system,
                    const typename nil::crypto3::zk::snark::placeholder_public_preprocessor<typename PlaceholderParams::field_type, PlaceholderParams>::preprocessed_data_type::common_data_type &common_data
                ) {
                    placeholder_info<PlaceholderParams> res;
                    auto &desc = common_data.desc;
                    auto &fri_params = common_data.commitment_params;

                    res.permutation_size = common_data.permuted_columns.size();
                    res.use_lookups = constraint_system.num_lookup_gates() != 0;
                    res.use_permutations = common_data.permuted_columns.size() != 0;

                    res.variable_value_batch_order = 0;
                    res.permutation_batch_order = res.use_lookups || res.use_permutations ? 1 : -1;
                    res.quotient_batch_order = res.use_lookups || res.use_permutations ? 2: 1;
                    res.lookup_batch_order = res.use_lookups? 3: -1;

                    res.batches_num = 3;
                    if( res.use_lookups || res.use_permutations ) res.batches_num++;
                    if( res.use_lookups ) res.batches_num++;

                    std::size_t cur = 0;
                    res.batches_sizes.resize(res.batches_num);
                    res.batches_sizes[cur++] = res.permutation_size * 2 + 2 + desc.constant_columns + desc.selector_columns;
                    res.batches_sizes[cur++] = desc.witness_columns + desc.public_input_columns;

                    std::size_t full_permutation_polynomial_size = res.use_permutations? (res.permutation_size + 2) : 0;
                    std::size_t full_lookup_polynomial_size = res.use_lookups? (constraint_system.lookup_poly_degree_bound() + 1) : 0;
                    std::size_t full_gate_polynomial_size = (common_data.max_gates_degree + 1);
                    std::size_t max_quotient_size = std::max(full_permutation_polynomial_size, full_lookup_polynomial_size);
                    max_quotient_size = std::max(max_quotient_size, full_gate_polynomial_size);

                    res.permutation_batch_size = 0;
                    res.permutation_poly_amount = res.use_permutations? 1: 0;
                    res.lookup_poly_amount = res.use_lookups? 1: 0;

                    if( res.use_lookups || res.use_permutations ){
                        if( res.use_lookups ) res.permutation_batch_size++;
                        if( res.use_permutations ) res.permutation_batch_size++;

                        if( common_data.max_quotient_chunks > 0 ){
                            res.permutation_batch_size += full_permutation_polynomial_size/common_data.max_quotient_chunks;
                            res.permutation_batch_size += full_lookup_polynomial_size/common_data.max_quotient_chunks;
                            res.permutation_poly_amount += full_permutation_polynomial_size/common_data.max_quotient_chunks;
                            res.lookup_poly_amount += full_lookup_polynomial_size/common_data.max_quotient_chunks;
                        }
                        res.batches_sizes[cur++] = res.permutation_batch_size;
                    }

                    max_quotient_size *= (desc.rows_amount - 1);
                    max_quotient_size = max_quotient_size  % desc.rows_amount == 0 ? max_quotient_size / desc.rows_amount : max_quotient_size / desc.rows_amount + 1 ;
                    if( common_data.max_quotient_chunks == 0 ){
                        res.quotient_size = res.batches_sizes[cur++] = max_quotient_size;
                    } else {
                        res.quotient_size = res.batches_sizes[cur++] = max_quotient_size < common_data.max_quotient_chunks? max_quotient_size: common_data.max_quotient_chunks;
                    }

                    if(res.use_lookups) res.batches_sizes[cur++] = constraint_system.sorted_lookup_columns_number();
                    res.round_proof_layers_num = 0;
                    for(std::size_t i = 0; i < fri_params.r; i++ ){
                        res.round_proof_layers_num += log2(fri_params.D[i]->m) -1;
                    }
                    res.poly_num = std::accumulate(res.batches_sizes.begin(), res.batches_sizes.end(), 0);

                    // variable indices
                    using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
                    auto &col_rotations = common_data.columns_rotations;
                    std::size_t j = 0;

                    std::map<std::size_t, std::size_t> zero_indices;

                    res.points_num = 2 * res.permutation_size + 4;
                    res.table_values_num = 0;
                    for(std::size_t i = 0; i < common_data.desc.constant_columns; i++){
                        for(auto& rot: col_rotations[i + common_data.desc.witness_columns + common_data.desc.public_input_columns]){
                            variable_type v(i, rot, true, variable_type::column_type::constant);
                            res.var_indices[v] = j;
                            if( rot == 0 ) zero_indices[i + common_data.desc.witness_columns + common_data.desc.public_input_columns] = j;
                            j++;
                            res.table_values_num++;
                        }
                    }
                    for(std::size_t i = 0; i < common_data.desc.selector_columns; i++){
                        for(auto& rot: col_rotations[i + common_data.desc.witness_columns + common_data.desc.public_input_columns + common_data.desc.constant_columns]){
                            variable_type v(i, rot, true, variable_type::column_type::selector);
                            res.var_indices[v] = j;
                            if( rot == 0) zero_indices[i + common_data.desc.witness_columns + common_data.desc.public_input_columns + common_data.desc.constant_columns] = j;
                            j++;
                            res.table_values_num++;
                        }
                    }
                    for(std::size_t i = 0; i < common_data.desc.witness_columns; i++){
                        for(auto& rot: col_rotations[i]){
                            variable_type v(i, rot, true, variable_type::column_type::witness);
                            res.var_indices[v] = j;
                            if(rot == 0) zero_indices[i] = j;
                            j++;
                            res.table_values_num++;
                        }
                    }
                    for(std::size_t i = 0; i < common_data.desc.public_input_columns; i++){
                        for(auto& rot: col_rotations[i + common_data.desc.witness_columns]){
                            variable_type v(i, rot, true, variable_type::column_type::public_input);
                            res.var_indices[v] = j;
                            if(rot == 0) zero_indices[i + common_data.desc.witness_columns] = j;
                            j++;
                            res.table_values_num++;
                        }
                    }
                    res.points_num += res.table_values_num;

                    for( std::size_t i = 0; i < common_data.permuted_columns.size(); i++ ){
                        std::size_t ind = common_data.permuted_columns[i];
                        res.permuted_zero_indices.push_back(zero_indices[ind]);
                    }

                    if( res.use_permutations ){
                        res.points_num += res.permutation_poly_amount + 1;
                    }
                    if( res.use_lookups ){
                        res.points_num += res.lookup_poly_amount + 1;
                    }
                    res.points_num += res.quotient_size;
                    res.points_num += constraint_system.sorted_lookup_columns_number() * 3;

                    res.sorted_poly_amount = constraint_system.sorted_lookup_columns_number();

                    res.quotient_poly_first_index = 2 * res.permutation_size + 4 + res.table_values_num;
                    if( res.use_permutations ) res.quotient_poly_first_index += res.permutation_poly_amount + 1;
                    if( res.use_lookups ) res.quotient_poly_first_index += res.lookup_poly_amount + 1;

                    return res;
                }


                template<typename PlaceholderParams>
                void print_placeholder_params(
                    const typename placeholder_public_preprocessor<
                        typename PlaceholderParams::field_type,
                        PlaceholderParams
                    >::preprocessed_data_type &preprocessed_data,
                    const typename PlaceholderParams::commitment_scheme_type &commitment_scheme,
                    const plonk_table_description<typename PlaceholderParams::field_type> &table_description,
                    std::string filename,
                    std::string circuit_name = "Sample proof"
                ){
                    boost::property_tree::ptree root;
                    root.put("test_name", circuit_name);
                    root.put("modulus", PlaceholderParams::field_type::modulus);
                    root.put("rows_amount", preprocessed_data.common_data.desc.rows_amount);
                    root.put("usable_rows_amount", preprocessed_data.common_data.desc.usable_rows_amount);
                    root.put("omega", preprocessed_data.common_data.basic_domain->get_domain_element(1));
                    root.put("verification_key", preprocessed_data.common_data.vk.to_string());

                    boost::property_tree::ptree ar_params_node;
                    boost::property_tree::ptree witness_node;
                    witness_node.put("", table_description.witness_columns);
                    ar_params_node.push_back(std::make_pair("", witness_node));
                    boost::property_tree::ptree public_input_node;
                    public_input_node.put("", table_description.public_input_columns);
                    ar_params_node.push_back(std::make_pair("", public_input_node));
                    boost::property_tree::ptree constant_node;
                    constant_node.put("", table_description.constant_columns);
                    ar_params_node.push_back(std::make_pair("", constant_node));
                    boost::property_tree::ptree selector_node;
                    selector_node.put("", table_description.selector_columns);
                    ar_params_node.push_back(std::make_pair("", witness_node));
                    root.add_child("ar_params", ar_params_node);

                    boost::property_tree::ptree c_rotations_node;
                    for( std::size_t i = 0; i < preprocessed_data.common_data.columns_rotations.size(); i++ ){
                        boost::property_tree::ptree column_node;
                        for( int r: preprocessed_data.common_data.columns_rotations[i]){
                            boost::property_tree::ptree rotation_node;
                            rotation_node.put("", r);
                            column_node.push_back(std::make_pair("", rotation_node));
                        }
                        c_rotations_node.push_back(std::make_pair("", column_node));
                    }
                    root.add_child("columns_rotations_node", c_rotations_node);

                    boost::property_tree::ptree commitment_scheme_params_node = commitment_scheme.get_params();
                    root.add_child("commitment_params_node", commitment_scheme_params_node);

                    std::ofstream out;
                    out.open(filename);
                    boost::property_tree::write_json(out, root);
                    out.close();
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PROFILING_HPP

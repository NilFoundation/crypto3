//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_COMMON_DATA_HPP
#define CRYPTO3_MARSHALLING_COMMON_DATA_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/commitment_params.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/kzg.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                // ******************* placeholder common data ********************************* //
                template<typename TTypeBase, typename CommonDataType>
                using placeholder_common_data = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
//                      typename CommonDataType::public_commitments_type commitments;
//                      0. It'll be used in verification key too. Don't duplicate it now;
                        typename commitment<TTypeBase, typename CommonDataType::commitment_scheme_type>::type,

//                      1.std::array<std::set<int>, ParamsType::arithmetization_params::TotalColumns> columns_rotations;
                        nil::marshalling::types::array_list <TTypeBase,
                            nil::marshalling::types::array_list <TTypeBase,
                                nil::marshalling::types::integral<TTypeBase, int>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,

//                      2. std::size_t witness_columns;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      3. std::size_t public_input_columns;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      4. std::size_t constant_columns;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      5. std::size_t selector_columns;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      6. std::size_t usable_rows_amount;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      7. std::size_t rows_amount;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      8. std::size_t max_gates_degree;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      9. std::size_t permutation_parts
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      10. std::size_t lookup_parts
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
//                      11. std::size_t max_quotient_chunks
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,

//                      12. permuted_columns // global indices of permuted columns
                        nil::marshalling::types::array_list <TTypeBase,
                            nil::marshalling::types::integral<TTypeBase, std::size_t>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,
//                      13. verification_key.constraint_system_with_params_hash
                        nil::marshalling::types::array_list <TTypeBase,
                            nil::marshalling::types::integral<TTypeBase, octet_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,
//                      14. commitment_scheme_type::params_type
                        typename nil::crypto3::marshalling::types::commitment_params<
                            TTypeBase, typename CommonDataType::commitment_scheme_type
                        >::type,
//                      15. commitment_scheme_type::preprocessed_data_type
                        typename nil::crypto3::marshalling::types::commitment_preprocessed_data<
                            TTypeBase, typename CommonDataType::commitment_scheme_type
                        >::type
                    >
                >;

                template<typename Endianness, typename CommonDataType>
                placeholder_common_data<nil::marshalling::field_type<Endianness>, CommonDataType>
                fill_placeholder_common_data(const CommonDataType &common_data){
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using result_type = placeholder_common_data<TTypeBase, CommonDataType>;

                    result_type result;

                    using array_int_marshalling_type = nil::marshalling::types::array_list <TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, int>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    >;

                    using column_r_marshalling_type = nil::marshalling::types::array_list <TTypeBase,
                        array_int_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    >;

                    column_r_marshalling_type filled_columns_rotations;
                    for( const auto &column_rotation:common_data.columns_rotations){
                        array_int_marshalling_type filled_column;
                        for( const auto &i:column_rotation){
                            filled_column.value().push_back(nil::marshalling::types::integral<TTypeBase, int>(i));
                        }
                        filled_columns_rotations.value().push_back(filled_column);
                    }

                    auto filled_commitments =
                    fill_commitment<Endianness, typename CommonDataType::commitment_scheme_type>(
                        common_data.commitments.fixed_values
                    );

                    nil::marshalling::types::array_list <TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, octet_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_constraint_system_with_params_hash;
                    if constexpr(nil::crypto3::hashes::is_poseidon<typename CommonDataType::transcript_hash_type>::value){
                        auto integral = typename CommonDataType::field_type::integral_type(common_data.vk.constraint_system_with_params_hash.data);
                        std::vector<unsigned char> blob;
                        export_bits(integral, std::back_inserter(blob), 8);
                        for( std::size_t i = blob.size(); i > 0; i--){
                            filled_constraint_system_with_params_hash.value().push_back(
                                nil::marshalling::types::integral<TTypeBase, octet_type>(blob[i-1])
                            );
                        }
                    } else {
                        for( std::size_t i = 0; i < common_data.vk.constraint_system_with_params_hash.size(); i++){
                            filled_constraint_system_with_params_hash.value().push_back(
                                nil::marshalling::types::integral<TTypeBase, octet_type>(common_data.vk.constraint_system_with_params_hash[i])
                            );
                        }
                    }

                    using permuted_column_indices_type = nil::marshalling::types::array_list <TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    >;
                    permuted_column_indices_type filled_permuted_columns;
                    for( const auto &index:common_data.permuted_columns){
                        filled_permuted_columns.value().push_back(nil::marshalling::types::integral<TTypeBase, std::size_t>(index));
                    }

                    auto filled_commitment_params = fill_commitment_params<Endianness, typename CommonDataType::commitment_scheme_type>(
                        common_data.commitment_params
                    );

                    auto filled_commitment_preprocessed_data = fill_commitment_preprocessed_data<Endianness, typename CommonDataType::commitment_scheme_type>(
                        common_data.commitment_scheme_data
                    );

                    return result_type(std::make_tuple(
                        filled_commitments,                                    // 0
                        filled_columns_rotations,                               // 1
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.desc.witness_columns),    // 2
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.desc.public_input_columns),   // 3
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.desc.constant_columns),   // 4
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.desc.selector_columns),   // 5
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.desc.usable_rows_amount),  // 6
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.desc.rows_amount),    // 7
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.max_gates_degree),    // 8
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.permutation_parts),   // 9
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.lookup_parts),    // 10
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.max_quotient_chunks),   // 11
                        filled_permuted_columns,    // 12
                        filled_constraint_system_with_params_hash,  // 13
                        filled_commitment_params,   // 14
                        filled_commitment_preprocessed_data  // 15
                    ));
                    return result;
                }

                template<typename Endianness, typename CommonDataType>
                CommonDataType make_placeholder_common_data(const
                    placeholder_common_data<nil::marshalling::field_type<Endianness>, CommonDataType> &filled_common_data
                ){
                    auto fixed_values = make_commitment<Endianness, typename CommonDataType::commitment_scheme_type>(std::get<0>(filled_common_data.value()));

                    typename CommonDataType::columns_rotations_type columns_rotations(
                        std::get<1>(filled_common_data.value()).value().size()
                    );
                    for(size_t i = 0; i < std::get<1>(filled_common_data.value()).value().size(); i++){
                        auto filled_column = std::get<1>(filled_common_data.value()).value().at(i);
                        for(size_t j = 0; j < filled_column.value().size(); j++) {
                            columns_rotations[i].insert(filled_column.value()[j].value());
                        }
                    }

                    typename CommonDataType::table_description_type desc(
                        std::get<2>(filled_common_data.value()).value(),
                        std::get<3>(filled_common_data.value()).value(),
                        std::get<4>(filled_common_data.value()).value(),
                        std::get<5>(filled_common_data.value()).value(),
                        std::get<6>(filled_common_data.value()).value(),
                        std::get<7>(filled_common_data.value()).value()
                    );
                    std::size_t max_gates_degree = std::get<8>(filled_common_data.value()).value();
                    std::size_t permutation_parts = std::get<9>(filled_common_data.value()).value();
                    std::size_t lookup_parts = std::get<10>(filled_common_data.value()).value();
                    std::size_t max_quotient_chunks = std::get<11>(filled_common_data.value()).value();

                    std::vector<std::size_t> permuted_columns;
                    for( std::size_t i = 0; i < std::get<12>(filled_common_data.value()).value().size(); i++){
                        permuted_columns.push_back(std::get<12>(filled_common_data.value()).value()[i].value());
                    }

                    typename CommonDataType::commitments_type commitments;
                    commitments.fixed_values = fixed_values;

                    typename CommonDataType::verification_key_type vk;
                    vk.fixed_values_commitment = fixed_values;
                    if constexpr(nil::crypto3::hashes::is_poseidon<typename CommonDataType::transcript_hash_type>::value){
                        std::vector<std::uint8_t> blob;
                        for( std::size_t i = 0; i < std::get<13>(filled_common_data.value()).value().size(); i++){
                            blob.push_back(std::uint8_t(std::get<13>(filled_common_data.value()).value()[i].value()));
                        }
                        typename CommonDataType::field_type::integral_type newval;
                        import_bits(newval, blob.begin(), blob.end(), 8, false);
                        vk.constraint_system_with_params_hash = typename CommonDataType::field_type::value_type(newval);
                    } else {
                        for( std::size_t i = 0; i < std::get<13>(filled_common_data.value()).value().size(); i++){
                            vk.constraint_system_with_params_hash[i] = (std::get<13>(filled_common_data.value()).value()[i].value());
                        }
                    }

                    typename CommonDataType::commitment_params_type commitment_params = make_commitment_params<
                        Endianness, typename CommonDataType::commitment_scheme_type
                    >(std::get<14>(filled_common_data.value()));

                    typename CommonDataType::commitment_scheme_data_type commitment_data = make_commitment_preprocessed_data<
                        Endianness, typename CommonDataType::commitment_scheme_type
                    >(std::get<15>(filled_common_data.value()));

                    return CommonDataType(
                        commitments,
                        columns_rotations,
                        desc,
                        max_gates_degree,
                        permutation_parts,
                        lookup_parts,
                        vk,
                        permuted_columns,
                        commitment_params,
                        commitment_data,
                        max_quotient_chunks
                    );
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_COMMON_DATA_HPP

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
//                      It'll be used in verification key too. Don't duplicate it now;
                        typename commitment<TTypeBase, typename CommonDataType::commitment_scheme_type>::type,

//                      std::array<std::set<int>, ParamsType::arithmetization_params::TotalColumns> columns_rotations;
                        nil::marshalling::types::array_list <TTypeBase,
                            nil::marshalling::types::array_list <TTypeBase,
                                nil::marshalling::types::integral<TTypeBase, int>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,

//                      std::size_t rows_amount;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,

//                      std::size_t usable_rows_amount;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,

//                      std::size_t max_gates_degree;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,

//                      verification_key.constraint_system_with_params_hash
                        nil::marshalling::types::array_list <TTypeBase,
                            nil::marshalling::types::integral<TTypeBase, octet_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >
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
                    for( std::size_t i = 0; i < common_data.vk.constraint_system_with_params_hash.size(); i++){
                        filled_constraint_system_with_params_hash.value().push_back(
                            nil::marshalling::types::integral<TTypeBase, octet_type>(common_data.vk.constraint_system_with_params_hash[i])
                        );
                    }

                    return result_type(std::make_tuple(
                        filled_commitments,
                        filled_columns_rotations,
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.rows_amount),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.usable_rows_amount),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.max_gates_degree),
                        filled_constraint_system_with_params_hash
                    ));
                }

                template<typename Endianness, typename CommonDataType>
                CommonDataType
                make_placeholder_common_data(const
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

                    auto rows_amount = std::get<2>(filled_common_data.value()).value();
                    auto usable_rows_amount = std::get<3>(filled_common_data.value()).value();
                    auto max_gates_degree = std::get<4>(filled_common_data.value()).value();

                    typename CommonDataType::commitments_type commitments;
                    commitments.fixed_values = fixed_values;

                    typename CommonDataType::verification_key_type vk;
                    vk.fixed_values_commitment = fixed_values;
                    for( std::size_t i = 0; i < std::get<5>(filled_common_data.value()).value().size(); i++){
                        vk.constraint_system_with_params_hash[i] = (std::get<5>(filled_common_data.value()).value()[i].value());
                    }

                    return CommonDataType(commitments, columns_rotations, rows_amount, usable_rows_amount, max_gates_degree, vk);
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_COMMON_DATA_HPP

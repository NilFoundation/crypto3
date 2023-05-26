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
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                /******************* placeholder public commitments***************************/
/*                template<typename TTypeBase, typename PublicCommitmentsType>
                using public_commitments_type = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
//                      typename constant_commitment_scheme_type::commitment_type fixed_values;
                        typename merkle_node_value<TTypeBase, typename PublicCommitmentsType::params_type::commitment_params_type>::type
                    >
                >;

                template <typename PublicCommitmentsType, typename Endianness>
                public_commitments_type<nil::marshalling::field_type<Endianness>, PublicCommitmentsType>
                fill_public_commitments(const PublicCommitmentsType &commitments){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = public_commitments_type<nil::marshalling::field_type<Endianness>, PublicCommitmentsType>;

                    return result_type(std::make_tuple(
                        fill_merkle_node_value<typename PublicCommitmentsType::params_type::commitment_params_type, Endianness>(commitments.fixed_values)
                    ));
                }
                
                template <typename PublicCommitmentsType, typename Endianness>
                PublicCommitmentsType
                make_public_commitments(const public_commitments_type<nil::marshalling::field_type<Endianness>, PublicCommitmentsType> &filled_public_commitments){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    PublicCommitmentsType result;
                    result.fixed_values = make_merkle_node_value<typename PublicCommitmentsType::params_type::commitment_params_type, Endianness>(std::get<0>(filled_public_commitments.value()));
                    return result;
                }
*/
                /******************* placeholder common data *********************************/
                template<typename TTypeBase, typename CommonDataType>
                using placeholder_common_data = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
//                        std::shared_ptr<math::evaluation_domain<typename CommonDataType::field_type>> basic_domain;

//                        typename CommonDataType::public_commitments_type commitments;
                        typename merkle_node_value<TTypeBase, typename CommonDataType::commitments_type::params_type::runtime_size_commitment_scheme_type::commitment_type>::type,

//                      std::array<std::vector<int>, ParamsType::arithmetization_params::TotalColumns> columns_rotations;
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
                        nil::marshalling::types::integral<TTypeBase, std::size_t>
                    >
                >;

                template<typename CommonDataType, typename Endianness>
                placeholder_common_data<nil::marshalling::field_type<Endianness>, CommonDataType>
                fill_placeholder_common_data(const CommonDataType &common_data){
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using FieldType = typename CommonDataType::field_type;
                    using result_type = placeholder_common_data<TTypeBase, CommonDataType>;
                    using commitments_type = typename CommonDataType::commitments_type::params_type::runtime_size_commitment_scheme_type::commitment_type;

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
                    fill_merkle_node_value<commitments_type, Endianness>(
                        common_data.commitments.fixed_values
                    );

                    return result_type(std::make_tuple(
                        filled_commitments,
                        filled_columns_rotations,
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.rows_amount),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.usable_rows_amount),
                        nil::marshalling::types::integral<TTypeBase, std::size_t>(common_data.max_gates_degree)
                    ));
                }

                template<typename CommonDataType, typename Endianness>
                CommonDataType
                make_placeholder_common_data(const  
                    placeholder_common_data<nil::marshalling::field_type<Endianness>, CommonDataType> &filled_common_data
                ){
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using FieldType = typename CommonDataType::field_type;
                    using commitments_type = typename CommonDataType::commitments_type::params_type::runtime_size_commitment_scheme_type::commitment_type;

                    auto fixed_values = make_merkle_node_value<commitments_type, Endianness>(std::get<0>(filled_common_data.value()));

                    typename CommonDataType::columns_rotations_type columns_rotations;
                    for(size_t i = 0; i < std::get<1>(filled_common_data.value()).value().size(); i++){
                        auto filled_column = std::get<1>(filled_common_data.value()).value().at(i);
                        for(size_t j = 0; j < filled_column.value().size(); j++){
                            columns_rotations[i].insert(filled_column.value()[j].value());
                        }
                    }
                    
                    auto rows_amount = std::get<2>(filled_common_data.value()).value();
                    auto usable_rows_amount = std::get<3>(filled_common_data.value()).value();
                    auto max_gates_degree = std::get<4>(filled_common_data.value()).value();

                    typename CommonDataType::commitments_type commitments;
                    commitments.fixed_values = fixed_values;
                    return CommonDataType(commitments, columns_rotations, rows_amount, usable_rows_amount, max_gates_degree);
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_COMMON_DATA_HPP

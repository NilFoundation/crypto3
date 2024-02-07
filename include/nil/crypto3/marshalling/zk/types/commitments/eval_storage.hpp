//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_MARSHALLING_EVAL_STORAGE_HPP
#define CRYPTO3_MARSHALLING_EVAL_STORAGE_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                // Default commitment scheme proof marshalling type in fact it'll be one of tuple's elements for LPC and KZG
                template <typename TTypeBase, typename commitment_scheme_type> struct eval_proof;

                template < typename TTypeBase, typename EvalStorage >
                    using eval_storage = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // batch_info.
                        // We'll check is it good for current EVM instance
                        // All z-s are placed into plain array
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename EvalStorage::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,

                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::integral<TTypeBase, uint8_t>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,

                        // evaluation_points_num.
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::integral<TTypeBase, uint8_t>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >
                    >
                >;

                template<typename Endianness, typename EvalStorage>
                eval_storage<nil::marshalling::field_type<Endianness>, EvalStorage>
                fill_eval_storage( const EvalStorage &z ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    nil::crypto3::marshalling::types::batch_info_type batch_info;

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, uint8_t>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_batch_info;
                    auto batches = z.get_batches();
                    for( std::size_t i = 0; i < batches.size(); i++ ){
                        batch_info[batches[i]] = z.get_batch_size(batches[i]);
                        filled_batch_info.value().push_back(nil::marshalling::types::integral<TTypeBase, uint8_t>(batches[i]));
                        filled_batch_info.value().push_back(nil::marshalling::types::integral<TTypeBase, uint8_t>(z.get_batch_size(batches[i])));
                    }

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, uint8_t>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_eval_points_num;
                    for( std::size_t i = 0; i < batches.size(); i++ ){
                        for( std::size_t j = 0; j < z.get_batch_size(batches[i]); j++ ){
                            filled_eval_points_num.value().push_back(
                                nil::marshalling::types::integral<TTypeBase, uint8_t>(z.get_poly_points_number(batches[i], j))
                            );
                        }
                    }

                    std::vector<typename EvalStorage::field_type::value_type> z_val;
                    for( std::size_t i = 0; i < batches.size(); i++ ){
                        for(std::size_t j = 0; j < z.get_batch_size(batches[i]); j++ ){
                            for(std::size_t k = 0; k < z.get_poly_points_number(batches[i], j); k++ ){
                                z_val.push_back(z.get(batches[i], j, k));
                            }
                        }
                    }
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        field_element<TTypeBase, typename EvalStorage::field_type::value_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_z = fill_field_element_vector<typename EvalStorage::field_type::value_type, Endianness>(z_val);

                    return eval_storage<TTypeBase, EvalStorage>(
                        std::tuple( filled_z, filled_batch_info, filled_eval_points_num )
                    );
                }

                template<typename Endianness, typename EvalStorage>
                EvalStorage make_eval_storage(
                    const eval_storage<nil::marshalling::field_type<Endianness>, EvalStorage> &filled_storage
                ){
                    EvalStorage z;
                    typename nil::crypto3::marshalling::types::batch_info_type batch_info;
                    std::vector<std::uint8_t> eval_points_num;

                    auto filled_batch_info = std::get<1>(filled_storage.value()).value();
                    for( std::size_t i = 0; i < filled_batch_info.size(); i+=2 ){
                        batch_info[filled_batch_info[i].value()] = filled_batch_info[i+1].value();
                        z.set_batch_size(filled_batch_info[i].value(), filled_batch_info[i+1].value());
                    }

                    auto filled_eval_points_num = std::get<2>(filled_storage.value()).value();
                    std::size_t cur = 0;
                    for( const auto &it:batch_info){
                        for( std::size_t i = 0; i < it.second; i++ ){
                            z.set_poly_points_number(it.first, i, filled_eval_points_num[cur].value());
                            cur++;
                        }
                    }

                    auto filled_z = std::get<0>(filled_storage.value()).value();
                    cur = 0;
                    for( const auto &it:batch_info){
                        for( std::size_t i = 0; i < it.second; i++ ){
                            for( std::size_t j = 0; j < z.get_poly_points_number(it.first, i); j++ ){
                                z.set(it.first, i, j, filled_z[cur].value());
                                cur++;
                            }
                        }
                    }

                    return z;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

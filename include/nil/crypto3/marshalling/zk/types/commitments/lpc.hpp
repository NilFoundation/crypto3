//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021-2022 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

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

#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template < typename TTypeBase, typename LPC >                
                    using lpc_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // batch_info. 
                        // We'll check is it good for current EVM instance
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
                        >,

                        // All z-s are placed into plain line lpc::proof::z
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            field_element<TTypeBase, typename LPC::basic_fri::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,

                        // One fri proof
                        typename fri_proof<TTypeBase, typename LPC::basic_fri>::type
                    >
                >;

                template<typename Endianness, typename LPC>
                lpc_proof<nil::marshalling::field_type<Endianness>, LPC> 
                fill_lpc_proof( const typename LPC::proof_type &proof ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    nil::crypto3::marshalling::types::batch_info_type batch_info;

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, uint8_t>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_batch_info;
                    auto batches = proof.z.get_batches();
                    for( std::size_t i = 0; i < batches.size(); i++ ){
                        batch_info[batches[i]] = proof.z.get_batch_size(batches[i]);
                        filled_batch_info.value().push_back(nil::marshalling::types::integral<TTypeBase, uint8_t>(batches[i]));
                        filled_batch_info.value().push_back(nil::marshalling::types::integral<TTypeBase, uint8_t>(proof.z.get_batch_size(batches[i])));
                    }

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, uint8_t>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_eval_points_num;
                    for( std::size_t i = 0; i < batches.size(); i++ ){
                        for( std::size_t j = 0; j < proof.z.get_batch_size(batches[i]); j++ ){
                            filled_eval_points_num.value().push_back(
                                nil::marshalling::types::integral<TTypeBase, uint8_t>(proof.z.get_poly_points_number(batches[i], j))
                            );
                        }
                    }

                    std::vector<typename LPC::basic_fri::field_type::value_type> z_val;
                    for( std::size_t i = 0; i < batches.size(); i++ ){
                        for(std::size_t j = 0; j < proof.z.get_batch_size(batches[i]); j++ ){
                            for(std::size_t k = 0; k < proof.z.get_poly_points_number(batches[i], j); k++ ){
                                z_val.push_back(proof.z.get(batches[i], j, k));
                            }
                        }
                    }
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        field_element<TTypeBase, typename LPC::basic_fri::field_type::value_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_z = fill_field_element_vector<typename LPC::basic_fri::field_type::value_type, Endianness>(z_val);

                    typename fri_proof<TTypeBase, typename LPC::basic_fri>::type filled_fri_proof = fill_fri_proof<Endianness, typename LPC::basic_fri>(
                        proof.fri_proof, batch_info
                    );

                    return lpc_proof<TTypeBase, LPC>(
                        std::tuple( filled_batch_info, filled_eval_points_num, filled_z, filled_fri_proof)
                    );
                }

                template<typename Endianness, typename LPC>
                typename LPC::proof_type make_lpc_proof(const lpc_proof<nil::marshalling::field_type<Endianness>, LPC> &filled_proof){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    typename LPC::proof_type proof;
                    typename nil::crypto3::marshalling::types::batch_info_type batch_info;
                    std::vector<std::uint8_t> eval_points_num;

                    auto filled_batch_info = std::get<0>(filled_proof.value()).value();
                    for( std::size_t i = 0; i < filled_batch_info.size(); i+=2 ){
                        batch_info[filled_batch_info[i].value()] = filled_batch_info[i+1].value();
                        proof.z.set_batch_size(filled_batch_info[i].value(), filled_batch_info[i+1].value());
                    }

                    auto filled_eval_points_num = std::get<1>(filled_proof.value()).value();
                    std::size_t cur = 0;
                    for( const auto &it:batch_info){
                        for( std::size_t i = 0; i < it.second; i++ ){
                            proof.z.set_poly_points_number(it.first, i, filled_eval_points_num[cur].value());
                            cur++;
                        }
                    }

                    auto filled_z = std::get<2>(filled_proof.value()).value();
                    cur = 0;
                    for( const auto &it:batch_info){
                        for( std::size_t i = 0; i < it.second; i++ ){
                            for( std::size_t j = 0; j < proof.z.get_poly_points_number(it.first, i); j++ ){
                                proof.z.set(it.first, i, j, filled_z[cur].value());
                                cur++;
                            }
                        }
                    }

                    proof.fri_proof = make_fri_proof<Endianness, typename LPC::basic_fri>(std::get<3>(filled_proof.value()), batch_info);
                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

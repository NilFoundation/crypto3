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
#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                // Default commitment type

                // * LPCScheme is like lpc_commitment_scheme
                template <typename TTypeBase, typename LPCScheme>
                struct commitment<TTypeBase, LPCScheme, std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>> {
                    using type = typename merkle_node_value< TTypeBase, typename LPCScheme::commitment_type>::type;
                };

                template <typename Endianness, typename LPCScheme>
                typename commitment<
                    nil::marshalling::field_type<Endianness>, LPCScheme,
                    std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                >::type
                fill_commitment(typename LPCScheme::commitment_type commitment){
                    return fill_merkle_node_value<typename LPCScheme::commitment_type, Endianness>( commitment );
                }

                template <typename Endianness, typename LPCScheme>
                typename LPCScheme::commitment_type
                make_commitment(typename commitment<
                    nil::marshalling::field_type<Endianness>, LPCScheme,
                    std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                >::type const& filled_commitment
                ){
                    return make_merkle_node_value<typename LPCScheme::commitment_type, Endianness>( filled_commitment );
                }

                // * LPCScheme is like lpc_commitment_scheme
                template <typename TTypeBase, typename LPCScheme>
                struct commitment_preprocessed_data<TTypeBase, LPCScheme, std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::integral<TTypeBase, std::size_t>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::integral<TTypeBase, std::size_t>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >,
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename LPCScheme::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                            >
                        >
                    >;
                };

                template <typename Endianness, typename LPCScheme>
                typename commitment_preprocessed_data<
                    nil::marshalling::field_type<Endianness>, LPCScheme,
                    std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                >::type
                fill_commitment_preprocessed_data(const typename LPCScheme::preprocessed_data_type lpc_data){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using field_marshalling_type = field_element<TTypeBase, typename LPCScheme::field_type::value_type>;

                    using result_type = typename commitment_preprocessed_data<
                        nil::marshalling::field_type<Endianness>, LPCScheme
                    >::type;
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_map_ids;
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_sizes;
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        field_element<TTypeBase, typename LPCScheme::field_type::value_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_values;

                    for(const auto&[k, v]:lpc_data){
                        filled_map_ids.value().push_back(nil::marshalling::types::integral<TTypeBase, std::size_t>(k));
                        filled_sizes.value().push_back(nil::marshalling::types::integral<TTypeBase, std::size_t>(v.size()));
                        for(std::size_t i = 0; i < v.size(); i++){
                            filled_values.value().push_back(field_marshalling_type((v[i])));
                        }
                    }
                    return result_type(
                        std::make_tuple(
                            filled_map_ids,
                            filled_sizes,
                            filled_values
                        )
                    );
                }

                template <typename Endianness, typename LPCScheme>
                typename LPCScheme::preprocessed_data_type
                make_commitment_preprocessed_data(typename commitment_preprocessed_data<
                    nil::marshalling::field_type<Endianness>, LPCScheme,
                    std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>
                >::type const& filled_commitment_preprocessed_data
                ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    typename LPCScheme::preprocessed_data_type result;
                    for(std::size_t i = 0; i < std::get<0>(filled_commitment_preprocessed_data.value()).value().size(); i++){
                        std::size_t k = std::get<0>(filled_commitment_preprocessed_data.value()).value()[i].value();
                        std::size_t size = std::get<1>(filled_commitment_preprocessed_data.value()).value()[i].value();
                        std::vector<typename LPCScheme::field_type::value_type> v;
                        for(std::size_t j = 0; j < size; j++){
                            v.push_back(std::get<2>(filled_commitment_preprocessed_data.value()).value()[i*size + j].value());
                        }
                        result[k] = v;
                    }

                    return result;
                }

                // FOR LPC only because of basic_fri field
                template <typename TTypeBase, typename LPCScheme>
                struct eval_proof<TTypeBase, LPCScheme, std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>> > {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // Evaluation points storage z
                            eval_storage<TTypeBase, typename LPCScheme::eval_storage_type>,

                            // One fri proof
                            typename fri_proof<TTypeBase, typename LPCScheme::basic_fri>::type
                        >
                    >;
                };

                template<typename Endianness, typename LPCScheme>
                typename eval_proof<nil::marshalling::field_type<Endianness>, LPCScheme,std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>>::type
                fill_eval_proof( const typename LPCScheme::proof_type &proof, const typename LPCScheme::fri_type::params_type& fri_params){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    nil::crypto3::marshalling::types::batch_info_type batch_info = proof.z.get_batch_info();

                    auto filled_z = fill_eval_storage<Endianness, typename LPCScheme::eval_storage_type>(proof.z);

                    typename fri_proof<TTypeBase, typename LPCScheme::basic_fri>::type filled_fri_proof = fill_fri_proof<Endianness, typename LPCScheme::basic_fri>(
                        proof.fri_proof, batch_info, fri_params
                    );

                    return typename eval_proof<TTypeBase, LPCScheme>::type(
                        std::tuple( filled_z, filled_fri_proof)
                    );
                }

                template<typename Endianness, typename LPCScheme>
                typename LPCScheme::proof_type make_eval_proof(
                    const typename eval_proof<nil::marshalling::field_type<Endianness>, LPCScheme, std::enable_if_t<nil::crypto3::zk::is_lpc<LPCScheme>>>::type &filled_proof
                ){
                    typename LPCScheme::proof_type proof;

                    proof.z = make_eval_storage<Endianness, typename LPCScheme::eval_storage_type>(std::get<0>(filled_proof.value()));
                    auto batch_info = proof.z.get_batch_info();
                    proof.fri_proof = make_fri_proof<Endianness, typename LPCScheme::basic_fri>(std::get<1>(filled_proof.value()), batch_info);

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

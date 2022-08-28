//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021-2022 Ilias Khairullin <ilias@nil.foundation>
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
                template < typename TTypeBase, typename LPCScheme >                
                    using lpc_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // lpc::proof::T_root
                        typename merkle_node_value<TTypeBase, typename LPCScheme::commitment_type>::type,

                        // lpc::proof::z it is std::array<std::vector<field_element>> or std::vector<std::vector<field_element>>
                        // Vectors in array are not fixed size. So we need sequence_size_field_prefix option
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::crypto3::marshalling::types::field_element_vector_type<TTypeBase, typename LPCScheme::field_type::value_type>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                        >,

                        // lpc::proof::fri_proofs array_elements are not fixed size. So we need sequence_size_field_prefix option
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            fri_proof<TTypeBase, typename LPCScheme::basic_fri>,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                        >
                    >
                >;

                template<typename Endianness, typename LPCScheme>
                lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme> 
                fill_lpc_proof( const typename LPCScheme::proof_type &proof ){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    auto filled_T_root = fill_merkle_node_value<typename LPCScheme::commitment_type, Endianness>(proof.T_root);
                   
                    nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::crypto3::marshalling::types::field_element_vector_type<TTypeBase, typename LPCScheme::field_type::value_type>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                    > filled_z;
                    for( size_t i = 0; i < proof.z.size(); i++){
                        filled_z.value().push_back(
                            fill_field_element_vector<typename LPCScheme::field_type::value_type, Endianness>(proof.z[i])
                        );
                    }

                    nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_proof<TTypeBase, typename LPCScheme::basic_fri>,
                        nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, size_t>>
                    > filled_fri_proofs;
                    for( size_t i = 0; i < proof.fri_proof.size(); i++){
                        filled_fri_proofs.value().push_back(
                            fill_fri_proof<Endianness, typename LPCScheme::basic_fri>(proof.fri_proof[i])
                        );
                    }

                    return lpc_proof<TTypeBase, LPCScheme>(std::tuple(
                        filled_T_root,
                        filled_z,
                        filled_fri_proofs
                    ));
                }

                template<typename Endianness, typename LPCScheme>
                typename LPCScheme::proof_type 
                make_lpc_proof(const lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme> &filled_proof){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    typename LPCScheme::proof_type proof;
                    proof.T_root = make_merkle_node_value<typename LPCScheme::merkle_proof_type, Endianness>(std::get<0>(filled_proof.value()));

                    auto filled_z = std::get<1>(filled_proof.value());
                    if constexpr(LPCScheme::is_const_size){
                        for( size_t i = 0; i < filled_z.value().size(); i ++){
                            proof.z[i] = make_field_element_vector<typename LPCScheme::field_type::value_type, Endianness>(filled_z.value()[i]);
                        }
                    } else {
                        for( size_t i = 0; i < filled_z.value().size(); i ++){
                            proof.z.push_back(make_field_element_vector<typename LPCScheme::field_type::value_type, Endianness>(filled_z.value()[i]));
                        }
                    }

                    auto filled_fri_proofs = std::get<2>(filled_proof.value());
                    for( size_t i = 0; i < filled_fri_proofs.value().size(); i ++){
                        proof.fri_proof[i] = make_fri_proof<Endianness, typename LPCScheme::basic_fri>(filled_fri_proofs.value()[i]);
                    }

                    return proof;
                }

/*                template<typename TTypeBase, typename LPCScheme>
                struct lpc_proof<
                    TTypeBase,
                    LPCScheme,
 {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                            // typename merkle_tree_type::value_type T_root;
                            typename merkle_node_value<TTypeBase, typename LPCScheme::merkle_proof_type>::type,
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // std::vector<typename FieldType::value_type> z;
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                field_element<TTypeBase, typename LPCScheme::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // std::array<typename fri_type::proof_type, lambda> fri_proof;
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                typename fri_proof<TTypeBase, typename LPCScheme::basic_fri>::type,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>>>;
                };

                template<typename TTypeBase, typename LPCScheme>
                struct lpc_proof<TTypeBase,
                                 LPCScheme,
                                 typename std::enable_if<
                                     std::is_same<LPCScheme,
                                                  nil::crypto3::zk::commitments::batched_list_polynomial_commitment<
                                                      typename LPCScheme::field_type,
                                                      typename LPCScheme::lpc_params,
                                                      LPCScheme::leaf_size,
                                                      LPCScheme::is_run_time_size>>::value>::type> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                            // typename merkle_tree_type::value_type T_root;
                            typename merkle_node_value<TTypeBase, typename LPCScheme::merkle_proof_type>::type,
                            // std::array<std::vector<typename FieldType::value_type>, leaf_size> z
                            // TODO: use nil::marshalling::option::fixed_size_storage with std::array
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    field_element<TTypeBase, typename LPCScheme::field_type::value_type>,
                                    nil::marshalling::option::sequence_size_field_prefix<
                                        nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // std::array<typename fri_type::proof_type, lambda> fri_proof;
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                typename fri_proof<TTypeBase, typename LPCScheme::basic_fri>::type,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>>>;
                };

                template<typename TTypeBase, typename LPCScheme>
                struct lpc_proof_evm<TTypeBase,
                                     LPCScheme,
                                     typename std::enable_if<
                                         std::is_same<LPCScheme,
                                                      nil::crypto3::zk::commitments::batched_list_polynomial_commitment<
                                                          typename LPCScheme::field_type,
                                                          typename LPCScheme::lpc_params,
                                                          LPCScheme::leaf_size,
                                                          LPCScheme::is_run_time_size>>::value>::type> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                            // typename merkle_tree_type::value_type T_root;
                            typename merkle_node_value<TTypeBase, typename LPCScheme::merkle_proof_type>::type,
                            // std::array<std::vector<typename FieldType::value_type>, leaf_size> z
                            // TODO: use nil::marshalling::option::fixed_size_storage with std::array
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::array_list<
                                    TTypeBase,
                                    field_element<TTypeBase, typename LPCScheme::field_type::value_type>,
                                    nil::marshalling::option::sequence_size_field_prefix<
                                        nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // std::array<typename fri_type::proof_type, lambda> fri_proof;
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                typename fri_proof_evm<TTypeBase, typename LPCScheme::basic_fri>::type,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>>>;
                };

                template<typename LPCScheme,
                         typename Endianness,
                         typename std::enable_if<std::is_same<LPCScheme,
                                                              nil::crypto3::zk::commitments::list_polynomial_commitment<
                                                                  typename LPCScheme::field_type,
                                                                  typename LPCScheme::lpc_params>>::value,
                                                 bool>::type = true>
                typename lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>::type
                    fill_lpc_proof(const typename LPCScheme::proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using uint64_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint64_t>;
                    using field_marhsalling_type = field_element<TTypeBase, typename LPCScheme::field_type::value_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using fri_proof_marshalling_type =
                        typename fri_proof<TTypeBase, typename LPCScheme::basic_fri>::type;
                    using fri_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;

                    // typename merkle_tree_type::value_type T_root;
                    typename merkle_node_value<TTypeBase, typename LPCScheme::merkle_proof_type>::type filled_T_root =
                        fill_merkle_node_value<typename LPCScheme::merkle_proof_type, Endianness>(proof.T_root);

                    // std::vector<typename FieldType::value_type> z;
                    field_vector_marshalling_type filled_z;
                    for (const auto &c : proof.z) {
                        filled_z.value().push_back(field_marhsalling_type(c));
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    fri_proof_vector_marshalling_type filled_fri_proof;
                    for (const auto &p : proof.fri_proof) {
                        filled_fri_proof.value().push_back(
                            fill_fri_proof<typename LPCScheme::basic_fri, Endianness>(p));
                    }

                    return typename lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>::type(
                        std::make_tuple(filled_T_root, filled_z, filled_fri_proof));
                }

                template<typename LPCScheme,
                         typename Endianness,
                         typename std::enable_if<std::is_same<LPCScheme,
                                                              nil::crypto3::zk::commitments::list_polynomial_commitment<
                                                                  typename LPCScheme::field_type,
                                                                  typename LPCScheme::lpc_params>>::value,
                                                 bool>::type = true>
                typename LPCScheme::proof_type make_lpc_proof(
                    const typename lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>::type &filled_proof) {

                    typename LPCScheme::proof_type proof;

                    // typename merkle_tree_type::value_type T_root;
                    proof.T_root = make_merkle_node_value<typename LPCScheme::merkle_proof_type, Endianness>(
                        std::get<0>(filled_proof.value()));

                    // std::vector<typename FieldType::value_type> z;
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        proof.z.push_back(std::get<1>(filled_proof.value()).value().at(i).value());
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    BOOST_ASSERT(proof.fri_proof.size() == std::get<2>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        proof.fri_proof.at(i) = make_fri_proof<typename LPCScheme::basic_fri, Endianness>(
                            std::get<2>(filled_proof.value()).value().at(i));
                    }

                    return proof;
                }

                template<typename LPCScheme,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<LPCScheme,
                                          nil::crypto3::zk::commitments::batched_list_polynomial_commitment<
                                              typename LPCScheme::field_type,
                                              typename LPCScheme::lpc_params,
                                              LPCScheme::leaf_size,
                                              LPCScheme::is_run_time_size>>::value,
                             bool>::type = true>
                typename lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>::type
                    fill_lpc_proof(const typename LPCScheme::proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using uint64_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint64_t>;
                    using field_marhsalling_type = field_element<TTypeBase, typename LPCScheme::field_type::value_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using field_vector_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        field_vector_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using fri_proof_marshalling_type =
                        typename fri_proof<TTypeBase, typename LPCScheme::basic_fri>::type;
                    using fri_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;

                    // typename merkle_tree_type::value_type T_root;
                    typename merkle_node_value<TTypeBase, typename LPCScheme::merkle_proof_type>::type filled_T_root =
                        fill_merkle_node_value<typename LPCScheme::merkle_proof_type, Endianness>(proof.T_root);

                    // std::array<std::vector<typename FieldType::value_type>, leaf_size> z
                    field_vector_vector_marshalling_type filled_z;
                    for (const auto &z_i : proof.z) {
                        field_vector_marshalling_type filled_z_i;
                        for (const auto &c : z_i) {
                            filled_z_i.value().push_back(field_marhsalling_type(c));
                        }
                        filled_z.value().push_back(filled_z_i);
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    fri_proof_vector_marshalling_type filled_fri_proof;
                    for (const auto &p : proof.fri_proof) {
                        filled_fri_proof.value().push_back(
                            fill_fri_proof<typename LPCScheme::basic_fri, Endianness>(p));
                    }

                    return typename lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>::type(
                        std::make_tuple(filled_T_root, filled_z, filled_fri_proof));
                }

                template<typename LPCScheme,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<LPCScheme,
                                          nil::crypto3::zk::commitments::batched_list_polynomial_commitment<
                                              typename LPCScheme::field_type,
                                              typename LPCScheme::lpc_params,
                                              LPCScheme::leaf_size,
                                              false>>::value,
                             bool>::type = true>
                typename LPCScheme::proof_type make_lpc_proof(
                    const typename lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>::type &filled_proof) {

                    typename LPCScheme::proof_type proof;

                    // typename merkle_tree_type::value_type T_root;
                    proof.T_root = make_merkle_node_value<typename LPCScheme::merkle_proof_type, Endianness>(
                        std::get<0>(filled_proof.value()));

                    // std::array<std::vector<typename FieldType::value_type>, leaf_size> z
                    BOOST_ASSERT(proof.z.size() == std::get<1>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        for (std::size_t j = 0; j < std::get<1>(filled_proof.value()).value().at(i).value().size();
                             ++j) {
                            proof.z.at(i).push_back(
                                std::get<1>(filled_proof.value()).value().at(i).value().at(j).value());
                        }
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    BOOST_ASSERT(proof.fri_proof.size() == std::get<2>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        proof.fri_proof.at(i) = make_fri_proof<typename LPCScheme::basic_fri, Endianness>(
                            std::get<2>(filled_proof.value()).value().at(i));
                    }

                    return proof;
                }

                template<typename LPCScheme,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<LPCScheme,
                                          nil::crypto3::zk::commitments::batched_list_polynomial_commitment<
                                              typename LPCScheme::field_type,
                                              typename LPCScheme::lpc_params,
                                              0,
                                              true>>::value,
                             bool>::type = true>
                typename LPCScheme::proof_type make_lpc_proof(
                    const typename lpc_proof<nil::marshalling::field_type<Endianness>, LPCScheme>::type &filled_proof) {

                    typename LPCScheme::proof_type proof;

                    // typename merkle_tree_type::value_type T_root;
                    proof.T_root = make_merkle_node_value<typename LPCScheme::merkle_proof_type, Endianness>(
                        std::get<0>(filled_proof.value()));

                    // std::vector<std::vector<typename FieldType::value_type>> z
                    proof.z.resize(std::get<1>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        for (std::size_t j = 0; j < std::get<1>(filled_proof.value()).value().at(i).value().size();
                             ++j) {
                            proof.z.at(i).push_back(
                                std::get<1>(filled_proof.value()).value().at(i).value().at(j).value());
                        }
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    BOOST_ASSERT(proof.fri_proof.size() == std::get<2>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        proof.fri_proof.at(i) = make_fri_proof<typename LPCScheme::basic_fri, Endianness>(
                            std::get<2>(filled_proof.value()).value().at(i));
                    }

                    return proof;
                }

                template<typename LPCScheme,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<LPCScheme,
                                          nil::crypto3::zk::commitments::batched_list_polynomial_commitment<
                                              typename LPCScheme::field_type,
                                              typename LPCScheme::lpc_params,
                                              LPCScheme::leaf_size,
                                              LPCScheme::is_run_time_size>>::value,
                             bool>::type = true>
                typename lpc_proof_evm<nil::marshalling::field_type<Endianness>, LPCScheme>::type
                    fill_lpc_proof_evm(const typename LPCScheme::proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using uint64_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint64_t>;
                    using field_marhsalling_type = field_element<TTypeBase, typename LPCScheme::field_type::value_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using field_vector_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        field_vector_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using fri_proof_marshalling_type =
                        typename fri_proof<TTypeBase, typename LPCScheme::basic_fri>::type;
                    using fri_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        fri_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;

                    // typename merkle_tree_type::value_type T_root;
                    typename merkle_node_value<TTypeBase, typename LPCScheme::merkle_proof_type>::type filled_T_root =
                        fill_merkle_node_value<typename LPCScheme::merkle_proof_type, Endianness>(proof.T_root);

                    // std::array<std::vector<typename FieldType::value_type>, leaf_size> z
                    field_vector_vector_marshalling_type filled_z;
                    for (const auto &z_i : proof.z) {
                        field_vector_marshalling_type filled_z_i;
                        for (const auto &c : z_i) {
                            filled_z_i.value().push_back(field_marhsalling_type(c));
                        }
                        filled_z.value().push_back(filled_z_i);
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    fri_proof_vector_marshalling_type filled_fri_proof;
                    for (const auto &p : proof.fri_proof) {
                        filled_fri_proof.value().push_back(
                            fill_fri_proof_evm<typename LPCScheme::basic_fri, Endianness>(p));
                    }

                    return typename lpc_proof_evm<nil::marshalling::field_type<Endianness>, LPCScheme>::type(
                        std::make_tuple(filled_T_root, filled_z, filled_fri_proof));
                }

                template<typename LPCScheme,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<LPCScheme,
                                          nil::crypto3::zk::commitments::batched_list_polynomial_commitment<
                                              typename LPCScheme::field_type,
                                              typename LPCScheme::lpc_params,
                                              LPCScheme::leaf_size,
                                              false>>::value,
                             bool>::type = true>
                typename LPCScheme::proof_type
                    make_lpc_proof_evm(const typename lpc_proof_evm<nil::marshalling::field_type<Endianness>,
                                                                    LPCScheme>::type &filled_proof) {

                    typename LPCScheme::proof_type proof;

                    // typename merkle_tree_type::value_type T_root;
                    proof.T_root = make_merkle_node_value<typename LPCScheme::merkle_proof_type, Endianness>(
                        std::get<0>(filled_proof.value()));

                    // std::array<std::vector<typename FieldType::value_type>, leaf_size> z
                    BOOST_ASSERT(proof.z.size() == std::get<1>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        for (std::size_t j = 0; j < std::get<1>(filled_proof.value()).value().at(i).value().size();
                             ++j) {
                            proof.z.at(i).push_back(
                                std::get<1>(filled_proof.value()).value().at(i).value().at(j).value());
                        }
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    BOOST_ASSERT(proof.fri_proof.size() == std::get<2>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        proof.fri_proof.at(i) = make_fri_proof_evm<typename LPCScheme::basic_fri, Endianness>(
                            std::get<2>(filled_proof.value()).value().at(i));
                    }

                    return proof;
                }

                template<typename LPCScheme,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<LPCScheme,
                                          nil::crypto3::zk::commitments::batched_list_polynomial_commitment<
                                              typename LPCScheme::field_type,
                                              typename LPCScheme::lpc_params,
                                              0,
                                              true>>::value,
                             bool>::type = true>
                typename LPCScheme::proof_type
                    make_lpc_proof_evm(const typename lpc_proof_evm<nil::marshalling::field_type<Endianness>,
                                                                    LPCScheme>::type &filled_proof) {

                    typename LPCScheme::proof_type proof;

                    // typename merkle_tree_type::value_type T_root;
                    proof.T_root = make_merkle_node_value<typename LPCScheme::merkle_proof_type, Endianness>(
                        std::get<0>(filled_proof.value()));

                    // std::vector<std::vector<typename FieldType::value_type>> z
                    proof.z.resize(std::get<1>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        for (std::size_t j = 0; j < std::get<1>(filled_proof.value()).value().at(i).value().size();
                             ++j) {
                            proof.z.at(i).push_back(
                                std::get<1>(filled_proof.value()).value().at(i).value().at(j).value());
                        }
                    }

                    // std::array<typename fri_type::proof_type, lambda> fri_proof;
                    BOOST_ASSERT(proof.fri_proof.size() == std::get<2>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        proof.fri_proof.at(i) = make_fri_proof_evm<typename LPCScheme::basic_fri, Endianness>(
                            std::get<2>(filled_proof.value()).value().at(i));
                    }

                    return proof;
                }*/
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_LPC_COMMITMENT_HPP

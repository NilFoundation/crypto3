//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP
#define CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP

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

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/batched_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename FRIScheme, typename = void>
                struct fri_round_proof;

                template<typename TTypeBase, typename FRIScheme, typename = void>
                struct fri_proof;

                template<typename TTypeBase, typename FRIScheme>
                struct fri_round_proof<
                    TTypeBase, FRIScheme,
                    typename std::enable_if<std::is_same<
                        FRIScheme, nil::crypto3::zk::commitments::fri<
                                       typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                       typename FRIScheme::transcript_hash_type, FRIScheme::m>>::value>::type> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // typename FieldType::value_type colinear_value;
                            field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                            // typename merkle_tree_type::value_type T_root;
                            nil::marshalling::types::array_list<
                                TTypeBase, nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // std::array<typename FieldType::value_type, m> y;
                            nil::marshalling::types::array_list<
                                TTypeBase, field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // merkle_proof_type colinear_path;
                            merkle_proof<TTypeBase, typename FRIScheme::merkle_proof_type>,
                            // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                            // std::array<merkle_proof_type, m> p;
                            nil::marshalling::types::array_list<
                                TTypeBase, merkle_proof<TTypeBase, typename FRIScheme::merkle_proof_type>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>>>;
                };

                template<typename TTypeBase, typename FRIScheme>
                struct fri_proof<
                    TTypeBase, FRIScheme,
                    typename std::enable_if<std::is_same<
                        FRIScheme, nil::crypto3::zk::commitments::fri<
                                       typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                       typename FRIScheme::transcript_hash_type, FRIScheme::m>>::value>::type> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // math::polynomial<typename FieldType::value_type> final_polynomial;
                            nil::marshalling::types::array_list<
                                TTypeBase, field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // std::vector<round_proof_type> round_proofs;    // 0..r-2
                            nil::marshalling::types::array_list<
                                TTypeBase, typename fri_round_proof<TTypeBase, FRIScheme>::type,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>>>;
                };

                template<typename TTypeBase, typename FRIScheme>
                struct fri_round_proof<
                    TTypeBase, FRIScheme,
                    typename std::enable_if<std::is_same<
                        FRIScheme, nil::crypto3::zk::commitments::batched_fri<
                                       typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                       typename FRIScheme::transcript_hash_type, FRIScheme::m,
                                       FRIScheme::leaf_size>>::value>::type> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // std::array<typename FieldType::value_type, leaf_size> colinear_value
                            // TODO: use nil::marshalling::option::fixed_size_storage with std::array
                            nil::marshalling::types::array_list<
                                TTypeBase, field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // typename merkle_tree_type::value_type T_root
                            nil::marshalling::types::array_list<
                                TTypeBase, nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // std::array<std::array<typename FieldType::value_type, m>, leaf_size> y
                            // TODO: use nil::marshalling::option::fixed_size_storage with std::array
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::array_list<
                                    TTypeBase, field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                                    nil::marshalling::option::sequence_size_field_prefix<
                                        nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // merkle_proof_type colinear_path
                            merkle_proof<TTypeBase, typename FRIScheme::merkle_proof_type>,
                            // std::array<merkle_proof_type, m> p
                            nil::marshalling::types::array_list<
                                TTypeBase, merkle_proof<TTypeBase, typename FRIScheme::merkle_proof_type>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>>>;
                };

                template<typename TTypeBase, typename FRIScheme>
                struct fri_proof<
                    TTypeBase, FRIScheme,
                    typename std::enable_if<std::is_same<
                        FRIScheme, nil::crypto3::zk::commitments::batched_fri<
                                       typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                       typename FRIScheme::transcript_hash_type, FRIScheme::m,
                                       FRIScheme::leaf_size>>::value>::type> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // std::array<math::polynomial<typename FieldType::value_type>, leaf_size>
                            // TODO: use nil::marshalling::option::fixed_size_storage with std::array
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                nil::marshalling::types::array_list<
                                    TTypeBase, field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                                    nil::marshalling::option::sequence_size_field_prefix<
                                        nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>,
                            // std::vector<round_proof_type> round_proofs
                            nil::marshalling::types::array_list<
                                TTypeBase, typename fri_round_proof<TTypeBase, FRIScheme>::type,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>>>;
                };

                template<typename FRIScheme, typename Endianness,
                         typename std::enable_if<
                             std::is_same<FRIScheme,
                                          nil::crypto3::zk::commitments::fri<
                                              typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                              typename FRIScheme::transcript_hash_type, FRIScheme::m>>::value,
                             bool>::type = true>
                typename fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type
                    fill_fri_round_proof(const typename FRIScheme::round_proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using uint64_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint64_t>;
                    using octet_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint8_t>;
                    using digest_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, octet_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using merkle_proof_marshalling_type =
                        merkle_proof<TTypeBase, typename FRIScheme::merkle_proof_type>;
                    using merkle_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, merkle_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using field_marhsalling_type = field_element<TTypeBase, typename FRIScheme::field_type::value_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using field_poly_marshalling_type = field_vector_marshalling_type;

                    // typename FieldType::value_type colinear_value;
                    field_marhsalling_type filled_colinear_value(proof.colinear_value);

                    // typename merkle_tree_type::value_type T_root;
                    digest_marshalling_type filled_T_root;
                    for (const auto c : proof.T_root) {
                        filled_T_root.value().push_back(octet_marshalling_type(c));
                    }

                    // std::array<typename FieldType::value_type, m> y;
                    field_vector_marshalling_type filled_y;
                    for (const auto &c : proof.y) {
                        filled_y.value().push_back(field_marhsalling_type(c));
                    }

                    // merkle_proof_type colinear_path;
                    merkle_proof_marshalling_type filled_colinear_path =
                        fill_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(proof.colinear_path);

                    // std::array<merkle_proof_type, m> p;
                    merkle_proof_vector_marshalling_type filled_p;
                    for (const auto &mp : proof.p) {
                        filled_p.value().push_back(
                            fill_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(mp));
                    }

                    return typename fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type(
                        std::make_tuple(filled_colinear_value, filled_T_root, filled_y, filled_colinear_path,
                                        filled_p));
                }

                template<typename FRIScheme, typename Endianness,
                         typename std::enable_if<
                             std::is_same<FRIScheme,
                                          nil::crypto3::zk::commitments::fri<
                                              typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                              typename FRIScheme::transcript_hash_type, FRIScheme::m>>::value,
                             bool>::type = true>
                typename FRIScheme::round_proof_type
                    make_fri_round_proof(const typename fri_round_proof<nil::marshalling::field_type<Endianness>,
                                                                        FRIScheme>::type &filled_proof) {

                    typename FRIScheme::round_proof_type proof;

                    // typename FieldType::value_type colinear_value;
                    proof.colinear_value = std::get<0>(filled_proof.value()).value();

                    // typename merkle_tree_type::value_type T_root;
                    BOOST_ASSERT(proof.T_root.size() == std::get<1>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        proof.T_root.at(i) = std::get<1>(filled_proof.value()).value().at(i).value();
                    }

                    // std::array<typename FieldType::value_type, m> y;
                    BOOST_ASSERT(proof.y.size() == std::get<2>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        proof.y.at(i) = std::get<2>(filled_proof.value()).value().at(i).value();
                    }

                    // merkle_proof_type colinear_path;
                    proof.colinear_path = make_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(
                        std::get<3>(filled_proof.value()));

                    // std::array<merkle_proof_type, m> p;
                    BOOST_ASSERT(proof.p.size() == std::get<4>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<4>(filled_proof.value()).value().size(); ++i) {
                        proof.p.at(i) = make_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(
                            std::get<4>(filled_proof.value()).value().at(i));
                    }

                    return proof;
                }

                template<typename FRIScheme, typename Endianness,
                         typename std::enable_if<
                             std::is_same<FRIScheme,
                                          nil::crypto3::zk::commitments::fri<
                                              typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                              typename FRIScheme::transcript_hash_type, FRIScheme::m>>::value,
                             bool>::type = true>
                typename fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type
                    fill_fri_proof(const typename FRIScheme::proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using uint64_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint64_t>;
                    using field_marhsalling_type = field_element<TTypeBase, typename FRIScheme::field_type::value_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using field_poly_marshalling_type = field_vector_marshalling_type;
                    using fri_round_proof_marshalling_type =
                        typename fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type;
                    using fri_round_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, fri_round_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;

                    // math::polynomial<typename FieldType::value_type> final_polynomial;
                    field_poly_marshalling_type filled_final_polynomial;
                    for (const auto &c : proof.final_polynomial) {
                        filled_final_polynomial.value().push_back(field_marhsalling_type(c));
                    }

                    // std::vector<round_proof_type> round_proofs;
                    fri_round_proof_vector_marshalling_type filled_round_proofs;
                    for (const auto &c : proof.round_proofs) {
                        filled_round_proofs.value().push_back(fill_fri_round_proof<FRIScheme, Endianness>(c));
                    }

                    return typename fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type(
                        std::make_tuple(filled_final_polynomial, filled_round_proofs));
                }

                template<typename FRIScheme, typename Endianness,
                         typename std::enable_if<
                             std::is_same<FRIScheme,
                                          nil::crypto3::zk::commitments::fri<
                                              typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                              typename FRIScheme::transcript_hash_type, FRIScheme::m>>::value,
                             bool>::type = true>
                typename FRIScheme::proof_type make_fri_proof(
                    const typename fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type &filled_proof) {

                    // math::polynomial<typename FieldType::value_type> final_polynomial;
                    std::vector<typename FRIScheme::field_type::value_type> final_polynomial;
                    for (std::size_t i = 0; i < std::get<0>(filled_proof.value()).value().size(); ++i) {
                        final_polynomial.emplace_back(std::get<0>(filled_proof.value()).value().at(i).value());
                    }

                    // std::vector<round_proof_type> round_proofs;
                    std::vector<typename FRIScheme::round_proof_type> round_proofs;
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        round_proofs.emplace_back(make_fri_round_proof<FRIScheme, Endianness>(
                            std::get<1>(filled_proof.value()).value().at(i)));
                    }

                    return typename FRIScheme::proof_type {
                        round_proofs,
                        nil::crypto3::math::polynomial<typename FRIScheme::field_type::value_type>(final_polynomial)};
                }

                template<
                    typename FRIScheme, typename Endianness,
                    typename std::enable_if<std::is_same<FRIScheme, nil::crypto3::zk::commitments::batched_fri<
                                                                        typename FRIScheme::field_type,
                                                                        typename FRIScheme::merkle_tree_hash_type,
                                                                        typename FRIScheme::transcript_hash_type,
                                                                        FRIScheme::m, FRIScheme::leaf_size>>::value,
                                            bool>::type = true>
                typename fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type
                    fill_fri_round_proof(const typename FRIScheme::round_proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using uint64_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint64_t>;
                    using octet_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint8_t>;
                    using digest_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, octet_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using merkle_proof_marshalling_type =
                        merkle_proof<TTypeBase, typename FRIScheme::merkle_proof_type>;
                    using merkle_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, merkle_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using field_marhsalling_type = field_element<TTypeBase, typename FRIScheme::field_type::value_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using field_vector_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, field_vector_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using field_poly_marshalling_type = field_vector_marshalling_type;

                    // std::array<typename FieldType::value_type, leaf_size> colinear_value;
                    field_vector_marshalling_type filled_colinear_value;
                    for (const auto &c : proof.colinear_value) {
                        filled_colinear_value.value().push_back(field_marhsalling_type(c));
                    }

                    // typename merkle_tree_type::value_type T_root;
                    digest_marshalling_type filled_T_root;
                    for (const auto c : proof.T_root) {
                        filled_T_root.value().push_back(octet_marshalling_type(c));
                    }

                    // std::array<std::array<typename FieldType::value_type, m>, leaf_size> y;
                    field_vector_vector_marshalling_type filled_y;
                    for (const auto &y_i : proof.y) {
                        field_vector_marshalling_type filled_y_i;
                        for (const auto &c : y_i) {
                            filled_y_i.value().push_back(field_marhsalling_type(c));
                        }
                        filled_y.value().push_back(filled_y_i);
                    }

                    // merkle_proof_type colinear_path;
                    merkle_proof_marshalling_type filled_colinear_path =
                        fill_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(proof.colinear_path);

                    // std::array<merkle_proof_type, m> p;
                    merkle_proof_vector_marshalling_type filled_p;
                    for (const auto &mp : proof.p) {
                        filled_p.value().push_back(
                            fill_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(mp));
                    }

                    return typename fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type(
                        std::make_tuple(filled_colinear_value, filled_T_root, filled_y, filled_colinear_path,
                                        filled_p));
                }

                template<
                    typename FRIScheme, typename Endianness,
                    typename std::enable_if<std::is_same<FRIScheme, nil::crypto3::zk::commitments::batched_fri<
                                                                        typename FRIScheme::field_type,
                                                                        typename FRIScheme::merkle_tree_hash_type,
                                                                        typename FRIScheme::transcript_hash_type,
                                                                        FRIScheme::m, FRIScheme::leaf_size>>::value,
                                            bool>::type = true>
                typename FRIScheme::round_proof_type
                    make_fri_round_proof(const typename fri_round_proof<nil::marshalling::field_type<Endianness>,
                                                                        FRIScheme>::type &filled_proof) {

                    typename FRIScheme::round_proof_type proof;

                    // std::array<typename FieldType::value_type, leaf_size> colinear_value;
                    BOOST_ASSERT(proof.colinear_value.size() == std::get<0>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<0>(filled_proof.value()).value().size(); ++i) {
                        proof.colinear_value.at(i) = std::get<0>(filled_proof.value()).value().at(i).value();
                    }

                    // typename merkle_tree_type::value_type T_root;
                    BOOST_ASSERT(proof.T_root.size() == std::get<1>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        proof.T_root.at(i) = std::get<1>(filled_proof.value()).value().at(i).value();
                    }

                    // std::array<std::array<typename FieldType::value_type, m>, leaf_size> y;
                    BOOST_ASSERT(proof.y.size() == std::get<2>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        BOOST_ASSERT(proof.y.at(i).size() ==
                                     std::get<2>(filled_proof.value()).value().at(i).value().size());
                        for (std::size_t j = 0; j < std::get<2>(filled_proof.value()).value().at(i).value().size();
                             ++j) {
                            proof.y.at(i).at(j) = std::get<2>(filled_proof.value()).value().at(i).value().at(j).value();
                        }
                    }

                    // merkle_proof_type colinear_path;
                    proof.colinear_path = make_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(
                        std::get<3>(filled_proof.value()));

                    // std::array<merkle_proof_type, m> p;
                    BOOST_ASSERT(proof.p.size() == std::get<4>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<4>(filled_proof.value()).value().size(); ++i) {
                        proof.p.at(i) = make_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(
                            std::get<4>(filled_proof.value()).value().at(i));
                    }

                    return proof;
                }

                template<
                    typename FRIScheme, typename Endianness,
                    typename std::enable_if<std::is_same<FRIScheme, nil::crypto3::zk::commitments::batched_fri<
                                                                        typename FRIScheme::field_type,
                                                                        typename FRIScheme::merkle_tree_hash_type,
                                                                        typename FRIScheme::transcript_hash_type,
                                                                        FRIScheme::m, FRIScheme::leaf_size>>::value,
                                            bool>::type = true>
                typename fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type
                    fill_fri_proof(const typename FRIScheme::proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using uint64_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint64_t>;
                    using field_marhsalling_type = field_element<TTypeBase, typename FRIScheme::field_type::value_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using field_poly_marshalling_type = field_vector_marshalling_type;
                    using field_poly_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, field_poly_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;
                    using fri_round_proof_marshalling_type =
                        typename fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type;
                    using fri_round_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, fri_round_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<uint64_t_marshalling_type>>;

                    // std::array<math::polynomial<typename FieldType::value_type>, leaf_size> final_polynomial
                    field_poly_vector_marshalling_type filled_final_polynomial;
                    for (const auto &poly : proof.final_polynomial) {
                        field_poly_marshalling_type filled_poly;
                        for (const auto &c : poly) {
                            filled_poly.value().push_back(field_marhsalling_type(c));
                        }
                        filled_final_polynomial.value().push_back(filled_poly);
                    }

                    // std::vector<round_proof_type> round_proofs;
                    fri_round_proof_vector_marshalling_type filled_round_proofs;
                    for (const auto &c : proof.round_proofs) {
                        filled_round_proofs.value().push_back(fill_fri_round_proof<FRIScheme, Endianness>(c));
                    }

                    return typename fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type(
                        std::make_tuple(filled_final_polynomial, filled_round_proofs));
                }

                template<
                    typename FRIScheme, typename Endianness,
                    typename std::enable_if<std::is_same<FRIScheme, nil::crypto3::zk::commitments::batched_fri<
                                                                        typename FRIScheme::field_type,
                                                                        typename FRIScheme::merkle_tree_hash_type,
                                                                        typename FRIScheme::transcript_hash_type,
                                                                        FRIScheme::m, FRIScheme::leaf_size>>::value,
                                            bool>::type = true>
                typename FRIScheme::proof_type make_fri_proof(
                    const typename fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme>::type &filled_proof) {

                    typename FRIScheme::proof_type proof;

                    // std::array<math::polynomial<typename FieldType::value_type>, leaf_size> final_polynomial;
                    for (std::size_t i = 0; i < std::get<0>(filled_proof.value()).value().size(); ++i) {
                        for (std::size_t j = 0; j < std::get<0>(filled_proof.value()).value().at(i).value().size();
                             ++j) {
                            proof.final_polynomial.at(i).emplace_back(
                                std::get<0>(filled_proof.value()).value().at(i).value().at(j).value());
                        }
                    }

                    // std::vector<round_proof_type> round_proofs;
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        proof.round_proofs.emplace_back(make_fri_round_proof<FRIScheme, Endianness>(
                            std::get<1>(filled_proof.value()).value().at(i)));
                    }

                    return proof;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename FRIScheme,
                         typename = typename std::enable_if<
                             std::is_same<FRIScheme,
                                          nil::crypto3::zk::commitments::fri<
                                              typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                              typename FRIScheme::transcript_hash_type, FRIScheme::m>>::value,
                             bool>::type,
                         typename... TOptions>
                using fri_round_proof = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                                   // typename FieldType::value_type colinear_value;
                                   field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                                   // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                                   // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                                   // typename merkle_tree_type::value_type T_root;
                                   nil::marshalling::types::array_list<
                                       TTypeBase, nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                       nil::marshalling::option::sequence_size_field_prefix<
                                           nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                                   // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                                   // std::array<typename FieldType::value_type, m> y;
                                   nil::marshalling::types::array_list<
                                       TTypeBase, field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                                       nil::marshalling::option::sequence_size_field_prefix<
                                           nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                                   // merkle_proof_type colinear_path;
                                   merkle_proof<TTypeBase, typename FRIScheme::merkle_proof_type>,
                                   // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                                   // std::array<merkle_proof_type, m> p;
                                   nil::marshalling::types::array_list<
                                       TTypeBase, merkle_proof<TTypeBase, typename FRIScheme::merkle_proof_type>,
                                       nil::marshalling::option::sequence_size_field_prefix<
                                           nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename TTypeBase, typename FRIScheme,
                         typename = typename std::enable_if<
                             std::is_same<FRIScheme,
                                          nil::crypto3::zk::commitments::fri<
                                              typename FRIScheme::field_type, typename FRIScheme::merkle_tree_hash_type,
                                              typename FRIScheme::transcript_hash_type, FRIScheme::m>>::value,
                             bool>::type,
                         typename... TOptions>
                using fri_proof = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                                   // math::polynomial<typename FieldType::value_type> final_polynomial;
                                   nil::marshalling::types::array_list<
                                       TTypeBase, field_element<TTypeBase, typename FRIScheme::field_type::value_type>,
                                       nil::marshalling::option::sequence_size_field_prefix<
                                           nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                                   // std::vector<round_proof_type> round_proofs;    // 0..r-2
                                   nil::marshalling::types::array_list<
                                       TTypeBase, fri_round_proof<TTypeBase, FRIScheme>,
                                       nil::marshalling::option::sequence_size_field_prefix<
                                           nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                //                template<typename TTypeBase, typename FRIScheme,
                //                         typename = typename std::enable_if<
                //                             std::is_same<FRIScheme,
                //                                          nil::crypto3::zk::snark::fri_commitment_scheme<
                //                                              typename FRIScheme::field_type, typename
                //                                              FRIScheme::merkle_tree_hash_type, typename
                //                                              FRIScheme::transcript_hash_type, FRIScheme::m>>::value,
                //                             bool>::type,
                //                         typename... TOptions>
                //                using fri_params = nil::marshalling::types::bundle<
                //                    TTypeBase, std::tuple<
                //                                   // std::size_t r;
                //                                   nil::marshalling::types::integral<TTypeBase, std::size_t>,
                //                                   // std::size_t max_degree;
                //                                   nil::marshalling::types::integral<TTypeBase, std::size_t>,
                //                                   // math::polynomial<typename FieldType::value_type> q;
                //                                   nil::marshalling::types::array_list<
                //                                       TTypeBase, field_element<TTypeBase, typename
                //                                       FRIScheme::field_type::value_type>,
                //                                       nil::marshalling::option::sequence_size_field_prefix<
                //                                           nil::marshalling::types::integral<TTypeBase,
                //                                           std::size_t>>>,
                //                                   // std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>>
                //                                   D;
                //                                   // basic_radix2_domain by default, vectors of omegas will be
                //                                   nil::marshalling::types::array_list<
                //                                       TTypeBase, field_element<TTypeBase, typename
                //                                       FRIScheme::field_type::value_type>,
                //                                       nil::marshalling::option::sequence_size_field_prefix<
                //                                           nil::marshalling::types::integral<TTypeBase,
                //                                           std::size_t>>>>>;

                template<typename FRIScheme, typename Endianness>
                fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>
                    fill_fri_round_proof(const typename FRIScheme::round_proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using octet_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint8_t>;
                    using digest_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, octet_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using merkle_proof_marshalling_type =
                        merkle_proof<TTypeBase, typename FRIScheme::merkle_proof_type>;
                    using merkle_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, merkle_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using field_marhsalling_type = field_element<TTypeBase, typename FRIScheme::field_type::value_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
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

                    return fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>(std::make_tuple(
                        filled_colinear_value, filled_T_root, filled_y, filled_colinear_path, filled_p));
                }

                template<typename FRIScheme, typename Endianness>
                typename FRIScheme::round_proof_type make_fri_round_proof(
                    const fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme> &filled_proof) {

                    typename FRIScheme::round_proof_type proof;

                    // typename FieldType::value_type colinear_value;
                    proof.colinear_value = std::get<0>(filled_proof.value()).value();

                    // typename merkle_tree_type::value_type T_root;
                    assert(proof.T_root.size() == std::get<1>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<1>(filled_proof.value()).value().size(); ++i) {
                        proof.T_root.at(i) = std::get<1>(filled_proof.value()).value().at(i).value();
                    }

                    // std::array<typename FieldType::value_type, m> y;
                    assert(proof.y.size() == std::get<2>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<2>(filled_proof.value()).value().size(); ++i) {
                        proof.y.at(i) = std::get<2>(filled_proof.value()).value().at(i).value();
                    }

                    // merkle_proof_type colinear_path;
                    proof.colinear_path = make_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(
                        std::get<3>(filled_proof.value()));

                    // std::array<merkle_proof_type, m> p;
                    assert(proof.p.size() == std::get<4>(filled_proof.value()).value().size());
                    for (std::size_t i = 0; i < std::get<4>(filled_proof.value()).value().size(); ++i) {
                        proof.p.at(i) = make_merkle_proof<typename FRIScheme::merkle_proof_type, Endianness>(
                            std::get<4>(filled_proof.value()).value().at(i));
                    }

                    return proof;
                }

                template<typename FRIScheme, typename Endianness>
                fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme>
                    fill_fri_proof(const typename FRIScheme::proof_type &proof) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using field_marhsalling_type = field_element<TTypeBase,
                        typename FRIScheme::field_type::value_type>;
                    using field_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, field_marhsalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using field_poly_marshalling_type = field_vector_marshalling_type;
                    using fri_round_proof_marshalling_type =
                        fri_round_proof<nil::marshalling::field_type<Endianness>, FRIScheme>;
                    using fri_round_proof_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, fri_round_proof_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;

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

                    return fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme>(
                        std::make_tuple(filled_final_polynomial, filled_round_proofs));
                }

                template<typename FRIScheme, typename Endianness>
                typename FRIScheme::proof_type
                    make_fri_proof(const fri_proof<nil::marshalling::field_type<Endianness>, FRIScheme> &filled_proof) {

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

                    return typename FRIScheme::proof_type {round_proofs, final_polynomial};
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FRI_COMMITMENT_HPP

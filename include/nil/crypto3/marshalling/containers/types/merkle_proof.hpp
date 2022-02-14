//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_MERKLE_PROOF_HPP
#define CRYPTO3_MARSHALLING_MERKLE_PROOF_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/field_type.hpp>

#include <nil/crypto3/merkle/tree.hpp>
#include <nil/crypto3/merkle/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase,
                         typename MerkleProof,
                         typename = typename std::enable_if<
                             std::is_same<MerkleProof,
                                          nil::crypto3::containers::merkle_proof<typename MerkleProof::hash_type,
                                                                                 MerkleProof::arity>>::value,
                             bool>::type,
                         typename... TOptions>
                using merkle_proof = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // leaf_index
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
                        // TODO: use nil::marshalling::option::fixed_size_storage with hash_type::digest_size
                        // TODO: review std::uint8_t type usage (for example, pedersen outputs array of bits)
                        // root
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                        // path
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            // layer path
                            nil::marshalling::types::array_list<
                                TTypeBase,
                                // path_element_t
                                nil::marshalling::types::bundle<
                                    TTypeBase,
                                    std::tuple<
                                        // position
                                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
                                        // TODO: use nil::marshalling::option::fixed_size_storage with
                                        //  hash_type::digest_size
                                        // TODO: review std::uint8_t type usage
                                        // hash
                                        nil::marshalling::types::array_list<
                                            TTypeBase,
                                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                                            nil::marshalling::option::sequence_size_field_prefix<
                                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>,
                                // TODO: use nil::marshalling::option::fixed_size_storage<MerkleProof::arity - 1>
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename MerkleProof,
                         typename = typename std::enable_if<
                             std::is_same<MerkleProof,
                                          nil::crypto3::containers::merkle_proof<typename MerkleProof::hash_type,
                                                                                 MerkleProof::arity>>::value>::type>
                struct merkle_proof_marshalling {
                    static void set_leaf_index(MerkleProof &mp, const std::size_t li) {
                        mp._li = li;
                    }

                    static void set_root(MerkleProof &mp, const typename MerkleProof::value_type &root) {
                        mp._root = root;
                    }

                    static void set_layer_element_hash(typename MerkleProof::path_element_type &element,
                                                       const typename MerkleProof::value_type &element_hash) {
                        element._hash = element_hash;
                    }

                    static void set_layer_element_position(typename MerkleProof::path_element_type &element,
                                                           std::size_t position) {
                        element._position = position;
                    }

                    static void append_path(MerkleProof &mp,
                                            const typename MerkleProof::path_type::value_type &path_layer) {
                        mp._path.emplace_back(path_layer);
                    }
                };

                template<typename MerkleProof, typename Endianness>
                merkle_proof<nil::marshalling::field_type<Endianness>, MerkleProof>
                    fill_merkle_proof(const MerkleProof &mp) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using octet_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint8_t>;
                    using digest_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        octet_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using layer_element_marshalling_type =
                        nil::marshalling::types::bundle<TTypeBase,
                                                        std::tuple<
                                                            // position
                                                            size_t_marshalling_type,
                                                            // hash
                                                            digest_marshalling_type>>;
                    using layer_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        layer_element_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using path_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        layer_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;

                    digest_marshalling_type filled_root;
                    auto &filled_root_val = filled_root.value();
                    for (const auto c : mp.root()) {
                        filled_root_val.push_back(octet_marshalling_type(c));
                    }

                    path_marshalling_type filled_path;
                    for (const auto &layer : mp.path()) {
                        layer_marshalling_type filled_layer;
                        for (const auto &el : layer) {
                            digest_marshalling_type filled_layer_element_hash;
                            for (const auto c : el.hash()) {
                                filled_layer_element_hash.value().push_back(octet_marshalling_type(c));
                            }
                            filled_layer.value().push_back(layer_element_marshalling_type(
                                std::make_tuple(size_t_marshalling_type(el.position()), filled_layer_element_hash)));
                        }
                        filled_path.value().push_back(filled_layer);
                    }

                    return merkle_proof<nil::marshalling::field_type<Endianness>, MerkleProof>(
                        std::make_tuple(size_t_marshalling_type(mp.leaf_index()), filled_root, filled_path));
                }

                template<typename MerkleProof, typename Endianness>
                MerkleProof make_merkle_proof(
                    const merkle_proof<nil::marshalling::field_type<Endianness>, MerkleProof> &filled_merkle_proof) {

                    MerkleProof mp;
                    merkle_proof_marshalling<MerkleProof>::set_leaf_index(
                        mp, std::get<0>(filled_merkle_proof.value()).value());

                    typename MerkleProof::value_type root;
                    // TODO: fix for the case of non-static container
                    for (std::size_t i = 0; i < root.size(); ++i) {
                        root.at(i) = std::get<1>(filled_merkle_proof.value()).value().at(i).value();
                    }
                    merkle_proof_marshalling<MerkleProof>::set_root(mp, root);

                    for (const auto &filled_layer : std::get<2>(filled_merkle_proof.value()).value()) {
                        typename MerkleProof::path_type::value_type path_layer;
                        for (std::size_t i = 0; i < path_layer.size(); ++i) {
                            typename MerkleProof::path_element_type layer_element;
                            typename MerkleProof::value_type element_hash;
                            // TODO: fix for the case of non-static container
                            for (std::size_t j = 0; j < element_hash.size(); ++j) {
                                element_hash.at(j) =
                                    std::get<1>(filled_layer.value().at(i).value()).value().at(j).value();
                            }
                            merkle_proof_marshalling<MerkleProof>::set_layer_element_hash(layer_element, element_hash);
                            merkle_proof_marshalling<MerkleProof>::set_layer_element_position(
                                layer_element, std::get<0>(filled_layer.value().at(i).value()).value());
                            path_layer.at(i) = layer_element;
                        }
                        merkle_proof_marshalling<MerkleProof>::append_path(mp, path_layer);
                    }

                    return mp;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_MERKLE_PROOF_HPP

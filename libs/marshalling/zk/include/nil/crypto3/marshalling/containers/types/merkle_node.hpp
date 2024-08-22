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

#ifndef CRYPTO3_MARSHALLING_MERKLE_NODE_HPP
#define CRYPTO3_MARSHALLING_MERKLE_NODE_HPP

#include <ratio>
#include <limits>
#include <type_traits>
#include <iterator>

#include <nil/crypto3/algebra/type_traits.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/field_type.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename T, typename = void>
                struct merkle_node_value;

                // For sha and similar hashes merkle tree node will contain a byte array.
                template<typename TTypeBase, typename ValueType>
                struct merkle_node_value<
                    TTypeBase,
                    ValueType,
                    typename std::enable_if<std::is_same<
                        std::uint8_t,
                        typename std::iterator_traits<typename ValueType::iterator>::value_type>::value>::type> {
                    using type = nil::marshalling::types::array_list<
                        TTypeBase,
                        nil::marshalling::types::integral<TTypeBase, std::uint8_t>,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<TTypeBase, std::uint64_t>>>;
                };

                // For Poseidon, Merkle node will contain a Group Element, not a vector of bytes.
                template<typename TTypeBase, typename GroupElementType>
                struct merkle_node_value<
                    TTypeBase,
                    GroupElementType,
                    typename std::enable_if<nil::crypto3::algebra::is_field_element<
                        GroupElementType
                    >::value>::type
                > {
                    using type = field_element<TTypeBase, GroupElementType>;
                };

                template<typename TTypeBase, typename MerkleProof>
                struct merkle_node_value<
                    TTypeBase,
                    MerkleProof,
                    typename std::enable_if<
                        std::is_same<MerkleProof,
                                     nil::crypto3::containers::merkle_proof<typename MerkleProof::hash_type,
                                                                            MerkleProof::arity>>::value>::type> {
                    using type = typename merkle_node_value<TTypeBase, typename MerkleProof::value_type>::type;
                };

                template<typename TTypeBase, typename MerkleTree>
                struct merkle_node_value<TTypeBase,
                                         MerkleTree,
                                         typename std::enable_if<std::is_same<
                                             MerkleTree,
                                             nil::crypto3::containers::merkle_tree<typename MerkleTree::hash_type,
                                                                                   MerkleTree::arity>>::value>::type> {
                    using type = typename merkle_node_value<TTypeBase, typename MerkleTree::value_type>::type;
                };

                template<
                    typename ValueType,
                    typename Endianness,
                    typename std::enable_if<
                        std::is_same<std::uint8_t,
                                     typename std::iterator_traits<typename ValueType::iterator>::value_type>::value,
                        bool>::type = true>
                typename merkle_node_value<nil::marshalling::field_type<Endianness>, ValueType>::type
                    fill_merkle_node_value(const ValueType &node_value) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using octet_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint8_t>;

                    typename merkle_node_value<nil::marshalling::field_type<Endianness>, ValueType>::type
                        filled_node_value;
                    for (const auto c : node_value) {
                        filled_node_value.value().push_back(octet_marshalling_type(c));
                    }
                    return filled_node_value;
                }

                template<
                    typename GroupElementType,
                    typename Endianness,
                    typename std::enable_if<nil::crypto3::algebra::is_field_element<
                        GroupElementType
                    >::value, bool>::type = true>
                typename merkle_node_value<
                    nil::marshalling::field_type<Endianness>,
                    GroupElementType
                >::type
                    fill_merkle_node_value(const GroupElementType &node_value) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    typename merkle_node_value<nil::marshalling::field_type<Endianness>, GroupElementType>::type filled_node_value =
                        field_element<TTypeBase, GroupElementType>(node_value);
                    return filled_node_value;
                }

                template<typename MerkleProof,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<
                                MerkleProof,
                                nil::crypto3::containers::merkle_proof<typename MerkleProof::hash_type,
                                                                       MerkleProof::arity>>::value,
                             bool>::type = true>
                typename merkle_node_value<nil::marshalling::field_type<Endianness>, MerkleProof>::type
                    fill_merkle_node_value(const typename MerkleProof::value_type &node_value) {
                    return fill_merkle_node_value<typename MerkleProof::value_type, Endianness>(node_value);
                }

                template<typename MerkleTree,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<
                                MerkleTree,
                                nil::crypto3::containers::merkle_tree<typename MerkleTree::hash_type,
                                                                      MerkleTree::arity>>::value,
                             bool>::type = true>
                typename merkle_node_value<nil::marshalling::field_type<Endianness>, MerkleTree>::type
                    fill_merkle_node_value(const typename MerkleTree::value_type &node_value) {
                    return fill_merkle_node_value<typename MerkleTree::value_type, Endianness>(node_value);
                }

                template<
                    typename ValueType,
                    typename Endianness,
                    typename std::enable_if<
                        std::is_same<std::uint8_t,
                                     typename std::iterator_traits<typename ValueType::iterator>::value_type>::value,
                        bool>::type = true>
                ValueType
                    make_merkle_node_value(const typename merkle_node_value<nil::marshalling::field_type<Endianness>,
                                                                            ValueType>::type &filled_node_value) {
                    ValueType node_value;
                    BOOST_ASSERT(node_value.size() == filled_node_value.value().size());
                    for (std::size_t i = 0; i < filled_node_value.value().size(); ++i) {
                        node_value.at(i) = filled_node_value.value().at(i).value();
                    }
                    return node_value;
                }

                template<
                    typename GroupElementType,
                    typename Endianness,
                    typename std::enable_if<nil::crypto3::algebra::is_field_element<
                        GroupElementType
                    >::value, bool>::type = true>
                GroupElementType make_merkle_node_value(const typename merkle_node_value<
                    nil::marshalling::field_type<Endianness>, GroupElementType>::type &filled_node_value) {
                    return filled_node_value.value();
                }

                template<typename MerkleProof,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<MerkleProof,
                                          nil::crypto3::containers::merkle_proof<typename MerkleProof::hash_type,
                                                                                 MerkleProof::arity>>::value,
                             bool>::type = true>
                typename MerkleProof::value_type
                    make_merkle_node_value(const typename merkle_node_value<nil::marshalling::field_type<Endianness>,
                                                                            MerkleProof>::type &filled_node_value) {
                    return make_merkle_node_value<typename MerkleProof::value_type, Endianness>(filled_node_value);
                }
                template<typename MerkleTree,
                         typename Endianness,
                         typename std::enable_if<
                             std::is_same<
                                MerkleTree,
                                nil::crypto3::containers::merkle_tree<typename MerkleTree::hash_type,
                                                                      MerkleTree::arity>>::value,
                             bool>::type = true>
                typename MerkleTree::value_type
                    make_merkle_node_value(const typename merkle_node_value<nil::marshalling::field_type<Endianness>,
                                                                            MerkleTree>::type &filled_node_value) {
                    return make_merkle_node_value<typename MerkleTree::value_type, Endianness>(filled_node_value);
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_MERKLE_NODE_HPP

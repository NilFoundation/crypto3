//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_MERKLE_TREE_HPP
#define CRYPTO3_MARSHALLING_MERKLE_TREE_HPP

#include <ratio>
#include <limits>
#include <type_traits>
#include <iterator>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/containers/types/merkle_node.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/marshalling/field_type.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename MerkleTree>
                using merkle_tree = nil::marshalling::types::array_list<
                    TTypeBase,
                    typename merkle_node_value<TTypeBase, MerkleTree>::type,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<TTypeBase, std::size_t>>>;

                template<typename MerkleTree, typename Endianness>
                merkle_tree<nil::marshalling::field_type<Endianness>, MerkleTree>
                    fill_merkle_tree(const MerkleTree& tree) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    merkle_tree<TTypeBase, MerkleTree> filled_tree;
                    for (const auto &hash_value : tree) {
                        filled_tree.value().push_back(
                            fill_merkle_node_value<MerkleTree, Endianness>(hash_value));
                    }
                    return filled_tree;
                }

                template<typename MerkleTree, typename Endianness>
                MerkleTree make_merkle_tree(const merkle_tree<
                        nil::marshalling::field_type<Endianness>, MerkleTree> &filled_merkle_tree) {
                    typename MerkleTree::container_type hashes;
                    for (std::size_t i = 0; i < filled_merkle_tree.value().size(); ++i) {
                        hashes.push_back(
                            make_merkle_node_value<MerkleTree, Endianness>(filled_merkle_tree.value().at(i)));
                    }
                    return MerkleTree(hashes.begin(), hashes.end());
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_MERKLE_TREE_HPP

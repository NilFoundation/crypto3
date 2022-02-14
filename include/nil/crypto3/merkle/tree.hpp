//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef CRYPTO3_MERKLE_TREE_HPP
#define CRYPTO3_MERKLE_TREE_HPP

#include <vector>

#include <boost/config.hpp>

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/merkle/node.hpp>

namespace nil {
    namespace crypto3 {
        namespace containers {
            namespace detail {
                // returns next highest power of two from a given number if it is not
                // already a power of two.
                size_t next_pow2(size_t n) {
                    return std::pow(2, std::ceil(std::log(n)));
                }
                // find power of 2 of a number which is power of 2
                size_t log2_pow2(size_t n) {
                    return next_pow2(n);
                }
                // Row_Count calculation given the number of _leafs in the tree and the branches.
                size_t merkle_tree_row_count(size_t leafs, size_t branches) {
                    // Optimization
                    if (branches == 2) {
                        return std::log2(leafs) + 1;
                    } else {
                        return std::log(leafs) / std::log(branches) + 1;
                    }
                }

                // Tree length calculation given the number of _leafs in the tree and the branches.
                size_t merkle_tree_length(size_t leafs, size_t branches) {
                    // Optimization
                    size_t len = leafs;
                    if (branches == 2) {
                        len = 2 * leafs - 1;
                    } else {
                        size_t cur = leafs;
                        while (cur != 0) {
                            cur /= branches;
                            len += cur;
                        }
                    }
                    return len;
                }

                // Tree length calculation given the number of _leafs in the tree, the
                // rows_to_discard, and the branches.
                size_t merkle_tree_cache_size(size_t leafs, size_t branches, size_t rows_to_discard) {
                    size_t shift = log2_pow2(branches);
                    size_t len = merkle_tree_length(leafs, branches);
                    size_t row_count = merkle_tree_row_count(leafs, branches);

                    // 'rc - 1' means that we start discarding rows above the base
                    // layer, which is included in the current rc.
                    size_t cache_base = row_count - 1 - rows_to_discard;

                    size_t cache_size = len;
                    size_t cur_leafs = leafs;

                    while (row_count > cache_base) {
                        cache_size -= cur_leafs;
                        cur_leafs >>= shift;    // cur /= branches
                        row_count -= 1;
                    }

                    return cache_size;
                }

                bool is_merkle_tree_size_valid(size_t leafs, size_t branches) {
                    if (branches == 0 || leafs != next_pow2(leafs) || branches != next_pow2(branches)) {
                        return false;
                    }

                    size_t cur = leafs;
                    size_t shift = log2_pow2(branches);
                    while (cur != 1) {
                        cur >>= shift;    // cur /= branches
                        if (cur > leafs || cur == 0) {
                            return false;
                        }
                    }

                    return true;
                }

                // Given a tree of 'rc' with the specified number of 'branches',
                // calculate the length of hashes required for the proof.
                size_t merkle_proof_lemma_length(size_t row_count, size_t branches) {
                    return 2 + ((branches - 1) * (row_count - 1));
                }

                // This method returns the number of '_leafs' given a merkle tree
                // length of 'len', where _leafs must be a power of 2, respecting the
                // number of branches.
                size_t merkle_tree_leafs(size_t len, size_t branches) {
                    size_t leafs = 0;
                    // Optimization:
                    if (branches == 2) {
                        leafs = (len >> 1) + 1;
                    } else {
                        size_t leafs = 1;
                        size_t cur = len;
                        size_t shift = log2_pow2(branches);
                        while (cur != 1) {
                            leafs <<= shift;    // _leafs *= branches
                            cur -= leafs;
                        }
                    };

                    return leafs;
                }
                // Merkle Tree.
                //
                // All _leafs and nodes are stored in a BGL graph structure.
                //
                // A merkle tree is a tree in which every non-leaf node is the hash of its
                // child nodes. A diagram for merkle_tree_impl arity = 2:
                //
                //         root = h1234 = h(h12 + h34)
                //        /                           \
                //  h12 = h(h1 + h2)            h34 = h(h3 + h4)
                //   /            \              /            \
                // h1 = h(tx1)  h2 = h(tx2)    h3 = h(tx3)  h4 = h(tx4)
                // ```
                //
                // In graph representation:
                //
                // ```text
                //    root -> h12, h34
                //    h12  -> h1, h2
                //    h34  -> h3, h4
                // ```
                //
                // Merkle root is always the top element.
                template<typename NodeType, size_t Arity = 2>
                struct merkle_tree_impl {
                    typedef NodeType node_type;

                    typedef typename node_type::hash_type hash_type;

                    typedef typename node_type::value_type value_type;
                    constexpr static const std::size_t value_bits = node_type::value_bits;

                public:
                    merkle_tree_impl (): _leafs(0), _size(0), rc(0) {};

                    template<
                        typename LeafRange,
                        typename Hashable = typename std::iterator_traits<typename LeafRange::iterator>::value_type>
                    merkle_tree_impl(std::vector<LeafRange> data) :
                        _leafs(data.size()), _size(detail::merkle_tree_length(_leafs, Arity)) {
                        BOOST_ASSERT_MSG(data.size() % Arity == 0, "Wrong leafs number");
                        hash_vector.resize(_size);
                        rc = detail::merkle_tree_row_count(_leafs, Arity);
                        size_t prev_layer_element = 0, start_layer_element = 0, layer_elements = _leafs;
                        for (size_t row_number = 0; row_number < rc; ++row_number) {
                            for (size_t current_element = start_layer_element;
                                 current_element < start_layer_element + layer_elements;
                                 ++current_element) {
                                if (row_number == 0) {
                                    hash_vector[current_element] = (static_cast<typename hash_type::digest_type>(crypto3::hash<hash_type>(data[current_element])));
                                } else {
                                    accumulator_set<hash_type> acc;
                                    for (size_t i = 0; i < Arity; ++i) {
                                        size_t children_index = (current_element - start_layer_element) * Arity + prev_layer_element + i;
                                        crypto3::hash<hash_type>(hash_vector[children_index].begin(), hash_vector[children_index].end(), acc);
                                    }
                                    hash_vector[current_element] = (accumulators::extract::hash<hash_type>(acc));
                                }
                            }
                            prev_layer_element = start_layer_element;
                            start_layer_element += layer_elements;
                            layer_elements /= Arity;
                        }
                    }

                    value_type root() {
                        return hash_vector[_size - 1];
                    }

                    value_type &operator[](std::size_t idx) {
                        return hash_vector[idx];
                    }

                    size_t row_count() const {
                        return rc;
                    }

                    size_t size() const {
                        return _size;
                    }

                    size_t leafs() const {
                        return _leafs;
                    }

                private:
                    std::vector<value_type> hash_vector;

                    size_t _leafs;
                    size_t _size;
                    // Note: The former 'upstream' merkle_light project uses 'height'
                    // (with regards to the tree property) incorrectly, so we've
                    // renamed it since it's actually a 'rc'.  For example, a
                    // tree with 2 leaf nodes and a single root node has a height of
                    // 1, but a rc of 2.
                    //
                    // Internally, this code considers only the rc.
                    size_t rc;
                };
            }    // namespace detail

            template<typename T, std::size_t Arity>
            using merkle_tree = typename std::conditional<nil::crypto3::detail::is_hash<T>::value,
                                                          detail::merkle_tree_impl<detail::merkle_tree_node<T>, Arity>,
                                                          detail::merkle_tree_impl<T, Arity>>::type;
        }    // namespace containers
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TREE_HPP

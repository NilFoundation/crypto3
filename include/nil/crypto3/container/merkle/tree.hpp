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

#include <nil/crypto3/container/merkle/node.hpp>

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
                // Row_Count calculation given the number of _leaves in the tree and the branches.
                size_t merkle_tree_row_count(size_t leafs, size_t branches) {
                    // Optimization
                    if (branches == 2) {
                        return std::log2(leafs) + 1;
                    } else {
                        return std::log(leafs) / std::log(branches) + 1;
                    }
                }

                // Tree length calculation given the number of _leaves in the tree and the branches.
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

                // Tree length calculation given the number of _leaves in the tree, the
                // rows_to_discard, and the branches.
                size_t merkle_tree_cache_size(size_t leafs, size_t branches, size_t rows_to_discard) {
                    size_t shift = log2_pow2(branches);
                    size_t len = merkle_tree_length(leafs, branches);
                    size_t row_count = merkle_tree_row_count(leafs, branches);

                    // '_rc - 1' means that we start discarding rows above the base
                    // layer, which is included in the current _rc.
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

                // Given a tree of '_rc' with the specified number of 'branches',
                // calculate the length of _hashes required for the proof.
                size_t merkle_proof_lemma_length(size_t row_count, size_t branches) {
                    return 2 + ((branches - 1) * (row_count - 1));
                }

                // This method returns the number of '_leaves' given a merkle tree
                // length of 'len', where _leaves must be a power of 2, respecting the
                // number of branches.
                size_t merkle_tree_leaves(size_t len, size_t branches) {
                    size_t leafs = 0;
                    // Optimization:
                    if (branches == 2) {
                        leafs = (len >> 1) + 1;
                    } else {
                        size_t leafs = 1;
                        size_t cur = len;
                        size_t shift = log2_pow2(branches);
                        while (cur != 1) {
                            leafs <<= shift;    // _leaves *= branches
                            cur -= leafs;
                        }
                    };

                    return leafs;
                }
                // Merkle Tree.
                //
                // All _leaves and nodes are stored in a BGL graph structure.
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
                    merkle_tree_impl() : _leaves(0), _size(0), _rc(0) {};

                    template<typename LeafIterator>
                    merkle_tree_impl(LeafIterator first, LeafIterator last) :
                        _leaves(std::distance(first, last)), _size(detail::merkle_tree_length(_leaves, Arity)),
                        _rc(detail::merkle_tree_row_count(_leaves, Arity)) {

                        BOOST_ASSERT_MSG(_leaves % Arity == 0 || _leaves == 1, "Wrong leafs number");

                        _hashes.reserve(_size);

                        while (first != last) {
                            _hashes.template emplace_back(crypto3::hash<hash_type>(*first++));
                        }

                        _hashes.resize(_size);

                        std::size_t row_idx = _leaves, row_size = _leaves / Arity;
                        typename std::vector<value_type>::iterator it = _hashes.begin();

                        for (size_t row_number = 1; row_number < _rc; ++row_number) {
                            for (size_t cur_element = row_idx; cur_element < row_idx + row_size; ++cur_element) {
                                accumulator_set<hash_type> acc;
                                for (size_t i = 0; i < Arity; ++i) {
                                    crypto3::hash<hash_type>(*it++, acc);
                                }
                                _hashes[cur_element] = accumulators::extract::hash<hash_type>(acc);
                            }
                            row_idx += row_size;
                            row_size /= Arity;
                        }
                    }

                    value_type root() const {
                        return _hashes[_size - 1];
                    }

                    value_type root() {
                        return _hashes[_size - 1];
                    }

                    value_type &operator[](std::size_t idx) {
                        return _hashes[idx];
                    }

                    value_type operator[](std::size_t idx) const {
                        return _hashes[idx];
                    }

                    size_t row_count() const {
                        return _rc;
                    }

                    size_t size() const {
                        return _size;
                    }

                    size_t leafs() const {
                        return _leaves;
                    }

                private:
                    std::vector<value_type> _hashes;

                    size_t _leaves;
                    size_t _size;
                    // Note: The former 'upstream' merkle_light project uses 'height'
                    // (with regards to the tree property) incorrectly, so we've
                    // renamed it since it's actually a '_rc'.  For example, a
                    // tree with 2 leaf nodes and a single root node has a height of
                    // 1, but a _rc of 2.
                    //
                    // Internally, this code considers only the _rc.
                    size_t _rc;
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

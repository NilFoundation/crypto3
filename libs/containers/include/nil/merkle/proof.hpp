//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
//  Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MERKLE_PROOF_HPP
#define CRYPTO3_MERKLE_PROOF_HPP

#include <algorithm>
#include <vector>

#include <boost/variant.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/merkle/merkle.hpp>
#include <nil/merkle/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace merkletree {
            template<std::size_t A, std::size_t B, std::size_t C>
            std::size_t base_path_length(std::size_t leaves) {
                std::size_t l;
                if (C > 0) {
                    l = leaves / C / B;
                } else if (B > 0) {
                    l = leaves / B;
                } else {
                    l = leaves;
                }

                return graph_height<A>(l) - 1;
            }

            template<std::size_t A, std::size_t B, std::size_t C>
            std::size_t compound_path_length(std::size_t leaves) {
                std::size_t len = base_path_length<A, B, C>(leaves);
                if (B > 0) {
                    len += 1;
                }

                if (C > 0) {
                    len += 1;
                }

                return len;
            }

            template<std::size_t A, std::size_t B, std::size_t C>
            std::size_t compound_tree_height(std::size_t leaves) {
                // base layer
                std::size_t a = graph_height<A>(leaves) - 1;

                // sub tree layer
                std::size_t b;
                if (B > 0) {
                    b = B - 1;
                } else {
                    b = 0;
                }

                // top tree layer
                std::size_t c;
                if (C > 0) {
                    c = C - 1;
                } else {
                    c = 0;
                }

                return a + b + c;
            }

            template<typename Hash>
            struct Proof_basic_policy {
                typedef std::array<uint8_t, Hash::digest_size> hash_result_type;
                constexpr static const std::size_t hash_digest_size = Hash::digest_size;
            };

            template<typename Hash, std::size_t BaseTreeArity = 2>
            struct Proof {
                typedef typename Proof_basic_policy<Hash>::hash_result_type element;
                constexpr static const std::size_t element_size = Proof_basic_policy<Hash>::hash_digest_size;

                std::vector<element> lemma; // layer
                std::vector<std::size_t> path; // branch index

                /// Creates new MT inclusion proof
                Proof(const std::vector<element> &lemma, const std::vector<std::size_t> &path) :
                    lemma(lemma), path(path) { }

                template<typename Store>
                Proof(MerkleTree<Hash, Store, BaseTreeArity> tree, size_t leaf) {
                    size_t base = 0;
                    size_t j = leaf;

                    // level 1 width
                    size_t width = tree.leafs;
                    size_t branches = BaseTreeArity;
                    BOOST_ASSERT_MSG(width == utilities::next_pow2(width), "Must be a power of 2 tree");
                    BOOST_ASSERT_MSG(branches == utilities::next_pow2(branches),"branches must be a power of 2");
                    size_t shift = utilities::log2_pow2(branches);
                    lemma.push_back(tree.read_at(j));
                    while (base + 1 < tree.len) {
                        size_t hash_index = (j / branches) * branches;
                        for (size_t k = hash_index; k < hash_index + branches; ++k) {
                            if (k != j) {
                                lemma.push_back(tree.read_at(base + k));
                            }
                        }
                        path.push_back(j % branches); // path_index
                        base += width;
                        width >>= shift; // width /= branches;
                        j >>= shift; // j /= branches;
                    }

                    // root is final
                    lemma.push_back(tree.root);

                    // Sanity check: if the `MerkleTree` lost its integrity and `data` doesn't match the
                    // expected values for `leafs` and `row_count` this can get ugly.
                    BOOST_ASSERT_MSG(
                        lemma.size() == utilities::get_merkle_proof_lemma_len(tree.row_count, branches),
                        "Invalid proof lemma length");
                    BOOST_ASSERT_MSG(
                        path.size() == tree.row_count - 1,
                        "Invalid proof path length");
                }

                /// Return proof target leaf
                element item() {
                    return *lemma.begin();
                }

                /// Return tree root
                element root() {
                    return *(lemma.end() - 1);
                }

                /// Verifies MT inclusion proof
                bool validate() {
                    std::size_t size = lemma.size();
                    if (size < 2) {
                        return false;
                    }

                    std::size_t branches = BaseTreeArity;
                    auto a = Algorithm<element>::default();
                    auto h = this->item();
                    auto path_index = 1;

                    for (size_t i = 1; i < size - 1; i += branches - 1) {
                        a.reset();
                        h = {
                            std::vector<element> nodes;
                            nodes.reserve(branches);
                            auto cur_index = 0;
                            for (j = 0; j < branches; ++j) {
                                if j == self.path[path_index - 1] {
                                    nodes.push(h.clone());
                                } else {
                                    nodes.push(self.lemma[i + cur_index].clone());
                                    cur_index += 1;
                                }
                            }

                            if cur_index != branches - 1 {
                                return false;
                            }

                            path_index += 1;
                            a.multi_node(&nodes, i - 1)
                        };
                    }

                    return h == root();
                }

                    /// Verifies MT inclusion proof and that leaf_data is the original leaf data for which proof was generated.
                template<template<typename> class Algorithm>
                bool validate_with_data(leaf_data: &dyn Hashable<A>) {
                    auto a = Algorithm<T>::default();
                    leaf_data.hash(&a);
                    const auto item = a.hash();
                    a.reset();
                    const auto leaf_hash = a.leaf(item);

                    if (leaf_hash == item()) {
                        return validate<Algorithm>();
                    } else {
                        return false;
                    }
                }
            };
        }    // namespace merkletree    
    }    // namespace crypto3
}    // namespace nil

#endif

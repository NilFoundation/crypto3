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

#include <boost/graph/adjacency_list.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/merkle/merkle.hpp>
#include <nil/merkle/proof.hpp>

namespace nil {
    namespace crypto3 {
        namespace merkletree {

            template<typename Hash>
            struct Proof_basic_policy {
                typedef typename Hash::digest_type hash_result_type;
                constexpr static const std::size_t hash_digest_size = Hash::digest_bits / 8 + (Hash::digest_bits % 8 ? 1 : 0);;
            };

            template<typename Hash, std::size_t Arity = 2>
            struct MerkleProof {

                MerkleProof(MerkleTree<Hash, Arity> tree, size_t leaf_idx) {
                    root = tree.root();
                    path.resize(tree.get_row_count() - 1);
                    leaf_index = leaf_idx;
                    size_t cur_leaf = leaf_idx;
                    size_t cur_row = 0;
                    while (cur_leaf != tree.get_len() - 1) {  // while it's not root
                        size_t parent = tree.parent(cur_leaf);
                        std::array<size_t, Arity> children = tree.children(parent);
                        size_t save_i = 0;
                        for (size_t i = 0; i < Arity; ++i) {
                            size_t current_child = children[i];
                            if (cur_leaf != current_child) {
                                path[cur_row][save_i] = path_element_t(tree[current_child], current_child % Arity);
                                ++save_i;
                            }
                        }
                        cur_row++;
                        cur_leaf = parent;
                    }
                }

                template <typename Hashable>
                bool validate(Hashable a) {
                    element d = crypto3::hash<Hash>(a);
                    for (size_t cur_row = 0; cur_row < path.size(); ++cur_row) {
                        std::array<uint8_t, element_size * Arity> new_input;
                        size_t missing_idx = Arity - 1; // If every previous index was fine - missing the last one.
                        for (size_t i = 0; i < Arity - 1; ++i) {
                            std::copy(path[cur_row][i].hash.begin(), path[cur_row][i].hash.end(),
                                      new_input.begin() + path[cur_row][i].position * element_size);
                            if (path[cur_row][i].position != i && missing_idx == Arity - 1) {
                                missing_idx = i;
                            }
                        }
                        std::copy(d.begin(), d.end(), new_input.begin() + missing_idx * element_size);
                        d = crypto3::hash<Hash>(new_input);
                    }
                    return (d == root);
                }

                size_t get_leaf_index() {
                    return leaf_index;
                }

                private:
                    typedef typename Proof_basic_policy<Hash>::hash_result_type element;
                    constexpr static const std::size_t element_size = Proof_basic_policy<Hash>::hash_digest_size;

                    size_t leaf_index;

                    element root;

                    struct path_element_t {
                        path_element_t(element x, size_t pos) : hash(x), position(pos) {}
                        path_element_t() {}
                        element hash;
                        size_t position;
                    };

                    std::vector<std::array<path_element_t, Arity - 1>> path;
            };
        }    // namespace merkletree    
    }    // namespace crypto3
}    // namespace nil

#endif

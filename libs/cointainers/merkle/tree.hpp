//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_HPP
#define FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_HPP

#include <cassert>
#include <map>
#include <vector>
#include <algorithm>
#include <cmath>

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace filecoin {
        namespace merkletree {
            template<typename Hash, std::size_t Arity = 2>
            typename Hash::digest_type hash_children_to_one(std::array<const typename Hash::digest_type, Arity> &children) {

                constexpr static const std::size_t arity = Arity;
                constexpr static const std::size_t digest_size = Hash::digest_size;

                crypto3::static_digest<Hash::digest_bits * arity> new_input;

                for (std::size_t i = 0; i < arity; ++i) {
                    assert(children[i].size() == digest_size);
                    std::copy(children[i].begin(), children[i].end(), new_input.begin() + i * digest_size);
                }

                return crypto3::hash<Hash>(new_input);
            }

            /**
             * A Merkle tree is maintained as two maps:
             * - a map from addresses to values, and
             * - a map from addresses to hashes.
             *
             * The second map maintains the intermediate hashes of a Merkle tree
             * built atop the values currently stored in the tree (the
             * implementation admits a very efficient support for sparse
             * trees). Besides offering methods to load and store values, the
             * class offers methods to retrieve the root of the Merkle tree and to
             * obtain the authentication paths for (the value at) a given address.
             */

            /**
             * A Merkle tree is maintained as two maps:
             * - a map from addresses to values, and
             * - a map from addresses to hashes.
             *
             * The second map maintains the intermediate hashes of a Merkle tree
             * built atop the values currently stored in the tree (the
             * implementation admits a very efficient support for sparse
             * trees). Besides offering methods to load and store values, the
             * class offers methods to retrieve the root of the Merkle tree and to
             * obtain the authentication paths for (the value at) a given address.
             */

            typedef std::vector<bool> merkle_authentication_node;
            typedef std::vector<merkle_authentication_node> merkle_authentication_path;

            template<typename Hash>
            struct merkle_tree {
                typedef Hash hash_type;

                typedef typename hash_type::digest_type digest_type;

                typedef merkle_authentication_path merkle_authentication_path_type;

                std::vector<digest_type> hash_defaults;
                std::map<size_t, std::vector<bool>> values;
                std::map<size_t, digest_type> hashes;

                size_t depth;
                size_t value_size;
                size_t digest_size;

                merkle_tree(const size_t depth, const size_t value_size) : depth(depth), value_size(value_size) {
                    assert(depth < sizeof(size_t) * CHAR_BIT);
                    assert(value_size <= Hash::digest_bits);

                    digest_type last;
                    hash_defaults.reserve(depth + 1);
                    hash_defaults.emplace_back(last);
                    for (size_t i = 0; i < depth; ++i) {
                        last = hash_children_to_one<hash_type>(last, last);
                        hash_defaults.emplace_back(last);
                    }

                    std::reverse(hash_defaults.begin(), hash_defaults.end());
                }

                merkle_tree(const size_t depth, const size_t value_size,
                            const std::vector<std::vector<bool>> &contents_as_vector) :
                    merkle_tree<hash_type>(depth, value_size) {
                    assert(algebra::log2(contents_as_vector.size()) <= depth);
                    for (size_t address = 0; address < contents_as_vector.size(); ++address) {
                        const size_t idx = address + (1ul << depth) - 1;
                        values[idx] = contents_as_vector[address];
                        hashes[idx] = contents_as_vector[address];
                        hashes[idx].resize(digest_size);
                    }

                    size_t idx_begin = (1ul << depth) - 1;
                    size_t idx_end = contents_as_vector.size() + ((1ul << depth) - 1);

                    for (int layer = depth; layer > 0; --layer) {
                        for (size_t idx = idx_begin; idx < idx_end; idx += 2) {
                            digest_type l = hashes[idx];    // this is sound, because idx_begin is always a left child
                            digest_type r = (idx + 1 < idx_end ? hashes[idx + 1] : hash_defaults[layer]);

                            digest_type h = hash_children_to_one<Hash>(l, r);
                            hashes[(idx - 1) / 2] = h;
                        }

                        idx_begin = (idx_begin - 1) / 2;
                        idx_end = (idx_end - 1) / 2;
                    }
                }
                merkle_tree(const size_t depth, const size_t value_size,
                            const std::map<size_t, std::vector<bool>> &contents) :
                    merkle_tree<hash_type>(depth, value_size) {

                    if (!contents.empty()) {
                        assert(contents.rbegin()->first < 1ul << depth);

                        for (auto it = contents.begin(); it != contents.end(); ++it) {
                            const size_t address = it->first;
                            const std::vector<bool> value = it->second;
                            const size_t idx = address + (1ul << depth) - 1;

                            values[address] = value;
                            hashes[idx] = value;
                            hashes[idx].resize(digest_size);
                        }

                        auto last_it = hashes.end();

                        for (int layer = depth; layer > 0; --layer) {
                            auto next_last_it = hashes.begin();

                            for (auto it = hashes.begin(); it != last_it; ++it) {
                                const size_t idx = it->first;
                                const digest_type hash = it->second;

                                if (idx % 2 == 0) {
                                    // this is the right child of its parent and by invariant we are missing the left child
                                    hashes[(idx - 1) / 2] = hash_children_to_one<hash_type>(hash_defaults[layer], hash);
                                } else {
                                    if (std::next(it) == last_it || std::next(it)->first != idx + 1) {
                                        // this is the left child of its parent and is missing its right child
                                        hashes[(idx - 1) / 2] = hash_children_to_one<hash_type>(hash, hash_defaults[layer]);
                                    } else {
                                        // typical case: this is the left child of the parent and adjacent to it there is a
                                        // right child
                                        hashes[(idx - 1) / 2] =
                                            hash_children_to_one<hash_type>(hash, std::next(it)->second);
                                        ++it;
                                    }
                                }
                            }

                            last_it = next_last_it;
                        }
                    }
                }

                std::vector<bool> get_value(const size_t address) const {
                    assert(algebra::log2(address) <= depth);

                    auto it = values.find(address);
                    std::vector<bool> padded_result = (it == values.end() ? std::vector<bool>(digest_size) : it->second);
                    padded_result.resize(value_size);

                    return padded_result;
                }

                void set_value(const size_t address, const std::vector<bool> &value) {
                    assert(algebra::log2(address) <= depth);
                    size_t idx = address + (1ul << depth) - 1;

                    assert(value.size() == value_size);
                    values[address] = value;
                    hashes[idx] = value;
                    hashes[idx].resize(digest_size);

                    for (int layer = depth - 1; layer >= 0; --layer) {
                        idx = (idx - 1) / 2;

                        auto it = hashes.find(2 * idx + 1);
                        digest_type l = (it == hashes.end() ? hash_defaults[layer + 1] : it->second);

                        it = hashes.find(2 * idx + 2);
                        digest_type r = (it == hashes.end() ? hash_defaults[layer + 1] : it->second);

                        digest_type h = hash_children_to_one<hash_type>(l, r);
                        hashes[idx] = h;
                    }
                }

                hash_value_type get_root() const {
                    auto it = hashes.find(0);
                    return (it == hashes.end() ? hash_defaults[0] : it->second);
                }

                merkle_authentication_path_type get_path(const size_t address) const {
                    merkle_authentication_path_type result(depth);
                    assert(algebra::log2(address) <= depth);
                    size_t idx = address + (1ul << depth) - 1;

                    for (size_t layer = depth; layer > 0; --layer) {
                        size_t sibling_idx = ((idx + 1) ^ 1) - 1;
                        auto it = hashes.find(sibling_idx);
                        if (layer == depth) {
                            auto it2 = values.find(sibling_idx - ((1ul << depth) - 1));
                            result[layer - 1] = (it2 == values.end() ? std::vector<bool>(value_size, false) : it2->second);
                            result[layer - 1].resize(digest_size);
                        } else {
                            result[layer - 1] = (it == hashes.end() ? hash_defaults[layer] : it->second);
                        }

                        idx = (idx - 1) / 2;
                    }

                    return result;
                }
            };
        }    // namespace merkletree
    }    // namespace filecoin
}    // namespace nil

#endif    // FILECOIN_STORAGE_PROOFS_CORE_MERKLE_TREE_HPP


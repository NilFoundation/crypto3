//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
//  Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@gmail.com>
//  Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
#include <stack>

#include <boost/variant.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/container/merkle/tree.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename, typename, std::size_t>
                class merkle_proof;
            }    // namespace components
        }        // namespace zk
        namespace marshalling {
            namespace types {
                template<typename, typename>
                class merkle_proof_marshalling;
            }
        }    // namespace marshalling
        namespace containers {
            namespace detail {
                template<typename NodeType, std::size_t Arity = 2, typename Enable = void>
                class merkle_proof_impl {
                public:
                    typedef NodeType node_type;
                    typedef typename node_type::hash_type hash_type;

                    constexpr static const std::size_t arity = Arity;

                    constexpr static const std::size_t value_bits = node_type::value_bits;
                    typedef typename node_type::value_type value_type;

                    struct path_element_type {
                        path_element_type(value_type x, size_t pos) : _hash(x), _position(pos) {
                        }
                        path_element_type() {
                        }

                        bool operator==(const path_element_type &rhs) const {
                            return _hash == rhs._hash && _position == rhs._position;
                        }
                        bool operator!=(const path_element_type &rhs) const {
                            return !(rhs == *this);
                        }

                        const value_type &hash() const {
                            return _hash;
                        }

                        std::size_t position() const {
                            return _position;
                        }

                        value_type _hash;
                        std::size_t _position;

                        template<typename, typename>
                        friend class nil::crypto3::marshalling::types::merkle_proof_marshalling;
                    };

                    typedef std::array<path_element_type, Arity - 1> layer_type;
                    typedef std::vector<layer_type> path_type;

                    merkle_proof_impl() : _li(0), _root(value_type()) {};

                    merkle_proof_impl(std::size_t li, value_type root, path_type path) : _li(li), _root(root),
                                                                                         _path(path){};

                    merkle_proof_impl(const merkle_tree<hash_type, arity> &tree, const std::size_t leaf_idx) {
                        _root = tree.root();
                        _path.resize(tree.row_count() - 1);
                        _li = leaf_idx;

                        typename std::vector<layer_type>::iterator v_itr = _path.begin();
                        std::size_t cur_leaf = leaf_idx;
                        std::size_t row_len = tree.leaves();
                        std::size_t row_begin_idx = 0;
                        while (cur_leaf != tree.size() - 1) {    // while it's not _root
                            std::size_t cur_leaf_pos = cur_leaf % arity;
                            std::size_t cur_leaf_arity_pos = (cur_leaf - row_begin_idx) / arity;
                            std::size_t begin_this_arity = cur_leaf - cur_leaf_pos;
                            typename layer_type::iterator a_itr = v_itr->begin();
                            for (size_t i = 0; i < cur_leaf_pos; ++i, ++begin_this_arity, ++a_itr) {
                                *a_itr = path_element_type(tree[begin_this_arity], i);
                            }
                            for (size_t i = cur_leaf_pos + 1; i < arity; ++i, ++begin_this_arity, ++a_itr) {
                                *a_itr = path_element_type(tree[begin_this_arity + 1], i);
                            }
                            v_itr++;
                            cur_leaf = row_len + row_begin_idx + cur_leaf_arity_pos;
                            row_begin_idx += row_len;
                            row_len /= arity;
                        }
                    }

                    // Specilized implementaions below.
                    template<typename Hashable, typename HashType = typename NodeType::hash_type>
                    typename std::enable_if_t<!crypto3::hashes::is_poseidon<HashType>::value,
                    bool> validate(const Hashable &a) const {
                        using hash_type = typename NodeType::hash_type;
                        value_type d = crypto3::hash<hash_type>(a);
                        for (auto &it : _path) {
                            accumulator_set<hash_type> acc;
                            size_t i = 0;
                            for (; (i < arity - 1) && i == it[i]._position; ++i) {
                                crypto3::hash<hash_type>(it[i]._hash.begin(), it[i]._hash.end(), acc);
                            }
                            crypto3::hash<hash_type>(d.begin(), d.end(), acc);
                            for (; i < arity - 1; ++i) {
                                crypto3::hash<hash_type>(it[i]._hash.begin(), it[i]._hash.end(), acc);
                            }
                            d = accumulators::extract::hash<hash_type>(acc);
                        }
                        return (d == _root);
                    }

                    // Specialize for poseidon.
                    template<typename Hashable, typename HashType = typename NodeType::hash_type>
                    typename std::enable_if_t<crypto3::hashes::is_poseidon<HashType>::value, bool>
                        validate(const Hashable &a) const {
                        BOOST_ASSERT_MSG(Arity == 2, "Poseidon is only supported for arity 2");

                        typedef NodeType node_type;
                        typedef typename node_type::hash_type hash_type;

                        constexpr static const std::size_t arity = Arity;

                        typedef typename node_type::value_type value_type;

                        value_type d = generate_poseidon_leaf_hash<hash_type>(a);// crypto3::hash<hash_type>(a);
                        for (auto &it : _path) {
                            std::vector<typename hash_type::digest_type> values;
                            size_t i = 0;
                            for (; (i < arity - 1) && i == it[i]._position; ++i) {
                                values.push_back(it[i]._hash);
                            }
                            values.push_back(d);
                            for (; i < arity - 1; ++i) {
                                values.push_back(it[i]._hash);
                            }
                            d = generate_poseidon_hash<hash_type>(values[0], values[1]);
                        }
                        return (d == _root);
                    }

                    static std::vector<merkle_proof_impl>
                        generate_compressed_proofs(const containers::merkle_tree<NodeType, Arity> &tree,
                                                    std::vector<std::size_t> leaf_idxs) {
                        assert(leaf_idxs.size() > 0);
                        std::vector<std::size_t> sorted_idx(leaf_idxs.size());
                        std::iota(sorted_idx.begin(), sorted_idx.end(), 0);
                        std::sort(sorted_idx.begin(), sorted_idx.end(), [&leaf_idxs](std::size_t i, std::size_t j) {
                                                                        return leaf_idxs[i] < leaf_idxs[j]; });
                        std::vector<merkle_proof_impl> result_proofs(leaf_idxs.size());
                        std::size_t row_len = tree.leaves();
                        std::vector<bool> known(2 * row_len, false);
                        std::size_t prev_leaf_idx = leaf_idxs[sorted_idx[0]] + 1;
                        for (auto idx : sorted_idx) {
                            auto leaf_idx = leaf_idxs[idx];
                            if (leaf_idx == prev_leaf_idx) {
                                result_proofs[idx] = merkle_proof_impl(leaf_idx, tree.root(), path_type());
                                assert(result_proofs[idx].path().size() == 0);
                                continue;
                            }
                            path_type path(tree.row_count() - 1);
                            typename path_type::iterator path_itr = path.begin();
                            std::size_t cur_leaf = leaf_idx;
                            std::size_t row_len = tree.leaves();
                            std::size_t row_begin_idx = 0;
                            bool finish_path = false;
                            while (cur_leaf != tree.size() - 1) {
                                std::size_t cur_leaf_pos = cur_leaf % Arity;
                                std::size_t cur_leaf_arity_pos = (cur_leaf - row_begin_idx) / Arity;
                                std::size_t begin_this_arity = cur_leaf - cur_leaf_pos;
                                typename layer_type::iterator layer_itr = path_itr->begin();
                                for (size_t i = 0; i < cur_leaf_pos; ++i, ++begin_this_arity) {
                                    if (!known[begin_this_arity]) {
                                        known[begin_this_arity] = true;
                                    } else {
                                        finish_path = true;
                                    }
                                    *layer_itr = path_element_type(tree[begin_this_arity], i);
                                    ++layer_itr;
                                }
                                for (size_t i = cur_leaf_pos + 1; i < Arity; ++i, ++begin_this_arity) {
                                    if (!known[begin_this_arity + 1]) {
                                        known[begin_this_arity + 1] = true;
                                    } else {
                                        finish_path = true;
                                    }
                                    *layer_itr = path_element_type(tree[begin_this_arity + 1], i);
                                    ++layer_itr;
                                }
                                path_itr++;
                                if (finish_path) {
                                    break;
                                }
                                cur_leaf = row_len + row_begin_idx + cur_leaf_arity_pos;
                                row_begin_idx += row_len;
                                row_len /= Arity;
                            }
                            path.resize(path_itr - path.begin());
                            result_proofs[idx] = merkle_proof_impl(leaf_idx, tree.root(), path);
                            prev_leaf_idx = leaf_idx;
                        }
                        return result_proofs;
                    }

                    template<typename Hashable>
                    static bool validate_compressed_proofs(const std::vector<merkle_proof_impl> &proofs,
                                                            const std::vector<Hashable> &a) {
                        assert(proofs.size() == a.size());
                        assert(proofs.size() > 0);
                        std::vector<std::size_t> sorted_idx(proofs.size());
                        std::iota(sorted_idx.begin(), sorted_idx.end(), 0);
                        std::sort(sorted_idx.begin(), sorted_idx.end(), [&proofs](std::size_t i, std::size_t j) {
                                                                        return proofs[i].leaf_index() >= proofs[j].leaf_index(); });
                        std::stack<std::pair<value_type, std::size_t>> st;
                        auto root = proofs[sorted_idx.back()].root();
                        auto full_proof_size = proofs[sorted_idx.back()].path().size();
                        for (auto idx : sorted_idx) {
                            auto path = proofs[idx].path();
                            value_type d = crypto3::hash<hash_type>(a[idx]);
                            std::vector<value_type> hashes = {d};
                            for (auto &it : path) {
                                accumulator_set<hash_type> acc;
                                std::size_t i = 0;
                                for (; (i < Arity - 1) && i == it[i].position(); ++i) {
                                    crypto3::hash<hash_type>(it[i].hash().begin(), it[i].hash().end(), acc);
                                }
                                crypto3::hash<hash_type>(d.begin(), d.end(), acc);
                                for (; i < Arity - 1; ++i) {
                                    crypto3::hash<hash_type>(it[i].hash().begin(), it[i].hash().end(), acc);
                                }
                                d = accumulators::extract::hash<hash_type>(acc);
                                hashes.push_back(d);
                            }
                            while (!st.empty()) {
                                auto top = st.top();
                                if (top.second >= hashes.size()) {
                                    break;
                                }
                                if (hashes[top.second] == top.first) {
                                    st.pop();
                                } else {
                                    return false;
                                }
                            }
                            if (path.size() < full_proof_size) {
                                st.push(std::make_pair(d, path.size()));
                            } else if (d != root) {
                                return false;
                            }
                        }
                        return true;
                    }

                    std::size_t leaf_index() const {
                        return _li;
                    }

                    bool operator==(const merkle_proof_impl &rhs) const {
                        return _li == rhs._li && _root == rhs._root && _path == rhs._path;
                    }
                    bool operator!=(const merkle_proof_impl &rhs) const {
                        return !(rhs == *this);
                    }

                    const value_type &root() const {
                        return _root;
                    }

                    const path_type &path() const {
                        return _path;
                    }

                private:
                    std::size_t _li;
                    value_type _root;
                    path_type _path;

                    template<typename, typename, std::size_t>
                    friend class nil::crypto3::zk::components::merkle_proof;

                    template<typename, typename>
                    friend class nil::crypto3::marshalling::types::merkle_proof_marshalling;
                };


            }    // namespace detail

            template<typename T, std::size_t Arity>
            using merkle_proof =
                typename std::conditional<nil::crypto3::detail::is_hash<T>::value,
                                          detail::merkle_proof_impl<detail::merkle_tree_node<T>, Arity>,
                                          detail::merkle_proof_impl<T, Arity>>::type;

        }    // namespace containers
    }        // namespace crypto3
}    // namespace nil

#endif

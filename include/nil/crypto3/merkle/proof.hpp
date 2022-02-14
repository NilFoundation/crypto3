//---------------------------------------------------------------------------//
//  MIT License
//
//  Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
//  Copyright (c) 2020-2021 Nikita Kaskov <nemo@nil.foundation>
//  Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#include <boost/variant.hpp>

#include <nil/crypto3/merkle/tree.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename, typename, std::size_t>
                struct merkle_proof;
            }    // namespace components
        }        // namespace zk
        namespace marshalling {
            namespace types {
                template<typename, typename>
                struct merkle_proof_marshalling;
            }
        }    // namespace marshalling
        namespace containers {
            namespace detail {
                template<typename NodeType, std::size_t Arity = 2>
                struct merkle_proof_impl {
                    typedef NodeType node_type;
                    typedef typename node_type::hash_type hash_type;

                    constexpr static const std::size_t arity = Arity;

                    constexpr static const std::size_t value_bits = node_type::value_bits;
                    typedef typename node_type::value_type value_type;

                    merkle_proof_impl() : _li(0) {};

                    merkle_proof_impl(merkle_tree<hash_type, arity> tree, std::size_t leaf_idx) {
                        _root = tree.root();
                        _path.resize(tree.row_count() - 1);
                        _li = leaf_idx;

                        typename std::vector<layer_type>::iterator v_itr = _path.begin();
                        std::size_t cur_leaf = leaf_idx;
                        std::size_t row_len = tree.leafs();
                        std::size_t row_begin_idx = 0;
                        while (cur_leaf != tree.size() - 1) {    // while it's not _root
                            std::size_t cur_leaf_pos = cur_leaf % arity;
                            std::size_t cur_leaf_arity_pos = (cur_leaf - row_begin_idx) / arity;
                            std::size_t begin_this_arity = cur_leaf - cur_leaf_pos;
                            typename layer_type::iterator a_itr = v_itr->begin();
                            for (size_t i = 0; i < cur_leaf_pos; ++i,  ++begin_this_arity,  ++a_itr) {
                                *a_itr = path_element_type(tree[begin_this_arity], i);
                            }
                            for (size_t i = cur_leaf_pos + 1; i < arity; ++i,  ++begin_this_arity,  ++a_itr) {
                                *a_itr = path_element_type(tree[begin_this_arity + 1], i);
                            }
                            v_itr++;
                            cur_leaf = row_len + row_begin_idx + cur_leaf_arity_pos;
                            row_begin_idx += row_len;
                            row_len /= arity;
                        }
                    }

                    template<typename Hashable>
                    bool validate(Hashable a) {
                        value_type d = crypto3::hash<hash_type>(a);

                        for (size_t cur_row = 0; cur_row < _path.size(); ++cur_row) {

                            accumulator_set<hash_type> acc;
                            bool was_missing = false;    // If every previous index was fine - missing the last one.

                            for (size_t i = 0; i < arity - 1; ++i) {
                                if (_path[cur_row][i]._position != i && !was_missing) {
                                    crypto3::hash<hash_type>(d.begin(), d.end(), acc);
                                    was_missing = true;
                                }
                                crypto3::hash<hash_type>(_path[cur_row][i]._hash.begin(), _path[cur_row][i]._hash.end(),
                                                         acc);
                            }
                            if (!was_missing) {
                                crypto3::hash<hash_type>(d.begin(), d.end(), acc);
                            }
                            d = accumulators::extract::hash<hash_type>(acc);
                        }
                        return (d == _root);
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

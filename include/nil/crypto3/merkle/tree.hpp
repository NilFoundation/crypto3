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

#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graph_as_tree.hpp>

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

#include <nil/crypto3/merkle/node.hpp>

enum vertex_hash_t { vertex_hash };

namespace boost {
    BOOST_INSTALL_PROPERTY(vertex, hash);
}

namespace nil {
    namespace crypto3 {
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
            size_t get_merkle_tree_row_count(size_t leafs, size_t branches) {
                // Optimization
                if (branches == 2) {
                    return std::log2(leafs) + 1;
                } else {
                    return std::log(leafs) / std::log(branches) + 1;
                }
            }

            // Tree length calculation given the number of _leafs in the tree and the branches.
            size_t get_merkle_tree_len(size_t leafs, size_t branches) {
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
            size_t get_merkle_tree_cache_size(size_t leafs, size_t branches, size_t rows_to_discard) {
                size_t shift = log2_pow2(branches);
                size_t len = get_merkle_tree_len(leafs, branches);
                size_t row_count = get_merkle_tree_row_count(leafs, branches);

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
            size_t get_merkle_proof_lemma_len(size_t row_count, size_t branches) {
                return 2 + ((branches - 1) * (row_count - 1));
            }

            // This method returns the number of '_leafs' given a merkle tree
            // length of 'len', where _leafs must be a power of 2, respecting the
            // number of branches.
            size_t get_merkle_tree_leafs(size_t len, size_t branches) {
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

            protected:
                typedef boost::adjacency_list<boost::vecS,
                                              boost::vecS,
                                              boost::bidirectionalS,
                                              boost::property<vertex_hash_t, value_type>>
                    graph_type;
                typedef typename boost::property_map<graph_type, vertex_hash_t>::type vertex_name_map_type;

            public:
                template<typename Hashable, size_t Size>
                merkle_tree_impl(std::vector<std::array<Hashable, Size>> data) :
                    _leafs(data.size()), _size(detail::get_merkle_tree_len(_leafs, Arity)) {
                    BOOST_ASSERT_MSG(data.size() % Arity == 0, "Wrong leafs number");

                    rc = detail::get_merkle_tree_row_count(_leafs, Arity);
                    for (size_t i = 0; i < _size; ++i) {
                        boost::add_vertex(_t);
                    }
                    size_t prev_layer_element = 0, start_layer_element = 0, layer_elements = _leafs;
                    for (size_t row_number = 0; row_number < rc; ++row_number) {
                        for (size_t current_element = start_layer_element;
                             current_element < start_layer_element + layer_elements;
                             ++current_element) {
                            if (row_number == 0) {
                                hash_map[current_element] = static_cast<typename hash_type::digest_type>(
                                    crypto3::hash<hash_type>(data[current_element]));
                            } else {
                                nil::crypto3::accumulator_set<hash_type> acc;
                                for (size_t i = 0; i < Arity; ++i) {
                                    size_t children_index =
                                        (current_element - start_layer_element) * Arity + prev_layer_element + i;
                                    crypto3::hash<hash_type>(
                                        hash_map[children_index].begin(), hash_map[children_index].end(), acc);
                                    add_edge(children_index, current_element, _t);
                                }
                                hash_map[current_element] = nil::crypto3::accumulators::extract::hash<hash_type>(acc);
                            }
                        }
                        prev_layer_element = start_layer_element;
                        start_layer_element += layer_elements;
                        layer_elements /= Arity;
                    }
                }

                std::array<size_t, Arity> children(size_t leaf_index) {
                    std::array<size_t, Arity> res;

                    typename boost::graph_traits<graph_type>::in_edge_iterator ein, edgein_end;

                    std::size_t i = 0;

                    for (boost::tie(ein, edgein_end) = in_edges(leaf_index, _t); ein != edgein_end; ++ein, ++i) {
                        res[i] = source(*ein, _t);
                    }
                    return res;
                }

                size_t parent(size_t leaf_index) {
                    typename boost::graph_traits<graph_type>::out_edge_iterator ei, edge_end;
                    boost::tie(ei, edge_end) = out_edges(leaf_index, _t);
                    return target(*ei, _t);
                }

                value_type root() {
                    return hash_map[_size - 1];
                }

                std::vector<value_type> hash_path(size_t leaf_index) {
                    std::vector<value_type> res;
                    res.push_back(hash_map[leaf_index]);
                    typename boost::graph_traits<graph_type>::adjacency_iterator ai, a_end;
                    boost::tie(ai, a_end) = adjacent_vertices(leaf_index, _t);
                    while (ai != a_end) {    // while not the root
                        res.push_back(get(hash_map, *ai));
                        boost::tie(ai, a_end) = adjacent_vertices(*ai, _t);
                    }
                    return res;
                }

                value_type &operator[](std::size_t idx) {
                    return hash_map[idx];
                }

                friend std::ostream &operator<<(std::ostream &o, merkle_tree_impl const &a) {
                    typename boost::graph_traits<graph_type>::vertex_iterator i, end;
                    typename boost::graph_traits<graph_type>::in_edge_iterator ein, edgein_end;
                    for (boost::tie(i, end) = vertices(a._t); i != end; ++i) {
                        boost::tie(ein, edgein_end) = in_edges(*i, a._t);
                        if (ein == edgein_end) {
                            std::cout << "(" << *i << ", " << get(a.hash_map, *i) << ") --- leaf";
                        } else {
                            std::cout << "(" << *i << ", " << get(a.hash_map, *i) << ") <-- ";
                        }
                        for (; ein != edgein_end; ++ein) {
                            size_t idx_vertex = source(*ein, a._t);
                            std::cout << "(" << idx_vertex << ", " << get(a.hash_map, idx_vertex) << ")  ";
                        }
                        std::cout << std::endl;
                    }
                    return o;
                }

                size_t row_count() {
                    return rc;
                }

                size_t size() {
                    return _size;
                }

                size_t leafs() {
                    return _leafs;
                }

            private:
                graph_type _t;
                vertex_name_map_type hash_map = get(vertex_hash, _t);

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
        using merkle_tree = typename std::conditional<detail::is_hash<T>::value,
                                                      detail::merkle_tree_impl<detail::merkle_tree_node<T>, Arity>,
                                                      detail::merkle_tree_impl<T, Arity>>::type;
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_TREE_HPP

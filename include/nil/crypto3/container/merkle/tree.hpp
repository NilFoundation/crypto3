//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@gmail.com>
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
#include <cmath>

#include <nil/crypto3/algebra/curves/pallas.hpp>

#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_sponge.hpp>
#include <nil/crypto3/hash/detail/poseidon/poseidon_policy.hpp>
#include <nil/crypto3/container/merkle/node.hpp>

namespace nil {
    namespace crypto3 {
        namespace containers {
            namespace detail {
                // returns next highest power of two from a given number if it is not
                // already a power of two.
                inline size_t next_pow2(size_t n) {
                    return std::pow(2, std::ceil(std::log(n)));
                }

                // find power of 2 of a number which is power of 2
                inline size_t log2_pow2(size_t n) {
                    return next_pow2(n);
                }

                // Row_Count calculation given the number of _leaves in the tree and the branches.
                inline size_t merkle_tree_row_count(size_t leafs, size_t branches) {
                    // Optimization
                    if (branches == 2) {
                        return std::log2(leafs) + 1;
                    } else {
                        return round(std::log(leafs) / std::log(branches)) + 1;
                    }
                }

                // Tree length calculation given the number of _leaves in the tree and the branches.
                inline size_t merkle_tree_length(size_t leafs, size_t branches) {
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

                // This method returns the number of '_leaves' given a merkle tree
                // length of 'len', where _leaves must be a power of 2, respecting the
                // number of branches.
                inline size_t merkle_tree_leaves(size_t tree_s, size_t branches) {
                    // Optimization
                    size_t len = tree_s;
                    if (branches == 2) {
                        len = (tree_s + 1) >> 1;
                    } else {
                        size_t cur = 1;
                        while (cur < len) {
                            len -= cur;
                            cur *= branches;
                        }
                    }
                    return len;
                }

                // Tree length calculation given the number of _leaves in the tree, the
                // rows_to_discard, and the branches.
                inline size_t merkle_tree_cache_size(size_t leafs, size_t branches, size_t rows_to_discard) {
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

                inline bool is_merkle_tree_size_valid(size_t leafs, size_t branches) {
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
                inline size_t merkle_proof_lemma_length(size_t row_count, size_t branches) {
                    return 2 + ((branches - 1) * (row_count - 1));
                }

                // Merkle Tree.
                //
                // All _leaves and nodes are stored in a BGL graph structure.
                //
                // A merkle tree is a tree in which every non-leaf node is the hash of its
                // child nodes. A diagram for merkle_tree_impl arity = 2:
                //
                //         root = h1234 = h(h12 + h34)
                //       ./                           \.
                //  h12 = h(h1 + h2)            h34 = h(h3 + h4)
                //  ./            \.            ./            \.
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

                    typedef std::vector<value_type> container_type;

                    typedef typename container_type::allocator_type allocator_type;
                    typedef typename container_type::reference reference;
                    typedef typename container_type::const_reference const_reference;
                    typedef typename container_type::size_type size_type;
                    typedef typename container_type::difference_type difference_type;
                    typedef typename container_type::pointer pointer;
                    typedef typename container_type::const_pointer const_pointer;
                    typedef typename container_type::iterator iterator;
                    typedef typename container_type::const_iterator const_iterator;
                    typedef typename container_type::reverse_iterator reverse_iterator;
                    typedef typename container_type::const_reverse_iterator const_reverse_iterator;

                    merkle_tree_impl() : _size(0), _leaves(0), _rc(0) {};

                    ~merkle_tree_impl() = default;

                    merkle_tree_impl(size_t n) :
                            _size(detail::merkle_tree_length(n, Arity)), _leaves(n),
                            _rc(detail::merkle_tree_row_count(n, Arity)) {
                        BOOST_ASSERT_MSG(pow(Arity, round(std::log(n) / std::log(Arity))) == n,
                                         "Wrong leaves number, it must be a power of Arity.");
                    }

                    merkle_tree_impl(const merkle_tree_impl &x) :
                            _hashes(x._hashes), _size(x._size), _leaves(x._leaves), _rc(x._rc) {
                    }

                    merkle_tree_impl(const merkle_tree_impl &x, const allocator_type &a) : _hashes(x.hashes(), a),
                                                                                           _size(x._size),
                                                                                           _leaves(x._leaves),
                                                                                           _rc(x._rc) {}

                    merkle_tree_impl(const std::initializer_list<value_type> &il) : _hashes(il) {
                        set_leaves(detail::merkle_tree_leaves(std::distance(il.begin(), il.end()), Arity));
                        set_row_count(detail::merkle_tree_row_count(_leaves, Arity));
                        set_complete_size(detail::merkle_tree_length(_leaves, Arity));
                    }

                    template<typename Iterator, typename std::enable_if<std::is_same<typename Iterator::value_type, value_type>::value, bool>::type = true>
                    merkle_tree_impl(Iterator first, Iterator last) : _hashes(first, last) {
                        set_leaves(detail::merkle_tree_leaves(std::distance(first, last), Arity));
                        set_row_count(detail::merkle_tree_row_count(_leaves, Arity));
                        set_complete_size(detail::merkle_tree_length(_leaves, Arity));
                    }

                    merkle_tree_impl(const std::initializer_list<value_type> &il, const allocator_type &a) : _hashes(il, a) {
                        set_leaves(detail::merkle_tree_leaves(std::distance(il.begin(), il.end()), Arity));
                        set_row_count(detail::merkle_tree_row_count(_leaves, Arity));
                        set_complete_size(detail::merkle_tree_length(_leaves, Arity));
                    }

                    merkle_tree_impl(merkle_tree_impl &&x)
                    BOOST_NOEXCEPT(std::is_nothrow_move_constructible<allocator_type>::value):
                            _hashes(x._hashes),
                            _size(x._size), _leaves(x._leaves), _rc(x._rc) {
                    }

                    merkle_tree_impl(merkle_tree_impl &&x, const allocator_type &a) :
                            _hashes(x.hashes(), a), _size(x._size), _leaves(x._leaves), _rc(x._rc) {
                    }

                    merkle_tree_impl &operator=(const merkle_tree_impl &x) {
                        _hashes = x.hashes();
                        return *this;
                    }

                    merkle_tree_impl &operator=(merkle_tree_impl &&x) {
                        _hashes = x._hashes;
                        _size = x._size;
                        _leaves = x._leaves;
                        _rc = x._rc;
                        return *this;
                    }

                    bool operator==(const merkle_tree_impl &rhs) const {
                        return _hashes == rhs.val;
                    }

                    bool operator!=(const merkle_tree_impl &rhs) const {
                        return !(rhs == *this);
                    }

                    allocator_type get_allocator() const BOOST_NOEXCEPT {
                        return this->val.__alloc();
                    }

                    iterator begin() BOOST_NOEXCEPT {
                        return _hashes.begin();
                    }

                    const_iterator begin() const BOOST_NOEXCEPT {
                        return _hashes.begin();
                    }

                    iterator end() BOOST_NOEXCEPT {
                        return _hashes.end();
                    }

                    const_iterator end() const BOOST_NOEXCEPT {
                        return _hashes.end();
                    }

                    reverse_iterator rbegin() BOOST_NOEXCEPT {
                        return _hashes.rbegin();
                    }

                    const_reverse_iterator rbegin() const BOOST_NOEXCEPT {
                        return _hashes.rbegin();
                    }

                    reverse_iterator rend() BOOST_NOEXCEPT {
                        return reverse_iterator(begin());
                    }

                    const_reverse_iterator rend() const BOOST_NOEXCEPT {
                        return const_reverse_iterator(begin());
                    }

                    const_iterator cbegin() const BOOST_NOEXCEPT {
                        return begin();
                    }

                    const_iterator cend() const BOOST_NOEXCEPT {
                        return end();
                    }

                    const_reverse_iterator crbegin() const BOOST_NOEXCEPT {
                        return rbegin();
                    }

                    const_reverse_iterator crend() const BOOST_NOEXCEPT {
                        return rend();
                    }

                    size_type size() const BOOST_NOEXCEPT {
                        return _hashes.size();
                    }

                    size_type complete_size() const BOOST_NOEXCEPT {
                        return _size;
                    }

                    size_type capacity() const BOOST_NOEXCEPT {
                        return _hashes.capacity();
                    }

                    bool empty() const BOOST_NOEXCEPT {
                        return (_hashes.size() == 0);
                    }

                    size_type max_size() const BOOST_NOEXCEPT {
                        return _hashes.max_size();
                    }

                    void reserve(size_type _n) {
                        return _hashes.reserve(_n);
                    }

                    void shrink_to_fit() BOOST_NOEXCEPT {
                        return _hashes.shrink_to_fit();
                    }

                    reference operator[](size_type _n) BOOST_NOEXCEPT {
                        return _hashes[_n];
                    }

                    const_reference operator[](size_type _n) const BOOST_NOEXCEPT {
                        return _hashes[_n];
                    }

                    reference at(size_type _n) {
                        return _hashes.at(_n);
                    }

                    const_reference at(size_type _n) const {
                        return _hashes.at(_n);
                    }

                    reference front() BOOST_NOEXCEPT {
                        return _hashes.front();
                    }

                    const_reference front() const BOOST_NOEXCEPT {
                        return _hashes.front();
                    }

                    reference back() BOOST_NOEXCEPT {
                        return _hashes.back();
                    }

                    const_reference back() const BOOST_NOEXCEPT {
                        return _hashes.back();
                    }

                    value_type *hashes() BOOST_NOEXCEPT {
                        return _hashes;
                    }

                    const value_type *hashes() const BOOST_NOEXCEPT {
                        return _hashes;
                    }

                    void push_back(const_reference _x) {
                        //    #error ERROR
                        _hashes.push_back(_x);
                    }

                    void push_back(value_type &&_x) {
                        //    #error ERROR
                        _hashes.push_back(_x);
                    }

                    //
                    template<class... Args>
                    reference emplace_back(Args &&..._args) {
                        return _hashes.template emplace_back(_args...);
                    }

                    template<class... Args>
                    iterator emplace(const_iterator _position, Args &&... _args) {
                        return _hashes.template emplace(_position, _args...);
                    }

                    void pop_back() {
                        _hashes.pop_back();
                    }

                    void clear() BOOST_NOEXCEPT {
                        _hashes.clear();
                    }

                    void resize(size_type _sz) {
                        return _hashes.resize(_sz);
                    }

                    void resize(size_type _sz, const_reference _x) {
                        return _hashes.resize(_sz, _x);
                    }

                    void swap(merkle_tree_impl &other) {
                        _hashes.swap(other.hashes());
                        std::swap(_leaves, other.leaves());
                        std::swap(_rc, other.rc());
                        std::swap(_size, other.size());
                    }

                    value_type root() const BOOST_NOEXCEPT {
                        BOOST_ASSERT_MSG(_size == _hashes.size(), "MerkleTree not fulfilled");
                        return _hashes[_size - 1];
                    }

                    value_type root() BOOST_NOEXCEPT {
                        BOOST_ASSERT_MSG(_size == _hashes.size(), "MerkleTree not fulfilled");
                        return _hashes[_size - 1];
                    }

                    size_t row_count() const {
                        return _rc;
                    }

                    size_t leaves() const {
                        return _leaves;
                    }

                    void set_leaves(size_t s) {
                        _leaves = s;
                    }

                    void set_row_count(size_t s) {
                        _rc = s;
                    }

                    void set_complete_size(size_t s) {
                        _size = s;
                    }

                protected:
                    container_type _hashes;

                    size_t _size;
                    size_t _leaves;
                    // Note: The former 'upstream' merkle_light project uses 'height'
                    // (with regards to the tree property) incorrectly, so we've
                    // renamed it since it's actually a '_rc'.  For example, a
                    // tree with 2 leaf nodes and a single root node has a height of
                    // 1, but a _rc of 2.
                    //
                    // Internally, this code considers only the _rc.
                    size_t _rc;
                };

                template<typename T, typename LeafIterator>
                typename T::digest_type generate_hash(LeafIterator first, LeafIterator last) {
                    accumulator_set<T> acc;
                    while (first != last) {
                        crypto3::hash<T>(*first++, acc);
                    }
                    return accumulators::extract::hash<T>(acc);
                }

                template<typename T, std::enable_if_t<crypto3::hashes::is_poseidon<T>::value, bool> = true>
                typename T::digest_type generate_poseidon_hash(typename T::digest_type first, typename T::digest_type second) {
                    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
                    using poseidon_policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
                    hashes::detail::poseidon_sponge_construction<poseidon_policy> sponge;
                    sponge.absorb(first);
                    sponge.absorb(second);
                    return sponge.squeeze();
                }

                template<typename T, typename LeafData = std::vector<std::uint8_t>,
                    std::enable_if_t<crypto3::hashes::is_poseidon<T>::value, bool> = true>
                typename T::digest_type generate_poseidon_leaf_hash(const LeafData &leaf) {
                    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
                    using poseidon_policy = nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>;
                    hashes::detail::poseidon_sponge_construction<poseidon_policy> sponge;
                    BOOST_ASSERT_MSG(leaf.size() % 64 == 0, "Leaf size must be a multiple of 64");
                    for(std::size_t i = 0; i < leaf.size(); i+=64) {
                        nil::crypto3::multiprecision::cpp_int first = 0;
                        std::size_t j = 0;
                        for(; j < 32; j++){
                            first <<= 8;
                            first += leaf[i + j];
                        }
                        nil::crypto3::multiprecision::cpp_int second = 0;
                        for(; j < 64; j++){
                            second <<= 8;
                            second += leaf[i + j];
                        }
                        sponge.absorb(first);
                        sponge.absorb(second);
                    }
                    return sponge.squeeze();
                }

                template<typename T,
                    std::size_t Arity, typename LeafIterator,
                    std::enable_if_t<crypto3::hashes::is_poseidon<typename T::hash_type>::value, bool> = true
                >
                merkle_tree_impl<T, Arity> make_merkle_tree(LeafIterator first, LeafIterator last) {
                    BOOST_ASSERT_MSG(Arity == 2, "Only arity 2 is supported for poseidon hash function");
                    typedef T node_type;
                    typedef typename node_type::hash_type hash_type;

                    merkle_tree_impl<T, Arity> ret(std::distance(first, last));

                    ret.reserve(ret.complete_size());

                    while (first != last) {
                        ret.emplace_back(generate_poseidon_leaf_hash<hash_type>(*first++));
                    }

                    std::size_t row_idx = ret.leaves(), row_size = row_idx / Arity;
                    typename merkle_tree_impl<T, Arity>::iterator it = ret.begin();

                    for (size_t row_number = 1; row_number < ret.row_count(); ++row_number, row_size /= Arity) {
                        for (size_t i = 0; i < row_size; ++i, it += Arity) {
                            ret.emplace_back(generate_poseidon_hash<hash_type>(*it, *(it + 1)));
                        }
                    }
                    return ret;
                }

                template<typename T, std::size_t Arity, typename LeafIterator,
                    std::enable_if_t<!crypto3::hashes::is_poseidon<typename T::hash_type>::value, bool> = true>
                merkle_tree_impl<T, Arity> make_merkle_tree(LeafIterator first, LeafIterator last) {
                    typedef T node_type;
                    typedef typename node_type::hash_type hash_type;

                    merkle_tree_impl<T, Arity> ret(std::distance(first, last));
                    ret.reserve(ret.complete_size());

                    while (first != last) {
                        ret.emplace_back(crypto3::hash<hash_type>(*first++));
                    }

                    std::size_t row_idx = ret.leaves(), row_size = row_idx / Arity;
                    typename merkle_tree_impl<T, Arity>::iterator it = ret.begin();

                    for (size_t row_number = 1; row_number < ret.row_count(); ++row_number, row_size /= Arity) {
                        for (size_t i = 0; i < row_size; ++i, it += Arity) {
                            ret.emplace_back(generate_hash<hash_type>(it, it + Arity));
                        }
                    }
                    return ret;
                }
            }    // namespace detail

            template<typename T, std::size_t Arity>
            using merkle_tree = typename std::conditional<nil::crypto3::detail::is_hash<T>::value,
                    detail::merkle_tree_impl<detail::merkle_tree_node<T>, Arity>,
                    detail::merkle_tree_impl<T, Arity>>::type;

            template<typename T, std::size_t Arity, typename LeafIterator>
            merkle_tree<T, Arity> make_merkle_tree(LeafIterator first, LeafIterator last) {
                return detail::make_merkle_tree<typename std::conditional<nil::crypto3::detail::is_hash<T>::value,
                        detail::merkle_tree_node<T>,
                        T>::type,
                        Arity>(first, last);
            }

        }    // namespace containers
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MERKLE_TREE_HPP

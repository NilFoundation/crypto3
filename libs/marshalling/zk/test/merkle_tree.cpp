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

#define BOOST_TEST_MODULE crypto3_marshalling_merkle_tree_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>

#include <iostream>
#include <iomanip>
#include <cmath>
#include <fstream>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/hash/block_to_field_elements_wrapper.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/marshalling/containers/types/merkle_tree.hpp>

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
generate_random_data(std::size_t leaf_number) {
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf;
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return std::rand() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

template<typename Endianness, typename Hash, std::size_t Arity, std::size_t LeafSize = 64>
void test_merkle_tree_marshalling(std::size_t tree_depth) {

    using namespace nil::crypto3::marshalling;
    using merkle_tree_type = nil::crypto3::containers::merkle_tree<Hash, Arity>;
    using merkle_tree_marshalling_type =
            types::merkle_tree<nil::marshalling::field_type<Endianness>, merkle_tree_type>;

    std::size_t leafs_number = std::pow(Arity, tree_depth);
    // You can also lazy convert byte stream to field elements stream using <nil/crypto3/hash/block_to_field_elements_wrapper.hpp>
    auto data = generate_random_data<std::uint8_t, LeafSize>(leafs_number);
    merkle_tree_type tree;

    if constexpr (nil::crypto3::algebra::is_field_element<typename Hash::word_type>::value) {
        // Populate the vector with wrappers, one for each block
        std::vector<
            nil::crypto3::hashes::block_to_field_elements_wrapper<
                typename Hash::word_type::field_type,
                std::array<std::uint8_t, LeafSize>
            >
        > wrappers;
        for (const auto& inner_containers : data) {
            wrappers.emplace_back(inner_containers);
        }
        tree = nil::crypto3::containers::make_merkle_tree<Hash, Arity>(wrappers.begin(), wrappers.end());
    } else {
        tree = nil::crypto3::containers::make_merkle_tree<Hash, Arity>(data.begin(), data.end());
    }

    auto filled_merkle_tree = types::fill_merkle_tree<merkle_tree_type, Endianness>(tree);
    merkle_tree_type _tree = types::make_merkle_tree<merkle_tree_type, Endianness>(filled_merkle_tree);
    BOOST_CHECK(tree == _tree);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_merkle_tree.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_merkle_tree.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    // print_merkle_tree(cv.cbegin(), cv.cend(), data[tree_idx].cbegin(), data[tree_idx].cend(), true);

    merkle_tree_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    merkle_tree_type constructed_val_read = types::make_merkle_tree<merkle_tree_type, Endianness>(test_val_read);
    BOOST_CHECK(tree == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(marshalling_merkle_tree_test_suite)

using curve_type = nil::crypto3::algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;

using HashTypes = boost::mpl::list<
        nil::crypto3::hashes::sha2<256>,
        nil::crypto3::hashes::keccak_1600<512>,
        nil::crypto3::hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>
    >;


BOOST_AUTO_TEST_CASE_TEMPLATE(marshalling_merkle_tree_arity_2_test, HashType, HashTypes) {
    std::srand(std::time(0));
    test_merkle_tree_marshalling<nil::marshalling::option::big_endian, HashType, 2>(2);
    test_merkle_tree_marshalling<nil::marshalling::option::big_endian, HashType, 2>(4);
    test_merkle_tree_marshalling<nil::marshalling::option::big_endian, HashType, 2, 320>(8);
}

// Poseidon hash function supports only Arity 2.
using BlockHashTypes = boost::mpl::list<
        nil::crypto3::hashes::sha2<256>,
        nil::crypto3::hashes::keccak_1600<512>
    >;

BOOST_AUTO_TEST_CASE_TEMPLATE(marshalling_merkle_tree_arity_3_test, HashType, BlockHashTypes) {
    test_merkle_tree_marshalling<nil::marshalling::option::big_endian, HashType, 3>(2);
    test_merkle_tree_marshalling<nil::marshalling::option::big_endian, HashType, 3>(4);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(marshalling_merkle_tree_arity_4_test, HashType, BlockHashTypes) {
    test_merkle_tree_marshalling<nil::marshalling::option::big_endian, HashType, 4>(2);
    test_merkle_tree_marshalling<nil::marshalling::option::big_endian, HashType, 4>(4);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(marshalling_merkle_tree_arity_5_test, HashType, BlockHashTypes) {
    test_merkle_tree_marshalling<nil::marshalling::option::big_endian, HashType, 5>(2);
    test_merkle_tree_marshalling<nil::marshalling::option::big_endian, HashType, 5>(4);
}

BOOST_AUTO_TEST_SUITE_END()

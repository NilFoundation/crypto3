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

#define BOOST_TEST_MODULE containter_merkletree_test

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/blake2b.hpp>
#include <nil/crypto3/hash/pedersen.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <chrono>
#include <cstdio>
#include <limits>
#include <type_traits>
#include <nil/crypto3/hash/algorithm/hash.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::containers;

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
    generate_random_data(std::size_t leaf_number) {
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf {};
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return std::rand() % (std::numeric_limits<ValueType>::max() + 1); });
        v.emplace_back(leaf);
    }
    return v;
}

template<typename Hash, size_t Arity, typename ValueType, std::size_t N>
void testing_validate_template_random_data(std::size_t leaf_number) {
    std::array<ValueType, N> data_not_in_tree = {0};
    auto data = generate_random_data<ValueType, N>(leaf_number);
    auto tree = make_merkle_tree<Hash, Arity>(data.begin(), data.end());

    std::size_t proof_idx = std::rand() % leaf_number;
    merkle_proof<Hash, Arity> proof(tree, proof_idx);
    bool good_validate = proof.validate(data[proof_idx]);
    bool wrong_leaf_validate = proof.validate(data[(proof_idx + 1) % leaf_number]);
    bool wrong_data_validate = proof.validate(data_not_in_tree);
    BOOST_CHECK(good_validate);
    BOOST_CHECK(!wrong_leaf_validate);
    BOOST_CHECK(!wrong_data_validate);
}

template<typename Hash, size_t Arity, typename Element>
void testing_validate_template(std::vector<Element> data) {
    std::array<uint8_t, 7> data_not_in_tree = {'\x6d', '\x65', '\x73', '\x73', '\x61', '\x67', '\x65'};
    merkle_tree<Hash, Arity> tree = make_merkle_tree<Hash, Arity>(data.begin(), data.end());
    merkle_tree<Hash, Arity> tree2(tree.begin(), tree.end());
//    for (auto i = 0; i < tree.size(); ++i) {
//        std::cout << tree[i] << std::endl;
//    }
//    tree.emplace_back(nil::crypto3::hash<typename Hash::hash_type>(data_not_in_tree[0]));
    merkle_proof<Hash, Arity> proof(tree, 0);
    bool good_validate = proof.validate(data[0]);
    bool wrong_leaf_validate = proof.validate(data[1]);
    bool wrong_data_validate = proof.validate(data_not_in_tree);
    BOOST_CHECK(true == good_validate);
    BOOST_CHECK(false == wrong_leaf_validate);
    BOOST_CHECK(false == wrong_data_validate);
}

template<typename Hash, size_t Arity, typename ValueType, std::size_t N>
void testing_validate_template_random_data_compressed_proofs(std::size_t leaf_number) {
    using merkle_proof_type = typename containers::merkle_proof<Hash, Arity>;
    using Element = std::array<ValueType, N>;
    std::array<ValueType, N> data_not_in_tree = {0};
    auto data = generate_random_data<ValueType, N>(leaf_number);
    auto tree = make_merkle_tree<Hash, Arity>(data.begin(), data.end());

    std::size_t num_idxs = std::rand() % leaf_number;
    while (num_idxs == 0) {
        num_idxs = std::rand() % leaf_number;
    }

    std::vector<std::size_t> proof_idxs;
    std::vector<Element> data_for_validation;
    for (std::size_t i = 0; i < num_idxs; ++i) {
        proof_idxs.emplace_back(std::rand() % leaf_number);
    }
    for (auto idx : proof_idxs) {
        data_for_validation.emplace_back(data[idx]);
    }

    // standard case
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<merkle_proof<Hash, Arity>> compressed_proofs = merkle_proof_type::generate_compressed_proofs(tree, proof_idxs);
    bool validate_compressed = merkle_proof_type::validate_compressed_proofs(compressed_proofs, data_for_validation);
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    // case for arity == 4
    if (leaf_number == 16) {
        std::vector<merkle_proof<Hash, Arity>> compressed_proofs_one_idx = merkle_proof_type::generate_compressed_proofs(tree, {3, 2, 1, 5, 11, 11, 0});
        bool validate_compressed_one_idx = merkle_proof_type::validate_compressed_proofs(compressed_proofs_one_idx, std::vector<Element>({data[3], data[2], data[1], data[5], data[11], data[11], data[0]}));
        BOOST_CHECK(validate_compressed_one_idx);
    }
    // one index
    std::size_t one_idx = std::rand() % leaf_number;
    std::vector<merkle_proof<Hash, Arity>> compressed_proofs_one_idx = merkle_proof_type::generate_compressed_proofs(tree, {one_idx});
    bool validate_compressed_one_idx = merkle_proof_type::validate_compressed_proofs(compressed_proofs_one_idx, std::vector<Element>({data[one_idx]}));
    // edge indexes
    std::vector<merkle_proof<Hash, Arity>> compressed_proofs_edge_idxs = merkle_proof_type::generate_compressed_proofs(tree, {0, leaf_number - 1});
    bool validate_compressed_edge_idxs = merkle_proof_type::validate_compressed_proofs(compressed_proofs_edge_idxs, std::vector<Element>({data[0], data[leaf_number - 1]}));
    // repeated indexes
    std::size_t repeated_idx = std::rand() % leaf_number;
    std::vector<merkle_proof<Hash, Arity>> compressed_proofs_repeated_idxs = merkle_proof_type::generate_compressed_proofs(tree, {repeated_idx, leaf_number / 2, repeated_idx});
    bool validate_compressed_repeated_idxs = merkle_proof_type::validate_compressed_proofs(compressed_proofs_repeated_idxs, std::vector<Element>({data[repeated_idx], data[leaf_number / 2], data[repeated_idx]}));
    // wrong leaf
    auto sorted_idxs = proof_idxs;
    std::sort(sorted_idxs.begin(), sorted_idxs.end());
    std::size_t wrong_leaf_idx = 0;
    for (auto idx : sorted_idxs) {
        if (idx == wrong_leaf_idx) {
            wrong_leaf_idx++;
        } else {
            break;
        }
    }
    auto data_wrong_leaf = data_for_validation;
    data_wrong_leaf[std::rand() % num_idxs] = data[wrong_leaf_idx];
    assert(data_wrong_leaf != data_for_validation);
    bool wrong_leaf_validate_compressed = merkle_proof_type::validate_compressed_proofs(compressed_proofs, data_wrong_leaf);
    // wrong data
    auto data_wrong_data = data_for_validation;
    data_wrong_data[std::rand() % num_idxs] = data_not_in_tree;
    assert(data_wrong_data != data_for_validation);
    bool wrong_data_validate_compressed = merkle_proof_type::validate_compressed_proofs(compressed_proofs, data_wrong_data);

    BOOST_CHECK(validate_compressed);
    BOOST_CHECK(validate_compressed_one_idx);
    BOOST_CHECK(validate_compressed_edge_idxs);
    BOOST_CHECK(validate_compressed_repeated_idxs);
    BOOST_CHECK(!wrong_leaf_validate_compressed);
    BOOST_CHECK(!wrong_data_validate_compressed);
}

template<typename Hash, size_t Arity, typename Element>
void testing_validate_template_compressed_proofs(std::vector<Element> data) {
    using merkle_proof_type = typename containers::merkle_proof<Hash, Arity>;
    merkle_tree<Hash, Arity> tree = make_merkle_tree<Hash, Arity>(data.begin(), data.end());

    std::size_t leaf_number = data.size();
    std::size_t num_idxs = std::rand() % leaf_number;
    while (num_idxs == 0) {
        num_idxs = std::rand() % leaf_number;
    }
    std::vector<std::size_t> proof_idxs;
    std::vector<Element> data_for_validation;
    for (std::size_t i = 0; i < num_idxs; ++i) {
        proof_idxs.emplace_back(std::rand() % leaf_number);
    }
    for (auto idx : proof_idxs) {
        data_for_validation.emplace_back(data[idx]);
    }

    // standart case
    std::vector<merkle_proof<Hash, Arity>> compressed_proofs = merkle_proof_type::generate_compressed_proofs(tree, proof_idxs);
    bool validate_compressed = merkle_proof_type::validate_compressed_proofs(compressed_proofs, data_for_validation);
    // one index
    std::size_t one_idx = std::rand() % leaf_number;
    std::vector<merkle_proof<Hash, Arity>> compressed_proofs_one_idx = merkle_proof_type::generate_compressed_proofs(tree, {one_idx});
    bool validate_compressed_one_idx = merkle_proof_type::validate_compressed_proofs(compressed_proofs_one_idx, std::vector<Element>({data[one_idx]}));
    // edge indexes
    std::vector<merkle_proof<Hash, Arity>> compressed_proofs_edge_idxs = merkle_proof_type::generate_compressed_proofs(tree, {0, leaf_number - 1});
    bool validate_compressed_edge_idxs = merkle_proof_type::validate_compressed_proofs(compressed_proofs_edge_idxs, std::vector<Element>({data[0], data[leaf_number - 1]}));
    // repeated indexes
    std::size_t repeated_idx = std::rand() % leaf_number;
    std::vector<merkle_proof<Hash, Arity>> compressed_proofs_repeated_idxs = merkle_proof_type::generate_compressed_proofs(tree, {repeated_idx, leaf_number - 1, repeated_idx});
    bool validate_compressed_repeated_idxs = merkle_proof_type::validate_compressed_proofs(compressed_proofs_repeated_idxs, std::vector<Element>({data[repeated_idx], data[leaf_number - 1], data[repeated_idx]}));
    // wrong leaf
    auto sorted_idxs = proof_idxs;
    std::sort(sorted_idxs.begin(), sorted_idxs.end());
    std::size_t wrong_leaf_idx = 0;
    for (auto idx : sorted_idxs) {
        if (idx == wrong_leaf_idx) {
            wrong_leaf_idx++;
        } else {
            break;
        }
    }
    auto data_wrong_leaf = data_for_validation;
    data_wrong_leaf[std::rand() % num_idxs] = data[wrong_leaf_idx];
    assert(data_wrong_leaf != data_for_validation);
    bool wrong_leaf_validate_compressed = merkle_proof_type::validate_compressed_proofs(compressed_proofs, data_wrong_leaf);
    // wrong data
    auto data_wrong_data = data_for_validation;
    data_wrong_data[std::rand() % num_idxs] = {'9'};
    assert(data_wrong_data != data_for_validation);
    bool wrong_data_validate_compressed = merkle_proof_type::validate_compressed_proofs(compressed_proofs, data_wrong_data);

    BOOST_CHECK(validate_compressed);
    BOOST_CHECK(validate_compressed_one_idx);
    BOOST_CHECK(validate_compressed_edge_idxs);
    BOOST_CHECK(validate_compressed_repeated_idxs);
    BOOST_CHECK(!wrong_leaf_validate_compressed);
    BOOST_CHECK(!wrong_data_validate_compressed);
}

template<typename Hash, size_t Arity, typename Element>
void testing_hash_template(std::vector<Element> data, std::string result) {
    merkle_tree<Hash, Arity> tree = make_merkle_tree<Hash, Arity>(data.begin(), data.end());
    BOOST_CHECK(result == std::to_string(tree.root()));
}

BOOST_AUTO_TEST_SUITE(containers_merkltree_test)

using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;
using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;

BOOST_AUTO_TEST_CASE(merkletree_construct_test_1) {
    std::vector<std::array<char, 1>> v = {{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}};
    merkle_tree<hashes::sha2<256>, 2> tree_res = make_merkle_tree<hashes::sha2<256>, 2>(v.begin(), v.end());
    merkle_tree<hashes::sha2<256>, 2> tree(tree_res.begin(), tree_res.end());
    BOOST_CHECK_EQUAL(tree.size(), 15);
    BOOST_CHECK_EQUAL(tree.leaves(), 8);
    BOOST_CHECK_EQUAL(tree.row_count(), 4);
}

BOOST_AUTO_TEST_CASE(merkletree_construct_test_2) {
    std::vector<std::array<char, 1>> v = {{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}};
    merkle_tree<hashes::sha2<256>, 3> tree_res = make_merkle_tree<hashes::sha2<256>, 3>(v.begin(), v.end());
    merkle_tree<hashes::sha2<256>, 3> tree(tree_res.begin(), tree_res.end());
    BOOST_CHECK_EQUAL(tree.size(), 13);
    BOOST_CHECK_EQUAL(tree.leaves(), 9);
    BOOST_CHECK_EQUAL(tree.row_count(), 3);
}


BOOST_AUTO_TEST_CASE(merkletree_validate_test_1) {
    std::vector<std::array<char, 1>> v = {{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}};
    testing_validate_template<hashes::sha2<256>, 2>(v);
    testing_validate_template<hashes::md5, 2>(v);
    testing_validate_template<hashes::blake2b<224>, 2>(v);
    testing_validate_template<poseidon_type, 2>(v);

    std::size_t leaf_number = 8;
    testing_validate_template_random_data<hashes::sha2<256>, 2, std::uint8_t, 1>(leaf_number);
    testing_validate_template_random_data<hashes::md5, 2, std::uint8_t, 1>(leaf_number);
    testing_validate_template_random_data<hashes::blake2b<224>, 2, std::uint8_t, 1>(leaf_number);
    testing_validate_template_random_data<poseidon_type, 2, std::uint8_t, 1>(leaf_number);
}

BOOST_AUTO_TEST_CASE(merkletree_validate_test_2) {
    std::vector<std::array<char, 1>> v = {{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}};
    testing_validate_template<hashes::sha2<256>, 3>(v);
    testing_validate_template<hashes::md5, 3>(v);
    testing_validate_template<hashes::blake2b<224>, 3>(v);

    std::size_t leaf_number = 9;
    testing_validate_template_random_data<hashes::sha2<256>, 3, std::uint8_t, 1>(leaf_number);
    testing_validate_template_random_data<hashes::md5, 3, std::uint8_t, 1>(leaf_number);
    testing_validate_template_random_data<hashes::blake2b<224>, 3, std::uint8_t, 1>(leaf_number);
}

BOOST_AUTO_TEST_CASE(merkletree_validate_test_3) {
    using hash_type = hashes::pedersen<
        hashes::find_group_hash_default_params, hashes::sha2<256>,
        algebra::curves::jubjub::template g1_type<nil::crypto3::algebra::curves::coordinates::affine,
                                                  nil::crypto3::algebra::curves::forms::twisted_edwards>>;
    std::size_t leaf_number = 8;
    testing_validate_template_random_data<hash_type, 2, bool, hash_type::digest_bits>(leaf_number);
}

BOOST_AUTO_TEST_CASE(merkletree_validate_test_4) {
    using hash_type = hashes::pedersen<
        hashes::find_group_hash_default_params, hashes::sha2<256>,
        algebra::curves::jubjub::template g1_type<nil::crypto3::algebra::curves::coordinates::affine,
                                                  nil::crypto3::algebra::curves::forms::twisted_edwards>>;
    testing_validate_template_random_data_compressed_proofs<hash_type, 2, bool, hash_type::digest_bits>(8);
    testing_validate_template_random_data_compressed_proofs<hash_type, 3, bool, hash_type::digest_bits>(9);
    testing_validate_template_random_data_compressed_proofs<hash_type, 4, bool, hash_type::digest_bits>(16);
}

BOOST_AUTO_TEST_CASE(merkletree_validate_test_5) {
    std::vector<std::array<char, 1>> v = {{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}};
    testing_validate_template_compressed_proofs<hashes::sha2<256>, 3>(v);
    testing_validate_template_compressed_proofs<hashes::md5, 3>(v);
    testing_validate_template_compressed_proofs<hashes::blake2b<224>, 3>(v);

    std::size_t leaf_number = 16;
    testing_validate_template_random_data_compressed_proofs<hashes::sha2<256>, 4, std::uint8_t, 1>(leaf_number);
    testing_validate_template_random_data_compressed_proofs<hashes::md5, 4, std::uint8_t, 1>(leaf_number);
    testing_validate_template_random_data_compressed_proofs<hashes::blake2b<224>, 4, std::uint8_t, 1>(leaf_number);
}

BOOST_AUTO_TEST_CASE(merkletree_hash_test_1) {
    std::vector<std::array<char, 1>> v = {{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}};
    testing_hash_template<hashes::sha2<256>, 2>(v, "3b828c4f4b48c5d4cb5562a474ec9e2fd8d5546fae40e90732ef635892e42720");
    testing_hash_template<hashes::md5, 2>(v, "11ee8b50825ce6f816a1ae06d4aa0045");
    testing_hash_template<hashes::blake2b<224>, 2>(v, "0ed2a2145cae554ca57f08420d6cb58629ca1e89dc92f819c6c1d13d");
}

BOOST_AUTO_TEST_CASE(merkletree_hash_test_2) {
    std::vector<std::array<char, 1>> v = {{'0'}, {'1'}, {'2'}, {'3'}, {'4'}, {'5'}, {'6'}, {'7'}, {'8'}};
    testing_hash_template<hashes::sha2<256>, 3>(v, "6831d4d32538bedaa7a51970ac10474d5884701c840781f0a434e5b6868d4b73");
    testing_hash_template<hashes::md5, 3>(v, "0733c4cd580b1523cfbb9751f42e9420");
    testing_hash_template<hashes::blake2b<224>, 3>(v, "d9d0ff26d10aaac2882c08eb2b55e78690c949d1a73b1cfc0eb322ee");
}

BOOST_AUTO_TEST_SUITE_END()

//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE crypto3_marshalling_merkle_proof_test

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

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/marshalling/containers/types/merkle_proof.hpp>

template<typename TIter>
void print_hex_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end, bool endl) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::dec;
    if (endl) {
        os << std::endl;
    }
}

template<typename MerkleProofIterator, typename VerifiedDataIterator>
void print_merkle_proof(MerkleProofIterator merkle_proof_begin, MerkleProofIterator merkle_proof_end,
                        VerifiedDataIterator verified_data_begin, VerifiedDataIterator verified_data_end, bool endl) {
    std::ofstream merkle_out;
    merkle_out.open("merkle_proof.txt");
    print_hex_byteblob(merkle_out, merkle_proof_begin, merkle_proof_end, endl);
    std::ofstream merkle_verified_data_out;
    merkle_verified_data_out.open("merkle_proof_verified_data.txt");
    print_hex_byteblob(merkle_verified_data_out, verified_data_begin, verified_data_end, endl);
}

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(FpCurveGroupElement e) {
    std::cout << e.X.data << " " << e.Y.data << " " << e.Z.data << std::endl;
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(Fp2CurveGroupElement e) {
    std::cout << "(" << e.X.data[0].data << " " << e.X.data[1].data << ") (" << e.Y.data[0].data << " "
              << e.Y.data[1].data << ") (" << e.Z.data[0].data << " " << e.Z.data[1].data << ")" << std::endl;
}

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
void test_merkle_proof(std::size_t tree_depth) {

    using namespace nil::crypto3::marshalling;
    using merkle_tree_type = nil::crypto3::containers::merkle_tree<Hash, Arity>;
    using merkle_proof_type = nil::crypto3::containers::merkle_proof<Hash, Arity>;
    using merkle_proof_marshalling_type =
            types::merkle_proof<nil::marshalling::field_type<Endianness>, merkle_proof_type>;

    std::size_t leafs_number = std::pow(Arity, tree_depth);
    auto data = generate_random_data<std::uint8_t, LeafSize>(leafs_number);
    merkle_tree_type tree = nil::crypto3::containers::make_merkle_tree<Hash, Arity>(data.begin(), data.end());
    std::size_t proof_idx = std::rand() % leafs_number;
    merkle_proof_type proof(tree, proof_idx);

    auto filled_merkle_proof = types::fill_merkle_proof<merkle_proof_type, Endianness>(proof);
    merkle_proof_type _proof = types::make_merkle_proof<merkle_proof_type, Endianness>(filled_merkle_proof);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_merkle_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_merkle_proof.write(write_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    print_merkle_proof(cv.cbegin(), cv.cend(), data[proof_idx].cbegin(), data[proof_idx].cend(), true);

    merkle_proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    merkle_proof_type constructed_val_read = types::make_merkle_proof<merkle_proof_type, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(marshalling_merkle_proof_test_suite)

using curve_type = nil::crypto3::algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;

using HashTypes = boost::mpl::list<
        nil::crypto3::hashes::sha2<256>,
        nil::crypto3::hashes::keccak_1600<512>,
        nil::crypto3::hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>
    >;


    BOOST_AUTO_TEST_CASE_TEMPLATE(marshalling_merkle_proof_arity_2_test, HashType, HashTypes) {
        std::srand(std::time(0));
        test_merkle_proof<nil::marshalling::option::big_endian, HashType, 2>(5);
        test_merkle_proof<nil::marshalling::option::big_endian, HashType, 2>(10);
        test_merkle_proof<nil::marshalling::option::big_endian, HashType, 2, 320>(15);
    }

// Poseidon hash function supports only Arity 2.
using BlockHashTypes = boost::mpl::list<
        nil::crypto3::hashes::sha2<256>,
        nil::crypto3::hashes::keccak_1600<512>
    >;

    BOOST_AUTO_TEST_CASE_TEMPLATE(marshalling_merkle_proof_arity_3_test, HashType, BlockHashTypes) {
        test_merkle_proof<nil::marshalling::option::big_endian, HashType, 3>(5);
        test_merkle_proof<nil::marshalling::option::big_endian, HashType, 3>(10);
    }

    BOOST_AUTO_TEST_CASE_TEMPLATE(marshalling_merkle_proof_arity_4_test, HashType, BlockHashTypes) {
        test_merkle_proof<nil::marshalling::option::big_endian, HashType, 4>(5);
        test_merkle_proof<nil::marshalling::option::big_endian, HashType, 4>(10);
    }

    BOOST_AUTO_TEST_CASE_TEMPLATE(marshalling_merkle_proof_arity_5_test, HashType, BlockHashTypes) {
        test_merkle_proof<nil::marshalling::option::big_endian, HashType, 5>(5);
        test_merkle_proof<nil::marshalling::option::big_endian, HashType, 5>(10);
    }

BOOST_AUTO_TEST_SUITE_END()

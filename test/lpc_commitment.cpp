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

#define BOOST_TEST_MODULE crypto3_marshalling_lpc_commitment_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/list_polynomial_commitment.hpp>

template<typename TIter>
void print_byteblob(TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        std::cout << std::hex << int(*it) << std::endl;
    }
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

template<typename Field, typename Hash, typename Endianness>
void test_lpc(std::size_t tree_depth) {
    using namespace nil::crypto3::marshalling;

    using commitment_scheme_type = nil::crypto3::zk::snark::list_polynomial_commitment_scheme<Field, Hash>;
    using commitment_scheme_marshalling_type =
        types::lpc_proof<nil::marshalling::field_type<Endianness>, commitment_scheme_type>;

    std::size_t leafs_number = 1 << tree_depth;
    typename commitment_scheme_type::proof_type lpc_proof;

    for (std::size_t i = 0; i < lpc_proof.z_openings.size(); ++i) {
        typename commitment_scheme_type::merkle_tree_type tree(generate_random_data<std::uint8_t, 32>(leafs_number));
        typename commitment_scheme_type::merkle_proof_type proof(tree, std::rand() % leafs_number);
        lpc_proof.z_openings.at(i) = proof;
    }

    for (std::size_t i = 0; i < lpc_proof.alpha_openings.size(); ++i) {
        for (std::size_t j = 0; j < lpc_proof.alpha_openings.at(i).size(); ++j) {
            typename commitment_scheme_type::merkle_tree_type tree(
                generate_random_data<std::uint8_t, 32>(leafs_number));
            typename commitment_scheme_type::merkle_proof_type proof(tree, std::rand() % leafs_number);
            lpc_proof.alpha_openings.at(i).at(j) = proof;
        }
    }

    for (std::size_t i = 0; i < lpc_proof.f_y_openings.size(); ++i) {
        for (std::size_t j = 0; j < lpc_proof.f_y_openings.at(i).size(); ++j) {
            typename commitment_scheme_type::merkle_tree_type tree(
                generate_random_data<std::uint8_t, 32>(leafs_number));
            typename commitment_scheme_type::merkle_proof_type proof(tree, std::rand() % leafs_number);
            lpc_proof.f_y_openings.at(i).at(j) = proof;
        }
    }

    for (std::size_t i = 0; i < lpc_proof.f_commitments.size(); ++i) {
        for (std::size_t j = 0; j < lpc_proof.f_commitments.at(i).size(); ++j) {
            lpc_proof.f_commitments.at(i).at(j) =
                nil::crypto3::hash<Hash>(generate_random_data<std::uint8_t, 32>(1).at(0));
        }
    }

    nil::crypto3::random::algebraic_random_device<Field> d;
    for (std::size_t i = 0; i < lpc_proof.f_ip1_coefficients.size(); ++i) {
        lpc_proof.f_ip1_coefficients.at(i) =
            typename decltype(lpc_proof.f_ip1_coefficients)::value_type({d(), d(), d(), d()});
    }

    auto filled_lpc_proof = types::fill_lpc_proof<commitment_scheme_type, Endianness>(lpc_proof);
    typename commitment_scheme_type::proof_type _lpc_proof =
        types::make_lpc_proof<commitment_scheme_type, Endianness>(filled_lpc_proof);
    BOOST_CHECK(lpc_proof == _lpc_proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_lpc_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_lpc_proof.write(write_iter, cv.size());

    commitment_scheme_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    typename commitment_scheme_type::proof_type constructed_val_read =
        types::make_lpc_proof<commitment_scheme_type, Endianness>(test_val_read);
    BOOST_CHECK(lpc_proof == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(lpc_test_suite)

BOOST_AUTO_TEST_CASE(lpc_bls12_381_be) {
    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using hash_type = nil::crypto3::hashes::sha2<256>;
    test_lpc<field_type, hash_type, nil::marshalling::option::big_endian>(3);
}

BOOST_AUTO_TEST_SUITE_END()

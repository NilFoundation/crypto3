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

template<typename FRIScheme>
typename FRIScheme::round_proof_type generate_random_fri_round_proof(std::size_t tree_depth) {
    std::random_device rd;
    std::size_t leafs_number = 1 << tree_depth;
    typename FRIScheme::round_proof_type proof;

    auto data = generate_random_data<std::uint8_t, 32>(leafs_number);
    typename FRIScheme::merkle_tree_type tree(data.cbegin(), data.cend());
    std::size_t idx = rd() % leafs_number;
    typename FRIScheme::merkle_proof_type mp(tree, idx);
    proof.colinear_path = mp;
    //    std::cout << "colinear_path_verifiable_data = hex\"";
    //    for (const auto c : data[idx]) {
    //        std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << int(c);
    //    }
    //    std::cout << "\";" << std::endl;

    //    std::cout << "p_verifiable_data" << " = [";
    for (std::size_t i = 0; i < proof.p.size(); ++i) {
        auto data = generate_random_data<std::uint8_t, 32>(leafs_number);
        typename FRIScheme::merkle_tree_type tree(data.cbegin(), data.cend());
        idx = rd() % leafs_number;
        typename FRIScheme::merkle_proof_type mp(tree, idx);
        proof.p.at(i) = mp;
        //        std::cout << "hex\"";
        //        for (const auto c : data[idx]) {
        //            std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << int(c);
        //        }
        //        std::cout << "\",";
    }
    //    std::cout << "];" << std::endl;

    nil::crypto3::random::algebraic_random_device<typename FRIScheme::field_type> d;
    proof.colinear_value = d();

    for (std::size_t i = 0; i < proof.y.size(); ++i) {
        proof.y.at(i) = d();
    }

    proof.T_root =
        nil::crypto3::hash<typename FRIScheme::transcript_hash_type>(generate_random_data<std::uint8_t, 32>(1).at(0));

    //    std::cout << "FRI round proof:" << std::endl;
    //    std::cout << "y = [";
    //    for (const auto &y_i : proof.y) {
    //        std::cout << std::dec << "uint256(" << y_i.data << "), ";
    //    }
    //    std::cout << "];" << std::endl << std::endl;
    //
    //    std::cout << "colinear_value = uint256(" << proof.colinear_value.data << ");" << std::endl;
    //
    //    std::cout << "T_root = hex\"";
    //    for (const auto c : proof.T_root) {
    //        std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << int(c);
    //    }
    //    std::cout << "\";" << std::endl;

    return proof;
}

template<typename FRIScheme>
typename FRIScheme::proof_type generate_random_fri_proof(std::size_t tree_depth, std::size_t round_proofs_n,
                                                         std::size_t degree) {
    typename FRIScheme::proof_type proof;

    for (std::size_t i = 0; i < round_proofs_n; ++i) {
        proof.round_proofs.emplace_back(generate_random_fri_round_proof<FRIScheme>(tree_depth));
    }

    nil::crypto3::random::algebraic_random_device<typename FRIScheme::field_type> d;
    for (std::size_t i = 0; i < degree; ++i) {
        proof.final_polynomial.emplace_back(d());
    }

    return proof;
}

template<typename LPCScheme>
typename LPCScheme::proof_type generate_lpc_proof(std::size_t tree_depth, std::size_t round_proofs_n,
                                                  std::size_t degree) {
    typename LPCScheme::proof_type proof;

    proof.T_root =
        nil::crypto3::hash<typename LPCScheme::transcript_hash_type>(generate_random_data<std::uint8_t, 32>(1).at(0));

    nil::crypto3::random::algebraic_random_device<typename LPCScheme::field_type> d;
    for (std::size_t i = 0; i < proof.z.size(); ++i) {
        proof.z.at(i) = d();
    }

    for (std::size_t i = 0; i < LPCScheme::lambda; ++i) {
        proof.fri_proof.at(i) =
            generate_random_fri_proof<typename LPCScheme::fri_type>(tree_depth, round_proofs_n, degree);
    }

    return proof;
}

template<typename Field, typename Hash, std::size_t Lambda, std::size_t R, std::size_t M, std::size_t K, typename Endianness>
void test_lpc(std::size_t tree_depth, std::size_t round_proofs_n,
              std::size_t degree) {
    using namespace nil::crypto3::marshalling;

    using lpc_params_type = nil::crypto3::zk::snark::list_polynomial_commitment_params<Hash, Hash, Lambda, R, M>;
    using commitment_scheme_type = nil::crypto3::zk::snark::list_polynomial_commitment_scheme<Field, lpc_params_type, K>;
    using proof_marshalling_type =
        types::lpc_proof<nil::marshalling::field_type<Endianness>, commitment_scheme_type>;

    typename commitment_scheme_type::proof_type proof = generate_lpc_proof<commitment_scheme_type>(tree_depth, round_proofs_n,
                                                                                                   degree);

    auto filled_proof = types::fill_lpc_proof<commitment_scheme_type, Endianness>(proof);
    typename commitment_scheme_type::proof_type _proof =
        types::make_lpc_proof<commitment_scheme_type, Endianness>(filled_proof);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_proof.write(write_iter, cv.size());
//    std::cout << "LPC proof (" << cv.size() << " bytes): ";
//    for (auto c : cv) {
//        std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << int(c);
//    }
//    std::cout << std::endl << std::endl;

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    typename commitment_scheme_type::proof_type constructed_val_read =
        types::make_lpc_proof<commitment_scheme_type, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(lpc_test_suite)

BOOST_AUTO_TEST_CASE(lpc_bls12_381_be) {
    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;
    constexpr static const std::size_t d = 16;
    constexpr static const std::size_t r = boost::static_log2<(d - k)>::value;
    constexpr static const std::size_t m = 2;

    test_lpc<field_type, hash_type, lambda, r, m, k, nil::marshalling::option::big_endian>(5, 6, 7);
}

BOOST_AUTO_TEST_SUITE_END()

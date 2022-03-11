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
#include <random>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/fri.hpp>

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::hex << int(*it) << std::endl;
    }
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams> &e) {
    os << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp2<FieldParams> &e) {
    os << "[" << e.data[0].data << "," << e.data[1].data << "]" << std::endl;
}

template<typename ValueType, std::size_t N>
typename std::enable_if<std::is_unsigned<ValueType>::value, std::vector<std::array<ValueType, N>>>::type
    generate_random_data(std::size_t leaf_number) {
    std::random_device rd;
    std::vector<std::array<ValueType, N>> v;
    for (std::size_t i = 0; i < leaf_number; ++i) {
        std::array<ValueType, N> leaf;
        std::generate(std::begin(leaf), std::end(leaf),
                      [&]() { return rd() % (std::numeric_limits<ValueType>::max() + 1); });
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
    std::cout << "colinear_path_verifiable_data = hex\"";
    for (const auto c : data[idx]) {
        std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << int(c);
    }
    std::cout << "\";" << std::endl;


    std::cout << "p_verifiable_data" << " = [";
    for (std::size_t i = 0; i < proof.p.size(); ++i) {
        auto data = generate_random_data<std::uint8_t, 32>(leafs_number);
        typename FRIScheme::merkle_tree_type tree(data.cbegin(), data.cend());
        idx = rd() % leafs_number;
        typename FRIScheme::merkle_proof_type mp(tree, idx);
        proof.p.at(i) = mp;
        std::cout << "hex\"";
        for (const auto c : data[idx]) {
            std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << int(c);
        }
        std::cout << "\",";
    }
    std::cout << "];" << std::endl;

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

template<typename Field, typename Hash, typename Endianness>
void test_fri_round_proof(std::size_t tree_depth) {
    using namespace nil::crypto3::marshalling;

    using commitment_scheme_type = nil::crypto3::zk::commitments::fri<Field, Hash, Hash>;
    using proof_marshalling_type =
        types::fri_round_proof<nil::marshalling::field_type<Endianness>, commitment_scheme_type>;

    typename commitment_scheme_type::round_proof_type proof =
        generate_random_fri_round_proof<commitment_scheme_type>(tree_depth);

    auto filled_proof = types::fill_fri_round_proof<commitment_scheme_type, Endianness>(proof);
    typename commitment_scheme_type::round_proof_type _proof =
        types::make_fri_round_proof<commitment_scheme_type, Endianness>(filled_proof);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_proof.write(write_iter, cv.size());
//    std::cout << "FRI round proof (" << cv.size() << " bytes): ";
//    for (auto c : cv) {
//        std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << int(c);
//    }
//    std::cout << std::endl << std::endl;

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    typename commitment_scheme_type::round_proof_type constructed_val_read =
        types::make_fri_round_proof<commitment_scheme_type, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

template<typename Field, typename Hash, typename Endianness>
void test_fri_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree) {
    using namespace nil::crypto3::marshalling;

    using commitment_scheme_type = nil::crypto3::zk::commitments::fri<Field, Hash, Hash>;
    using proof_marshalling_type = types::fri_proof<nil::marshalling::field_type<Endianness>, commitment_scheme_type>;

    typename commitment_scheme_type::proof_type proof =
        generate_random_fri_proof<commitment_scheme_type>(tree_depth, round_proofs_n, degree);

    auto filled_proof = types::fill_fri_proof<commitment_scheme_type, Endianness>(proof);
    typename commitment_scheme_type::proof_type _proof =
        types::make_fri_proof<commitment_scheme_type, Endianness>(filled_proof);
    BOOST_CHECK(proof == _proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_proof.write(write_iter, cv.size());
//    std::cout << "FRI proof (" << cv.size() << " bytes): ";
//    for (auto c : cv) {
//        std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << int(c);
//    }
//    std::cout << std::endl << std::endl;

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    typename commitment_scheme_type::proof_type constructed_val_read =
        types::make_fri_proof<commitment_scheme_type, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(fri_test_suite)

BOOST_AUTO_TEST_CASE(fri_round_proof_bls12_381_be) {
    std::srand(std::time(0));
    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    test_fri_round_proof<field_type, hash_type, nil::marshalling::option::big_endian>(5);
}

BOOST_AUTO_TEST_CASE(fri_proof_bls12_381_be) {
    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    test_fri_proof<field_type, hash_type, nil::marshalling::option::big_endian>(5, 6, 7);
}

//BOOST_AUTO_TEST_CASE(fri_basic_test) {
//
//
//    // setup
//    using curve_type = nil::crypto3::algebra::curves::alt_bn128_254;
//    using field_type = typename curve_type::scalar_field_type;
//    using Endianness = nil::marshalling::option::big_endian;
//
//    typedef nil::crypto3::hashes::keccak_1600<256> merkle_hash_type;
//    typedef nil::crypto3::hashes::keccak_1600<256> transcript_hash_type;
//
//    typedef typename nil::crypto3::containers::merkle_tree<merkle_hash_type, 2> merkle_tree_type;
//
//    constexpr static const std::size_t d = 16;
//
//    constexpr static const std::size_t r = boost::static_log2<d>::value;
//    constexpr static const std::size_t m = 2;
//
//    typedef nil::crypto3::zk::commitments::fri<field_type, merkle_hash_type, transcript_hash_type, m> fri_type;
//    typedef typename fri_type::proof_type proof_type;
//    typedef typename fri_type::params_type params_type;
//    using proof_marshalling_type = nil::crypto3::marshalling::types::fri_proof<nil::marshalling::field_type<Endianness>, fri_type>;
//
//    params_type params;
//
//    constexpr static const std::size_t d_extended = d;
//    std::size_t extended_log = boost::static_log2<d_extended>::value;
//    std::vector<std::shared_ptr<nil::crypto3::math::evaluation_domain<field_type>>> D =
//        fri_type::calculate_domain_set(extended_log, r);
//
//    nil::crypto3::math::polynomial<typename field_type::value_type> q = {0, 0, 1};
//    params.r = r;
//    params.D = D;
//    params.q = q;
//    params.max_degree = d - 1;
//
////    for (std::size_t i = 1; i < 100000; i += 1000) {
//////        std::cout << "log_result = " << std::log2(i) << std::endl;
////        std::cout << "Assert.equal(" << std::ceil(std::log2(i)) << ", field_math.log2(i), \"Log2 result is not correct\");" << std::endl;
////        std::cout << "i += 1000;" << std::endl;
////    }
//
//    BOOST_CHECK(D[1]->m == D[0]->m / 2);
//    BOOST_CHECK(D[1]->get_domain_element(1) == D[0]->get_domain_element(1).squared());
//    BOOST_CHECK(params.q.evaluate(D[0]->get_domain_element(1)) == D[0]->get_domain_element(1).squared());
//
//    // commit
//    nil::crypto3::math::polynomial<typename field_type::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};
//
//    merkle_tree_type commit_merkle = fri_type::commit(f, D[0]);
//    std::array<typename field_type::value_type, 1> evaluation_points = {D[0]->get_domain_element(1).pow(5)};
//
//    // eval
//    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
//    nil::crypto3::zk::snark::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript(init_blob);
//
//    // LPC-related logic, here we "nulify" it via U = 0, V - 1
//    // TODO: Make FRI independent from LPC input
//    nil::crypto3::math::polynomial<typename field_type::value_type> U = {0};
//    nil::crypto3::math::polynomial<typename field_type::value_type> V = {1};
//
//    proof_type proof = fri_type::proof_eval(f, f, commit_merkle, transcript, params);
//
//    auto filled_proof = nil::crypto3::marshalling::types::fill_fri_proof<fri_type, Endianness>(proof);
//    std::vector<std::uint8_t> cv;
//    cv.resize(filled_proof.length(), 0x00);
//    auto write_iter = cv.begin();
//    nil::marshalling::status_type status = filled_proof.write(write_iter, cv.size());
//    std::cout << "params.r = " << params.r << ";" << std::endl;
//    std::cout << "params.max_degree = " << params.max_degree << ";" << std::endl;
//    std::size_t i = 0;
//    for (const auto &Di : params.D) {
//        std::cout << "D_omegas[" << i++ << "] = " << std::static_pointer_cast<nil::crypto3::math::basic_radix2_domain<field_type>>(Di)->omega.data << ";" << std::endl;
//    }
//    i = 0;
//    for (const auto &qi : params.q) {
//        std::cout << "q[" << i++ << "] = " << qi.data << ";" << std::endl;
//    }
//    std::cout << "FRI proof (" << cv.size() << " bytes): ";
//    for (auto c : cv) {
//        std::cout << std::setfill('0') << std::setw(2) << std::right << std::hex << int(c);
//    }
//    std::cout << std::dec << std::endl << std::endl;
//
//    // verify
//    nil::crypto3::zk::snark::fiat_shamir_heuristic_sequential<transcript_hash_type> transcript_verifier(init_blob);
//
//    BOOST_CHECK(fri_type::verify_eval(proof, transcript_verifier, params, U, V));
//
//    typename field_type::value_type verifier_next_challenge = transcript_verifier.template challenge<field_type>();
//    typename field_type::value_type prover_next_challenge = transcript.template challenge<field_type>();
//    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);
//}

BOOST_AUTO_TEST_SUITE_END()

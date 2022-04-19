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

#define BOOST_TEST_MODULE crypto3_marshalling_placeholder_proof_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/zk/types/placeholder/proof.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>

#include <../test/test_plonk_component.hpp>

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::endl << std::dec;
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp<FieldParams> &e,
                         bool endline = true) {
    os << e.data;
    if (endline) {
        os << std::endl;
    }
}

template<typename FieldParams>
void print_field_element(std::ostream &os,
                         const typename nil::crypto3::algebra::fields::detail::element_fp2<FieldParams> &e,
                         bool endline = true) {
    os << e.data[0].data << ", " << e.data[1].data;
    if (endline) {
        os << std::endl;
    }
}

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, nil::crypto3::algebra::curves::coordinates::affine>::value>::type
    print_curve_point(std::ostream &os,
                      const nil::crypto3::algebra::curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X, false);
    os << "], Y: [";
    print_field_element(os, p.Y, false);
    os << "] )" << std::endl;
}

template<typename CurveParams, typename Form, typename Coordinates>
typename std::enable_if<std::is_same<Coordinates, nil::crypto3::algebra::curves::coordinates::projective>::value ||
                        std::is_same<Coordinates, nil::crypto3::algebra::curves::coordinates::jacobian_with_a4_0>::value
                        // || std::is_same<Coordinates, nil::crypto3::algebra::curves::coordinates::inverted>::value
                        >::type
    print_curve_point(std::ostream &os,
                      const nil::crypto3::algebra::curves::detail::curve_element<CurveParams, Form, Coordinates> &p) {
    os << "( X: [";
    print_field_element(os, p.X, false);
    os << "], Y: [";
    print_field_element(os, p.Y, false);
    os << "], Z:[";
    print_field_element(os, p.Z, false);
    os << "] )" << std::endl;
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
                                                  std::size_t degree, std::size_t k) {
    typename LPCScheme::proof_type proof;

    proof.T_root =
        nil::crypto3::hash<typename LPCScheme::transcript_hash_type>(generate_random_data<std::uint8_t, 32>(1).at(0));

    nil::crypto3::random::algebraic_random_device<typename LPCScheme::field_type> d;
    for (std::size_t i = 0; i < k; ++i) {
        proof.z.push_back(d());
    }

    for (std::size_t i = 0; i < LPCScheme::lambda; ++i) {
        proof.fri_proof.at(i) =
            generate_random_fri_proof<typename LPCScheme::fri_type>(tree_depth, round_proofs_n, degree);
    }

    return proof;
}

template<typename Proof>
typename Proof::evaluation_proof generate_placeholder_eval_proof(std::size_t tree_depth, std::size_t round_proofs_n,
                                                                 std::size_t degree, std::size_t num, std::size_t k) {
    typename Proof::evaluation_proof eval_proof;

    nil::crypto3::random::algebraic_random_device<typename Proof::field_type> d;
    eval_proof.challenge = d();

    for (auto i = 0; i < num; ++i) {
        eval_proof.witness.emplace_back(
            generate_lpc_proof<typename Proof::commitment_scheme_type_witness>(tree_depth, round_proofs_n, degree, k));
        eval_proof.permutation.emplace_back(generate_lpc_proof<typename Proof::commitment_scheme_type_permutation>(
            tree_depth, round_proofs_n, degree, k));
        eval_proof.quotient.emplace_back(
            generate_lpc_proof<typename Proof::commitment_scheme_type_quotient>(tree_depth, round_proofs_n, degree, k));
        eval_proof.id_permutation.emplace_back(
            generate_lpc_proof<typename Proof::commitment_scheme_type_public>(tree_depth, round_proofs_n, degree, k));
        eval_proof.sigma_permutation.emplace_back(
            generate_lpc_proof<typename Proof::commitment_scheme_type_public>(tree_depth, round_proofs_n, degree, k));
        eval_proof.public_input.emplace_back(
            generate_lpc_proof<typename Proof::commitment_scheme_type_public>(tree_depth, round_proofs_n, degree, k));
        eval_proof.constant.emplace_back(
            generate_lpc_proof<typename Proof::commitment_scheme_type_public>(tree_depth, round_proofs_n, degree, k));
        eval_proof.selector.emplace_back(
            generate_lpc_proof<typename Proof::commitment_scheme_type_public>(tree_depth, round_proofs_n, degree, k));
        eval_proof.special_selectors.emplace_back(
            generate_lpc_proof<typename Proof::commitment_scheme_type_public>(tree_depth, round_proofs_n, degree, k));
    }

    return eval_proof;
}

template<typename Proof>
Proof generate_placeholder_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree,
                                 std::size_t num, std::size_t k) {
    Proof proof;
    std::size_t _i = 0;
    for (const auto c : generate_random_data<std::uint8_t, 32>(1)[0]) {
        proof.v_perm_commitment[_i++] = c;
    }
    proof.witness_commitments.resize(num);
    proof.T_commitments.resize(num);
    for (std::size_t i = 0; i < num; i++) {
        _i = 0;
        for (const auto c : generate_random_data<std::uint8_t, 32>(1)[0]) {
            proof.witness_commitments[i][_i++] = c;
        }
        _i = 0;
        for (const auto c : generate_random_data<std::uint8_t, 32>(1)[0]) {
            proof.T_commitments[i][_i++] = c;
        }
    }

    proof.eval_proof = generate_placeholder_eval_proof<Proof>(tree_depth, round_proofs_n, degree, num, k);
    return proof;
}

template<typename Proof, typename Endianness>
void test_placeholder_eval_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree,
                                 std::size_t num, std::size_t k) {
    using namespace nil::crypto3::marshalling;

    using proof_marshalling_type = types::placeholder_evaluation_proof<nil::marshalling::field_type<Endianness>, Proof>;

    auto proof = generate_placeholder_eval_proof<Proof>(tree_depth, round_proofs_n, degree, num, k);
    auto filled_placeholder_proof = types::fill_placeholder_evaluation_proof<Proof, Endianness>(proof);
    auto _proof = types::make_placeholder_evaluation_proof<Proof, Endianness>(filled_placeholder_proof);
    BOOST_CHECK(_proof == proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_placeholder_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_placeholder_proof.write(write_iter, cv.size());

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_placeholder_evaluation_proof<Proof, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

template<typename Proof, typename Endianness>
void test_random_placeholder_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree,
                                   std::size_t num, std::size_t k) {
    using namespace nil::crypto3::marshalling;

    using proof_marshalling_type = types::placeholder_proof<nil::marshalling::field_type<Endianness>, Proof>;

    Proof proof = generate_placeholder_proof<Proof>(tree_depth, round_proofs_n, degree, num, k);
    auto filled_placeholder_proof = types::fill_placeholder_proof<Proof, Endianness>(proof);
    Proof _proof = types::make_placeholder_proof<Proof, Endianness>(filled_placeholder_proof);
    BOOST_CHECK(_proof == proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_placeholder_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_placeholder_proof.write(write_iter, cv.size());

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_placeholder_proof<Proof, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

template<typename Endianness, typename Proof>
void test_placeholder_proof_marshalling(const Proof &proof) {
    using namespace nil::crypto3::marshalling;

    using proof_marshalling_type = types::placeholder_proof<nil::marshalling::field_type<Endianness>, Proof>;
    auto filled_placeholder_proof = types::fill_placeholder_proof<Proof, Endianness>(proof);
    Proof _proof = types::make_placeholder_proof<Proof, Endianness>(filled_placeholder_proof);
    BOOST_CHECK(_proof == proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_placeholder_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_placeholder_proof.write(write_iter, cv.size());
    std::cout << "proof (" << cv.size() << " bytes) = " << std::endl;
    std::ofstream proof_file;
    proof_file.open("placeholder_proof.txt");
    print_byteblob(proof_file, cv.cbegin(), cv.cend());

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_placeholder_proof<Proof, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(placeholder_marshalling_proof_test_suite)

BOOST_AUTO_TEST_CASE(placeholder_proof_pallas_unified_addition_be) {
    using Endianness = nil::marshalling::option::big_endian;
    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = zk::components::curve_element_unified_addition<ArithmetizationType, curve_type, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10>;

    auto P = algebra::random_element<curve_type::template g1_type<>>().to_affine();
    auto Q = algebra::random_element<curve_type::template g1_type<>>().to_affine();

    typename component_type::params_type params = {
        {var(0, 1, false, var::column_type::public_input), var(0, 2, false, var::column_type::public_input)},
        {var(0, 3, false, var::column_type::public_input), var(0, 4, false, var::column_type::public_input)}};

    std::vector<typename BlueprintFieldType::value_type> public_input = {0, P.X, P.Y, Q.X, Q.Y};

    auto proof = create_component_proof<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input);
    test_placeholder_proof_marshalling<Endianness>(proof);
}

BOOST_AUTO_TEST_SUITE_END()

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

#define BOOST_TEST_MODULE crypto3_marshalling_redshift_proof_test

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
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/zk/types/redshift/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

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

template<typename RedshiftProof>
typename RedshiftProof::evaluation_proof generate_redshift_eval_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree,
                                      std::size_t num) {
    typename RedshiftProof::evaluation_proof eval_proof;

    nil::crypto3::random::algebraic_random_device<typename RedshiftProof::field_type> d;
    eval_proof.challenge = d();

    for (auto i = 0; i < num; ++i) {
        eval_proof.witness.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_witness>(
            tree_depth, round_proofs_n, degree));
        eval_proof.permutation.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_permutation>(
            tree_depth, round_proofs_n, degree));
        eval_proof.quotient.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_quotient>(
            tree_depth, round_proofs_n, degree));
        eval_proof.id_permutation.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(
            tree_depth, round_proofs_n, degree));
        eval_proof.sigma_permutation.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(
            tree_depth, round_proofs_n, degree));
        eval_proof.public_input.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(
            tree_depth, round_proofs_n, degree));
        eval_proof.constant.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(
            tree_depth, round_proofs_n, degree));
        eval_proof.selector.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(
            tree_depth, round_proofs_n, degree));
        eval_proof.special_selectors.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(
            tree_depth, round_proofs_n, degree));
    }

    return eval_proof;
}

template<typename RedshiftProof>
RedshiftProof generate_redshift_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree,
                                 std::size_t num) {
    RedshiftProof proof;
    std::size_t k = 0;
    for (const auto c : generate_random_data<std::uint8_t, 32>(1)[0]) {
        proof.v_perm_commitment[k++] = c;
    }
    proof.witness_commitments.resize(num);
    proof.T_commitments.resize(num);
    for (std::size_t i = 0; i < num; i++) {
        k = 0;
        for (const auto c : generate_random_data<std::uint8_t, 32>(1)[0]) {
            proof.witness_commitments[i][k++] = c;
        }
        k = 0;
        for (const auto c : generate_random_data<std::uint8_t, 32>(1)[0]) {
            proof.T_commitments[i][k++] = c;
        }
    }

    proof.eval_proof = generate_redshift_eval_proof<RedshiftProof>(tree_depth,  round_proofs_n,  degree,
                                                       num);
    return proof;
}

template<typename RedshiftProof, typename Endianness>
void test_redshift_eval_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree,
                         std::size_t num) {
    using namespace nil::crypto3::marshalling;

    using proof_marshalling_type = types::redshift_evaluation_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>;

    auto proof = generate_redshift_eval_proof<RedshiftProof>(tree_depth,  round_proofs_n,  degree,
                                                                 num);
    auto filled_redshift_proof = types::fill_redshift_evaluation_proof<RedshiftProof, Endianness>(proof);
    auto _proof = types::make_redshift_evaluation_proof<RedshiftProof, Endianness>(filled_redshift_proof);
    BOOST_CHECK(_proof == proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_redshift_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_redshift_proof.write(write_iter, cv.size());

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_redshift_evaluation_proof<RedshiftProof, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

template<typename RedshiftProof, typename Endianness>
void test_redshift_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree,
                         std::size_t num) {
    using namespace nil::crypto3::marshalling;

    using proof_marshalling_type = types::redshift_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>;

    RedshiftProof proof = generate_redshift_proof<RedshiftProof>(tree_depth,  round_proofs_n,  degree,
                                                                  num);
    auto filled_redshift_proof = types::fill_redshift_proof<RedshiftProof, Endianness>(proof);
    RedshiftProof _proof = types::make_redshift_proof<RedshiftProof, Endianness>(filled_redshift_proof);
    BOOST_CHECK(_proof == proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_redshift_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_redshift_proof.write(write_iter, cv.size());

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_redshift_proof<RedshiftProof, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

constexpr static const std::size_t table_rows_log = 4;
struct redshift_test_params {
    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<512>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 2;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

BOOST_AUTO_TEST_SUITE(redshift_marshalling_proof_test_suite)

BOOST_AUTO_TEST_CASE(redshift_proof_bls12_381_be) {
    using curve_type = nil::crypto3::algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    constexpr static const std::size_t opening_points_witness = 1;
    constexpr static const std::size_t opening_points_v_p = 2;
    constexpr static const std::size_t opening_points_t = 1;
    constexpr static const std::size_t opening_points_public = 1;

    typedef nil::crypto3::zk::snark::redshift_params<field_type, redshift_test_params::witness_columns,
                            redshift_test_params::public_input_columns, redshift_test_params::constant_columns,
                            redshift_test_params::selector_columns> circuit_2_params;

    typedef nil::crypto3::zk::commitments::list_polynomial_commitment<field_type,
                                                    typename circuit_2_params::commitment_params_type,
                                                    opening_points_witness>
        commitment_scheme_witness_type;
    typedef nil::crypto3::zk::commitments::list_polynomial_commitment<field_type,
                                                    typename circuit_2_params::commitment_params_type,
                                                    opening_points_v_p>
        commitment_scheme_permutation_type;
    typedef nil::crypto3::zk::commitments::list_polynomial_commitment<field_type,
                                                    typename circuit_2_params::commitment_params_type,
                                                    opening_points_t>
        commitment_scheme_quotient_type;
    typedef nil::crypto3::zk::commitments::list_polynomial_commitment<field_type,
                                                    typename circuit_2_params::commitment_params_type,
                                                    opening_points_public>
        commitment_scheme_public_input_type;
    using proof_type = nil::crypto3::zk::snark::redshift_proof<
        field_type,
        commitment_scheme_witness_type,
        commitment_scheme_permutation_type,
        commitment_scheme_quotient_type,
        commitment_scheme_public_input_type>;

    test_redshift_eval_proof<proof_type, nil::marshalling::option::big_endian>(3, 3, 3, 3);
    test_redshift_proof<proof_type, nil::marshalling::option::big_endian>(3, 3, 3, 3);

}

BOOST_AUTO_TEST_SUITE_END()

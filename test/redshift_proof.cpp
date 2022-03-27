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
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/zk/types/redshift/proof.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::endl << std::dec;
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

template<typename RedshiftProof>
typename RedshiftProof::evaluation_proof generate_redshift_eval_proof(std::size_t tree_depth,
                                                                      std::size_t round_proofs_n, std::size_t degree,
                                                                      std::size_t num, std::size_t k) {
    typename RedshiftProof::evaluation_proof eval_proof;

    nil::crypto3::random::algebraic_random_device<typename RedshiftProof::field_type> d;
    eval_proof.challenge = d();

    for (auto i = 0; i < num; ++i) {
        eval_proof.witness.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_witness>(
            tree_depth, round_proofs_n, degree, k));
        eval_proof.permutation.emplace_back(
            generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_permutation>(tree_depth, round_proofs_n,
                                                                                           degree, k));
        eval_proof.quotient.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_quotient>(
            tree_depth, round_proofs_n, degree, k));
        eval_proof.id_permutation.emplace_back(
            generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(tree_depth, round_proofs_n,
                                                                                      degree, k));
        eval_proof.sigma_permutation.emplace_back(
            generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(tree_depth, round_proofs_n,
                                                                                      degree, k));
        eval_proof.public_input.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(
            tree_depth, round_proofs_n, degree, k));
        eval_proof.constant.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(
            tree_depth, round_proofs_n, degree, k));
        eval_proof.selector.emplace_back(generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(
            tree_depth, round_proofs_n, degree, k));
        eval_proof.special_selectors.emplace_back(
            generate_lpc_proof<typename RedshiftProof::commitment_scheme_type_public>(tree_depth, round_proofs_n,
                                                                                      degree, k));
    }

    return eval_proof;
}

template<typename RedshiftProof>
RedshiftProof generate_redshift_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree,
                                      std::size_t num, std::size_t k) {
    RedshiftProof proof;
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

    proof.eval_proof = generate_redshift_eval_proof<RedshiftProof>(tree_depth, round_proofs_n, degree, num, k);
    return proof;
}

template<typename RedshiftProof, typename Endianness>
void test_redshift_eval_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree, std::size_t num,
                              std::size_t k) {
    using namespace nil::crypto3::marshalling;

    using proof_marshalling_type =
        types::redshift_evaluation_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>;

    auto proof = generate_redshift_eval_proof<RedshiftProof>(tree_depth, round_proofs_n, degree, num, k);
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
void test_random_redshift_proof(std::size_t tree_depth, std::size_t round_proofs_n, std::size_t degree, std::size_t num,
                                std::size_t k) {
    using namespace nil::crypto3::marshalling;

    using proof_marshalling_type = types::redshift_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>;

    RedshiftProof proof = generate_redshift_proof<RedshiftProof>(tree_depth, round_proofs_n, degree, num, k);
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

template<typename Endianness, typename RedshiftProof>
void test_redshift_proof_marshalling(const RedshiftProof &proof) {
    using namespace nil::crypto3::marshalling;

    using proof_marshalling_type = types::redshift_proof<nil::marshalling::field_type<Endianness>, RedshiftProof>;

    auto filled_redshift_proof = types::fill_redshift_proof<RedshiftProof, Endianness>(proof);
    RedshiftProof _proof = types::make_redshift_proof<RedshiftProof, Endianness>(filled_redshift_proof);
    BOOST_CHECK(_proof == proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_redshift_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_redshift_proof.write(write_iter, cv.size());
    std::cout << "proof (" << cv.size() << " bytes) = ";
    // print_byteblob(std::cout, cv.cbegin(), cv.cend());

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

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log) {
    using namespace nil::crypto3;

    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    constexpr std::size_t expand_factor = 0;
    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        zk::commitments::detail::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.q = q;
    params.max_degree = (1 << degree_log) - 1;

    return params;
}

template<typename ComponentType, typename BlueprintFieldType, typename ArithmetizationParams, typename MerkleHashType,
         typename TranscriptHashType, std::size_t Lambda, typename Endianness>
void test_component_proof_marshalling(typename ComponentType::public_params_type init_params,
                                      typename ComponentType::private_params_type assignment_params) {

    using namespace nil::crypto3;

    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using component_type = ComponentType;

    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

    zk::blueprint<ArithmetizationType> bp(desc);
    zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);

    std::size_t start_row = component_type::allocate_rows(bp);
    component_type::generate_gates(bp, public_assignment, init_params, start_row);
    component_type::generate_copy_constraints(bp, public_assignment, init_params, start_row);
    component_type::generate_assignments(private_assignment, public_assignment, init_params, assignment_params,
                                         start_row);

    // bp.fix_usable_rows();
    private_assignment.padding();
    public_assignment.padding();
    std::cout << "Usable rows: " << desc.usable_rows_amount << std::endl;
    std::cout << "Padded rows: " << desc.rows_amount << std::endl;

    zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                             public_assignment);

    using params = zk::snark::redshift_params<BlueprintFieldType, ArithmetizationParams, MerkleHashType,
                                              TranscriptHashType, Lambda>;
    using types = zk::snark::detail::redshift_policy<BlueprintFieldType, params>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, typename params::merkle_hash_type,
                                                   typename params::transcript_hash_type, 2>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size = 12;

    typename types::preprocessed_public_data_type public_preprocessed_data =
        zk::snark::redshift_public_preprocessor<BlueprintFieldType, params>::process(bp, public_assignment, desc,
                                                                                     fri_params, permutation_size);
    typename types::preprocessed_private_data_type private_preprocessed_data =
        zk::snark::redshift_private_preprocessor<BlueprintFieldType, params>::process(bp, private_assignment, desc);

    auto proof = zk::snark::redshift_prover<BlueprintFieldType, params>::process(
        public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);
    using proof_marshalling_type =
        marshalling::types::redshift_proof<nil::marshalling::field_type<Endianness>, decltype(proof)>;
    test_redshift_proof_marshalling<Endianness>(proof);

    bool verifier_res = zk::snark::redshift_verifier<BlueprintFieldType, params>::process(public_preprocessed_data,
                                                                                          proof, bp, fri_params);
    BOOST_CHECK(verifier_res);
}

BOOST_AUTO_TEST_SUITE(redshift_marshalling_proof_test_suite)

BOOST_AUTO_TEST_CASE(redshift_proof_bls12_381_be) {
    using curve_type = nil::crypto3::algebra::curves::pallas;
    using FieldType = typename curve_type::base_field_type;

    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns,
                                                              SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<FieldType, ArithmetizationParams>;
    using component_type =
        nil::crypto3::zk::components::curve_element_unified_addition<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5,
                                                                     6, 7, 8, 9, 10>;

    using merkle_hash_type = nil::crypto3::hashes::keccak_1600<256>;
    using transcript_hash_type = nil::crypto3::hashes::keccak_1600<256>;

    typename component_type::public_params_type public_params = {};
    typename component_type::private_params_type private_params = {
        nil::crypto3::algebra::random_element<curve_type::template g1_type<>>(),
        nil::crypto3::algebra::random_element<curve_type::template g1_type<>>()};

    test_component_proof_marshalling<component_type, FieldType, ArithmetizationParams, merkle_hash_type,
                                     transcript_hash_type, 10, nil::marshalling::option::big_endian>(public_params,
                                                                                                     private_params);
}

BOOST_AUTO_TEST_SUITE_END()

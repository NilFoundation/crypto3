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

#include <nil/crypto3/marshalling/zk/types/redshift/proof.hpp>
#include <nil/crypto3/marshalling/zk/types/redshift/common_data.hpp>

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
    // using lpc_marshalling_type = types::lpc_proof<nil::marshalling::field_type<Endianness>, typename
    // RedshiftProof::commitment_scheme_type_witness>; using fri_marshalling_type =
    // types::fri_proof<nil::marshalling::field_type<Endianness>, typename
    // RedshiftProof::commitment_scheme_type_witness::fri_type>; auto filled_lpc = types::fill_lpc_proof<typename
    // RedshiftProof::commitment_scheme_type_witness, Endianness>(proof.eval_proof.witness[0]); auto filled_fri =
    // types::fill_fri_proof<typename RedshiftProof::commitment_scheme_type_witness::fri_type,
    // Endianness>(proof.eval_proof.witness[0].fri_proof[0]); std::vector<std::uint8_t> ccv;
    // ccv.resize(filled_lpc.length(), 0x00);
    // auto write_iterc = ccv.begin();
    // nil::marshalling::status_type cstatus = filled_lpc.write(write_iterc, ccv.size());
    // std::cout << "lpc (" << ccv.size() << " bytes) = " << std::endl;
    // ccv.resize(filled_fri.length(), 0x00);
    // write_iterc = ccv.begin();
    // cstatus = filled_lpc.write(write_iterc, ccv.size());
    // std::cout << "fri (" << ccv.size() << " bytes) = " << std::endl;

    auto filled_redshift_proof = types::fill_redshift_proof<RedshiftProof, Endianness>(proof);
    RedshiftProof _proof = types::make_redshift_proof<RedshiftProof, Endianness>(filled_redshift_proof);
    BOOST_CHECK(_proof == proof);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_redshift_proof.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_redshift_proof.write(write_iter, cv.size());
    std::cout << "proof (" << cv.size() << " bytes) = " << std::endl;
    std::ofstream proof_file;
    proof_file.open("redshift.txt");
    print_byteblob(proof_file, cv.cbegin(), cv.cend());

    proof_marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = types::make_redshift_proof<RedshiftProof, Endianness>(test_val_read);
    BOOST_CHECK(proof == constructed_val_read);
}

template<typename Endianness, typename RedshiftPolicy>
void test_redshift_common_data_marshalling(
    const typename RedshiftPolicy::preprocessed_public_data_type::common_data_type &common_data) {
    using namespace nil::crypto3::marshalling;

    using marshalling_type =
        types::redshift_verifier_common_data<nil::marshalling::field_type<Endianness>, RedshiftPolicy>;

    auto filled_val = types::fill_redshift_verifier_common_data<RedshiftPolicy, Endianness>(common_data);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_val.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_val.write(write_iter, cv.size());
    std::cout << "common_data (" << cv.size() << " bytes) = " << std::endl;
    std::ofstream proof_file;
    proof_file.open("common_data.txt");
    print_byteblob(proof_file, cv.cbegin(), cv.cend());
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

    std::cout << "fri_params.r = " << fri_params.r << std::endl;
    std::cout << "fri_params.max_degree = " << fri_params.max_degree << std::endl;
    std::cout << "fri_params.q = ";
    for (const auto &coeff : fri_params.q) {
        std::cout << coeff.data << ", ";
    }
    std::cout << std::endl;
    std::cout << "fri_params.D_omegas = ";
    for (const auto &dom : fri_params.D) {
        std::cout << static_cast<nil::crypto3::math::basic_radix2_domain<BlueprintFieldType> &>(*dom).omega.data
                  << ", ";
    }
    std::cout << std::endl;
    std::cout << "lpc_params.lambda = " << params::commitment_params_type::lambda << std::endl;
    std::cout << "lpc_params.m = " << params::commitment_params_type::m << std::endl;
    std::cout << "lpc_params.r = " << params::commitment_params_type::r << std::endl;
    std::cout << "common_data.rows_amount = " << public_preprocessed_data.common_data.rows_amount << std::endl;
    std::cout << "common_data.omega = "
              << static_cast<nil::crypto3::math::basic_radix2_domain<BlueprintFieldType> &>(
                     *public_preprocessed_data.common_data.basic_domain)
                     .omega.data
              << std::endl;
    std::cout << "columns_rotations (" << public_preprocessed_data.common_data.columns_rotations.size()
              << " number) = {" << std::endl;
    for (const auto &column_rotations : public_preprocessed_data.common_data.columns_rotations) {
        std::cout << "[";
        for (auto rot : column_rotations) {
            std::cout << int(rot) << ", ";
        }
        std::cout << "]," << std::endl;
    }
    std::cout << "}" << std::endl;
    auto proof = zk::snark::redshift_prover<BlueprintFieldType, params>::process(
        public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);
    using proof_marshalling_type =
        marshalling::types::redshift_proof<nil::marshalling::field_type<Endianness>, decltype(proof)>;
    test_redshift_proof_marshalling<Endianness>(proof);

    bool verifier_res = zk::snark::redshift_verifier<BlueprintFieldType, params>::process(public_preprocessed_data,
                                                                                          proof, bp, fri_params);
    BOOST_CHECK(verifier_res);

    test_redshift_common_data_marshalling<Endianness, types>(public_preprocessed_data.common_data);
}

BOOST_AUTO_TEST_SUITE(redshift_marshalling_proof_test_suite)

BOOST_AUTO_TEST_CASE(redshift_proof_pallas_unified_addition_be) {
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

    // auto P = nil::crypto3::algebra::random_element<curve_type::template g1_type<>>();
    // auto Q = nil::crypto3::algebra::random_element<curve_type::template g1_type<>>();
    // print_curve_point(std::cout, P);
    // print_curve_point(std::cout, Q);
    auto P = typename curve_type::template g1_type<>::value_type(
        typename FieldType::integral_type(
            "27051394659719220028518019675882008165050688997034652269377427647537907151531"),
        typename FieldType::integral_type(
            "21822416251756708135025948123768256435855398384772800303773249136047377552748"),
        typename FieldType::integral_type(
            "4513575749500539555089017060302131147770340137568767831860577667019486447126"));
    auto Q = typename curve_type::template g1_type<>::value_type(
        typename FieldType::integral_type(
            "27186088112168502962664987267099559313950899872804580248315246368032569661930"),
        typename FieldType::integral_type(
            "20390446623186344996164510355695306887861826808016772560867363266916574794339"),
        typename FieldType::integral_type(
            "13987831508602163988836506420714044551742920178521063041629360005595904804315"));

    typename component_type::public_params_type public_params = {};
    typename component_type::private_params_type private_params = {P, Q};

    test_component_proof_marshalling<component_type, FieldType, ArithmetizationParams, merkle_hash_type,
                                     transcript_hash_type, 1, nil::marshalling::option::big_endian>(public_params,
                                                                                                    private_params);
}

BOOST_AUTO_TEST_SUITE_END()

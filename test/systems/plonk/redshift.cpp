//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE redshift_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/gates_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include "nil/crypto3/zk/snark/systems/plonk/redshift/detail/redshift_policy.hpp"
#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/gate.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        zk::commitments::detail::calculate_domain_set<FieldType>(degree_log, degree_log - 1);

    params.r = degree_log - 1;
    params.D = domain_set;
    params.q = q;
    params.max_degree = (1 << degree_log) - 1;

    return params;
}

BOOST_AUTO_TEST_SUITE(redshift_prover_test_suite)

using curve_type = algebra::curves::bls12<381>;
using FieldType = typename curve_type::scalar_field_type;

// lpc params
constexpr static const std::size_t m = 2;
constexpr static const std::size_t k = 1;

constexpr static const std::size_t table_rows_log = 4;
constexpr static const std::size_t table_rows = 1 << table_rows_log;
constexpr static const std::size_t permutation_size = 4;
constexpr static const std::size_t usable_rows = 1 << table_rows_log;

struct redshift_test_params {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 2;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

constexpr static const std::size_t table_columns =
    redshift_test_params::witness_columns + redshift_test_params::public_input_columns;

typedef commitments::fri<FieldType, redshift_test_params::merkle_hash_type,
                              redshift_test_params::transcript_hash_type, m>
    fri_type;

typedef redshift_params<FieldType, redshift_test_params::witness_columns, 
    redshift_test_params::public_input_columns, redshift_test_params::constant_columns,
    redshift_test_params::selector_columns> circuit_2_params;


BOOST_AUTO_TEST_CASE(redshift_split_polynomial_test) {

    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};
    std::size_t expected_size = 4;
    std::size_t max_degree = 3;

    std::vector<math::polynomial<typename FieldType::value_type>> f_splitted =
                            zk::snark::detail::split_polynomial<FieldType>(f, max_degree);

    BOOST_CHECK(f_splitted.size() == expected_size);

    typename FieldType::value_type y = algebra::random_element<FieldType>();

    typename FieldType::value_type f_at_y = f.evaluate(y);
    typename FieldType::value_type f_splitted_at_y = FieldType::value_type::zero();
    for (std::size_t i = 0; i < f_splitted.size(); i++) {
        f_splitted_at_y = f_splitted_at_y + f_splitted[i].evaluate(y) * y.pow((max_degree + 1) * i);
    }

    BOOST_CHECK(f_at_y == f_splitted_at_y);
}

BOOST_AUTO_TEST_CASE(redshift_permutation_polynomials_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size, usable_rows> circuit =
        circuit_test_2<FieldType>();

    constexpr std::size_t argument_size = 3;

    using policy_type = zk::snark::detail::redshift_policy<FieldType, circuit_2_params>;

    constexpr static const std::size_t r = table_rows_log - 1;
    typedef commitments::list_polynomial_commitment<FieldType, circuit_2_params::commitment_params_type, k> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, table_rows, usable_rows);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename policy_type::preprocessed_public_data_type preprocessed_public_data =
        redshift_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), assignments.table_description(), fri_params, columns_with_copy_constraints.size());

    typename policy_type::preprocessed_private_data_type preprocessed_private_data =
        redshift_private_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.private_table());

    auto polynomial_table =
                            plonk_polynomial_table<FieldType, redshift_test_params::witness_columns,
                                redshift_test_params::public_input_columns, 
                                redshift_test_params::constant_columns,
                                redshift_test_params::selector_columns>(
                                preprocessed_private_data.private_polynomial_table,
                                preprocessed_public_data.public_polynomial_table);

    std::shared_ptr<math::evaluation_domain<FieldType>> domain = preprocessed_public_data.common_data.basic_domain;
    typename FieldType::value_type id_res = FieldType::value_type::one();
    typename FieldType::value_type sigma_res = FieldType::value_type::one();
    for (std::size_t i = 0; i < table_rows; i++) {
        for (std::size_t j = 0; j < preprocessed_public_data.identity_polynomials.size(); j++) {
            id_res = id_res * preprocessed_public_data.identity_polynomials[j].evaluate(domain->get_domain_element(i));
        } 

        for (std::size_t j = 0; j < preprocessed_public_data.permutation_polynomials.size(); j++) {
            sigma_res = sigma_res * preprocessed_public_data.permutation_polynomials[j].evaluate(domain->get_domain_element(i));
        }
    }
    BOOST_CHECK_MESSAGE(id_res == sigma_res, "Simple check");

    typename FieldType::value_type beta = algebra::random_element<FieldType>();
    typename FieldType::value_type gamma = algebra::random_element<FieldType>();

    id_res = FieldType::value_type::one();
    sigma_res = FieldType::value_type::one();

    for (std::size_t i = 0; i < table_rows; i++) {
        for (std::size_t j = 0; j < preprocessed_public_data.identity_polynomials.size(); j++) {
            id_res = id_res * (
                            polynomial_table[j].evaluate(domain->get_domain_element(i)) +
                            beta * preprocessed_public_data.identity_polynomials[j].evaluate(domain->get_domain_element(i))
                            + gamma);
        } 

        for (std::size_t j = 0; j < preprocessed_public_data.permutation_polynomials.size(); j++) {
            sigma_res = sigma_res * (
                            polynomial_table[j].evaluate(domain->get_domain_element(i)) +
                            beta * preprocessed_public_data.permutation_polynomials[j].evaluate(domain->get_domain_element(i))
                            + gamma);
        } 
    }
    BOOST_CHECK_MESSAGE(id_res == sigma_res, "Complex check");
}

BOOST_AUTO_TEST_CASE(redshift_permutation_argument_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size, usable_rows> circuit =
        circuit_test_2<FieldType>();

    constexpr std::size_t argument_size = 3;

    using policy_type = zk::snark::detail::redshift_policy<FieldType, circuit_2_params>;

    constexpr static const std::size_t r = table_rows_log - 1;
    typedef commitments::list_polynomial_commitment<FieldType, circuit_2_params::commitment_params_type, k> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, table_rows, usable_rows);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename policy_type::preprocessed_public_data_type preprocessed_public_data =
        redshift_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), assignments.table_description(), fri_params, columns_with_copy_constraints.size());

    typename policy_type::preprocessed_private_data_type preprocessed_private_data =
        redshift_private_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.private_table());

    auto polynomial_table =
                            plonk_polynomial_table<FieldType, redshift_test_params::witness_columns,
                                redshift_test_params::public_input_columns, 
                                redshift_test_params::constant_columns,
                                redshift_test_params::selector_columns>(
                                preprocessed_private_data.private_polynomial_table,
                                preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<redshift_test_params::transcript_hash_type> prover_transcript(init_blob);
    transcript::fiat_shamir_heuristic_sequential<redshift_test_params::transcript_hash_type> verifier_transcript(init_blob);

    typename redshift_permutation_argument<FieldType, lpc_type, lpc_type, circuit_2_params>::prover_result_type
        prover_res = redshift_permutation_argument<FieldType, lpc_type, lpc_type, circuit_2_params>::prove_eval(
            constraint_system, preprocessed_public_data, polynomial_table, fri_params, prover_transcript);

    // Challenge phase
    typename FieldType::value_type y = algebra::random_element<FieldType>();
    std::vector<typename FieldType::value_type> f_at_y(permutation_size);
    for (int i = 0; i < permutation_size; i++) {
        f_at_y[i] = polynomial_table[i].evaluate(y);
    }

    typename FieldType::value_type v_p_at_y = prover_res.permutation_polynomial.evaluate(y);
    typename FieldType::value_type v_p_at_y_shifted = prover_res.permutation_polynomial.evaluate(circuit.omega * y);

    std::array<typename FieldType::value_type, 3> verifier_res =
        redshift_permutation_argument<FieldType, lpc_type, lpc_type, circuit_2_params>::verify_eval(
            preprocessed_public_data, y, f_at_y, v_p_at_y, v_p_at_y_shifted,
            prover_res.permutation_poly_precommitment.root(),
            verifier_transcript);

    typename FieldType::value_type verifier_next_challenge = verifier_transcript.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = prover_transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    for (int i = 0; i < argument_size; i++) {
        BOOST_CHECK(prover_res.F[i].evaluate(y) == verifier_res[i]);
    }
}


BOOST_AUTO_TEST_CASE(redshift_lookup_argument_test) {

    // zk::snark::redshift_preprocessor<typename curve_type::base_field_type, 5, 2> preprocess;

    // auto preprocessed_data = preprocess::process(cs, assignments);
    // zk::snark::redshift_prover<typename curve_type::base_field_type, 5, 2, 2, 2> prove;
}

BOOST_AUTO_TEST_CASE(redshift_gate_argument_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size, usable_rows> circuit =
        circuit_test_2<FieldType>();

    using policy_type = zk::snark::detail::redshift_policy<FieldType, circuit_2_params>;

    constexpr static const std::size_t r = table_rows_log - 1;
    typedef commitments::list_polynomial_commitment<FieldType, circuit_2_params::commitment_params_type, k> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, table_rows, usable_rows);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename policy_type::preprocessed_public_data_type preprocessed_public_data =
        redshift_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), assignments.table_description(), fri_params, columns_with_copy_constraints.size());

    typename policy_type::preprocessed_private_data_type preprocessed_private_data =
        redshift_private_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.private_table());

    auto polynomial_table =
                            plonk_polynomial_table<FieldType, redshift_test_params::witness_columns,
                                redshift_test_params::public_input_columns, 
                                redshift_test_params::constant_columns,
                                redshift_test_params::selector_columns>(
                                preprocessed_private_data.private_polynomial_table,
                                preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<redshift_test_params::transcript_hash_type> prover_transcript(init_blob);
    transcript::fiat_shamir_heuristic_sequential<redshift_test_params::transcript_hash_type> verifier_transcript(init_blob);

    std::array<math::polynomial<typename FieldType::value_type>, 1> prover_res =
        redshift_gates_argument<FieldType, circuit_2_params>::prove_eval(constraint_system, polynomial_table,
                                                                         prover_transcript);

    // Challenge phase
    typename FieldType::value_type y = algebra::random_element<FieldType>();

    typename policy_type::evaluation_map columns_at_y;
    for (std::size_t i = 0; i < redshift_test_params::witness_columns; i++) {
        auto key = std::make_tuple(i, plonk_variable<FieldType>::rotation_type::current,
                                   plonk_variable<FieldType>::column_type::witness);
        columns_at_y[key] = polynomial_table.witness(i).evaluate(y);
    }

    std::array<typename FieldType::value_type, 1> verifier_res =
        redshift_gates_argument<FieldType, circuit_2_params>::verify_eval(constraint_system.gates(), preprocessed_public_data.public_polynomial_table, columns_at_y, y,
                                                                          verifier_transcript);

    typename FieldType::value_type verifier_next_challenge = verifier_transcript.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = prover_transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    BOOST_CHECK(prover_res[0].evaluate(y) == verifier_res[0]);
}

BOOST_AUTO_TEST_CASE(redshift_prover_basic_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size, usable_rows> circuit =
        circuit_test_2<FieldType>();

    using policy_type = zk::snark::detail::redshift_policy<FieldType, circuit_2_params>;

    typedef commitments::list_polynomial_commitment<FieldType, circuit_2_params::commitment_params_type, k> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, table_rows, usable_rows);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename policy_type::preprocessed_public_data_type preprocessed_public_data =
        redshift_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), assignments.table_description(), fri_params, columns_with_copy_constraints.size());

    typename policy_type::preprocessed_private_data_type preprocessed_private_data =
        redshift_private_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.private_table());
    
    auto proof = redshift_prover<FieldType, circuit_2_params>::process(preprocessed_public_data,
                                                                       preprocessed_private_data, constraint_system,
                                                                       assignments, fri_params);

    bool verifier_res = redshift_verifier<FieldType, circuit_2_params>::process(preprocessed_public_data, proof, 
                                                                        constraint_system, fri_params);
    BOOST_CHECK(verifier_res);
}

BOOST_AUTO_TEST_SUITE_END()
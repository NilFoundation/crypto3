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
#include <nil/crypto3/zk/snark/relations/plonk/permutation.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/commitments/fri.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        fri_type::calculate_domain_set(degree_log, degree_log - 1);

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
    constexpr static const std::size_t public_columns = 1;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

constexpr static const std::size_t table_columns =
    redshift_test_params::witness_columns + redshift_test_params::public_columns;

typedef fri_commitment_scheme<FieldType, redshift_test_params::merkle_hash_type,
                              redshift_test_params::transcript_hash_type, m>
    fri_type;

typedef redshift_params<3, 1> circuit_2_params;

BOOST_AUTO_TEST_CASE(redshift_prover_basic_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size, usable_rows> circuit =
        circuit_test_2<FieldType>();

    using policy_type = zk::snark::detail::redshift_policy<FieldType, circuit_2_params>;

    typedef list_polynomial_commitment_scheme<FieldType, circuit_2_params::commitment_params_type, k> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    typename policy_type::constraint_system_type constraint_system({}, table_rows);

    typename policy_type::variable_assignment_type assigments = circuit.table;

    policy_type::circuit_short_description<lpc_type> short_description;
    short_description.columns_with_copy_constraints = {0, 1, 2, 3};
    short_description.table_rows = table_rows;
    short_description.usable_rows = usable_rows;
    short_description.delta = circuit.delta;
    short_description.permutation = circuit.permutation;

    typename policy_type::preprocessed_public_data_type preprocessed_public_data =
        redshift_public_preprocessor<FieldType, circuit_2_params, k>::process(
            constraint_system, assigments.public_table(), short_description);

    typename policy_type::preprocessed_private_data_type preprocessed_private_data =
        redshift_private_preprocessor<FieldType, circuit_2_params, k>::process(
            constraint_system, assigments.private_table(), short_description);
    
    auto proof = redshift_prover<FieldType, circuit_2_params>::process(preprocessed_public_data,
                                                                       preprocessed_private_data, constraint_system,
                                                                       assigments, short_description, fri_params);

    bool verifier_res = redshift_verifier<FieldType, circuit_2_params>::process(proof, short_description);
    BOOST_CHECK(verifier_res);
}

BOOST_AUTO_TEST_CASE(redshift_permutation_argument_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size, usable_rows> circuit =
        circuit_test_2<FieldType>();

    constexpr std::size_t argument_size = 3;

    using policy_type = zk::snark::detail::redshift_policy<FieldType, circuit_2_params>;

    constexpr static const std::size_t r = table_rows_log - 1;
    typedef list_polynomial_commitment_scheme<FieldType, circuit_2_params::commitment_params_type, k> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    typename policy_type::constraint_system_type constraint_system({}, table_rows);
    typename policy_type::variable_assignment_type assigments = circuit.table;

    policy_type::circuit_short_description<lpc_type> short_description;
    short_description.columns_with_copy_constraints = {0, 1, 2, 3};
    short_description.table_rows = table_rows;
    short_description.usable_rows = usable_rows;
    short_description.delta = circuit.delta;
    short_description.permutation = circuit.permutation;

    typename policy_type::preprocessed_public_data_type preprocessed_public_data =
        redshift_public_preprocessor<FieldType, circuit_2_params, k>::process(
            constraint_system, assigments.public_table(), short_description);

    typename policy_type::preprocessed_private_data_type preprocessed_private_data =
        redshift_private_preprocessor<FieldType, circuit_2_params, k>::process(
            constraint_system, assigments.private_table(), short_description);

    plonk_polynomial_table<FieldType, circuit_2_params::witness_columns> polynomial_table =
                            plonk_polynomial_table<FieldType, circuit_2_params::witness_columns>(
                                preprocessed_private_data.private_polynomial_table,
                                preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    fiat_shamir_heuristic_sequential<redshift_test_params::transcript_hash_type> prover_transcript(init_blob);
    fiat_shamir_heuristic_sequential<redshift_test_params::transcript_hash_type> verifier_transcript(init_blob);

    typename redshift_permutation_argument<FieldType, lpc_type, lpc_type, circuit_2_params>::prover_result_type
        prover_res = redshift_permutation_argument<FieldType, lpc_type, lpc_type, circuit_2_params>::prove_eval(
            prover_transcript, preprocessed_public_data, short_description, polynomial_table, fri_params);

    // Challenge phase
    typename FieldType::value_type y = algebra::random_element<FieldType>();
    std::vector<typename FieldType::value_type> f_at_y(permutation_size);
    for (int i = 0; i < permutation_size; i++) {
        f_at_y[i] = circuit.column_polynomials[i].evaluate(y);
    }

    typename FieldType::value_type v_p_at_y = prover_res.permutation_polynomial.evaluate(y);
    typename FieldType::value_type v_p_at_y_shifted = prover_res.permutation_polynomial.evaluate(circuit.omega * y);

    std::array<typename FieldType::value_type, 3> verifier_res =
        redshift_permutation_argument<FieldType, lpc_type, lpc_type, circuit_2_params>::verify_eval(
            verifier_transcript, preprocessed_public_data, short_description, y, f_at_y, v_p_at_y, v_p_at_y_shifted,
            prover_res.permutation_poly_commitment.root());

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
    typedef list_polynomial_commitment_scheme<FieldType, circuit_2_params::commitment_params_type, k> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    typename policy_type::constraint_system_type constraint_system(circuit.gates, table_rows);
    typename policy_type::variable_assignment_type assigments = circuit.table;

    policy_type::circuit_short_description<lpc_type> short_description;
    short_description.columns_with_copy_constraints = {0, 1, 2, 3};
    short_description.table_rows = table_rows;
    short_description.usable_rows = usable_rows;
    short_description.delta = circuit.delta;
    short_description.permutation = circuit.permutation;

    typename policy_type::preprocessed_public_data_type preprocessed_public_data =
        redshift_public_preprocessor<FieldType, circuit_2_params, k>::process(
            constraint_system, assigments.public_table(), short_description);

    typename policy_type::preprocessed_private_data_type preprocessed_private_data =
        redshift_private_preprocessor<FieldType, circuit_2_params, k>::process(
            constraint_system, assigments.private_table(), short_description);

    plonk_polynomial_table<FieldType, circuit_2_params::witness_columns> polynomial_table =
                            plonk_polynomial_table<FieldType, circuit_2_params::witness_columns>(
                                preprocessed_private_data.private_polynomial_table,
                                preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    fiat_shamir_heuristic_sequential<redshift_test_params::transcript_hash_type> prover_transcript(init_blob);
    fiat_shamir_heuristic_sequential<redshift_test_params::transcript_hash_type> verifier_transcript(init_blob);

    std::array<math::polynomial<typename FieldType::value_type>, 1> prover_res =
        redshift_gates_argument<FieldType, circuit_2_params>::prove_eval(constraint_system, polynomial_table,
                                                                         prover_transcript);

    // Challenge phase
    typename FieldType::value_type y = algebra::random_element<FieldType>();

    typename policy_type::evaluation_map columns_at_y;
    for (int i = 0; i < table_columns; i++) {
        auto key = std::make_tuple(i, plonk_variable<FieldType>::rotation_type::current,
                                   plonk_variable<FieldType>::column_type::witness);
        columns_at_y[key] = circuit.column_polynomials[i].evaluate(y);
    }

    std::array<typename FieldType::value_type, 1> verifier_res =
        redshift_gates_argument<FieldType, circuit_2_params>::verify_eval(circuit.gates, columns_at_y, y,
                                                                          verifier_transcript);

    typename FieldType::value_type verifier_next_challenge = verifier_transcript.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = prover_transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    BOOST_CHECK(prover_res[0].evaluate(y) == verifier_res[0]);
}

BOOST_AUTO_TEST_SUITE_END()
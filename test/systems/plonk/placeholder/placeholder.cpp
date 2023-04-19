//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#define BOOST_TEST_MODULE placeholder_test

#include <string>
#include <random>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
// #include <nil/crypto3/zk/snark/systems/plonk/placeholder/gates_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
    using dist_type = std::uniform_int_distribution<int>;
    static std::random_device random_engine;

    std::vector<std::size_t> step_list;
    std::size_t steps_sum = 0;
    while (steps_sum != r) {
        if (r - steps_sum <= max_step) {
            while (r - steps_sum != 1) {
                step_list.emplace_back(r - steps_sum - 1);
                steps_sum += step_list.back();
            }
            step_list.emplace_back(1);
            steps_sum += step_list.back();
        } else {
            step_list.emplace_back(dist_type(1, max_step)(random_engine));
            steps_sum += step_list.back();
        }
    }
    return step_list;
}

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log, const int max_step = 1) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    constexpr std::size_t expand_factor = 4;

    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.max_degree = (1 << degree_log) - 1;
    params.step_list = generate_random_step_list(r, max_step);

    return params;
}

BOOST_AUTO_TEST_SUITE(placeholder_prover_test_suite)

// using curve_type = algebra::curves::bls12<381>;
using curve_type = algebra::curves::pallas;
using FieldType = typename curve_type::base_field_type;

// lpc params
constexpr static const std::size_t m = 2;

constexpr static const std::size_t table_rows_log = 4;
constexpr static const std::size_t table_rows = 1 << table_rows_log;
constexpr static const std::size_t permutation_size = 4;
constexpr static const std::size_t usable_rows = (1 << table_rows_log) - 3;

struct placeholder_test_params {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 1;
    constexpr static const std::size_t constant_columns = 0;
    constexpr static const std::size_t selector_columns = 2;

    using arithmetization_params =
        plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

struct placeholder_test_params_lookups {
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    constexpr static const std::size_t witness_columns = 3;
    constexpr static const std::size_t public_input_columns = 0;
    constexpr static const std::size_t constant_columns = 3;
    constexpr static const std::size_t selector_columns = 1;

    using arithmetization_params =
        plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t r = table_rows_log - 1;
    constexpr static const std::size_t m = 2;
};

constexpr static const std::size_t table_columns =
    placeholder_test_params::witness_columns + placeholder_test_params::public_input_columns;

typedef commitments::fri<
    FieldType, 
    placeholder_test_params::merkle_hash_type,
    placeholder_test_params::transcript_hash_type, 
    placeholder_test_params::lambda, m, 4
> fri_type;

typedef placeholder_params<FieldType, typename placeholder_test_params::arithmetization_params> circuit_2_params;
typedef placeholder_params<FieldType, typename placeholder_test_params_lookups::arithmetization_params>
    circuit_3_params;

BOOST_AUTO_TEST_CASE(placeholder_split_polynomial_test) {

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

BOOST_AUTO_TEST_CASE(placeholder_permutation_polynomials_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size> circuit =
        circuit_test_2<FieldType>();

    constexpr std::size_t argument_size = 3;

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_2_params>;

    typedef commitments::list_polynomial_commitment<FieldType, circuit_2_params::batched_commitment_params_type>
        lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_2_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), desc, fri_params, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.private_table(), desc, fri_params);

    auto polynomial_table =
        plonk_polynomial_dfs_table<FieldType, typename placeholder_test_params::arithmetization_params>(
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table);

    std::shared_ptr<math::evaluation_domain<FieldType>> domain = preprocessed_public_data.common_data.basic_domain;
    typename FieldType::value_type id_res = FieldType::value_type::one();
    typename FieldType::value_type sigma_res = FieldType::value_type::one();
    for (std::size_t i = 0; i < table_rows; i++) {
        for (auto &identity_polynomial : preprocessed_public_data.identity_polynomials) {
            id_res = id_res * identity_polynomial.evaluate(domain->get_domain_element(i));
        }

        for (auto &permutation_polynomial : preprocessed_public_data.permutation_polynomials) {
            sigma_res = sigma_res * permutation_polynomial.evaluate(domain->get_domain_element(i));
        }
    }
    BOOST_CHECK_MESSAGE(id_res == sigma_res, "Simple check");

    typename FieldType::value_type beta = algebra::random_element<FieldType>();
    typename FieldType::value_type gamma = algebra::random_element<FieldType>();

    id_res = FieldType::value_type::one();
    sigma_res = FieldType::value_type::one();

    for (std::size_t i = 0; i < table_rows; i++) {
        for (std::size_t j = 0; j < preprocessed_public_data.identity_polynomials.size(); j++) {
            id_res = id_res *
                     (polynomial_table[j].evaluate(domain->get_domain_element(i)) +
                      beta * preprocessed_public_data.identity_polynomials[j].evaluate(domain->get_domain_element(i)) +
                      gamma);
        }

        for (std::size_t j = 0; j < preprocessed_public_data.permutation_polynomials.size(); j++) {
            sigma_res =
                sigma_res *
                (polynomial_table[j].evaluate(domain->get_domain_element(i)) +
                 beta * preprocessed_public_data.permutation_polynomials[j].evaluate(domain->get_domain_element(i)) +
                 gamma);
        }
    }
    BOOST_CHECK_MESSAGE(id_res == sigma_res, "Complex check");
}

BOOST_AUTO_TEST_CASE(placeholder_permutation_argument_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size> circuit =
        circuit_test_2<FieldType>();

    constexpr std::size_t argument_size = 3;

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_2_params>;

    typedef commitments::list_polynomial_commitment<FieldType, circuit_2_params::batched_commitment_params_type>
        lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_2_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), desc, fri_params, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.private_table(), desc, fri_params);

    auto polynomial_table =
        plonk_polynomial_dfs_table<FieldType, typename placeholder_test_params::arithmetization_params>(
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> prover_transcript(
        init_blob);
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> verifier_transcript(
        init_blob);

    typename placeholder_permutation_argument<FieldType, circuit_2_params>::prover_result_type prover_res =
        placeholder_permutation_argument<FieldType, circuit_2_params>::prove_eval(
            constraint_system, preprocessed_public_data, desc, polynomial_table, fri_params, prover_transcript);

    // Challenge phase
    typename FieldType::value_type y = algebra::random_element<FieldType>();
    std::vector<typename FieldType::value_type> f_at_y(permutation_size);
    for (int i = 0; i < permutation_size; i++) {
        f_at_y[i] = polynomial_table[i].evaluate(y);
    }

    typename FieldType::value_type v_p_at_y = prover_res.permutation_polynomial_dfs.evaluate(y);
    typename FieldType::value_type v_p_at_y_shifted = prover_res.permutation_polynomial_dfs.evaluate(circuit.omega * y);

    std::array<typename FieldType::value_type, 3> verifier_res =
        placeholder_permutation_argument<FieldType, circuit_2_params>::verify_eval(
            preprocessed_public_data, y, f_at_y, v_p_at_y, v_p_at_y_shifted,
            prover_res.permutation_poly_precommitment.root(), verifier_transcript);

    typename FieldType::value_type verifier_next_challenge = verifier_transcript.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = prover_transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    for (int i = 0; i < argument_size; i++) {
        BOOST_CHECK(prover_res.F_dfs[i].evaluate(y) == verifier_res[i]);
        for (std::size_t j = 0; j < desc.rows_amount; j++) {
            BOOST_CHECK(prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(
                            j)) == FieldType::value_type::zero());
        }
    }
}

BOOST_AUTO_TEST_CASE(placeholder_lookup_argument_test, *boost::unit_test::disabled()) {

    circuit_description<FieldType, circuit_3_params, table_rows_log, 3> circuit = circuit_test_3<FieldType>();

    constexpr std::size_t argument_size = 5;

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_3_params>;

    typedef commitments::list_polynomial_commitment<FieldType,
        circuit_3_params::batched_commitment_params_type> lpc_type;
    //typedef commitments::lpc<FieldType, circuit_3_params::batched_commitment_params_type> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_3_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename placeholder_public_preprocessor<FieldType, circuit_3_params>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<FieldType, circuit_3_params>::process(
            constraint_system, assignments.public_table(), desc, fri_params, 0);

    typename placeholder_private_preprocessor<FieldType, circuit_3_params>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<FieldType, circuit_3_params>::process(
            constraint_system, assignments.private_table(), desc, fri_params);

    auto polynomial_table =
        plonk_polynomial_dfs_table<FieldType, typename placeholder_test_params_lookups::arithmetization_params>(
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params_lookups::transcript_hash_type>
        prover_transcript(init_blob);
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params_lookups::transcript_hash_type>
        verifier_transcript(init_blob);

    typename placeholder_lookup_argument<FieldType, lpc_type, circuit_3_params>::prover_lookup_result prover_res =
        placeholder_lookup_argument<FieldType, lpc_type, circuit_3_params>::prove_eval(
            constraint_system, preprocessed_public_data, assignments, fri_params, prover_transcript
    );

    // Challenge phase
    typename FieldType::value_type y = algebra::random_element<FieldType>();
    typename policy_type::evaluation_map columns_at_y;
    for (std::size_t i = 0; i < placeholder_test_params::witness_columns; i++) {

        std::size_t i_global_index = i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<FieldType>::column_type::witness);
            columns_at_y[key] = polynomial_table.witness(i).evaluate(y * circuit.omega.pow(rotation));
        }
    }
    for (std::size_t i = 0; i < 0 + placeholder_test_params_lookups::constant_columns; i++) {

        std::size_t i_global_index = placeholder_test_params_lookups::witness_columns +
                                     placeholder_test_params_lookups::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<FieldType>::column_type::constant);

            columns_at_y[key] = polynomial_table.constant(i).evaluate(y * circuit.omega.pow(rotation));
        }
    }
    for (std::size_t i = 0; i < placeholder_test_params_lookups::selector_columns; i++) {

        std::size_t i_global_index = placeholder_test_params_lookups::witness_columns +
                                     placeholder_test_params_lookups::constant_columns +
                                     placeholder_test_params_lookups::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<FieldType>::column_type::selector);

            columns_at_y[key] = polynomial_table.selector(i).evaluate(y * circuit.omega.pow(rotation));
        }
    }

    typename FieldType::value_type input_at_y = prover_res.input_polynomial.evaluate(y);
    typename FieldType::value_type input_at_y_shifted =
        prover_res.input_polynomial.evaluate(circuit.omega.inversed() * y);

    typename FieldType::value_type value_at_y = prover_res.value_polynomial.evaluate(y);

    typename FieldType::value_type v_l_at_y = prover_res.V_L_polynomial.evaluate(y);
    typename FieldType::value_type v_l_at_y_shifted = prover_res.V_L_polynomial.evaluate(circuit.omega * y);

    std::array<typename FieldType::value_type, 5> verifier_res =
        placeholder_lookup_argument<FieldType, lpc_type, circuit_3_params>::verify_eval(
            preprocessed_public_data, constraint_system.lookup_gates(), y, columns_at_y, input_at_y, input_at_y_shifted,
            value_at_y, v_l_at_y, v_l_at_y_shifted, prover_res.input_precommitment.root(),
            prover_res.value_precommitment.root(), prover_res.V_L_precommitment.root(), verifier_transcript);

    typename FieldType::value_type verifier_next_challenge = verifier_transcript.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = prover_transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    for (int i = 0; i < argument_size; i++) {
        BOOST_CHECK(prover_res.F[i].evaluate(y) == verifier_res[i]);
        for (std::size_t j = 0; j < desc.rows_amount; j++) {
            BOOST_CHECK(prover_res.F[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(
                            j)) == FieldType::value_type::zero());
        }
    }
}

BOOST_AUTO_TEST_CASE(placeholder_gate_argument_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size> circuit =
        circuit_test_2<FieldType>();

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_2_params>;

    typedef commitments::list_polynomial_commitment<FieldType, circuit_2_params::commitment_params_type> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_2_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), desc, fri_params, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.private_table(), desc, fri_params);

    auto polynomial_table =
        plonk_polynomial_dfs_table<FieldType, typename placeholder_test_params::arithmetization_params>(
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> prover_transcript(
        init_blob);
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> verifier_transcript(
        init_blob);

    std::array<math::polynomial_dfs<typename FieldType::value_type>, 1> prover_res =
        placeholder_gates_argument<FieldType, circuit_2_params>::prove_eval(
            constraint_system, polynomial_table, preprocessed_public_data.common_data.basic_domain,
            preprocessed_public_data.common_data.max_gates_degree, prover_transcript);

    // Challenge phase
    typename FieldType::value_type y = algebra::random_element<FieldType>();
    typename FieldType::value_type omega = preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

    typename policy_type::evaluation_map columns_at_y;
    for (std::size_t i = 0; i < placeholder_test_params::witness_columns; i++) {

        std::size_t i_global_index = i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<FieldType>::column_type::witness);
            columns_at_y[key] = polynomial_table.witness(i).evaluate(y * omega.pow(rotation));
        }
    }
    for (std::size_t i = 0; i < 0 + placeholder_test_params::public_input_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {

            auto key = std::make_tuple(i, rotation, plonk_variable<FieldType>::column_type::public_input);

            columns_at_y[key] = polynomial_table.public_input(i).evaluate(y * omega.pow(rotation));
        }
    }
    for (std::size_t i = 0; i < 0 + placeholder_test_params::constant_columns; i++) {

        std::size_t i_global_index =
            placeholder_test_params::witness_columns + placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<FieldType>::column_type::constant);

            columns_at_y[key] = polynomial_table.constant(i).evaluate(y * omega.pow(rotation));
        }
    }
    for (std::size_t i = 0; i < placeholder_test_params::selector_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::constant_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<FieldType>::column_type::selector);

            columns_at_y[key] = polynomial_table.selector(i).evaluate(y * omega.pow(rotation));
        }
    }

    std::array<typename FieldType::value_type, 1> verifier_res =
        placeholder_gates_argument<FieldType, circuit_2_params>::verify_eval(constraint_system.gates(), columns_at_y, y,
                                                                             verifier_transcript);

    typename FieldType::value_type verifier_next_challenge = verifier_transcript.template challenge<FieldType>();
    typename FieldType::value_type prover_next_challenge = prover_transcript.template challenge<FieldType>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    BOOST_CHECK(prover_res[0].evaluate(y) == verifier_res[0]);
}

BOOST_AUTO_TEST_CASE(placeholder_prover_basic_test) {

    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size> circuit =
        circuit_test_2<FieldType>();

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_2_params>;

    //    typedef commitments::list_polynomial_commitment<FieldType,
    //        circuit_2_params::batched_commitment_params_type> lpc_type;
    typedef commitments::lpc<FieldType, circuit_2_params::batched_commitment_params_type> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_2_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), desc, fri_params, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.private_table(), desc, fri_params);

    auto proof = placeholder_prover<FieldType, circuit_2_params>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, fri_params);

    bool verifier_res = placeholder_verifier<FieldType, circuit_2_params>::process(
        preprocessed_public_data, proof, constraint_system, fri_params);
    BOOST_CHECK(verifier_res);
}

BOOST_AUTO_TEST_CASE(placeholder_prover_lookup_test, *boost::unit_test::disabled()) {
    circuit_description<FieldType, circuit_3_params, table_rows_log, 3> circuit = circuit_test_3<FieldType>();

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_3_params>;

    typedef commitments::lpc<FieldType, circuit_3_params::batched_commitment_params_type> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_3_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<FieldType, circuit_3_params>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<FieldType, circuit_3_params>::process(
            constraint_system, assignments.public_table(), desc, fri_params, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<FieldType, circuit_3_params>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<FieldType, circuit_3_params>::process(
            constraint_system, assignments.private_table(), desc, fri_params);

    auto proof = placeholder_prover<FieldType, circuit_3_params>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, fri_params);

    bool verifier_res = placeholder_verifier<FieldType, circuit_3_params>::process(preprocessed_public_data, proof,
                                                                                   constraint_system, fri_params);
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#include <nil/crypto3/zk/snark/systems/plonk/redshift/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/preprocessor.hpp>
#include <nil/crypto3/zk/snark/relations/non_linear_combination.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/permutation.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/commitments/fri_commitment.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk::snark;

template<typename FieldType>
math::polynomial<typename FieldType::value_type>
    lagrange_polynomial(std::shared_ptr<math::evaluation_domain<FieldType>> domain, std::size_t number) {
    std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> evaluation_points;
    for (std::size_t i = 0; i < domain->m; i++) {
        evaluation_points.push_back(std::make_pair(domain->get_domain_element(i), (i != number) ?
                                                                                      FieldType::value_type::zero() :
                                                                                      FieldType::value_type::one()));
    }
    math::polynomial<typename FieldType::value_type> f = math::lagrange_interpolation(evaluation_points);

    return f;
}

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        fri_type::calculate_domain_set(degree_log, degree_log - 1);

    params.r = degree_log - 1;
    params.D = domain_set;
    params.q = q;
    params.max_degree = 1 << degree_log;

    return params;
}

template<typename FieldType>
std::vector<math::polynomial<typename FieldType::value_type>> 
    create_random_table(const std::size_t table_rows, const std::size_t table_width, 
        plonk_permutation permutation, const std::shared_ptr<math::evaluation_domain<FieldType>> &domain) {
        std::vector<math::polynomial<typename FieldType::value_type>> table(table_width);

        std::vector<std::vector<typename FieldType::value_type>> tmp(table_width);

        for (std::size_t i = 0; i < table_width; i++) {
            tmp[i].resize(table_rows);
            for (std::size_t j = 0; j < table_rows; j++) {
                tmp[i][j] = algebra::random_element<FieldType>();
            }
        }

        for (std::size_t i = 0; i < table_width; i++) {
            for (std::size_t j = 0; j < table_rows; j++) {
                auto key = std::make_pair(i, j);
                auto ids = permutation[key];
                if (ids.first != i || ids.second != j) {
                    tmp[i][j] = tmp[ids.first][ids.second];
                }
            }
        }

        for (std::size_t i = 0; i < table_width; i++) {
            domain->inverse_fft(tmp[i]);
            table[i] = math::polynomial<typename FieldType::value_type>(tmp[i]);
        }

        return table;
}

BOOST_AUTO_TEST_SUITE(redshift_prover_test_suite)

using curve_type = algebra::curves::bls12<381>;
using FieldType = typename curve_type::scalar_field_type;
typedef hashes::sha2<256> merkle_hash_type;
typedef hashes::sha2<256> transcript_hash_type;

constexpr std::size_t m = 2;

typedef fri_commitment_scheme<FieldType, merkle_hash_type, m> fri_type;

constexpr std::size_t argument_size = 3;

BOOST_AUTO_TEST_CASE(redshift_prover_basic_test) {

    // zk::snark::redshift_preprocessor<typename curve_type::base_field_type, 5, 2> preprocess;

    // auto preprocessed_data = preprocess::process(cs, assignments);
    // zk::snark::redshift_prover<typename curve_type::base_field_type, 5, 2, 2, 2> prove;
}

BOOST_AUTO_TEST_CASE(redshift_permutation_argument_test) {
    const std::size_t table_rows_log = 4;
    const std::size_t table_rows = (1 << table_rows_log) - 1;
    const std::size_t table_columns = 4;
    const std::size_t permutation_size1 = 4;
    const std::size_t usable_rows = (1 << table_rows_log) - 1;
    circuit_description<FieldType, table_rows_log, table_columns, permutation_size1, usable_rows> circuit = circuit_test_1<FieldType>();

    const std::size_t circuit_log = 2;
    const std::size_t circuit_rows = 1 << circuit_log;
    const std::size_t permutation_size = 2;
    const std::size_t columns_amount = 2;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;
    typedef list_polynomial_commitment_scheme<FieldType, merkle_hash_type, lambda, k, circuit_log - 1, m> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(circuit_log);
    std::shared_ptr<math::evaluation_domain<FieldType>> domain = fri_params.D[0];
    math::polynomial<typename FieldType::value_type> lagrange_0 = lagrange_polynomial<FieldType>(domain, 0);

    typename FieldType::value_type omega = domain->get_domain_element(1);

    typename FieldType::value_type delta = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;

    plonk_permutation permutation(columns_amount, circuit_rows);
    permutation.cells_equal(std::make_pair(2, 2), std::make_pair(1, 1));

    std::vector<math::polynomial<typename FieldType::value_type>> S_id = redshift_preprocessor<FieldType, columns_amount, 1>::identity_polynomials(
        permutation_size, circuit_rows, omega, delta, domain);
    std::vector<math::polynomial<typename FieldType::value_type>> S_sigma = redshift_preprocessor<FieldType, columns_amount, 1>::permutation_polynomials(
        permutation_size, circuit_rows, omega, delta, permutation, domain);

    // construct circuit values
    std::vector<math::polynomial<typename FieldType::value_type>> f = create_random_table(circuit_rows, columns_amount, permutation, domain);

    // construct q_last, q_blind
    math::polynomial<typename FieldType::value_type> q_last = redshift_preprocessor<FieldType, columns_amount, 1>::selector_last(
        circuit_rows, circuit_rows, domain);
    math::polynomial<typename FieldType::value_type> q_blind = redshift_preprocessor<FieldType, columns_amount, 1>::selector_blind(
        circuit_rows, circuit_rows, domain);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    fiat_shamir_heuristic_updated<hashes::keccak_1600<512>> prover_transcript(init_blob);
    fiat_shamir_heuristic_updated<hashes::keccak_1600<512>> verifier_transcript(init_blob);

    typename redshift_permutation_argument<FieldType, lpc_type>::prover_result_type prover_res =
        redshift_permutation_argument<FieldType, lpc_type>::prove_eval(prover_transcript, circuit_rows,
                                                                       permutation_size, domain, lagrange_0, S_id,
                                                                       S_sigma, f, q_last, q_blind, fri_params);

    // Challenge phase
    // typename FieldType::value_type y = algebra::random_element<FieldType>();
    typename FieldType::value_type y(2);
    std::vector<typename FieldType::value_type> f_at_y(permutation_size);
    for (int i = 0; i < permutation_size; i++) {
        f_at_y[i] = f[i].evaluate(y);
    }

    typename FieldType::value_type v_p_at_y = prover_res.permutation_polynomial.evaluate(y);
    typename FieldType::value_type v_p_at_y_shifted = prover_res.permutation_polynomial.evaluate(omega * y);

    std::array<typename FieldType::value_type, 3> verifier_res =
        redshift_permutation_argument<FieldType, lpc_type>::verify_eval(
            verifier_transcript, circuit_rows, permutation_size, domain, y, f_at_y, v_p_at_y, v_p_at_y_shifted,
            lagrange_0, S_id, S_sigma, q_last, q_blind, prover_res.permutation_poly_commitment.root());

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
    auto circuit = circuit_test_1<FieldType>();

    const std::size_t circuit_log = 2;
    const std::size_t circuit_rows = 1 << circuit_log;
    const std::size_t permutation_size = 2;
    const std::size_t columns_amount = 2;

    constexpr static const std::size_t lambda = 40;
    constexpr static const std::size_t k = 1;
    typedef list_polynomial_commitment_scheme<FieldType, merkle_hash_type, lambda, k, circuit_log - 1, m> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(circuit_log);
    std::shared_ptr<math::evaluation_domain<FieldType>> domain = fri_params.D[0];
    math::polynomial<typename FieldType::value_type> lagrange_0 = lagrange_polynomial<FieldType>(domain, 0);
    
    typename FieldType::value_type omega = domain->get_domain_element(1);

    typename FieldType::value_type delta = algebra::fields::arithmetic_params<FieldType>::multiplicative_generator;

    plonk_permutation permutation(columns_amount, circuit_rows);
    permutation.cells_equal(std::make_pair(2, 2), std::make_pair(1, 1));

    std::vector<math::polynomial<typename FieldType::value_type>> S_id = redshift_preprocessor<FieldType, columns_amount, 1>::identity_polynomials(
        permutation_size, circuit_rows, omega, delta, domain);
    std::vector<math::polynomial<typename FieldType::value_type>> S_sigma = redshift_preprocessor<FieldType, columns_amount, 1>::permutation_polynomials(
        permutation_size, circuit_rows, omega, delta, permutation, domain);

    // construct circuit values
    std::vector<math::polynomial<typename FieldType::value_type>> f = create_random_table(circuit_rows, columns_amount, permutation, domain);

    std::vector<math::polynomial<typename FieldType::value_type>> constraints_1 = {f[0] * f[1], f[0] + f[0]};
    std::vector<math::polynomial<typename FieldType::value_type>> constraints_2 = {f[1] - f[0]};


    // construct q_last, q_blind
    math::polynomial<typename FieldType::value_type> q_last = redshift_preprocessor<FieldType, columns_amount, 1>::selector_last(
        circuit_rows, circuit_rows, domain);
    math::polynomial<typename FieldType::value_type> q_blind = redshift_preprocessor<FieldType, columns_amount, 1>::selector_blind(
        circuit_rows, circuit_rows, domain);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    fiat_shamir_heuristic_updated<hashes::keccak_1600<512>> prover_transcript(init_blob);
    fiat_shamir_heuristic_updated<hashes::keccak_1600<512>> verifier_transcript(init_blob);

    /*std::array<math::polynomial<typename FieldType::value_type>, 1> prover_res =
        redshift_gates_argument<FieldType, lpc_type>::prove_eval(prover_transcript, circuit_rows,
                                                                       permutation_size, domain, lagrange_0, S_id,
                                                                       S_sigma, f, q_last, q_blind, fri_params);*/
}

BOOST_AUTO_TEST_SUITE_END()
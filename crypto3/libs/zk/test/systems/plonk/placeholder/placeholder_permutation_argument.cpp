//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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
// Test for permutation argument for circuit2
//

#define BOOST_TEST_MODULE placeholder_permutation_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/permutation_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/lookup_argument.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/gates_argument.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/batched_commitment.hpp>
#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

BOOST_AUTO_TEST_SUITE(permutation_argument)
    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<256>;
        using transcript_hash_type = hashes::keccak_1600<256>;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<field_type>;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using commitment_scheme_params_type = nil::crypto3::zk::commitments::commitment_scheme_params_type<field_type, std::vector<std::uint8_t>>;
    using placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, commitment_scheme_params_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, placeholder_params_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
            typename placeholder_test_params::merkle_hash_type,
            typename placeholder_test_params::transcript_hash_type,
            placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;

    using kzg_type = commitments::batched_kzg<curve_type, typename placeholder_test_params::transcript_hash_type>;
    using kzg_scheme_type = typename commitments::kzg_commitment_scheme<kzg_type>;
    using kzg_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, kzg_scheme_type>;

    BOOST_FIXTURE_TEST_CASE(permutation_polynomials_test, test_tools::random_test_initializer<field_type>) {
        typename field_type::value_type pi0 = alg_random_engines.template get_alg_engine<field_type>()();
        auto circuit = circuit_test_t<field_type>(
                pi0,
                alg_random_engines.template get_alg_engine<field_type>(),
                generic_random_engine
        );

        plonk_table_description<field_type> desc(
                circuit.table.witnesses().size(),
                circuit.table.public_inputs().size(),
                circuit.table.constants().size(),
                circuit.table.selectors().size(),
                circuit.usable_rows,
                circuit.table_rows);

        std::size_t table_rows_log = std::log2(desc.rows_amount);

        typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                       circuit.lookup_gates);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        typename lpc_type::fri_type::params_type fri_params(1, table_rows_log, placeholder_test_params::lambda, 4);
        lpc_scheme_type lpc_scheme(fri_params);
        transcript_type lpc_transcript;

        typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.move_public_table(), desc, lpc_scheme
        );

        typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.move_private_table(), desc
        );

        auto polynomial_table =
                plonk_polynomial_dfs_table<field_type>(
                        lpc_preprocessed_private_data.private_polynomial_table,
                        lpc_preprocessed_public_data.public_polynomial_table);

        std::shared_ptr<math::evaluation_domain<field_type>> domain = lpc_preprocessed_public_data.common_data.basic_domain;
        typename field_type::value_type id_res = field_type::value_type::one();
        typename field_type::value_type sigma_res = field_type::value_type::one();
        for (std::size_t i = 0; i < desc.rows_amount; i++) {
            for (auto &identity_polynomial: lpc_preprocessed_public_data.identity_polynomials) {
                id_res = id_res * identity_polynomial.evaluate(domain->get_domain_element(i));
            }

            for (auto &permutation_polynomial: lpc_preprocessed_public_data.permutation_polynomials) {
                sigma_res = sigma_res * permutation_polynomial.evaluate(domain->get_domain_element(i));
            }
        }
        BOOST_CHECK_MESSAGE(id_res == sigma_res, "Simple check");

        typename field_type::value_type beta = algebra::random_element<field_type>();
        typename field_type::value_type gamma = algebra::random_element<field_type>();

        id_res = field_type::value_type::one();
        sigma_res = field_type::value_type::one();
        const auto &permuted_columns = lpc_preprocessed_public_data.common_data.permuted_columns;

        for (std::size_t i = 0; i < desc.rows_amount; i++) {
            for (std::size_t j = 0; j < lpc_preprocessed_public_data.identity_polynomials.size(); j++) {
                id_res = id_res *
                         (polynomial_table[permuted_columns[j]].evaluate(domain->get_domain_element(i)) +
                          beta *
                          lpc_preprocessed_public_data.identity_polynomials[j].evaluate(domain->get_domain_element(i)) +
                          gamma);
            }

            for (std::size_t j = 0; j < lpc_preprocessed_public_data.permutation_polynomials.size(); j++) {
                sigma_res =
                        sigma_res *
                        (polynomial_table[permuted_columns[j]].evaluate(domain->get_domain_element(i)) +
                         beta * lpc_preprocessed_public_data.permutation_polynomials[j].evaluate(
                                 domain->get_domain_element(i)) +
                         gamma);
            }
        }
        BOOST_CHECK_MESSAGE(id_res == sigma_res, "Complex check");
    }

    BOOST_FIXTURE_TEST_CASE(placeholder_split_polynomial_test, test_tools::random_test_initializer<field_type>) {
        math::polynomial<typename field_type::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};
        std::size_t expected_size = 4;
        std::size_t max_degree = 3;

        std::vector<math::polynomial<typename field_type::value_type>> f_splitted =
                zk::snark::detail::split_polynomial<field_type>(f, max_degree);

        BOOST_CHECK(f_splitted.size() == expected_size);

        typename field_type::value_type y = alg_random_engines.template get_alg_engine<field_type>()();

        typename field_type::value_type f_at_y = f.evaluate(y);
        typename field_type::value_type f_splitted_at_y = field_type::value_type::zero();
        for (std::size_t i = 0; i < f_splitted.size(); i++) {
            f_splitted_at_y = f_splitted_at_y + f_splitted[i].evaluate(y) * y.pow((max_degree + 1) * i);
        }

        BOOST_CHECK(f_at_y == f_splitted_at_y);
    }

    BOOST_FIXTURE_TEST_CASE(permutation_argument_test, test_tools::random_test_initializer<field_type>) {
        auto pi0 = alg_random_engines.template get_alg_engine<field_type>()();
        auto circuit = circuit_test_t<field_type>(
                pi0,
                alg_random_engines.template get_alg_engine<field_type>(),
                generic_random_engine
        );

        plonk_table_description<field_type> desc(
                circuit.table.witnesses().size(),
                circuit.table.public_inputs().size(),
                circuit.table.constants().size(),
                circuit.table.selectors().size(),
                circuit.usable_rows,
                circuit.table_rows);

        std::size_t table_rows_log = std::log2(desc.rows_amount);

        const std::size_t argument_size = 3;

        typename lpc_type::fri_type::params_type fri_params(1, table_rows_log, placeholder_test_params::lambda, 4);
        lpc_scheme_type lpc_scheme(fri_params);

        typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                       circuit.lookup_gates);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        transcript_type transcript;

        typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.move_public_table(), desc, lpc_scheme
        );

        typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.move_private_table(), desc
        );

        auto polynomial_table =
                plonk_polynomial_dfs_table<field_type>(
                        preprocessed_private_data.private_polynomial_table,
                        preprocessed_public_data.public_polynomial_table);

        std::vector<std::uint8_t> init_blob{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> prover_transcript(
                init_blob);
        transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> verifier_transcript(
                init_blob);

        typename placeholder_permutation_argument<field_type, lpc_placeholder_params_type>::prover_result_type prover_res =
                placeholder_permutation_argument<field_type, lpc_placeholder_params_type>::prove_eval(
                        constraint_system, preprocessed_public_data, desc, polynomial_table, lpc_scheme,
                        prover_transcript);

        // Challenge phase
        const auto &permuted_columns = preprocessed_public_data.common_data.permuted_columns;

        typename field_type::value_type y = algebra::random_element<field_type>();
        std::vector<typename field_type::value_type> f_at_y(permuted_columns.size());
        std::vector<typename field_type::value_type> S_id(permuted_columns.size());
        std::vector<typename field_type::value_type> S_sigma(permuted_columns.size());
        for (std::size_t i = 0; i < permuted_columns.size(); i++) {
            f_at_y[i] = polynomial_table[permuted_columns[i]].evaluate(y);
            S_id[i] = preprocessed_public_data.identity_polynomials[i].evaluate(y);
            S_sigma[i] = preprocessed_public_data.permutation_polynomials[i].evaluate(y);
        }

        auto omega = preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

        typename field_type::value_type v_p_at_y = prover_res.permutation_polynomial_dfs.evaluate(y);
        typename field_type::value_type v_p_at_y_shifted = prover_res.permutation_polynomial_dfs.evaluate(omega * y);

        std::vector<typename field_type::value_type> special_selector_values(3);
        special_selector_values[0] = preprocessed_public_data.common_data.lagrange_0.evaluate(y);
        special_selector_values[1] = preprocessed_public_data.q_last.evaluate(y);
        special_selector_values[2] = preprocessed_public_data.q_blind.evaluate(y);


        auto permutation_commitment = lpc_scheme.commit(PERMUTATION_BATCH);
        std::array<typename field_type::value_type, argument_size> verifier_res =
                placeholder_permutation_argument<field_type, lpc_placeholder_params_type>::verify_eval(
                        preprocessed_public_data.common_data,
                        S_id, S_sigma,
                        special_selector_values,
                        y, f_at_y, v_p_at_y, v_p_at_y_shifted, {}, verifier_transcript
                );

        typename field_type::value_type verifier_next_challenge = verifier_transcript.template challenge<field_type>();
        typename field_type::value_type prover_next_challenge = prover_transcript.template challenge<field_type>();
        BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

        for (std::size_t i = 0; i < argument_size; i++) {
            BOOST_CHECK(prover_res.F_dfs[i].evaluate(y) == verifier_res[i]);
            for (std::size_t j = 0; j < desc.rows_amount; j++) {
                BOOST_CHECK(
                        prover_res.F_dfs[i].evaluate(
                                preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) ==
                        field_type::value_type::zero()
                );
            }
        }
    }

BOOST_AUTO_TEST_SUITE_END()

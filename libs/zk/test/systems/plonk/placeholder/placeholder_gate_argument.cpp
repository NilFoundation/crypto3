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
// Test gate argument for single circuit - circuit_test_t

#define BOOST_TEST_MODULE placeholder_gate_argument_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/gates_argument.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_policy.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

BOOST_AUTO_TEST_SUITE(placeholder_gate_argument)
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

    BOOST_FIXTURE_TEST_CASE(placeholder_gate_argument_test, test_tools::random_test_initializer<field_type>) {
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

        typename policy_type::constraint_system_type constraint_system(
                circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        typename lpc_type::fri_type::params_type fri_params(1, table_rows_log, placeholder_test_params::lambda, 4);
        lpc_scheme_type lpc_scheme(fri_params);

        std::vector<std::uint8_t> init_blob{0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        transcript_type transcript(init_blob);

        typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.public_table(), desc, lpc_scheme
        );

        typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.private_table(), desc
        );

        auto polynomial_table =
                plonk_polynomial_dfs_table<field_type>(
                        preprocessed_private_data.private_polynomial_table,
                        preprocessed_public_data.public_polynomial_table);

        transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> prover_transcript = transcript;
        transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> verifier_transcript = transcript;

        math::polynomial_dfs<typename field_type::value_type> mask_polynomial(
                0, preprocessed_public_data.common_data.basic_domain->m,
                typename field_type::value_type(1)
        );
        mask_polynomial -= preprocessed_public_data.q_last;
        mask_polynomial -= preprocessed_public_data.q_blind;

        std::array<math::polynomial_dfs<typename field_type::value_type>, 1> prover_res =
                placeholder_gates_argument<field_type, lpc_placeholder_params_type>::prove_eval(
                        constraint_system, polynomial_table, preprocessed_public_data.common_data.basic_domain,
                        preprocessed_public_data.common_data.max_gates_degree, mask_polynomial, prover_transcript);

        // Challenge phase
        typename field_type::value_type y = algebra::random_element<field_type>();
        typename field_type::value_type omega = preprocessed_public_data.common_data.basic_domain->get_domain_element(
                1);

        typename policy_type::evaluation_map columns_at_y;
        for (std::size_t i = 0; i < desc.witness_columns; i++) {

            std::size_t i_global_index = i;

            for (int rotation: preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
                auto key = std::make_tuple(i, rotation,
                                           plonk_variable<typename field_type::value_type>::column_type::witness);
                columns_at_y[key] = polynomial_table.witness(i).evaluate(y * omega.pow(rotation));
            }
        }
        for (std::size_t i = 0; i < 0 + desc.public_input_columns; i++) {

            std::size_t i_global_index = desc.witness_columns + i;

            for (int rotation: preprocessed_public_data.common_data.columns_rotations[i_global_index]) {

                auto key = std::make_tuple(i, rotation,
                                           plonk_variable<typename field_type::value_type>::column_type::public_input);

                columns_at_y[key] = polynomial_table.public_input(i).evaluate(y * omega.pow(rotation));
            }
        }
        for (std::size_t i = 0; i < 0 + desc.constant_columns; i++) {

            std::size_t i_global_index =
                    desc.witness_columns + desc.public_input_columns + i;

            for (int rotation: preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
                auto key = std::make_tuple(i, rotation,
                                           plonk_variable<typename field_type::value_type>::column_type::constant);

                columns_at_y[key] = polynomial_table.constant(i).evaluate(y * omega.pow(rotation));
            }
        }
        for (std::size_t i = 0; i < desc.selector_columns; i++) {

            std::size_t i_global_index = desc.witness_columns + desc.constant_columns + desc.public_input_columns + i;

            for (int rotation: preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
                auto key = std::make_tuple(i, rotation,
                                           plonk_variable<typename field_type::value_type>::column_type::selector);

                columns_at_y[key] = polynomial_table.selector(i).evaluate(y * omega.pow(rotation));
            }
        }

        auto mask_value = field_type::value_type::one() - preprocessed_public_data.q_last.evaluate(y) -
                          preprocessed_public_data.q_blind.evaluate(y);
        std::array<typename field_type::value_type, 1> verifier_res =
                placeholder_gates_argument<field_type, lpc_placeholder_params_type>::verify_eval(
                        constraint_system.gates(), columns_at_y, y, mask_value, verifier_transcript);

        typename field_type::value_type verifier_next_challenge = verifier_transcript.template challenge<field_type>();
        typename field_type::value_type prover_next_challenge = prover_transcript.template challenge<field_type>();
        BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

        BOOST_CHECK(prover_res[0].evaluate(y) == verifier_res[0]);
    }

BOOST_AUTO_TEST_SUITE_END()

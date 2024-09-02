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
#ifndef CRYPTO3_ZK_TEST_PLACEHOLDER_TEST_RUNNER_HPP
#define CRYPTO3_ZK_TEST_PLACEHOLDER_TEST_RUNNER_HPP

#include <cmath>
#include <utility>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg_v2.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

template<typename FieldType,
        typename merkle_hash_type,
        typename transcript_hash_type,
        bool UseGrinding = false,
        std::size_t max_quotient_poly_chunks = 0>
struct placeholder_test_runner {
    using field_type = FieldType;

    struct placeholder_test_params {
        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    typedef placeholder_circuit_params<field_type> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
            merkle_hash_type,
            transcript_hash_type,
            placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;
    using circuit_type = circuit_description<field_type, placeholder_circuit_params<field_type>>;

    placeholder_test_runner(const circuit_type &circuit_in)
            : circuit(circuit_in), desc(circuit_in.table.witnesses().size(),
                                        circuit_in.table.public_inputs().size(),
                                        circuit_in.table.constants().size(),
                                        circuit_in.table.selectors().size(),
                                        circuit_in.usable_rows,
                                        circuit_in.table_rows),
              constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates, circuit.lookup_tables),
              assignments(circuit.table), table_rows_log(std::log2(circuit_in.table_rows)),
              fri_params(1, table_rows_log, placeholder_test_params::lambda, 4) {
    }

    bool run_test() {
        lpc_scheme_type lpc_scheme(fri_params);

        typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.move_public_table(), desc, lpc_scheme, max_quotient_poly_chunks);

        typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
                lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.move_private_table(), desc);

        auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
                lpc_preprocessed_public_data, std::move(lpc_preprocessed_private_data), desc, constraint_system,
                lpc_scheme);

        bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
                lpc_preprocessed_public_data.common_data, lpc_proof, desc, constraint_system, lpc_scheme);
        return verifier_res;
    }

    circuit_type circuit;
    plonk_table_description<field_type> desc;
    typename policy_type::constraint_system_type constraint_system;
    typename policy_type::variable_assignment_type assignments;
    std::size_t table_rows_log;
    typename lpc_type::fri_type::params_type fri_params;
};

template<typename curve_type,
        typename transcript_hash_type,
        bool UseGrinding = false>
struct placeholder_kzg_test_runner {
    using field_type = typename curve_type::scalar_field_type;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using circuit_params = placeholder_circuit_params<field_type>;

    using kzg_type = commitments::batched_kzg<curve_type, transcript_hash_type>;
    using kzg_scheme_type = typename commitments::kzg_commitment_scheme<kzg_type>;
    using kzg_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, kzg_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, kzg_placeholder_params_type>;

    using circuit_type =
            circuit_description<field_type,
                    placeholder_circuit_params<field_type> >;

    placeholder_kzg_test_runner(const circuit_type &circuit_in)
            : circuit(circuit_in),
              desc(circuit_in.table.witnesses().size(),
                   circuit_in.table.public_inputs().size(),
                   circuit_in.table.constants().size(),
                   circuit_in.table.selectors().size(),
                   circuit_in.usable_rows,
                   circuit_in.table_rows) {
    }

    bool run_test() {

        typename policy_type::constraint_system_type
                constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
        typename policy_type::variable_assignment_type
                assignments = circuit.table;

        bool verifier_res;

        std::size_t d = circuit.table_rows;
        std::size_t t = d;
        typename kzg_scheme_type::params_type kzg_params(d, t);
        kzg_scheme_type kzg_scheme(kzg_params);

        typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
                kzg_preprocessed_public_data =
                placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
                        constraint_system, assignments.public_table(), desc, kzg_scheme);

        typename placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
                kzg_preprocessed_private_data = placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::process(
                constraint_system, assignments.private_table(), desc);

        auto kzg_proof = placeholder_prover<field_type, kzg_placeholder_params_type>::process(
                kzg_preprocessed_public_data, std::move(kzg_preprocessed_private_data), desc, constraint_system,
                kzg_scheme);

        verifier_res = placeholder_verifier<field_type, kzg_placeholder_params_type>::process(
                kzg_preprocessed_public_data.common_data, kzg_proof, desc, constraint_system, kzg_scheme);
        return verifier_res;
    }

    circuit_type circuit;
    plonk_table_description<field_type> desc;
};

template<typename curve_type,
        typename transcript_hash_type,
        bool UseGrinding = false>
struct placeholder_kzg_test_runner_v2 {
    using field_type = typename curve_type::scalar_field_type;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using circuit_params = placeholder_circuit_params<field_type>;

    using kzg_type = commitments::batched_kzg<curve_type, transcript_hash_type>;
    using kzg_scheme_type = typename commitments::kzg_commitment_scheme_v2<kzg_type>;
    using kzg_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, kzg_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, kzg_placeholder_params_type>;

    using circuit_type =
            circuit_description<field_type,
                    placeholder_circuit_params<field_type>>;

    placeholder_kzg_test_runner_v2(const circuit_type &circuit_in)
            : circuit(circuit_in),
              desc(circuit_in.table.witnesses().size(),
                   circuit_in.table.public_inputs().size(),
                   circuit_in.table.constants().size(),
                   circuit_in.table.selectors().size(),
                   circuit_in.usable_rows,
                   circuit_in.table_rows) {
    }

    bool run_test() {

        typename policy_type::constraint_system_type
                constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
        typename policy_type::variable_assignment_type
                assignments = circuit.table;

        bool verifier_res;

        typename kzg_type::field_type::value_type alpha(7);
        auto kzg_params = kzg_scheme_type::create_params(circuit.table_rows, alpha);
        kzg_scheme_type kzg_scheme(kzg_params);

        typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
                kzg_preprocessed_public_data =
                placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
                        constraint_system, assignments.public_table(), desc, kzg_scheme);

        typename placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
                kzg_preprocessed_private_data = placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::process(
                constraint_system, assignments.private_table(), desc);

        auto kzg_proof = placeholder_prover<field_type, kzg_placeholder_params_type>::process(
                kzg_preprocessed_public_data, std::move(kzg_preprocessed_private_data), desc, constraint_system,
                kzg_scheme);

        verifier_res = placeholder_verifier<field_type, kzg_placeholder_params_type>::process(
                kzg_preprocessed_public_data.common_data, kzg_proof, desc, constraint_system, kzg_scheme);
        return verifier_res;
    }

    circuit_type circuit;
    plonk_table_description<field_type> desc;
};

#endif // CRYPTO3_ZK_TEST_PLACEHOLDER_TEST_RUNNER_HPP

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
#include <regex>

#include <boost/test/included/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
/*
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/pairing/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
*/
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks64.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/md5.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

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
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg_v2.hpp>
#include <nil/crypto3/zk/commitments/batched_commitment.hpp>
#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

template<typename CommitmentSchemeParamsType, typename TranscriptHashType>
class dummy_commitment_scheme_type : public nil::crypto3::zk::commitments::polys_evaluator<CommitmentSchemeParamsType, TranscriptHashType> {
private:
public:
    using params_type = CommitmentSchemeParamsType;
    using commitment_type = typename params_type::commitment_type;
    using field_type = typename params_type::field_type;
    using transcript_hash_type = TranscriptHashType;
    using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;
    using preprocessed_data_type = bool;

    params_type get_commitment_params() const {
        return params_type();
    }

    struct proof_type{
        nil::crypto3::zk::commitments::eval_storage<field_type> z;
    };

    preprocessed_data_type preprocess(transcript_type &preprocessed_transript) const{
        return true;
    }

    void setup(transcript_type &preprocessed_transript, preprocessed_data_type prep = true){
    }

    void mark_batch_as_fixed(std::size_t batch_id){
    }

    proof_type proof_eval(
        transcript_type &transcript
    ){
        this->eval_polys();
        return proof_type({this->_z});
    }

    commitment_type commit(
        std::size_t index
    ){
        this->state_commited(index);
        std::vector<std::uint8_t> arr = {std::uint8_t(index)};

        return commitment_type(arr);
    }

    bool verify_eval(
        const proof_type &proof,
        const std::map<std::size_t, commitment_type> &commitments,
        transcript_type &transcript
    ) const {
        return true;
    }
};

inline std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
    using dist_type = std::uniform_int_distribution<int>;
    static std::random_device random_engine;

    std::vector<std::size_t> step_list;
    std::size_t steps_sum = 0;
    while (steps_sum != r) {
        if (r - steps_sum <= std::size_t(max_step)) {
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

template<typename kzg_type>
typename kzg_type::params_type create_kzg_params(std::size_t degree_log) {
    // TODO: what cases t != d?
    typename kzg_type::field_type::value_type alpha (7);
    std::size_t d = 1 << degree_log;

    typename kzg_type::params_type params(d, d, alpha);
    return params;
}

template<typename kzg_type>
typename kzg_type::params_type create_kzg_v2_params(std::size_t degree_log) {
    // TODO: what cases t != d?
    typename kzg_type::field_type::value_type alpha (7);
    std::size_t d = 1 << degree_log;

    typename kzg_type::params_type params(d, 1, alpha);
    return params;
}

template<typename FieldType, typename merkle_hash_type, typename transcript_hash_type,
    std::size_t WitnessColumns, std::size_t PublicInputColumns, std::size_t ConstantColumns, std::size_t SelectorColumns,
    std::size_t usable_rows_amount, bool UseGrinding = false, std::size_t max_quotient_poly_chunks = 0>
struct placeholder_test_runner {
    using field_type = FieldType;

    struct placeholder_test_params {
        constexpr static const std::size_t usable_rows = 13;

        constexpr static const std::size_t witness_columns = WitnessColumns;
        constexpr static const std::size_t public_input_columns = PublicInputColumns;
        constexpr static const std::size_t constant_columns = ConstantColumns;
        constexpr static const std::size_t selector_columns = SelectorColumns;

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
    using circuit_type = circuit_description<field_type, placeholder_circuit_params<field_type>, usable_rows_amount>;

    placeholder_test_runner(const circuit_type& circuit_in, std::size_t usable_rows, std::size_t table_rows)
        : circuit(circuit_in)
        , desc(WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns)
        , constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates, circuit.lookup_tables)
        , assignments(circuit.table)
        , table_rows_log(std::log2(table_rows))
        , fri_params(1,table_rows_log, placeholder_test_params::lambda, 4)
    {
        desc.rows_amount = table_rows;
        desc.usable_rows_amount = usable_rows;
    }

    bool run_test() {
        lpc_scheme_type lpc_scheme(fri_params);

        typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
            lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.move_public_table(), desc, lpc_scheme, max_quotient_poly_chunks
            );

        typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
            lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
                constraint_system, assignments.move_private_table(), desc
            );

        auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
            lpc_preprocessed_public_data, std::move(lpc_preprocessed_private_data), desc, constraint_system, lpc_scheme
        );

        bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
            lpc_preprocessed_public_data.common_data, lpc_proof, desc, constraint_system, lpc_scheme
        );
        return verifier_res;
    }

    circuit_type circuit;
    plonk_table_description<field_type> desc;
    typename policy_type::constraint_system_type constraint_system;
    typename policy_type::variable_assignment_type assignments;
    std::size_t table_rows_log;
    typename lpc_type::fri_type::params_type fri_params;
};



BOOST_AUTO_TEST_SUITE(placeholder_circuit2)
    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = 3;
        constexpr static const std::size_t public_input_columns = 1;
        constexpr static const std::size_t constant_columns = 0;
        constexpr static const std::size_t selector_columns = 2;

        constexpr static const std::size_t lambda = 10;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<field_type>;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using commitment_scheme_params_type = nil::crypto3::zk::commitments::commitment_scheme_params_type<field_type, std::vector<std::uint8_t>>;
    using commitment_scheme_dummy_type = dummy_commitment_scheme_type<commitment_scheme_params_type, typename placeholder_test_params::transcript_hash_type>;
    using placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, commitment_scheme_dummy_type>;
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

BOOST_FIXTURE_TEST_CASE(prover_test, test_tools::random_test_initializer<field_type>) {
    typename field_type::value_type pi0 = alg_random_engines.template get_alg_engine<field_type>()();
    auto circuit = circuit_test_t<field_type>(
        pi0,
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );
    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates, circuit.copy_constraints,
        circuit.lookup_gates, circuit.lookup_tables,
        circuit.public_input_sizes
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    bool verifier_res;

    // Dummy commitment scheme
    commitment_scheme_dummy_type commitment_scheme;

    typename placeholder_public_preprocessor<field_type, placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, commitment_scheme
        );

    typename placeholder_private_preprocessor<field_type, placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto proof = placeholder_prover<field_type, placeholder_params_type>::process(
        preprocessed_public_data, std::move(preprocessed_private_data), desc, constraint_system, commitment_scheme
    );

    verifier_res = placeholder_verifier<field_type, placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, commitment_scheme
    );
    BOOST_CHECK(verifier_res);

    // Public inputs checks
    // Completely correct public input
    typename placeholder_params_type::public_input_type public_input(1);
    public_input[0] = {pi0, 0, 1};
    verifier_res = placeholder_verifier<field_type, placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, commitment_scheme, public_input
    );
    BOOST_CHECK(verifier_res);

    // Completely correct zeroes after it are not important
    public_input[0] = {pi0, 0, 1, 0};
    verifier_res = placeholder_verifier<field_type, placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, commitment_scheme, public_input
    );
    BOOST_CHECK(verifier_res);

    // Incorrect public input
    public_input[0] = {pi0, 1};
    verifier_res = placeholder_verifier<field_type, placeholder_params_type>::process(
        preprocessed_public_data.common_data, proof, desc, constraint_system, commitment_scheme, public_input
    );
    BOOST_CHECK(!verifier_res);

    // LPC commitment scheme
    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);
    transcript_type lpc_transcript;

    // Normally we would use "assignments.move_public_table()" here, but assignments are reused in this test.
    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme
        );

    // Normally we would use "assignments.move_private_table()" here, but assignments are reused in this test.
    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, std::move(lpc_preprocessed_private_data), desc, constraint_system, lpc_scheme
    );

    verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data.common_data, lpc_proof, desc, constraint_system, lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    // KZG commitment scheme
    auto kzg_params = create_kzg_params<kzg_type>(table_rows_log);
    kzg_scheme_type kzg_scheme(kzg_params);

    typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
        kzg_preprocessed_public_data = placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, kzg_scheme
        );

    typename placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
        kzg_preprocessed_private_data = placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto kzg_proof = placeholder_prover<field_type, kzg_placeholder_params_type>::process(
        kzg_preprocessed_public_data, std::move(kzg_preprocessed_private_data), desc, constraint_system, kzg_scheme
    );

    verifier_res = placeholder_verifier<field_type, kzg_placeholder_params_type>::process(
        kzg_preprocessed_public_data.common_data, kzg_proof, desc, constraint_system, kzg_scheme
    );
    BOOST_CHECK(verifier_res);
}

BOOST_FIXTURE_TEST_CASE(permutation_polynomials_test, test_tools::random_test_initializer<field_type>) {
    typename field_type::value_type pi0 = alg_random_engines.template get_alg_engine<field_type>()();
    auto circuit = circuit_test_t<field_type>(
        pi0,
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );
    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(1,table_rows_log, placeholder_test_params::lambda, 4);
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
            lpc_preprocessed_private_data.private_polynomial_table, lpc_preprocessed_public_data.public_polynomial_table);

    std::shared_ptr<math::evaluation_domain<field_type>> domain = lpc_preprocessed_public_data.common_data.basic_domain;
    typename field_type::value_type id_res = field_type::value_type::one();
    typename field_type::value_type sigma_res = field_type::value_type::one();
    for (std::size_t i = 0; i < desc.rows_amount; i++) {
        for (auto &identity_polynomial : lpc_preprocessed_public_data.identity_polynomials) {
            id_res = id_res * identity_polynomial.evaluate(domain->get_domain_element(i));
        }

        for (auto &permutation_polynomial : lpc_preprocessed_public_data.permutation_polynomials) {
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
                      beta * lpc_preprocessed_public_data.identity_polynomials[j].evaluate(domain->get_domain_element(i)) +
                      gamma);
        }

        for (std::size_t j = 0; j < lpc_preprocessed_public_data.permutation_polynomials.size(); j++) {
            sigma_res =
                sigma_res *
                (polynomial_table[permuted_columns[j]].evaluate(domain->get_domain_element(i)) +
                 beta * lpc_preprocessed_public_data.permutation_polynomials[j].evaluate(domain->get_domain_element(i)) +
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
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );
    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
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
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> prover_transcript(init_blob);
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> verifier_transcript(init_blob);

    typename placeholder_permutation_argument<field_type, lpc_placeholder_params_type>::prover_result_type prover_res =
        placeholder_permutation_argument<field_type, lpc_placeholder_params_type>::prove_eval(
            constraint_system, preprocessed_public_data, desc, polynomial_table, lpc_scheme, prover_transcript);

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
                prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) == field_type::value_type::zero()
            );
        }
    }
}

BOOST_FIXTURE_TEST_CASE(placeholder_gate_argument_test, test_tools::random_test_initializer<field_type>) {
    auto pi0 = alg_random_engines.template get_alg_engine<field_type>()();
    auto circuit = circuit_test_t<field_type>(
        pi0,
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::log2(desc.rows_amount);

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(1, table_rows_log, placeholder_test_params::lambda, 4);
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
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
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table);

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
    typename field_type::value_type omega = preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

    typename policy_type::evaluation_map columns_at_y;
    for (std::size_t i = 0; i < placeholder_test_params::witness_columns; i++) {

        std::size_t i_global_index = i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::witness);
            columns_at_y[key] = polynomial_table.witness(i).evaluate(y * omega.pow(rotation));
        }
    }
    for (std::size_t i = 0; i < 0 + placeholder_test_params::public_input_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {

            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::public_input);

            columns_at_y[key] = polynomial_table.public_input(i).evaluate(y * omega.pow(rotation));
        }
    }
    for (std::size_t i = 0; i < 0 + placeholder_test_params::constant_columns; i++) {

        std::size_t i_global_index =
            placeholder_test_params::witness_columns + placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::constant);

            columns_at_y[key] = polynomial_table.constant(i).evaluate(y * omega.pow(rotation));
        }
    }
    for (std::size_t i = 0; i < placeholder_test_params::selector_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::constant_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::selector);

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

BOOST_AUTO_TEST_SUITE(placeholder_circuit3_lookup_test)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t usable_rows = 4;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_3;
        constexpr static const std::size_t public_input_columns = public_columns_3;
        constexpr static const std::size_t constant_columns = constant_columns_3;
        constexpr static const std::size_t selector_columns = selector_columns_3;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(lookup_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_3<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );
    constexpr std::size_t argument_size = 4;

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(1, table_rows_log, placeholder_test_params::lambda, 4, true);
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto polynomial_table =
        plonk_polynomial_dfs_table<field_type>(
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table
    );

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript_type prover_transcript(init_blob);
    transcript_type verifier_transcript(init_blob);

    placeholder_lookup_argument_prover<field_type, lpc_scheme_type, lpc_placeholder_params_type> lookup_prover(
        constraint_system, preprocessed_public_data, polynomial_table, lpc_scheme, prover_transcript);
    auto prover_res = lookup_prover.prove_eval();
    auto omega = preprocessed_public_data.common_data.basic_domain->get_domain_element(1);

    // Challenge phase
    typename field_type::value_type y = algebra::random_element<field_type>();
    typename policy_type::evaluation_map columns_at_y;
    for (std::size_t i = 0; i < placeholder_test_params::witness_columns; i++) {

        std::size_t i_global_index = i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::witness);
            columns_at_y[key] = polynomial_table.witness(i).evaluate(y * omega.pow(rotation));
        }
    }

    for (std::size_t i = 0; i < 0 + placeholder_test_params::constant_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::constant);

            columns_at_y[key] = polynomial_table.constant(i).evaluate(y * omega.pow(rotation));
        }
    }

    for (std::size_t i = 0; i < placeholder_test_params::selector_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::constant_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::selector);

            columns_at_y[key] = polynomial_table.selector(i).evaluate(y * omega.pow(rotation));
        }
    }

    lpc_scheme.append_eval_point(LOOKUP_BATCH, y);
    lpc_scheme.append_eval_point(LOOKUP_BATCH, y * omega);
    lpc_scheme.append_eval_point(LOOKUP_BATCH, y * omega.pow(usable_rows));

    lpc_scheme.commit(PERMUTATION_BATCH);
    lpc_scheme.append_eval_point(PERMUTATION_BATCH, y);
    lpc_scheme.append_eval_point(PERMUTATION_BATCH, preprocessed_public_data.common_data.permutation_parts, y * omega);

    transcript_type transcript;
    lpc_scheme.setup(transcript, preprocessed_public_data.common_data.commitment_scheme_data);
    auto lpc_proof = lpc_scheme.proof_eval(transcript);
    // Prepare sorted and V_L values
    std::vector<typename field_type::value_type> special_selector_values(3);
    special_selector_values[0] = preprocessed_public_data.common_data.lagrange_0.evaluate(y);
    special_selector_values[1] = preprocessed_public_data.q_last.evaluate(y);
    special_selector_values[2] = preprocessed_public_data.q_blind.evaluate(y);

    std::vector<typename field_type::value_type> special_selector_values_shifted(2);
    special_selector_values_shifted[0] = preprocessed_public_data.q_last.evaluate(y * omega);
    special_selector_values_shifted[1] = preprocessed_public_data.q_blind.evaluate(y * omega);

    placeholder_lookup_argument_verifier<field_type, lpc_type, lpc_placeholder_params_type> lookup_verifier;
    std::array<typename field_type::value_type, argument_size> verifier_res = lookup_verifier.verify_eval(
        preprocessed_public_data.common_data,
        special_selector_values, special_selector_values_shifted,
        constraint_system,
        y, columns_at_y, lpc_proof.z.get(LOOKUP_BATCH),
        lpc_proof.z.get(PERMUTATION_BATCH, preprocessed_public_data.common_data.permutation_parts),
        {},
        prover_res.lookup_commitment,
        verifier_transcript
    );

    typename field_type::value_type verifier_next_challenge = verifier_transcript.template challenge<field_type>();
    typename field_type::value_type prover_next_challenge = prover_transcript.template challenge<field_type>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    for (int i = 0; i < argument_size; i++) {
        BOOST_CHECK(prover_res.F_dfs[i].evaluate(y) == verifier_res[i]);
        if( prover_res.F_dfs[i].evaluate(y) != verifier_res[i] ){
            std::cout << prover_res.F_dfs[i].evaluate(y) << "!=" << verifier_res[i] << std::endl;
        }
        for (std::size_t j = 0; j < desc.rows_amount; j++) {
            if(prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) != field_type::value_type::zero()){
                std::cout << "!["<< i << "][" << j << "]" << std::endl;

            }
            BOOST_CHECK(prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) == field_type::value_type::zero());
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit4_lookup_test)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t usable_rows = 5;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_4;
        constexpr static const std::size_t public_input_columns = public_columns_4;
        constexpr static const std::size_t constant_columns = constant_columns_4;
        constexpr static const std::size_t selector_columns = selector_columns_4;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(lookup_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_4<field_type>(
        alg_random_engines.template get_alg_engine<field_type>(),
        generic_random_engine
    );
    constexpr std::size_t argument_size = 4;

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(1, table_rows_log, placeholder_test_params::lambda, 4);
    lpc_scheme_type lpc_scheme(fri_params);

    transcript_type transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme);

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);
    lpc_scheme.setup(transcript, preprocessed_public_data.common_data.commitment_scheme_data);

    auto polynomial_table =
        plonk_polynomial_dfs_table<field_type>(
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript_type prover_transcript(init_blob);
    transcript_type verifier_transcript(init_blob);

    placeholder_lookup_argument_prover<field_type, lpc_scheme_type, lpc_placeholder_params_type> prover(
            constraint_system, preprocessed_public_data, polynomial_table, lpc_scheme, prover_transcript);
    auto prover_res = prover.prove_eval();

    // Challenge phase
    auto omega = preprocessed_public_data.common_data.basic_domain->get_domain_element(1);
    typename field_type::value_type y = alg_random_engines.template get_alg_engine<field_type>()();
    typename policy_type::evaluation_map columns_at_y;
    for (std::size_t i = 0; i < placeholder_test_params::witness_columns; i++) {

        std::size_t i_global_index = i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::witness);
            columns_at_y[key] = polynomial_table.witness(i).evaluate(y * omega.pow(rotation));
        }
    }

    for (std::size_t i = 0; i < 0 + placeholder_test_params::constant_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::constant);

            columns_at_y[key] = polynomial_table.constant(i).evaluate(y * omega.pow(rotation));
        }
    }


    for (std::size_t i = 0; i < placeholder_test_params::selector_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::constant_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::selector);

            columns_at_y[key] = polynomial_table.selector(i).evaluate(y * omega.pow(rotation));
        }
    }

    lpc_scheme.append_eval_point(LOOKUP_BATCH, y);
    lpc_scheme.append_eval_point(LOOKUP_BATCH, y * omega);
    lpc_scheme.append_eval_point(LOOKUP_BATCH, y * omega.pow(usable_rows));

    lpc_scheme.commit(PERMUTATION_BATCH);
    lpc_scheme.append_eval_point(PERMUTATION_BATCH, y);
    lpc_scheme.append_eval_point(PERMUTATION_BATCH, y * omega);

    auto lpc_proof = lpc_scheme.proof_eval(transcript);
    // Prepare sorted, V_L and V_S values.

    auto special_selectors = (field_type::value_type::one() - (preprocessed_public_data.q_last.evaluate(y) +
            preprocessed_public_data.q_blind.evaluate(y)));
    auto half = prover_res.F_dfs[2].evaluate(y) * special_selectors.inversed();

    std::vector<typename field_type::value_type> special_selector_values(3);
    special_selector_values[0] = preprocessed_public_data.common_data.lagrange_0.evaluate(y);
    special_selector_values[1] = preprocessed_public_data.q_last.evaluate(y);
    special_selector_values[2] = preprocessed_public_data.q_blind.evaluate(y);

    std::vector<typename field_type::value_type> special_selector_values_shifted(2);
    special_selector_values_shifted[0] = preprocessed_public_data.q_last.evaluate(y * omega);
    special_selector_values_shifted[1] = preprocessed_public_data.q_blind.evaluate(y * omega);

    placeholder_lookup_argument_verifier<field_type, lpc_type, lpc_placeholder_params_type> verifier;
    std::array<typename field_type::value_type, argument_size> verifier_res = verifier.verify_eval(
        preprocessed_public_data.common_data,
        special_selector_values, special_selector_values_shifted,
        constraint_system,
        y, columns_at_y, lpc_proof.z.get(LOOKUP_BATCH),
        lpc_proof.z.get(PERMUTATION_BATCH, 0),
        {},
        prover_res.lookup_commitment,
        verifier_transcript
    );

    typename field_type::value_type verifier_next_challenge = verifier_transcript.template challenge<field_type>();
    typename field_type::value_type prover_next_challenge = prover_transcript.template challenge<field_type>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    for (std::size_t i = 0; i < argument_size; i++) {
        BOOST_CHECK(prover_res.F_dfs[i].evaluate(y) == verifier_res[i]);
        for (std::size_t j = 0; j < desc.rows_amount; j++) {
            if (prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) !=
                    field_type::value_type::zero()){
                std::cout << "!["<< i << "][" << j << "]" << std::endl;
            }
            BOOST_CHECK(
                prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) ==
                field_type::value_type::zero());
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit1)

using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;
using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;

using TestRunners = boost::mpl::list<
    placeholder_test_runner<
        algebra::curves::pallas::base_field_type,
        poseidon_type,
        poseidon_type,
        witness_columns_1,
        public_columns_1,
        constant_columns_1,
        selector_columns_1,
        rows_amount_1
    >,
    placeholder_test_runner<
        algebra::curves::pallas::base_field_type,
        hashes::keccak_1600<512>,
        hashes::keccak_1600<512>,
        witness_columns_1,
        public_columns_1,
        constant_columns_1,
        selector_columns_1,
        rows_amount_1
    >
>;

BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, TestRunner, TestRunners) {
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_1<field_type>(
        random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
        random_test_initializer.generic_random_engine
    );
    TestRunner test_runner(circuit, circuit.usable_rows, circuit.table_rows);
    BOOST_CHECK(test_runner.run_test());
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit1_goldilocks)

using field_type = typename algebra::fields::goldilocks64;
using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;

using TestRunners = boost::mpl::list<
    placeholder_test_runner<
        field_type,
        hashes::keccak_1600<512>,
        hashes::keccak_1600<512>,
        witness_columns_1,
        public_columns_1,
        constant_columns_1,
        selector_columns_1,
        rows_amount_1
    >
>;
BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, TestRunner, TestRunners) {
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_1<field_type>(
        random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
        random_test_initializer.generic_random_engine
    );
    TestRunner test_runner(circuit, circuit.usable_rows, circuit.table_rows);
    BOOST_CHECK(test_runner.run_test());
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit3)

using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;
using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;
const size_t usable_rows_3 = 4;

using TestRunners = boost::mpl::list<
    placeholder_test_runner<
        algebra::curves::pallas::base_field_type,
        poseidon_type,
        poseidon_type,
        witness_columns_3,
        public_columns_3,
        constant_columns_3,
        selector_columns_3,
        usable_rows_3
    >,
    placeholder_test_runner<
        algebra::curves::pallas::base_field_type,
        hashes::keccak_1600<512>,
        hashes::keccak_1600<512>,
        witness_columns_3,
        public_columns_3,
        constant_columns_3,
        selector_columns_3,
        usable_rows_3
    >
>;
BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, TestRunner, TestRunners) {
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_3<field_type>(
        random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
        random_test_initializer.generic_random_engine
    );
    TestRunner test_runner(circuit, usable_rows_3, 1 << 3);
    BOOST_CHECK(test_runner.run_test());
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit4)

using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;
using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;
const size_t usable_rows_4 = 5;

using TestRunners = boost::mpl::list<
    placeholder_test_runner<algebra::curves::pallas::base_field_type, poseidon_type, poseidon_type, witness_columns_4, public_columns_4, constant_columns_4, selector_columns_4, usable_rows_4>,
    placeholder_test_runner<algebra::curves::pallas::base_field_type, hashes::keccak_1600<512>, hashes::keccak_1600<512>, witness_columns_4, public_columns_4, constant_columns_4, selector_columns_4, usable_rows_4>
    >;
BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, TestRunner, TestRunners) {
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_4<field_type>(
        random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
        random_test_initializer.generic_random_engine
    );
    TestRunner test_runner(circuit, usable_rows_4, 1 << 3);
    BOOST_CHECK(test_runner.run_test());
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit5)
using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;
using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;

using TestRunners = boost::mpl::list<
    placeholder_test_runner<algebra::curves::pallas::base_field_type, poseidon_type, poseidon_type, witness_columns_5, public_columns_5, constant_columns_5, selector_columns_5, usable_rows_5, false, 10>,
    placeholder_test_runner<algebra::curves::pallas::base_field_type, hashes::keccak_1600<512>, hashes::keccak_1600<512>, witness_columns_5, public_columns_5, constant_columns_5, selector_columns_5, usable_rows_5, false, 10>
>;
BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, TestRunner, TestRunners) {
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_5<field_type>(
        random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
        random_test_initializer.generic_random_engine
    );
    TestRunner test_runner(circuit, circuit.usable_rows, circuit.table_rows);
    BOOST_CHECK(test_runner.run_test());
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit6)

using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;
using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;

using TestRunners = boost::mpl::list<
    placeholder_test_runner<algebra::curves::pallas::base_field_type, poseidon_type, poseidon_type, witness_columns_6, public_columns_6, constant_columns_6, selector_columns_6, usable_rows_6, true>,
    placeholder_test_runner<algebra::curves::pallas::base_field_type, hashes::keccak_1600<512>, hashes::keccak_1600<512>, witness_columns_6, public_columns_6, constant_columns_6, selector_columns_6, usable_rows_6, true>
>;
BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, TestRunner, TestRunners) {
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_6<field_type>(
        random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
        random_test_initializer.generic_random_engine
    );
    TestRunner test_runner(circuit, circuit.usable_rows, circuit.table_rows);
    BOOST_CHECK(test_runner.run_test());
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit7)

using curve_type = algebra::curves::pallas;
using field_type = typename curve_type::base_field_type;
using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;

using TestRunners = boost::mpl::list<
    placeholder_test_runner<algebra::curves::pallas::base_field_type, poseidon_type, poseidon_type, witness_columns_7, public_columns_7, constant_columns_7, selector_columns_7, usable_rows_7, true, 8>,
    placeholder_test_runner<algebra::curves::pallas::base_field_type, hashes::keccak_1600<512>, hashes::keccak_1600<512>, witness_columns_7, public_columns_7, constant_columns_7, selector_columns_7, usable_rows_7, true, 8>,
    placeholder_test_runner<algebra::curves::pallas::base_field_type, hashes::keccak_1600<512>, hashes::keccak_1600<512>, witness_columns_7, public_columns_7, constant_columns_7, selector_columns_7, usable_rows_7, true, 10>,
    placeholder_test_runner<algebra::curves::pallas::base_field_type, hashes::keccak_1600<512>, hashes::keccak_1600<512>, witness_columns_7, public_columns_7, constant_columns_7, selector_columns_7, usable_rows_7, true, 30>,
    placeholder_test_runner<algebra::curves::pallas::base_field_type, hashes::keccak_1600<512>, hashes::keccak_1600<512>, witness_columns_7, public_columns_7, constant_columns_7, selector_columns_7, usable_rows_7, true, 50>
    >;
BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, TestRunner, TestRunners) {
    test_tools::random_test_initializer<field_type> random_test_initializer;
    auto circuit = circuit_test_7<field_type>(
        random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
        random_test_initializer.generic_random_engine
    );
    TestRunner test_runner(circuit, circuit.usable_rows, circuit.table_rows);
    BOOST_CHECK(test_runner.run_test());
}
BOOST_AUTO_TEST_SUITE_END()


template<
    typename curve_type,
    typename merkle_hash_type,
    typename transcript_hash_type,
    std::size_t WitnessColumns,
    std::size_t PublicInputColumns,
    std::size_t ConstantColumns,
    std::size_t SelectorColumns,
    std::size_t usable_rows_amount,
    std::size_t permutation,
    bool UseGrinding = false>
struct placeholder_kzg_test_runner {
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        constexpr static const std::size_t usable_rows = usable_rows_amount;

        constexpr static const std::size_t witness_columns = WitnessColumns;
        constexpr static const std::size_t public_input_columns = PublicInputColumns;
        constexpr static const std::size_t constant_columns = ConstantColumns;
        constexpr static const std::size_t selector_columns = SelectorColumns;
    };

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using circuit_params = placeholder_circuit_params<field_type>;

    using kzg_type = commitments::batched_kzg<curve_type, transcript_hash_type>;
    using kzg_scheme_type = typename commitments::kzg_commitment_scheme<kzg_type>;
    using kzg_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, kzg_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, kzg_placeholder_params_type>;

    using circuit_type =
        circuit_description<field_type,
        placeholder_circuit_params<field_type>,
        usable_rows_amount>;

    placeholder_kzg_test_runner()
        : desc(WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns)
    {
    }

    bool run_test() {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto pi0 = random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()();
        auto circuit = circuit_test_t<field_type>(
            pi0,
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
        );
        desc.rows_amount = circuit.table_rows;
        desc.usable_rows_amount = circuit.usable_rows;
        std::size_t table_rows_log = std::log2(circuit.table_rows);

        typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        bool verifier_res;

        // KZG commitment scheme
        auto kzg_params = create_kzg_params<kzg_type>(table_rows_log);
        kzg_scheme_type kzg_scheme(kzg_params);

        typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
            kzg_preprocessed_public_data =
            placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
                constraint_system, assignments.public_table(), desc, kzg_scheme
            );

        typename placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
            kzg_preprocessed_private_data = placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::process(
                constraint_system, assignments.private_table(), desc
            );

        auto kzg_proof = placeholder_prover<field_type, kzg_placeholder_params_type>::process(
            kzg_preprocessed_public_data, std::move(kzg_preprocessed_private_data), desc, constraint_system, kzg_scheme
        );

        verifier_res = placeholder_verifier<field_type, kzg_placeholder_params_type>::process(
            kzg_preprocessed_public_data.common_data, kzg_proof, desc, constraint_system, kzg_scheme
        );
        return verifier_res;
    }

    plonk_table_description<field_type> desc;
};


BOOST_AUTO_TEST_SUITE(placeholder_circuit2_kzg)

    using TestRunners = boost::mpl::list<
    placeholder_kzg_test_runner<
        algebra::curves::bls12<381>,
        hashes::keccak_1600<256>,
        hashes::keccak_1600<256>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        true>
        /*
    , placeholder_kzg_test_runner<
        algebra::curves::alt_bn128_254,
        hashes::keccak_1600<256>,
        hashes::keccak_1600<256>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        4, true>*/
    , placeholder_kzg_test_runner<
        algebra::curves::mnt4_298,
        hashes::keccak_1600<256>,
        hashes::keccak_1600<256>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        true>
    , placeholder_kzg_test_runner<
        algebra::curves::mnt6_298,
        hashes::keccak_1600<256>,
        hashes::keccak_1600<256>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        true>
        /*, -- Not yet implemented
    placeholder_kzg_test_runner<
        algebra::curves::mnt6_298,
        hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<algebra::curves::mnt6_298>>,
        hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<algebra::curves::mnt6_298>>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        4,
        true>
        */
    >;

BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, TestRunner, TestRunners) {
    TestRunner test_runner;
    BOOST_CHECK(test_runner.run_test());
}
BOOST_AUTO_TEST_SUITE_END()


template<
    typename curve_type,
    typename merkle_hash_type,
    typename transcript_hash_type,
    std::size_t WitnessColumns,
    std::size_t PublicInputColumns,
    std::size_t ConstantColumns,
    std::size_t SelectorColumns,
    std::size_t usable_rows_amount,
    std::size_t permutation,
    bool UseGrinding = false>
struct placeholder_kzg_test_runner_v2 {
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        constexpr static const std::size_t usable_rows = usable_rows_amount;

        constexpr static const std::size_t witness_columns = WitnessColumns;
        constexpr static const std::size_t public_input_columns = PublicInputColumns;
        constexpr static const std::size_t constant_columns = ConstantColumns;
        constexpr static const std::size_t selector_columns = SelectorColumns;
    };

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using circuit_params = placeholder_circuit_params<field_type>;

    using kzg_type = commitments::batched_kzg<curve_type, transcript_hash_type>;
    using kzg_scheme_type = typename commitments::kzg_commitment_scheme_v2<kzg_type>;
    using kzg_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, kzg_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, kzg_placeholder_params_type>;

    using circuit_type =
        circuit_description<field_type,
        placeholder_circuit_params<field_type>,
        usable_rows_amount>;

    placeholder_kzg_test_runner_v2()
        : desc(WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns)
    {
    }

    bool run_test() {
        test_tools::random_test_initializer<field_type> random_test_initializer;
        auto pi0 = random_test_initializer.alg_random_engines.template get_alg_engine<field_type>()();
        auto circuit = circuit_test_t<field_type>(
            pi0,
            random_test_initializer.alg_random_engines.template get_alg_engine<field_type>(),
            random_test_initializer.generic_random_engine
        );
        desc.rows_amount = circuit.table_rows;
        desc.usable_rows_amount = circuit.usable_rows;
        std::size_t table_rows_log = std::log2(circuit.table_rows);

        typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
        typename policy_type::variable_assignment_type assignments = circuit.table;

        bool verifier_res;

        // KZG commitment scheme
        auto kzg_params = create_kzg_v2_params<kzg_type>(table_rows_log);
        kzg_scheme_type kzg_scheme(kzg_params);

        typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
            kzg_preprocessed_public_data =
            placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
                constraint_system, assignments.public_table(), desc, kzg_scheme
            );

        typename placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
            kzg_preprocessed_private_data = placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::process(
                    constraint_system, assignments.private_table(), desc
                    );

        auto kzg_proof = placeholder_prover<field_type, kzg_placeholder_params_type>::process(
                kzg_preprocessed_public_data, std::move(kzg_preprocessed_private_data), desc, constraint_system, kzg_scheme
                );

        verifier_res = placeholder_verifier<field_type, kzg_placeholder_params_type>::process(
                kzg_preprocessed_public_data.common_data, kzg_proof, desc, constraint_system, kzg_scheme
                );
        return verifier_res;
    }

    plonk_table_description<field_type> desc;
};


BOOST_AUTO_TEST_SUITE(placeholder_circuit2_kzg_v2)

    using TestRunners = boost::mpl::list<
    placeholder_kzg_test_runner_v2<
        algebra::curves::bls12_381,
        hashes::keccak_1600<256>,
        hashes::keccak_1600<256>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        true>
/*  , placeholder_kzg_test_runner<
        algebra::curves::alt_bn128_254,
        hashes::keccak_1600<256>,
        hashes::keccak_1600<256>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        4, true>*/
    , placeholder_kzg_test_runner<
        algebra::curves::mnt4_298,
        hashes::keccak_1600<256>,
        hashes::keccak_1600<256>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        true>
    , placeholder_kzg_test_runner_v2<
        algebra::curves::mnt6_298,
        hashes::keccak_1600<256>,
        hashes::keccak_1600<256>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        true>
        /*, -- Not yet implemented
    placeholder_kzg_test_runner<
        algebra::curves::mnt6_298,
        hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<algebra::curves::mnt6_298>>,
        hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<algebra::curves::mnt6_298>>,
        witness_columns_t,
        public_columns_t,
        constant_columns_t,
        selector_columns_t,
        usable_rows_t,
        4,
        true>
        */
    >;

BOOST_AUTO_TEST_CASE_TEMPLATE(prover_test, TestRunner, TestRunners) {
    TestRunner test_runner;
    BOOST_CHECK(test_runner.run_test());
}

BOOST_AUTO_TEST_SUITE_END()

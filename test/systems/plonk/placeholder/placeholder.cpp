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

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/md5.hpp>
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
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/kzg.hpp>
#include <nil/crypto3/zk/commitments/batched_commitment.hpp>

#include "circuits.hpp"

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;

template<typename CommitmentSchemeParamsType, typename TranscriptHashType>
class dummy_commitment_scheme_type:public nil::crypto3::zk::commitments::polys_evaluator<CommitmentSchemeParamsType, TranscriptHashType>{
private:
public:
    using params_type = CommitmentSchemeParamsType;
    using commitment_type = typename params_type::commitment_type;
    using field_type = typename params_type::field_type;
    using transcript_hash_type = TranscriptHashType;
    using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;

    struct proof_type{
        nil::crypto3::zk::commitments::eval_storage<field_type> z;
    };

    void setup(transcript_type &preprocessed_transript){
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

template<typename kzg_type>
typename kzg_type::params_type create_kzg_params(std::size_t degree_log) {
    // TODO: what cases t != d?
    typename kzg_type::field_type::value_type alpha (7);
    std::size_t d = 1 << degree_log;

    typename kzg_type::params_type params(d, d, alpha);
    return params;
}

// *******************************************************************************
// * Randomness setup
// *******************************************************************************/
using dist_type = std::uniform_int_distribution<int>;
std::size_t test_global_seed = 0;
boost::random::mt11213b test_global_rnd_engine;
template<typename FieldType>
nil::crypto3::random::algebraic_engine<FieldType> test_global_alg_rnd_engine;

struct test_initializer {
    // Enumerate all fields used in tests;
    using field1_type = algebra::curves::pallas::base_field_type;

    test_initializer() {
        test_global_seed = 0;

        for (std::size_t i = 0; i + 1 < boost::unit_test::framework::master_test_suite().argc; i++) {
            if (std::string(boost::unit_test::framework::master_test_suite().argv[i]) == "--seed") {
                if (std::string(boost::unit_test::framework::master_test_suite().argv[i + 1]) == "random") {
                    std::random_device rd;
                    test_global_seed = rd();
                    std::cout << "Random seed = " << test_global_seed << std::endl;
                    break;
                }
                if (std::regex_match(boost::unit_test::framework::master_test_suite().argv[i + 1],
                                     std::regex(("((\\+|-)?[[:digit:]]+)(\\.(([[:digit:]]+)?))?")))) {
                    test_global_seed = atoi(boost::unit_test::framework::master_test_suite().argv[i + 1]);
                    break;
                }
            }
        }

        BOOST_TEST_MESSAGE("test_global_seed = " << test_global_seed);
        test_global_rnd_engine = boost::random::mt11213b(test_global_seed);
        test_global_alg_rnd_engine<field1_type> = nil::crypto3::random::algebraic_engine<field1_type>(test_global_seed);
    }

    void setup() {
    }

    void teardown() {
    }

    ~test_initializer() {
    }
};

BOOST_AUTO_TEST_SUITE(placeholder_circuit1)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;
    constexpr static const std::size_t table_rows_log = 4;

    struct placeholder_test_params {
        constexpr static const std::size_t table_rows = 1 << table_rows_log;
        constexpr static const std::size_t permutation_size = 4;
        constexpr static const std::size_t usable_rows = (1 << table_rows_log) - 3;


        constexpr static const std::size_t witness_columns = witness_columns_1;
        constexpr static const std::size_t public_input_columns = public_columns_1;
        constexpr static const std::size_t constant_columns = constant_columns_1;
        constexpr static const std::size_t selector_columns = selector_columns_1;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };
    typedef placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params> circuit_params;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<        
        merkle_hash_type,
        transcript_hash_type, 
        placeholder_test_params::lambda, 
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, lpc_placeholder_params_type>;

BOOST_FIXTURE_TEST_CASE(prover_test, test_initializer) {
    auto circuit = circuit_test_1<field_type>(test_global_alg_rnd_engine<field_type>);

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = placeholder_test_params::table_rows;
    desc.usable_rows_amount = placeholder_test_params::usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename lpc_type::fri_type::params_type fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, assignments, lpc_scheme
    );

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_proof, constraint_system, lpc_scheme
    );
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit2)
    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

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

        constexpr static const std::size_t lambda = 1;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<
        field_type, 
        typename placeholder_test_params::arithmetization_params
    >;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using commitment_scheme_params_type = nil::crypto3::zk::commitments::commitment_scheme_params_type<field_type, std::vector<std::uint8_t>>;
    using commitment_scheme_dummy_type = dummy_commitment_scheme_type<commitment_scheme_params_type, typename placeholder_test_params::transcript_hash_type>;
    using placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, commitment_scheme_dummy_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, placeholder_params_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<        
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type, 
        placeholder_test_params::lambda, 
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;

    using kzg_type = commitments::batched_kzg<curve_type, typename placeholder_test_params::transcript_hash_type>;
    using kzg_scheme_type = typename commitments::kzg_commitment_scheme<kzg_type>;
    using kzg_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, kzg_scheme_type>;

BOOST_FIXTURE_TEST_CASE(prover_test, test_initializer){
    typename field_type::value_type pi0 = test_global_alg_rnd_engine<field_type>();
    auto circuit = circuit_test_t<field_type>(pi0, test_global_alg_rnd_engine<field_type>);

    plonk_table_description<field_type, typename circuit_t_params::arithmetization_params> desc;
    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    bool verifier_res;

    // Dummy commitment scheme
    commitment_scheme_dummy_type commitment_scheme;

    typename placeholder_public_preprocessor<field_type, placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, commitment_scheme, columns_with_copy_constraints.size()
        );

    typename placeholder_private_preprocessor<field_type, placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto proof = placeholder_prover<field_type, placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, commitment_scheme
    );

    verifier_res = placeholder_verifier<field_type, placeholder_params_type>::process(
        preprocessed_public_data, proof, constraint_system, commitment_scheme
    );
    BOOST_CHECK(verifier_res);

    // Public inputs checks
    // Completely correct public input
    typename placeholder_params_type::public_input_type public_input = {{{pi0, 0, 1}}};
    verifier_res = placeholder_verifier<field_type, placeholder_params_type>::process(
        preprocessed_public_data, proof, constraint_system, commitment_scheme, public_input
    );
    BOOST_CHECK(verifier_res);

    // Completely correct zeroes after it are not important
    public_input =  {{{pi0, 0, 1, 0}}};
    verifier_res = placeholder_verifier<field_type, placeholder_params_type>::process(
        preprocessed_public_data, proof, constraint_system, commitment_scheme, public_input
    );
    BOOST_CHECK(verifier_res);

    // Incorrect public input
    public_input =  {{{pi0, 1}}};
    verifier_res = placeholder_verifier<field_type, placeholder_params_type>::process(
        preprocessed_public_data, proof, constraint_system, commitment_scheme, public_input
    );    
    BOOST_CHECK(!verifier_res);

    // LPC commitment scheme
    typename lpc_type::fri_type::params_type fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);
    transcript_type lpc_transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto lpc_proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_preprocessed_private_data, desc, constraint_system, assignments, lpc_scheme
    );

    verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        lpc_preprocessed_public_data, lpc_proof, constraint_system, lpc_scheme
    );
    BOOST_CHECK(verifier_res);

    // KZG commitment scheme
    auto kzg_params = create_kzg_params<kzg_type>(table_rows_log);
    kzg_scheme_type kzg_scheme(kzg_params);

    typename placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
        kzg_preprocessed_public_data = placeholder_public_preprocessor<field_type, kzg_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, kzg_scheme, columns_with_copy_constraints.size()
        );

    typename placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::preprocessed_data_type
        kzg_preprocessed_private_data = placeholder_private_preprocessor<field_type, kzg_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto kzg_proof = placeholder_prover<field_type, kzg_placeholder_params_type>::process(
        kzg_preprocessed_public_data, kzg_preprocessed_private_data, desc, constraint_system, assignments, kzg_scheme
    );

    verifier_res = placeholder_verifier<field_type, kzg_placeholder_params_type>::process(
        kzg_preprocessed_public_data, kzg_proof, constraint_system, kzg_scheme
    );
    BOOST_CHECK(verifier_res);
}


BOOST_AUTO_TEST_CASE(permutation_polynomials_test) {
    constexpr std::size_t argument_size = 3;

    auto circuit = circuit_test_t<field_type>();

    plonk_table_description<field_type, typename circuit_t_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename lpc_type::fri_type::params_type fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);
    transcript_type lpc_transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto polynomial_table =
        plonk_polynomial_dfs_table<field_type, typename placeholder_test_params::arithmetization_params>(
            lpc_preprocessed_private_data.private_polynomial_table, lpc_preprocessed_public_data.public_polynomial_table);

    std::shared_ptr<math::evaluation_domain<field_type>> domain = lpc_preprocessed_public_data.common_data.basic_domain;
    typename field_type::value_type id_res = field_type::value_type::one();
    typename field_type::value_type sigma_res = field_type::value_type::one();
    for (std::size_t i = 0; i < table_rows; i++) {
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

    for (std::size_t i = 0; i < table_rows; i++) {
        for (std::size_t j = 0; j < lpc_preprocessed_public_data.identity_polynomials.size(); j++) {
            id_res = id_res *
                     (polynomial_table[j].evaluate(domain->get_domain_element(i)) +
                      beta * lpc_preprocessed_public_data.identity_polynomials[j].evaluate(domain->get_domain_element(i)) +
                      gamma);
        }

        for (std::size_t j = 0; j < lpc_preprocessed_public_data.permutation_polynomials.size(); j++) {
            sigma_res =
                sigma_res *
                (polynomial_table[j].evaluate(domain->get_domain_element(i)) +
                 beta * lpc_preprocessed_public_data.permutation_polynomials[j].evaluate(domain->get_domain_element(i)) +
                 gamma);
        }
    }
    BOOST_CHECK_MESSAGE(id_res == sigma_res, "Complex check");
}

BOOST_AUTO_TEST_CASE(placeholder_split_polynomial_test) {
    math::polynomial<typename field_type::value_type> f = {1, 3, 4, 1, 5, 6, 7, 2, 8, 7, 5, 6, 1, 2, 1, 1};
    std::size_t expected_size = 4;
    std::size_t max_degree = 3;

    std::vector<math::polynomial<typename field_type::value_type>> f_splitted =
        zk::snark::detail::split_polynomial<field_type>(f, max_degree);

    BOOST_CHECK(f_splitted.size() == expected_size);

    typename field_type::value_type y = algebra::random_element<field_type>();

    typename field_type::value_type f_at_y = f.evaluate(y);
    typename field_type::value_type f_splitted_at_y = field_type::value_type::zero();
    for (std::size_t i = 0; i < f_splitted.size(); i++) {
        f_splitted_at_y = f_splitted_at_y + f_splitted[i].evaluate(y) * y.pow((max_degree + 1) * i);
    }

    BOOST_CHECK(f_at_y == f_splitted_at_y);
}

BOOST_AUTO_TEST_CASE(permutation_argument_test) {
    auto circuit = circuit_test_t<field_type>();

    constexpr std::size_t argument_size = 3;

    auto fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);

    plonk_table_description<field_type, typename circuit_t_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    transcript_type transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc
        );

    auto polynomial_table =
        plonk_polynomial_dfs_table<field_type, typename placeholder_test_params::arithmetization_params>(
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> prover_transcript(init_blob);
    transcript::fiat_shamir_heuristic_sequential<placeholder_test_params::transcript_hash_type> verifier_transcript(init_blob);

    typename placeholder_permutation_argument<field_type, lpc_placeholder_params_type>::prover_result_type prover_res =
        placeholder_permutation_argument<field_type, lpc_placeholder_params_type>::prove_eval(
            constraint_system, preprocessed_public_data, desc, polynomial_table, lpc_scheme, prover_transcript);

    // Challenge phase
    typename field_type::value_type y = algebra::random_element<field_type>();
    std::vector<typename field_type::value_type> f_at_y(permutation_size);
    for (int i = 0; i < permutation_size; i++) {
        f_at_y[i] = polynomial_table[i].evaluate(y);
    }

    typename field_type::value_type v_p_at_y = prover_res.permutation_polynomial_dfs.evaluate(y);
    typename field_type::value_type v_p_at_y_shifted = prover_res.permutation_polynomial_dfs.evaluate(circuit.omega * y);

    auto permutation_commitment = lpc_scheme.commit(PERMUTATION_BATCH);
    std::array<typename field_type::value_type, 3> verifier_res =
        placeholder_permutation_argument<field_type, lpc_placeholder_params_type>::verify_eval(
            preprocessed_public_data, y, f_at_y, v_p_at_y, v_p_at_y_shifted, verifier_transcript
        );

    typename field_type::value_type verifier_next_challenge = verifier_transcript.template challenge<field_type>();
    typename field_type::value_type prover_next_challenge = prover_transcript.template challenge<field_type>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    for (int i = 0; i < argument_size; i++) {
        BOOST_CHECK(prover_res.F_dfs[i].evaluate(y) == verifier_res[i]);
        for (std::size_t j = 0; j < desc.rows_amount; j++) {
            BOOST_CHECK(
                prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) == field_type::value_type::zero());
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit3)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t permutation_size = 4;
    constexpr static const std::size_t usable_rows = 4;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_3;
        constexpr static const std::size_t public_input_columns = public_columns_3;
        constexpr static const std::size_t constant_columns = constant_columns_3;
        constexpr static const std::size_t selector_columns = selector_columns_3;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<        
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type, 
        placeholder_test_params::lambda, 
        placeholder_test_params::m,
        true
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(prover_test, test_initializer) {
    auto circuit = circuit_test_3<field_type>();

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates, 
        circuit.copy_constraints, 
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    auto fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};
   
    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, proof, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}

BOOST_AUTO_TEST_CASE(lookup_test) {
    auto circuit = circuit_test_3<field_type>();
    constexpr std::size_t argument_size = 4;

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates, 
        circuit.copy_constraints, 
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    auto fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto polynomial_table =
        plonk_polynomial_dfs_table<field_type, typename placeholder_test_params::arithmetization_params>(
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table
    );

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript_type prover_transcript(init_blob);
    transcript_type verifier_transcript(init_blob);

    auto prover_res =
        placeholder_lookup_argument<field_type, lpc_scheme_type, lpc_placeholder_params_type>::prove_eval(
            constraint_system, preprocessed_public_data, polynomial_table, lpc_scheme, prover_transcript
    );

    // Challenge phase
    typename field_type::value_type y = algebra::random_element<field_type>();
    typename policy_type::evaluation_map columns_at_y;
    for (std::size_t i = 0; i < placeholder_test_params::witness_columns; i++) {

        std::size_t i_global_index = i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::witness);
            columns_at_y[key] = polynomial_table.witness(i).evaluate(y * circuit.omega.pow(rotation));
        }
    }

    for (std::size_t i = 0; i < 0 + placeholder_test_params::constant_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::constant);

            columns_at_y[key] = polynomial_table.constant(i).evaluate(y * circuit.omega.pow(rotation));
        }
    }

    for (std::size_t i = 0; i < placeholder_test_params::selector_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::constant_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::selector);

            columns_at_y[key] = polynomial_table.selector(i).evaluate(y * circuit.omega.pow(rotation));
        }
    }

    lpc_scheme.append_eval_point(LOOKUP_BATCH, y);
    lpc_scheme.append_eval_point(LOOKUP_BATCH, y * circuit.omega);
    lpc_scheme.append_eval_point(LOOKUP_BATCH, y * circuit.omega.pow(usable_rows));

    lpc_scheme.commit(PERMUTATION_BATCH);
    lpc_scheme.append_eval_point(PERMUTATION_BATCH, y);
    lpc_scheme.append_eval_point(PERMUTATION_BATCH, y * circuit.omega);

    transcript_type transcript;
    auto lpc_proof = lpc_scheme.proof_eval(transcript);
    // Prepare sorted and V_L values
    
    auto special_selectors = (field_type::value_type::one() - (preprocessed_public_data.q_last.evaluate(y) +
            preprocessed_public_data.q_blind.evaluate(y)));
    auto half = prover_res.F_dfs[2].evaluate(y) * special_selectors.inversed();

    std::array<typename field_type::value_type, argument_size> verifier_res = 
    placeholder_lookup_argument<field_type, lpc_type, lpc_placeholder_params_type>::verify_eval(
        preprocessed_public_data, 
        constraint_system.lookup_gates(), 
        constraint_system.lookup_tables(), 
        y, columns_at_y, lpc_proof.z.get(LOOKUP_BATCH),
        lpc_proof.z.get(PERMUTATION_BATCH, 0),
        prover_res.lookup_commitment, 
        verifier_transcript
    );

    typename field_type::value_type verifier_next_challenge = verifier_transcript.template challenge<field_type>();
    typename field_type::value_type prover_next_challenge = prover_transcript.template challenge<field_type>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    for (int i = 0; i < argument_size; i++) {
        BOOST_CHECK(prover_res.F_dfs[i].evaluate(y) == verifier_res[i]);        
        for (std::size_t j = 0; j < desc.rows_amount; j++) {
            if(prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) != field_type::value_type::zero()){
                std::cout << "!["<< i << "][" << j << "]" << std::endl;

            }
            BOOST_CHECK(prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) == field_type::value_type::zero());
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(placeholder_circuit4)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t permutation_size = 4;
    constexpr static const std::size_t usable_rows = 5;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_4;
        constexpr static const std::size_t public_input_columns = public_columns_4;
        constexpr static const std::size_t constant_columns = constant_columns_4;
        constexpr static const std::size_t selector_columns = selector_columns_4;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<        
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type, 
        placeholder_test_params::lambda, 
        placeholder_test_params::m,
        true
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(prover_test, test_initializer) {
    auto circuit = circuit_test_4<field_type>(test_global_alg_rnd_engine<field_type>);

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates, 
        circuit.copy_constraints, 
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    auto fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, proof, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}

BOOST_AUTO_TEST_CASE(lookup_test) {
    auto circuit = circuit_test_4<field_type>(test_global_alg_rnd_engine<field_type>);
    constexpr std::size_t argument_size = 4;

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates, 
        circuit.copy_constraints, 
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    auto fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};
    transcript_type transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto polynomial_table =
        plonk_polynomial_dfs_table<field_type, typename placeholder_test_params::arithmetization_params>(
            preprocessed_private_data.private_polynomial_table, preprocessed_public_data.public_polynomial_table);

    std::vector<std::uint8_t> init_blob {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    transcript_type prover_transcript(init_blob);
    transcript_type verifier_transcript(init_blob);

    auto prover_res =
        placeholder_lookup_argument<field_type, lpc_scheme_type, lpc_placeholder_params_type>::prove_eval(
            constraint_system, preprocessed_public_data, polynomial_table, lpc_scheme, prover_transcript
    );

    // Challenge phase
    typename field_type::value_type y = algebra::random_element<field_type>();
    typename policy_type::evaluation_map columns_at_y;
    for (std::size_t i = 0; i < placeholder_test_params::witness_columns; i++) {

        std::size_t i_global_index = i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::witness);
            columns_at_y[key] = polynomial_table.witness(i).evaluate(y * circuit.omega.pow(rotation));
        }
    }

    for (std::size_t i = 0; i < 0 + placeholder_test_params::constant_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::constant);

            columns_at_y[key] = polynomial_table.constant(i).evaluate(y * circuit.omega.pow(rotation));
        }
    }

    for (std::size_t i = 0; i < placeholder_test_params::selector_columns; i++) {

        std::size_t i_global_index = placeholder_test_params::witness_columns +
                                     placeholder_test_params::constant_columns +
                                     placeholder_test_params::public_input_columns + i;

        for (int rotation : preprocessed_public_data.common_data.columns_rotations[i_global_index]) {
            auto key = std::make_tuple(i, rotation, plonk_variable<typename field_type::value_type>::column_type::selector);

            columns_at_y[key] = polynomial_table.selector(i).evaluate(y * circuit.omega.pow(rotation));
        }
    }

    lpc_scheme.append_eval_point(LOOKUP_BATCH, y);
    lpc_scheme.append_eval_point(LOOKUP_BATCH, y * circuit.omega);
    lpc_scheme.append_eval_point(LOOKUP_BATCH, y * circuit.omega.pow(usable_rows));

    lpc_scheme.commit(PERMUTATION_BATCH);
    lpc_scheme.append_eval_point(PERMUTATION_BATCH, y);
    lpc_scheme.append_eval_point(PERMUTATION_BATCH, y * circuit.omega);

    auto lpc_proof = lpc_scheme.proof_eval(transcript);
    // Prepare sorted, V_L and V_S values.
    
    auto special_selectors = (field_type::value_type::one() - (preprocessed_public_data.q_last.evaluate(y) +
            preprocessed_public_data.q_blind.evaluate(y)));
    auto half = prover_res.F_dfs[2].evaluate(y) * special_selectors.inversed();

    std::array<typename field_type::value_type, argument_size> verifier_res = 
    placeholder_lookup_argument<field_type, lpc_type, lpc_placeholder_params_type>::verify_eval(
        preprocessed_public_data, 
        constraint_system.lookup_gates(), 
        constraint_system.lookup_tables(), 
        y, columns_at_y, lpc_proof.z.get(LOOKUP_BATCH),
        lpc_proof.z.get(PERMUTATION_BATCH, 0),
        prover_res.lookup_commitment, 
        verifier_transcript
    );

    typename field_type::value_type verifier_next_challenge = verifier_transcript.template challenge<field_type>();
    typename field_type::value_type prover_next_challenge = prover_transcript.template challenge<field_type>();
    BOOST_CHECK(verifier_next_challenge == prover_next_challenge);

    for (int i = 0; i < argument_size; i++) {
        BOOST_CHECK(prover_res.F_dfs[i].evaluate(y) == verifier_res[i]);        
        for (std::size_t j = 0; j < desc.rows_amount; j++) {
            if(prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) != field_type::value_type::zero()){
                std::cout << "!["<< i << "][" << j << "]" << std::endl;

            }
            BOOST_CHECK(prover_res.F_dfs[i].evaluate(preprocessed_public_data.common_data.basic_domain->get_domain_element(j)) == field_type::value_type::zero());
        }
    }
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit6)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 3;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t permutation_size = 3;
    constexpr static const std::size_t usable_rows = 6;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_6;
        constexpr static const std::size_t public_input_columns = public_columns_6;
        constexpr static const std::size_t constant_columns = constant_columns_6;
        constexpr static const std::size_t selector_columns = selector_columns_6;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<        
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type, 
        placeholder_test_params::lambda, 
        placeholder_test_params::m,
        true
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(prover_test, test_initializer) {
    auto circuit = circuit_test_6<field_type>();

    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates, 
        circuit.copy_constraints, 
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    auto fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};
    transcript_type transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, proof, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit7)
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    constexpr static const std::size_t table_rows_log = 4;
    constexpr static const std::size_t table_rows = 1 << table_rows_log;
    constexpr static const std::size_t permutation_size = 3;
    constexpr static const std::size_t usable_rows = 14;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_7;
        constexpr static const std::size_t public_input_columns = public_columns_7;
        constexpr static const std::size_t constant_columns = constant_columns_7;
        constexpr static const std::size_t selector_columns = selector_columns_7;

        using arithmetization_params =
            plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns, selector_columns>;

        constexpr static const std::size_t lambda = 40;
        constexpr static const std::size_t m = 2;
    };

    using circuit_params = placeholder_circuit_params<field_type, typename placeholder_test_params::arithmetization_params>;
    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;
    using lpc_params_type = commitments::list_polynomial_commitment_params<        
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type, 
        placeholder_test_params::lambda, 
        placeholder_test_params::m,
        true
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_params, lpc_scheme_type>;
    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_params>;

BOOST_FIXTURE_TEST_CASE(prover_test, test_initializer) {
    auto circuit = circuit_test_7<field_type>(test_global_alg_rnd_engine<field_type>, test_global_rnd_engine);
    plonk_table_description<field_type, typename circuit_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates, 
        circuit.copy_constraints, 
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    auto fri_params = create_fri_params<typename lpc_type::fri_type, field_type>(table_rows_log);
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};
    transcript_type transcript;

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    typename placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_private_data = placeholder_private_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.private_table(), desc);

    auto proof = placeholder_prover<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, preprocessed_private_data, desc, constraint_system, assignments, lpc_scheme);

    bool verifier_res = placeholder_verifier<field_type, lpc_placeholder_params_type>::process(
        preprocessed_public_data, proof, constraint_system, lpc_scheme);
    BOOST_CHECK(verifier_res);
}
BOOST_AUTO_TEST_SUITE_END()

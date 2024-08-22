#define BOOST_TEST_MODULE crypto3_marshalling_placeholder_preprocessed_public_data_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <filesystem>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <regex>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <boost/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>


#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/pairing/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/pairing/mnt6.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/pairing/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>


#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/poseidon.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/profiling.hpp>
#include <nil/crypto3/zk/test_tools/random_test_initializer.hpp>

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/kzg.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/preprocessed_public_data.hpp>
#include "./detail/circuits.hpp"
#include "random_test_data_generation.hpp"


using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;


template<typename PreprocessedPublicDataType>
void test_placeholder_public_preprocessed_data_marshalling(
        PreprocessedPublicDataType preprocessed_data) {
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    auto filled_preprocessed_data = nil::crypto3::marshalling::types::fill_placeholder_preprocessed_public_data<Endianness, PreprocessedPublicDataType>(preprocessed_data);
//    auto _preprocessed_data = nil::crypto3::marshalling::types::make_placeholder_preprocessed_public_data<Endianness, PreprocessedPublicDataType>(filled_preprocessed_data);
//    BOOST_CHECK(preprocessed_data == _preprocessed_data);
//
//    std::vector<std::uint8_t> cv;
//    cv.resize(filled_preprocessed_data.length(), 0x00);
//    auto write_iter = cv.begin();
//    auto status = filled_preprocessed_data.write(write_iter, cv.size());
//    BOOST_CHECK(status == nil::marshalling::status_type::success);
//
//    nil::crypto3::marshalling::types::placeholder_preprocessed_public_data<TTypeBase, PreprocessedPublicDataType> test_val_read;
//    auto read_iter = cv.begin();
//    test_val_read.read(read_iter, cv.size());
//    BOOST_CHECK(status == nil::marshalling::status_type::success);
//    auto constructed_val_read = nil::crypto3::marshalling::types::make_placeholder_preprocessed_public_data<Endianness, PreprocessedPublicDataType>(
//            test_val_read
//    );
//    BOOST_CHECK(preprocessed_data == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(placeholder_circuit1_poseidon)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using poseidon_type = hashes::poseidon<nil::crypto3::hashes::detail::mina_poseidon_policy<field_type>>;
    using merkle_hash_type = poseidon_type;
    using transcript_hash_type = poseidon_type;

    struct placeholder_test_params {
        constexpr static const std::size_t witness_columns = witness_columns_1;
        constexpr static const std::size_t public_input_columns = public_columns_1;
        constexpr static const std::size_t constant_columns = constant_columns_1;
        constexpr static const std::size_t selector_columns = selector_columns_1;

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

BOOST_AUTO_TEST_CASE(prover_test) {
    auto circuit = circuit_test_1<field_type>();

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};


    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    using preprocessed_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type;
    test_placeholder_public_preprocessed_data_marshalling<preprocessed_data_type>(lpc_preprocessed_public_data);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit1)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;
    using merkle_hash_type = hashes::keccak_1600<512>;
    using transcript_hash_type = hashes::keccak_1600<512>;

    struct placeholder_test_params {
        constexpr static const std::size_t witness_columns = witness_columns_1;
        constexpr static const std::size_t public_input_columns = public_columns_1;
        constexpr static const std::size_t constant_columns = constant_columns_1;
        constexpr static const std::size_t selector_columns = selector_columns_1;

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

BOOST_AUTO_TEST_CASE(prover_test) {
    auto circuit = circuit_test_1<field_type>();

    plonk_table_description<field_type> desc(
        placeholder_test_params::witness_columns,
        placeholder_test_params::public_input_columns,
        placeholder_test_params::constant_columns,
        placeholder_test_params::selector_columns
    );

    desc.rows_amount = circuit.table_rows;
    desc.usable_rows_amount = circuit.usable_rows;
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    using preprocessed_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type;
    test_placeholder_public_preprocessed_data_marshalling<preprocessed_data_type>(lpc_preprocessed_public_data);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit2)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = 3;
        constexpr static const std::size_t public_input_columns = 1;
        constexpr static const std::size_t constant_columns = 0;
        constexpr static const std::size_t selector_columns = 2;

        constexpr static const std::size_t lambda = 1;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<field_type>;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_t_params>;

BOOST_FIXTURE_TEST_CASE(preprocessed_data_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto pi0 = nil::crypto3::algebra::random_element<field_type>();
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
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    // LPC commitment scheme
    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size()
        );

    using preprocessed_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type;
    test_placeholder_public_preprocessed_data_marshalling<preprocessed_data_type>(lpc_preprocessed_public_data);
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(placeholder_circuit3)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

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

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_3<field_type>(
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
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    using preprocessed_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type;
    test_placeholder_public_preprocessed_data_marshalling<preprocessed_data_type>(preprocessed_public_data);
}

BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(placeholder_circuit4)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

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

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_4<field_type>(
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
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    using preprocessed_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type;
    test_placeholder_public_preprocessed_data_marshalling<preprocessed_data_type>(preprocessed_public_data);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit5)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;

    using curve_type = algebra::curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_5;
        constexpr static const std::size_t public_input_columns = public_columns_5;
        constexpr static const std::size_t constant_columns = constant_columns_5;
        constexpr static const std::size_t selector_columns = selector_columns_5;

        constexpr static const std::size_t lambda = 1;
        constexpr static const std::size_t m = 2;
    };
    using circuit_t_params = placeholder_circuit_params<field_type>;

    using transcript_type = typename transcript::fiat_shamir_heuristic_sequential<typename placeholder_test_params::transcript_hash_type>;

    using lpc_params_type = commitments::list_polynomial_commitment_params<
        typename placeholder_test_params::merkle_hash_type,
        typename placeholder_test_params::transcript_hash_type,
        placeholder_test_params::m
    >;

    using lpc_type = commitments::list_polynomial_commitment<field_type, lpc_params_type>;
    using lpc_scheme_type = typename commitments::lpc_commitment_scheme<lpc_type>;
    using lpc_placeholder_params_type = nil::crypto3::zk::snark::placeholder_params<circuit_t_params, lpc_scheme_type>;

    using policy_type = zk::snark::detail::placeholder_policy<field_type, circuit_t_params>;

BOOST_FIXTURE_TEST_CASE(preprocessed_data_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto pi0 = nil::crypto3::algebra::random_element<field_type>();
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
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints, circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    bool verifier_res;

    // LPC commitment scheme
    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4
    );
    lpc_scheme_type lpc_scheme(fri_params);

    using preprocessed_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type;
    preprocessed_data_type lpc_preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, 10
        );

    test_placeholder_public_preprocessed_data_marshalling<preprocessed_data_type>(lpc_preprocessed_public_data);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit6)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_6;
        constexpr static const std::size_t public_input_columns = public_columns_6;
        constexpr static const std::size_t constant_columns = constant_columns_6;
        constexpr static const std::size_t selector_columns = selector_columns_6;

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

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_6<field_type>(
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
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    using preprocessed_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type;
    test_placeholder_public_preprocessed_data_marshalling<preprocessed_data_type>(preprocessed_public_data);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(placeholder_circuit7)
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using curve_type = algebra::curves::pallas;
    using field_type = typename curve_type::base_field_type;

    struct placeholder_test_params {
        using merkle_hash_type = hashes::keccak_1600<512>;
        using transcript_hash_type = hashes::keccak_1600<512>;

        constexpr static const std::size_t witness_columns = witness_columns_7;
        constexpr static const std::size_t public_input_columns = public_columns_7;
        constexpr static const std::size_t constant_columns = constant_columns_7;
        constexpr static const std::size_t selector_columns = selector_columns_7;

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

BOOST_FIXTURE_TEST_CASE(proof_marshalling_test, test_tools::random_test_initializer<field_type>) {
    auto circuit = circuit_test_7<field_type>(
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
    std::size_t table_rows_log = std::ceil(std::log2(circuit.table_rows));

    typename policy_type::constraint_system_type constraint_system(
        circuit.gates,
        circuit.copy_constraints,
        circuit.lookup_gates,
        circuit.lookup_tables
    );
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename lpc_type::fri_type::params_type fri_params(
        1, table_rows_log, placeholder_test_params::lambda, 4, true
    );
    lpc_scheme_type lpc_scheme(fri_params);

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type
        preprocessed_public_data = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::process(
            constraint_system, assignments.public_table(), desc, lpc_scheme, columns_with_copy_constraints.size());

    using preprocessed_data_type = placeholder_public_preprocessor<field_type, lpc_placeholder_params_type>::preprocessed_data_type;
    test_placeholder_public_preprocessed_data_marshalling<preprocessed_data_type>(preprocessed_public_data);
}

BOOST_AUTO_TEST_SUITE_END()


#define BOOST_TEST_MODULE crypto3_marshalling_placeholder_common_data_test

#include <boost/test/unit_test.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int.hpp>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/endianness.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/number.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/type_traits.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/random/algebraic_random_device.hpp>

#include <nil/crypto3/marshalling/zk/types/placeholder/common_data.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/placeholder/preprocessor.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/verifier.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/params.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/profiling.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>

#include <../test/test_plonk_component.hpp>
#include "./detail/circuits.hpp"


using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::zk::snark;


template<typename CommonDataType>
void test_placeholder_common_data(CommonDataType common_data){
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using marshalling_type = nil::crypto3::marshalling::types::placeholder_common_data<TTypeBase, CommonDataType>;

    auto filled_common_data = nil::crypto3::marshalling::types::fill_placeholder_common_data<CommonDataType, Endianness>(common_data);
    auto _common_data = nil::crypto3::marshalling::types::make_placeholder_common_data<CommonDataType, Endianness>(filled_common_data);
    BOOST_CHECK(common_data == _common_data);

    std::vector<std::uint8_t> cv;
    cv.resize(filled_common_data.length(), 0x00);
    auto write_iter = cv.begin();
    nil::marshalling::status_type status = filled_common_data.write(write_iter, cv.size());

    marshalling_type test_val_read;
    auto read_iter = cv.begin();
    status = test_val_read.read(read_iter, cv.size());
    auto constructed_val_read = nil::crypto3::marshalling::types::make_placeholder_common_data<CommonDataType, Endianness>(test_val_read);
    BOOST_CHECK(common_data == constructed_val_read);
}

BOOST_AUTO_TEST_SUITE(placeholder_marshalling_proof_test_suite)

BOOST_AUTO_TEST_CASE(placeholder_proof_pallas_unified_addition_be) {
    using namespace nil::crypto3;
    using Endianness = nil::marshalling::option::big_endian;
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 5;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = zk::components::curve_element_unified_addition<ArithmetizationType, curve_type, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10>;
    using functor_result_check_type = curve_type::template g1_type<>; 

     //auto P = curve_type::template g1_type<>::value_type::one().to_affine();
     //auto Q = curve_type::template g1_type<>::value_type::one().to_affine();
    auto P = algebra::random_element<curve_type::template g1_type<>>().to_affine();
    auto Q = algebra::random_element<curve_type::template g1_type<>>().to_affine();

    auto expected_res = P + Q;

    typename component_type::params_type params = {
        {var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)},
        {var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)}};

    std::vector<typename BlueprintFieldType::value_type> public_input = {P.X, P.Y, Q.X, Q.Y};

    auto result_check = [&expected_res](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_res.X == assignment.var_value(real_res.X));
        assert(expected_res.Y == assignment.var_value(real_res.Y));
    };

    using placeholder_params =
        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;

    auto [desc, bp, fri_params, assignments, public_preprocessed_data, private_preprocessed_data] =
    nil::crypto3::prepare_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check
    );

    test_placeholder_common_data(public_preprocessed_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()


BOOST_AUTO_TEST_SUITE(marshalling_placeholder_common_data_test_2)
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

typedef commitments::fri<FieldType, placeholder_test_params::merkle_hash_type,
                         placeholder_test_params::transcript_hash_type, m, 1>
    fri_type;

typedef placeholder_params<FieldType, typename placeholder_test_params::arithmetization_params> circuit_2_params;
typedef placeholder_params<FieldType, typename placeholder_test_params_lookups::arithmetization_params>
    circuit_3_params;


BOOST_AUTO_TEST_CASE(marshalling_placeholder_common_data_with_circuit_2_params){
    circuit_description<FieldType, circuit_2_params, table_rows_log, permutation_size> circuit =
        circuit_test_2<FieldType>();

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_2_params>;

//    typedef commitments::list_polynomial_commitment<FieldType,
//        circuit_2_params::batched_commitment_params_type> lpc_type;
    typedef commitments::lpc<FieldType, circuit_2_params::batched_commitment_params_type, 0, false> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_2_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    std::vector<std::size_t> columns_with_copy_constraints = {0, 1, 2, 3};

    typename placeholder_public_preprocessor<FieldType, circuit_2_params>::preprocessed_data_type
        preprocessed_public_data =
        placeholder_public_preprocessor<FieldType, circuit_2_params>::process(
            constraint_system, assignments.public_table(), desc,
            fri_params, columns_with_copy_constraints.size());

    test_placeholder_common_data(preprocessed_public_data.common_data);
}

BOOST_AUTO_TEST_CASE(marshalling_placeholder_common_data_with_circuit_3_params){
    circuit_description<FieldType, circuit_3_params, table_rows_log, 3> circuit = circuit_test_3<FieldType>();

    constexpr std::size_t argument_size = 5;

    using policy_type = zk::snark::detail::placeholder_policy<FieldType, circuit_3_params>;

//    typedef commitments::list_polynomial_commitment<FieldType,
//        circuit_3_params::batched_commitment_params_type> lpc_type;
    typedef commitments::lpc<FieldType, circuit_3_params::batched_commitment_params_type, 1, true> lpc_type;

    typename fri_type::params_type fri_params = create_fri_params<fri_type, FieldType>(table_rows_log);

    plonk_table_description<FieldType, typename circuit_3_params::arithmetization_params> desc;

    desc.rows_amount = table_rows;
    desc.usable_rows_amount = usable_rows;

    typename policy_type::constraint_system_type constraint_system(circuit.gates, circuit.copy_constraints,
                                                                   circuit.lookup_gates);
    typename policy_type::variable_assignment_type assignments = circuit.table;

    typename placeholder_public_preprocessor<FieldType, circuit_3_params>::preprocessed_data_type
        preprocessed_public_data =
        placeholder_public_preprocessor<FieldType, circuit_3_params>::process(
            constraint_system, assignments.public_table(), desc, fri_params, 0);

    test_placeholder_common_data(preprocessed_public_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()
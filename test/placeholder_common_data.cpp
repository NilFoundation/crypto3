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

template<typename CommonDataType>
void test_placeholder_common_data(CommonDataType common_data){
    using Endianness = nil::marshalling::option::big_endian;
    using TTypeBase = nil::marshalling::field_type<Endianness>;
    using marshalling_type = nil::crypto3::marshalling::types::placeholder_common_data<TTypeBase, CommonDataType>;

    std::cout << "We are in the small convenient function" << std::endl;
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
    std::cout << "Hello world!" << std::endl;

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

    auto [proof, fri_params, public_preprocessed_data, bp] =
        nil::crypto3::create_component_proof<component_type, BlueprintFieldType, ArithmetizationParams, hash_type,
                                             Lambda>(params, public_input, result_check);
    using placeholder_params =
        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;
//    nil::crypto3::zk::snark::placeholder_profiling<placeholder_params>::print_params(
//        proof, fri_params, public_preprocessed_data.common_data);*/
    std::cout << "It's marshallilng common data test" << std::endl;
    std::cout << public_preprocessed_data.common_data.rows_amount << " " 
        << public_preprocessed_data.common_data.usable_rows_amount << std::endl;
    test_placeholder_common_data(public_preprocessed_data.common_data);
}
BOOST_AUTO_TEST_SUITE_END()

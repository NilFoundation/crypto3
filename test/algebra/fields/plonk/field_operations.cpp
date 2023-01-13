//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_unified_addition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/subtraction.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication_by_constant.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/division_or_zero.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_multiplication) {

    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 3;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = blueprint::components::multiplication<ArithmetizationType, BlueprintFieldType, 3>;

    typename BlueprintFieldType::value_type x = 2;
    typename BlueprintFieldType::value_type y = 12;
    typename BlueprintFieldType::value_type expected_res = x * y;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    std::vector<typename BlueprintFieldType::value_type> public_input = {x, y};

    auto result_check = [&expected_res](blueprint::assignment<ArithmetizationType> &assignment,
        component_type::result_type &real_res) {
        assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2},{},{0});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_addition) {

    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 3;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = blueprint::components::addition<ArithmetizationType, BlueprintFieldType, 3>;

    typename BlueprintFieldType::value_type x = 2;
    typename BlueprintFieldType::value_type y = 22;
    typename BlueprintFieldType::value_type expected_res = x + y;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    std::vector<typename BlueprintFieldType::value_type> public_input = {x, y};

    auto result_check = [&expected_res](blueprint::assignment<ArithmetizationType> &assignment,
        component_type::result_type &real_res) {
        assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2},{},{0});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_division) {

    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 4;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = blueprint::components::division<ArithmetizationType, BlueprintFieldType, 4>;

    typename BlueprintFieldType::value_type x = 16;
    typename BlueprintFieldType::value_type y = 2;
    typename BlueprintFieldType::value_type expected_res = x / y;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    std::vector<typename BlueprintFieldType::value_type> public_input = {x, y};

    auto result_check = [&expected_res](blueprint::assignment<ArithmetizationType> &assignment,
        component_type::result_type &real_res) {
        assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2, 3},{},{0});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_subtraction) {

    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 3;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = blueprint::components::subtraction<ArithmetizationType, BlueprintFieldType, 3>;

    typename BlueprintFieldType::value_type x = 0x56BC8334B5713726A_cppui256;
    typename BlueprintFieldType::value_type y = 101;
    typename BlueprintFieldType::value_type expected_res = x - y;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    std::vector<typename BlueprintFieldType::value_type> public_input = {x, y};

    auto result_check = [&expected_res](blueprint::assignment<ArithmetizationType> &assignment,
        component_type::result_type &real_res) {
        assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2},{},{0});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_mul_by_constant) {

    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 2;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = blueprint::components::mul_by_constant<ArithmetizationType, BlueprintFieldType, 2>;

    typename BlueprintFieldType::value_type x = 2;
    typename BlueprintFieldType::value_type y = 22;
    typename BlueprintFieldType::value_type expected_res = x * y;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), y};

    std::vector<typename BlueprintFieldType::value_type> public_input = {x};

    auto result_check = [&expected_res](blueprint::assignment<ArithmetizationType> &assignment,
        component_type::result_type &real_res) {
        assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1},{0},{0});
    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_div_or_zero) {

    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 5;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = blueprint::components::division_or_zero<ArithmetizationType, BlueprintFieldType, 5>;

    typename BlueprintFieldType::value_type x = 2;
    typename BlueprintFieldType::value_type y = 0;
    typename BlueprintFieldType::value_type expected_res = 0;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    std::vector<typename BlueprintFieldType::value_type> public_input = {x, y};

    auto result_check = [&expected_res](blueprint::assignment<ArithmetizationType> &assignment,
        component_type::result_type &real_res) {
        assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2, 3, 4},{0},{0});
    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

BOOST_AUTO_TEST_SUITE_END()

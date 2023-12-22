//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_logic_or_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/logic_or_flag.hpp>

#include "../../../test_plonk_component.hpp"

template<typename BlueprintFieldType, std::size_t WitnessColumns>
auto test_logic_or_flag(std::vector<typename BlueprintFieldType::value_type> public_input) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1 + 1 * (WitnessColumns == 2);

    using ArithmetizationParams = nil::crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType =
        nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using component_type = nil::blueprint::components::logic_or_flag<ArithmetizationType>;
    using var = typename component_type::var;

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance(witnesses, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>());

    var x(0, 0, false, var::column_type::public_input);
    var y(0, 1, false, var::column_type::public_input);

    typename component_type::input_type instance_input = {x, y};

    typename BlueprintFieldType::value_type fx =
        (public_input[0].is_zero() ? public_input[0] : BlueprintFieldType::value_type::one());
    typename BlueprintFieldType::value_type fy =
        (public_input[1].is_zero() ? public_input[1] : BlueprintFieldType::value_type::one());
    typename BlueprintFieldType::value_type expected_result = fx + fy - fx * fy;

    auto result_check = [&expected_result, &public_input](AssignmentType &assignment,
                                                          typename component_type::result_type &real_res) {
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "logic or test: \n";
        std::cout << "input   : " << public_input[0].data << " " << public_input[1].data << "\n";
        std::cout << "expected: " << expected_result.data << "\n";
        std::cout << "real    : " << var_value(assignment, real_res.output).data << "\n\n";
#endif
        assert(var_value(assignment, real_res.output) == expected_result);
    };

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
    nil::crypto3::test_empty_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FieldType, std::size_t RandomTestsAmount, std::size_t WitnessColumns>
void test_logic_or_flag_random_inputs() {

    nil::crypto3::random::algebraic_engine<FieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        typename FieldType::value_type input_x = generate_random();
        typename FieldType::value_type input_y = generate_random();

        test_logic_or_flag<FieldType, WitnessColumns>({input_x, input_y});
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_logic_or_test_suite)

template<std::uint32_t WitnessesAmount>
void test_witness_size() {
    using field_type = typename nil::crypto3::algebra::curves::pallas::base_field_type;
    test_logic_or_flag<field_type, WitnessesAmount>({0, 0});
    test_logic_or_flag_random_inputs<field_type, random_tests_amount, WitnessesAmount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_logic_or_flag_two_all) {
    test_witness_size<2>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_logic_or_flag_three_all) {
    test_witness_size<3>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_logic_or_flag_four_all) {
    test_witness_size<4>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_logic_or_flag_five_all) {
    test_witness_size<5>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_logic_or_flag_six_all) {
    test_witness_size<6>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_logic_or_flag_seven_all) {
    test_witness_size<7>();
}

BOOST_AUTO_TEST_SUITE_END()
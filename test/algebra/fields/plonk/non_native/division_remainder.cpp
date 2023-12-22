//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_algebra_fields_plonk_non_native_division_remainder_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/division_remainder.hpp>

#include "../../../../test_plonk_component.hpp"

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R,
         bool CheckInputs, bool CustomAssignments = false >
auto test_division_remainder(typename BlueprintFieldType::value_type x,
                             typename BlueprintFieldType::value_type y,
                             const std::map<std::pair<std::size_t, std::size_t>,
                                            typename BlueprintFieldType::value_type> &patches = {}) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<
        WitnessesAmount, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    using component_type = nil::blueprint::components::division_remainder<ArithmetizationType>;

    var x_var(0, 0, false, var::column_type::public_input),
        y_var(0, 1, false, var::column_type::public_input);

    std::vector<typename BlueprintFieldType::value_type> public_input = {x, y};

    typename component_type::input_type instance_input = {x_var, y_var};

    value_type expected_result_quotient = y != 0 ? value_type(integral_type(x.data) / integral_type(y.data)) : 0,
               expected_result_remainder = y != 0 ? value_type(integral_type(x.data) % integral_type(y.data)) : 0;

    value_type max_val = value_type(2).pow(R);
    bool expected_to_pass = x < max_val && y < max_val && expected_result_remainder < max_val &&
                            expected_result_quotient < max_val && y != value_type(0);

    auto result_check = [expected_result_quotient, expected_result_remainder, expected_to_pass]
                        (AssignmentType &assignment, typename component_type::result_type &real_res) {
        if (!expected_to_pass) return;
        assert(expected_result_quotient == var_value(assignment, real_res.quotient));
        assert(expected_result_remainder == var_value(assignment, real_res.remainder));
    };

    std::array<std::uint32_t, WitnessesAmount> witnesses;
    for (std::uint32_t i = 0; i < WitnessesAmount; i++) {
        witnesses[i] = i;
    }

    component_type component_instance =
        component_type(witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0}, R, CheckInputs);

    if (!CustomAssignments) {
        if (expected_to_pass) {
            nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                component_instance, public_input, result_check, instance_input,
                nil::crypto3::detail::connectedness_check_type::STRONG, R, CheckInputs);
            nil::crypto3::test_empty_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                component_instance, public_input, result_check, instance_input,
                nil::crypto3::detail::connectedness_check_type::STRONG, R, CheckInputs);
        } else {
            nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams,
                                                 hash_type, Lambda>(
                                                    component_instance, public_input, result_check, instance_input,
                                                    nil::crypto3::detail::connectedness_check_type::STRONG,
                                                    R, CheckInputs);
        }
    } else {
        auto custom_assignment = nil::crypto3::generate_patched_assignments<
             BlueprintFieldType, ArithmetizationParams, component_type>(patches);

        nil::crypto3::test_component_to_fail_custom_assignments<component_type, BlueprintFieldType,
                ArithmetizationParams, hash_type, Lambda>(
                        component_instance, public_input, result_check,
                        custom_assignment, instance_input,
                        nil::crypto3::detail::connectedness_check_type::STRONG, R, CheckInputs);
    }
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R, bool CheckInputs>
void test_division_remainder_specific_inputs() {
    using value_type = typename BlueprintFieldType::value_type;

    test_division_remainder<BlueprintFieldType, WitnessesAmount, R, CheckInputs>(42, 12);
    test_division_remainder<BlueprintFieldType, WitnessesAmount, R, CheckInputs>(120, 0);

    if (CheckInputs) return;

    test_division_remainder<BlueprintFieldType, WitnessesAmount, R, CheckInputs>(1337, -1);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R, bool CheckInputs,
         std::size_t RandomTestsAmount>
void test_division_remainder_random_inputs() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    boost::random::uniform_int_distribution<std::uint32_t> distribution(0, R-1);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        value_type max_val_x = value_type(2).pow(R),
                   max_val_y = value_type(2).pow(distribution(seed_seq));
        value_type x = generate_random(),
                   y = generate_random();
        integral_type x_integral = integral_type(x.data) & integral_type((max_val_x - 1).data),
                      y_integral = integral_type(y.data) & integral_type((max_val_y - 1).data);
        x = value_type(x_integral);
        y = value_type(y_integral);

        test_division_remainder<BlueprintFieldType, WitnessesAmount, R, CheckInputs>(x, y);
        test_division_remainder<BlueprintFieldType, WitnessesAmount, R, CheckInputs>(y, x);
        test_division_remainder<BlueprintFieldType, WitnessesAmount, R, CheckInputs>(x, x);
	}

    if (CheckInputs) return;

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        value_type max_val_x = value_type(2).pow(R),
                   max_val_y = value_type(2).pow(distribution(seed_seq));
        value_type x = generate_random(),
                   y = generate_random();
        integral_type x_integral = integral_type(x.data) | integral_type((max_val_x).data),
                      y_integral = integral_type(y.data) & integral_type((max_val_y - 1).data);
        x = value_type(x_integral);
        y = value_type(y_integral);

        //std::cout << "x = " << x.data << std::endl;
        //std::cout << "y = " << y.data << std::endl;

        test_division_remainder<BlueprintFieldType, WitnessesAmount, R, CheckInputs>(x, y);
        test_division_remainder<BlueprintFieldType, WitnessesAmount, R, CheckInputs>(y, x);
        test_division_remainder<BlueprintFieldType, WitnessesAmount, R, CheckInputs>(x, x);
	}
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_vesta_15_126) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder_specific_inputs<field_type, 15, 126, true>();
    test_division_remainder_random_inputs<field_type, 15, 126, true, random_tests_amount>();
    test_division_remainder_specific_inputs<field_type, 15, 126, false>();
    test_division_remainder_random_inputs<field_type, 15, 126, false, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_vesta_15_64) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder_specific_inputs<field_type, 15, 64, true>();
    test_division_remainder_random_inputs<field_type, 15, 64, true, random_tests_amount>();
    test_division_remainder_specific_inputs<field_type, 15, 64, false>();
    test_division_remainder_random_inputs<field_type, 15, 64, false, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_pallas_15_32) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder_specific_inputs<field_type, 15, 32, true>();
    test_division_remainder_random_inputs<field_type, 15, 32, true, random_tests_amount>();
    test_division_remainder_specific_inputs<field_type, 15, 32, false>();
    test_division_remainder_random_inputs<field_type, 15, 32, false, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_pallas_15_16) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder_specific_inputs<field_type, 15, 16, true>();
    test_division_remainder_random_inputs<field_type, 15, 16, true, random_tests_amount>();
    test_division_remainder_specific_inputs<field_type, 15, 16, false>();
    test_division_remainder_random_inputs<field_type, 15, 16, false, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_pallas_9_64) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder_specific_inputs<field_type, 9, 64, true>();
    test_division_remainder_random_inputs<field_type, 9, 64, true, random_tests_amount>();
    test_division_remainder_specific_inputs<field_type, 9, 64, false>();
    test_division_remainder_random_inputs<field_type, 9, 64, false, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_vesta_9_32) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder_specific_inputs<field_type, 9, 32, true>();
    test_division_remainder_random_inputs<field_type, 9, 32, true, random_tests_amount>();
    test_division_remainder_specific_inputs<field_type, 9, 32, false>();
    test_division_remainder_random_inputs<field_type, 9, 32, false, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_vesta_9_16) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder_specific_inputs<field_type, 9, 16, true>();
    test_division_remainder_random_inputs<field_type, 9, 16, true, random_tests_amount>();
    test_division_remainder_specific_inputs<field_type, 9, 16, false>();
    test_division_remainder_random_inputs<field_type, 9, 16, false, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_vesta_3_64) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder_specific_inputs<field_type, 3, 64, true>();
    test_division_remainder_random_inputs<field_type, 3, 64, true, random_tests_amount>();
    test_division_remainder_specific_inputs<field_type, 3, 64, false>();
    test_division_remainder_random_inputs<field_type, 3, 64, false, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_oops_y_minus_r_is_zero) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = field_type::value_type;

    std::map<std::pair<std::size_t, std::size_t>, value_type> patches;
    value_type x = 8, y = 2;
    patches[std::make_pair(0, 2)] = 8;
    patches[std::make_pair(0, 3)] = 0;
    patches[std::make_pair(0, 4)] = 0;

    using field_type_2 = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder<field_type, 15, 64, true>(x, y, patches);
}


BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_division_remainder_oops_divide_by_zero) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = field_type::value_type;

    std::map<std::pair<std::size_t, std::size_t>, value_type> patches;
    value_type x = 8, y = 0;
    patches[std::make_pair(0, 2)] = 8;
    patches[std::make_pair(0, 3)] = 0;
    patches[std::make_pair(0, 4)] = -8;

    using field_type_2 = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_division_remainder<field_type, 15, 64, true>(x, y, patches);
}

BOOST_AUTO_TEST_SUITE_END()

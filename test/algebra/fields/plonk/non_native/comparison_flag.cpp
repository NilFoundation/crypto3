//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_comparison_flag_test

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
#include <nil/blueprint/components/algebra/fields/plonk/non_native/comparison_flag.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include "test_plonk_component.hpp"

using nil::blueprint::components::detail::comparison_mode;

template <typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::size_t R, comparison_mode Mode,
          bool CustomAssignments = false>
auto test_comparison_flag(typename BlueprintFieldType::value_type x, typename BlueprintFieldType::value_type y,
                          const std::map<std::pair<std::size_t, std::size_t>,
                          typename BlueprintFieldType::value_type> &patches = {}) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<
        WitnessesAmount, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using component_type = nil::blueprint::components::comparison_flag<ArithmetizationType, WitnessesAmount>;
	using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using value_type = typename BlueprintFieldType::value_type;

    var x_var(0, 0, false, var::column_type::public_input),
        y_var(0, 1, false, var::column_type::public_input);

    std::vector<typename BlueprintFieldType::value_type> public_input = {x, y};

    typename component_type::input_type instance_input = {x_var, y_var};

    value_type max_value = value_type(2).pow(R) - 1;

    bool expected_to_pass = x <= max_value && y <= max_value;

    auto result_check = [&x, &y, expected_to_pass](AssignmentType &assignment,
                                                   typename component_type::result_type &real_res) {
        if (!expected_to_pass || CustomAssignments) return;
        value_type expected_result = 0;
        switch (Mode) {
            case comparison_mode::FLAG:
                expected_result = x > y ? 1
                                        : x == y ? 0 : -1;
                break;
            case comparison_mode::LESS_THAN:
                expected_result = x < y ? 1 : 0;
                break;
            case comparison_mode::GREATER_THAN:
                expected_result = x > y ? 1 : 0;
                break;
            case comparison_mode::LESS_EQUAL:
                expected_result = x <= y ? 1 : 0;
                break;
            case comparison_mode::GREATER_EQUAL:
                expected_result = x >= y ? 1 : 0;
                break;
        }
        assert(var_value(assignment, real_res.flag) == expected_result);
    };

    component_type component_instance = WitnessesAmount == 15 ?
                                            component_type({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0},
                                                           {0}, R, Mode)
                                      : WitnessesAmount == 9 ? component_type({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {0},
                                                                              R, Mode)
                                                             : component_type({0, 1, 2}, {0}, {0}, R, Mode);

    if (!(WitnessesAmount == 15 || WitnessesAmount == 9 || WitnessesAmount == 3)) {
        BOOST_ASSERT_MSG(false, "Please add support for WitnessesAmount that you passed here!") ;
    }

    if (!CustomAssignments) {
        if (expected_to_pass) {
            nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                boost::get<component_type>(component_instance), public_input, result_check, instance_input);
        } else {
            nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams,
                                                 hash_type, Lambda>(
                                                    boost::get<component_type>(component_instance), public_input, result_check, instance_input);
        }
    } else {
        // Currently, the only custom assignment test here is for failure
        auto custom_assignment = nil::crypto3::generate_patched_assignments<
             BlueprintFieldType, ArithmetizationParams, component_type>(patches);

        nil::crypto3::test_component_to_fail_custom_assignments<component_type, BlueprintFieldType,
                ArithmetizationParams, hash_type, Lambda>(
                        boost::get<component_type>(component_instance), public_input, result_check,
                        custom_assignment, instance_input);
    }
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t R, comparison_mode Mode>
void test_comparison_flag_specific_inputs() {
    using value_type = typename BlueprintFieldType::value_type;

    test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(
        value_type(78), value_type(109));
    test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(
        value_type(109), value_type(78));
    test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(
        value_type(300), value_type(300));

    test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(
        value_type(-1), value_type(0));
    test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(
        value_type(value_type(2).pow(R) - 1), value_type(R));
    test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(
        value_type(value_type(2).pow(R) + 1), value_type(value_type(2).pow(R) + 1));
    test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(
        value_type(value_type(2).pow(R)), value_type(value_type(2).pow(R) + 2));
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t R, comparison_mode Mode,
         std::size_t RandomTestsAmount>
void test_comparison_flag_random_inputs() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    value_type max_val = value_type(2).pow(R);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        value_type x = generate_random(),
                   y = generate_random();
        integral_type x_integral = integral_type(x.data) & integral_type((max_val - 1).data),
                      y_integral = integral_type(y.data) & integral_type((max_val - 1).data);
        x = x_integral;
        y = y_integral;
        // Sanity check.
        assert(x < max_val && y < max_val);
        test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(x, y);
        test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(y, x);
        test_comparison_flag<BlueprintFieldType, WitnessesAmount, R, Mode>(x, x);
	}
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_15_254_flag) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 15, field_type::modulus_bits - 1, comparison_mode::FLAG>();
    test_comparison_flag_random_inputs<field_type, 15, field_type::modulus_bits - 1,
                                  comparison_mode::FLAG, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_15_254_less_than) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 15, field_type::modulus_bits - 1, comparison_mode::LESS_THAN>();
    test_comparison_flag_random_inputs<field_type, 15, field_type::modulus_bits - 1,
                                  comparison_mode::LESS_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_15_254_less_equal) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 15, field_type::modulus_bits - 1, comparison_mode::LESS_EQUAL>();
    test_comparison_flag_random_inputs<field_type, 15, field_type::modulus_bits - 1,
                                  comparison_mode::LESS_EQUAL, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_15_254_greater_than) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 15, field_type::modulus_bits - 1,
                                         comparison_mode::GREATER_THAN>();
    test_comparison_flag_random_inputs<field_type, 15, field_type::modulus_bits - 1,
                                  comparison_mode::GREATER_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_15_254_greater_equal) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 15, field_type::modulus_bits - 1, comparison_mode::GREATER_EQUAL>();
    test_comparison_flag_random_inputs<field_type, 15, field_type::modulus_bits - 1,
                                  comparison_mode::GREATER_EQUAL, random_tests_amount>();
}


BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_15_135_flag) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 15, 137, comparison_mode::FLAG>();
    test_comparison_flag_random_inputs<field_type, 15, 137,
                                  comparison_mode::FLAG, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_9_32_flag) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 9, 32, comparison_mode::FLAG>();
    test_comparison_flag_random_inputs<field_type, 9, 32,
                                  comparison_mode::FLAG, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_9_64_FLAG) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 9, 64, comparison_mode::FLAG>();
    test_comparison_flag_random_inputs<field_type, 9, 64,
                                  comparison_mode::FLAG, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_9_128_flag) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 9, 128, comparison_mode::FLAG>();
    test_comparison_flag_random_inputs<field_type, 9, 128,
                                  comparison_mode::FLAG, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_9_64_greater_than) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 9, 64, comparison_mode::GREATER_THAN>();
    test_comparison_flag_random_inputs<field_type, 9, 64,
                                  comparison_mode::GREATER_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_9_64_greater_equal) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 9, 64, comparison_mode::GREATER_EQUAL>();
    test_comparison_flag_random_inputs<field_type, 9, 64,
                                  comparison_mode::GREATER_EQUAL, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_9_77_flag) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 9, 77, comparison_mode::FLAG>();
    test_comparison_flag_random_inputs<field_type, 9, 77,
                                  comparison_mode::FLAG, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_3_64_greater_than) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 3, 64, comparison_mode::GREATER_THAN>();
    test_comparison_flag_random_inputs<field_type, 3, 64,
                                  comparison_mode::GREATER_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_3_64_greater_equal) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;

    test_comparison_flag_specific_inputs<field_type, 3, 64, comparison_mode::GREATER_EQUAL>();
    test_comparison_flag_random_inputs<field_type, 3, 64,
                                       comparison_mode::GREATER_EQUAL, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_comparison_oops_wrong_chunks) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;

    std::map<std::pair<std::size_t, std::size_t>, value_type> patches;
    value_type greater_value = -4;
    patches[std::make_pair(1, 0)] = 1024;
    patches[std::make_pair(1, 0)] = 512;
    // Modifying the chunks.
    patches[std::make_pair(1, 0)] = 0;
    for (std::size_t i = 3; i < 15; i += 2) {
        patches[std::make_pair(1, i)] = 0;
    }
    // Modifying the flags.
    patches[std::make_pair(0, 5)] = patches[std::make_pair(0, 6)] = 0;
    patches[std::make_pair(0, 7)] = -2;
    patches[std::make_pair(0, 8)] = greater_value;
    for (std::size_t i = 9; i < 15; i++) {
        patches[std::make_pair(0, i)] = greater_value;
    }
    patches[std::make_pair(1, 2)] = greater_value;
    patches[std::make_pair(2, 2)] = greater_value;
    patches[std::make_pair(2, 3)] = 1;
    test_comparison_flag<field_type, 15, 14, comparison_mode::LESS_THAN, true>(1024, 512, patches);
}

BOOST_AUTO_TEST_SUITE_END()
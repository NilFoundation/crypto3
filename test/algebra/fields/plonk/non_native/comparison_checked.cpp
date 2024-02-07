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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_comparison_checked_test

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

#include <nil/blueprint/components/algebra/fields/plonk/non_native/comparison_checked.hpp>

#include "../../../../test_plonk_component.hpp"

using nil::blueprint::components::comparison_mode;

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R,
         comparison_mode Mode, bool CustomAssignments = false >
auto test_comparison_checked(typename BlueprintFieldType::value_type x,
                     typename BlueprintFieldType::value_type y,
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

    using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using value_type = typename BlueprintFieldType::value_type;
    using component_type = nil::blueprint::components::comparison_checked<ArithmetizationType>;

    var x_var(0, 0, false, var::column_type::public_input),
        y_var(0, 1, false, var::column_type::public_input);

    std::vector<typename BlueprintFieldType::value_type> public_input = {x, y};

    typename component_type::input_type instance_input = {x_var, y_var};

    auto result_check = [](AssignmentType &assignment, typename component_type::result_type &real_res) {};

    value_type max_val = value_type(2).pow(R);
    bool expected_to_pass = x < max_val && y < max_val;
    switch (Mode) {
        case comparison_mode::LESS_THAN:
            expected_to_pass &= x < y;
            break;
        case comparison_mode::LESS_EQUAL:
            expected_to_pass &= x <= y;
            break;
        case comparison_mode::GREATER_THAN:
            expected_to_pass &= x > y;
            break;
        case comparison_mode::GREATER_EQUAL:
            expected_to_pass &= x >= y;
            break;
    }

    std::array<std::uint32_t, WitnessesAmount> witnesses;
    for (std::uint32_t i = 0; i < WitnessesAmount; i++) {
        witnesses[i] = i;
    }

    component_type component_instance =
        component_type(witnesses, std::array<std::uint32_t, 1>{0}, std::array<std::uint32_t, 1>{0}, R, Mode);

    if (!CustomAssignments) {
        if (expected_to_pass) {
            nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                component_instance, public_input, result_check, instance_input,
                nil::blueprint::connectedness_check_type::type::STRONG, R, Mode);
        } else {
            nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams,
                                                 hash_type, Lambda>(
                                                    component_instance, public_input, result_check, instance_input,
                                                    nil::blueprint::connectedness_check_type::type::STRONG, R, Mode);
        }
    } else {
        auto custom_assignment = nil::crypto3::generate_patched_assignments<
             BlueprintFieldType, ArithmetizationParams, component_type>(patches);

        if (expected_to_pass) {
            nil::crypto3::test_component_custom_assignments<component_type, BlueprintFieldType, ArithmetizationParams,
                    hash_type, Lambda>(
                        component_instance, public_input,
                        result_check, custom_assignment, instance_input,
                        nil::blueprint::connectedness_check_type::type::STRONG, R, Mode);
        } else {
            nil::crypto3::test_component_to_fail_custom_assignments<component_type, BlueprintFieldType,
                    ArithmetizationParams, hash_type, Lambda>(
                            component_instance, public_input, result_check,
                            custom_assignment, instance_input,
                            nil::blueprint::connectedness_check_type::type::STRONG, R, Mode);
        }
    }
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R, comparison_mode Mode>
void test_comparison_checked_specific_inputs() {
    using value_type = typename BlueprintFieldType::value_type;

    test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(0, 42);
    test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(400 - 1, 400);
    test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(70, 70);
    test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(700001, 700001);
    test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(-1, 404);
    test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(300 - value_type(2).pow(R) + 1, 300);
    test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(value_type(2).pow(R) + 1, value_type(2).pow(R));
    test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(value_type(2).pow(R), -1);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R,
         comparison_mode Mode, std::size_t RandomTestsAmount>
void test_comparison_checked_random_inputs() {
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
        x = value_type(x_integral);
        y = value_type(y_integral);

        test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(x, y);
        test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(y, x);
        test_comparison_checked<BlueprintFieldType, WitnessesAmount, R, Mode>(x, x);
	}
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_vesta_15_4_less_than) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 15, 4, comparison_mode::LESS_THAN>();
    test_comparison_checked_random_inputs<field_type, 15, 4, comparison_mode::LESS_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_vesta_15_128_greater_than) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 15, 128, comparison_mode::GREATER_THAN>();
    test_comparison_checked_random_inputs<field_type, 15, 128, comparison_mode::GREATER_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_pallas_15_251_greater_equal) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 15, 251, comparison_mode::GREATER_EQUAL>();
    test_comparison_checked_random_inputs<field_type, 15, 251, comparison_mode::GREATER_EQUAL, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_vesta_15_253_less_equal) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 15, 253, comparison_mode::LESS_EQUAL>();
    test_comparison_checked_random_inputs<field_type, 15, 253, comparison_mode::LESS_EQUAL, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_vesta_9_4_less_than) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 9, 4, comparison_mode::LESS_THAN>();
    test_comparison_checked_random_inputs<field_type, 9, 4, comparison_mode::LESS_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_pallas_9_32_greater_than) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 9, 32, comparison_mode::GREATER_THAN>();
    test_comparison_checked_random_inputs<field_type, 9, 32, comparison_mode::GREATER_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_pallas_3_16_greater_equal) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 3, 16, comparison_mode::GREATER_EQUAL>();
    test_comparison_checked_random_inputs<field_type, 3, 16, comparison_mode::GREATER_EQUAL, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_pallas_3_16_greater_than) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 3, 16, comparison_mode::GREATER_THAN>();
    test_comparison_checked_random_inputs<field_type, 3, 16, comparison_mode::GREATER_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_pallas_9_33_less_equal) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 9, 33, comparison_mode::LESS_EQUAL>();
    test_comparison_checked_random_inputs<field_type, 9, 33, comparison_mode::LESS_EQUAL, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_pallas_9_64_greater_equal) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 9, 64, comparison_mode::GREATER_EQUAL>();
    test_comparison_checked_random_inputs<field_type, 9, 64, comparison_mode::GREATER_EQUAL, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_vesta_9_127_less_than) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 9, 127, comparison_mode::LESS_THAN>();
    test_comparison_checked_random_inputs<field_type, 9, 127, comparison_mode::LESS_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_pallas_15_253_greater_than) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_comparison_checked_specific_inputs<field_type, 9, 253, comparison_mode::GREATER_THAN>();
    test_comparison_checked_random_inputs<field_type, 9, 253, comparison_mode::GREATER_THAN, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_mnt4_15_less_equal) {
    using field_type = nil::crypto3::algebra::curves::mnt4<298>::base_field_type;
    test_comparison_checked_specific_inputs<field_type, 15, 296, comparison_mode::LESS_EQUAL>();
    test_comparison_checked_random_inputs<field_type, 15, 296, comparison_mode::LESS_EQUAL, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_oops_wrong_chunks) {
    using field_type = nil::crypto3::algebra::curves::mnt4<298>::base_field_type;
    using value_type = typename field_type::value_type;

    value_type x = -1,
               y = value_type(2).pow(8) - 1;

    std::map<std::pair<std::size_t, std::size_t>, value_type> patches = {};
    for (std::size_t i = 2; i < 15; i++) {
        patches[std::make_pair(0, i)] = 0;
    }
    for (std::size_t i = 0; i < 15; i++) {
        patches[std::make_pair(1, i)] = 0;
    }
    patches[std::make_pair(2, 0)] = x;
    patches[std::make_pair(2, 1)] = y - x;

    test_comparison_checked<field_type, 15, 8, comparison_mode::LESS_EQUAL, true>(x, y, patches);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_non_native_comparison_checked_oops_chunk_overflow) {
    // Due to the way the component works, the only time first chunk overflow is actually harmful is
    // when it occurs on maximum possible R. Testing on R less than that would not reveal if the
    // first chunk constraints are correct or not.
    using field_type = nil::crypto3::algebra::curves::vesta::base_field_type;
    using value_type = typename field_type::value_type;

    value_type val_253 = value_type(2).pow(253) - 1,
               val_254 = value_type(2).pow(254) - 1,
               difference = val_253 - val_254;
    std::map<std::pair<std::size_t, std::size_t>, value_type> patches;
    value_type sum, sum_diff;
    // 21 rows, 13 padding.
    std::array<uint32_t, 10> corrections = {
        2, 0, 0, 0, 0, 0x2246, 0x98fc099, 0x4a8dd8c, 0x46eb210, 1
    };
    auto place_gate_chunks = [&patches](std::size_t row, std::size_t idx, uint32_t chunk) {
        std::array<bool, 32> bits;
        for (std::size_t i = 0; i < 32; i++) {
            bits[i] = chunk & (1 << (31 - i));
        }
        if (idx == 1) {
            for (std::size_t i = 0; i < 13; i++) {
                patches[std::make_pair(row, i + 2)] = 2 * bits[4 + i * 2] + bits[4 + i * 2 + 1];
            }
            patches[std::make_pair(row + 1, 0)] = 2 * bits[30] + bits[31];
        } else {
            for (std::size_t i = 0; i < 14; i++) {
                patches[std::make_pair(row + 1, i + 1)] = 2 * bits[4 + i * 2] + bits[4 + i * 2 + 1];
            }
        }
    };
    sum = 3 / value_type(2).pow(28);
    sum_diff = 0;
    for (std::size_t i = 2; i < 21; i += 2) {
        if (i != 2) {
            place_gate_chunks(i - 2, 0, uint32_t((1 << 28) - 1));
        } else {
            place_gate_chunks(i - 2, 0, uint32_t(3));
        }
        patches[std::make_pair(i, 0)] = sum = sum * value_type(2).pow(28) + (i != 2) * (value_type(2).pow(28) - 1);
        place_gate_chunks(i - 2, 1, uint32_t(corrections[i / 2 - 1]));
        patches[std::make_pair(i, 1)] = sum_diff = sum_diff * value_type(2).pow(28) +
                                        value_type(corrections[i / 2 - 1]);
    }
    assert(sum_diff == difference);
    assert(sum == val_254);
    test_comparison_checked<field_type, 15, 253, comparison_mode::LESS_THAN, true>(val_254, val_253, patches);
}

BOOST_AUTO_TEST_SUITE_END()

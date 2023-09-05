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

#define BOOST_TEST_MODULE blueprint_plonk_range_check_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/range_check.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include "../../../test_plonk_component.hpp"

template<typename BlueprintFieldType>
std::size_t clz(typename BlueprintFieldType::value_type value) {
    std::size_t count = 0;
    typename BlueprintFieldType::integral_type integral = typename BlueprintFieldType::integral_type(value.data);
    while (integral != 0) {
        integral >>= 1;
        ++count;
    }
    return count;
}

template <typename BlueprintFieldType, std::uint32_t WitnessesAmount, std::size_t R,
          bool CustomAssignments = false >
auto test_range_check(typename BlueprintFieldType::value_type input,
                      const std::map<std::pair<std::size_t, std::size_t>, typename BlueprintFieldType::value_type>
                        &patches = {}) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    // We use either one or two depending on whether R divides chunk_size or not.
    // Since we need to know SelectorColumns amount before the component is actually intialized,
    // we use two.
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<
        WitnessesAmount, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using component_type = nil::blueprint::components::range_check<ArithmetizationType>;
	using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
    using value_type = typename BlueprintFieldType::value_type;

    var x(0, 0, false, var::column_type::public_input);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input};

    typename component_type::input_type instance_input = {x};

    #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
    std::cout << "range_check_test_input: " << std::hex << public_input[0].data << "\n";
    #endif

    auto result_check = [](AssignmentType &assignment, typename component_type::result_type &real_res) {};
    const bool expected_to_pass = input < value_type(2).pow(R);

    std::array<std::uint32_t, WitnessesAmount> witnesses;
    for (std::uint32_t i = 0; i < WitnessesAmount; i++) {
        witnesses[i] = i;
    }

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>({0}),
                                                       std::array<std::uint32_t, 1>({0}), R);

    if (!CustomAssignments) {
        if (expected_to_pass) {
            nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
                component_instance, public_input, result_check, instance_input, R);
        } else {
            nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams,
                                                 hash_type, Lambda>(
                                                    component_instance, public_input, result_check, instance_input, R);
        }
    } else {
        auto custom_assignment = nil::crypto3::generate_patched_assignments<
             BlueprintFieldType, ArithmetizationParams, component_type>(patches);

        if (expected_to_pass) {
            nil::crypto3::test_component_custom_assignments<component_type, BlueprintFieldType, ArithmetizationParams,
                    hash_type, Lambda>(
                        component_instance, public_input,
                        result_check, custom_assignment, instance_input, R);
        } else {
            nil::crypto3::test_component_to_fail_custom_assignments<component_type, BlueprintFieldType,
                    ArithmetizationParams, hash_type, Lambda>(
                            component_instance, public_input, result_check,
                            custom_assignment, instance_input, R);
        }
    }
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R>
void test_range_check_specific_inputs() {
    using value_type = typename BlueprintFieldType::value_type;

    test_range_check<BlueprintFieldType, WitnessesAmount, R>(0);
    test_range_check<BlueprintFieldType, WitnessesAmount, R>(1);
    test_range_check<BlueprintFieldType, WitnessesAmount, R>(2);
    test_range_check<BlueprintFieldType, WitnessesAmount, R>(35000);
    test_range_check<BlueprintFieldType, WitnessesAmount, R>(value_type(2).pow(R) - 1);
    test_range_check<BlueprintFieldType, WitnessesAmount, R>(-1);
    test_range_check<BlueprintFieldType, WitnessesAmount, R>(value_type(2).pow(R));
    test_range_check<BlueprintFieldType, WitnessesAmount, R>(
        0x4000000000000000000000000000000000000000000000000000000000000000_cppui256
    );
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R, std::size_t RandomTestsAmount>
void test_range_check_random_inputs() {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    value_type max_value = value_type(2).pow(R);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        value_type input = generate_random();
    	integral_type input_integral = integral_type(input.data);
        input_integral = input_integral & integral_type((max_value - 1).data);
    	value_type input_scalar = input_integral;
        // Sanity check
        assert(input_scalar < max_value);
        test_range_check<BlueprintFieldType, WitnessesAmount, R>(input_scalar);
	}
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::uint32_t R, std::size_t RandomTestsAmount>
void test_range_check_fail_random_inputs(){
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    value_type max_value = value_type(2).pow(R);
    integral_type restriction_modulus = BlueprintFieldType::modulus - integral_type(max_value.data);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        value_type input = generate_random();
        input = max_value + (value_type(integral_type(input.data) % restriction_modulus));
        // Sanity check
        assert(input >= max_value);
        test_range_check<BlueprintFieldType, WitnessesAmount, R>(input);
	}
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_bls12_15_64) {
    using field_type = nil::crypto3::algebra::fields::bls12_fr<381>;
    test_range_check_specific_inputs<field_type, 15, 64>();
    test_range_check_random_inputs<field_type, 15, 64, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 15, 64, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_15_64) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_range_check_specific_inputs<field_type, 15, 64>();
    test_range_check_random_inputs<field_type, 15, 64, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 15, 64, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_15_64) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 15, 64>();
    test_range_check_random_inputs<field_type, 15, 64, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 15, 64, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_bls12_15_254) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 15, 254>();
    test_range_check_random_inputs<field_type, 15, 254, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 15, 254, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_15_254) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 15, 254>();
    test_range_check_random_inputs<field_type, 15, 254, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 15, 254, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_15_254) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 15, 254>();
    test_range_check_random_inputs<field_type, 15, 254, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 15, 254, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_15_1) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 15, 1>();
    test_range_check_fail_random_inputs<field_type, 15, 1, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_9_1) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 9, 1>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_bls12_9_121) {
    using field_type = nil::crypto3::algebra::fields::bls12_fr<381>;
    test_range_check_specific_inputs<field_type, 9, 121>();
    test_range_check_random_inputs<field_type, 9, 121, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 9, 121, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_9_121) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_range_check_specific_inputs<field_type, 9, 121>();
    test_range_check_random_inputs<field_type, 9, 121, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 9, 121, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_9_128) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_range_check_specific_inputs<field_type, 9, 128>();
    test_range_check_random_inputs<field_type, 9, 128, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 9, 128, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_9_121) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 9, 121>();
    test_range_check_random_inputs<field_type, 9, 121, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 9, 121, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_16_32) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 15, 32>();
    test_range_check_random_inputs<field_type, 15, 32, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 15, 32, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_9_253) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 9, 253>();
    test_range_check_random_inputs<field_type, 9, 253, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 9, 253, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_bls12_9_254) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 9, 254>();
    test_range_check_random_inputs<field_type, 9, 254, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 9, 254, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_pallas_9_254) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 9, 254>();
    test_range_check_random_inputs<field_type, 9, 254, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 9, 254, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_vesta_9_254) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type, 9, 254>();
    test_range_check_random_inputs<field_type, 9, 254, random_tests_amount>();
    test_range_check_fail_random_inputs<field_type, 9, 254, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_oops_first_chunk_overflow) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;
    // 17 rows, 1 padding
    std::map<std::pair<std::size_t, std::size_t>, value_type> patches;
    value_type test_val = value_type(2).pow(253) + 11;
    patches[std::make_pair(1, 2)] = value_type(2);
    value_type sum = 1 / (value_type(8));
    for (std::size_t i = 1; i < 17; i++) {
        patches[std::make_pair(i, 0)] = sum = value_type(2).pow(16) * sum + (i != 16 ? 0 : 11);
    }
    assert(sum == test_val);
    // For 17th row we have to also get 11 assigned.
    patches[std::make_pair(16, 8)] = 3;
    patches[std::make_pair(16, 7)] = 2;
    test_range_check<field_type, 9, 253, true>(test_val, patches);

    using field_type_2 = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check<field_type_2, 15, 1, true>(2,
        {std::make_pair(std::make_pair(1, 14), 2),
         std::make_pair(std::make_pair(1, 0 ), 2)});
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fields_range_check_oops_wrong_chunks) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    using value_type = typename field_type::value_type;

    std::map<std::pair<std::size_t, std::size_t>, value_type> patches;
    patches[std::make_pair(1, 0)] = 1024;
    for (std::size_t i = 1; i < 15; i++) {
        patches[std::make_pair(1, i)] = 0;
    }
    test_range_check<field_type, 15, 8, true>(1024, patches);
}

BOOST_AUTO_TEST_SUITE_END()
//---------------------------------------------------------------------------//
// Copyright (c) 2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
//               2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_keccak_test

#include <array>
#include <cstdlib>
#include <ctime>
#include <random>

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

// #include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/keccak.hpp>
// #include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/hashes/keccak/keccak_padding.hpp>

#include "../../test_plonk_component.hpp"

template<typename BlueprintFieldType>
std::size_t number_bits(typename BlueprintFieldType::value_type value) {
    using integral_type = typename BlueprintFieldType::integral_type;

    integral_type integral_value = integral_type(value.data);
    std::size_t result = 0;
    while (integral_value > 0) {
        integral_value >>= 1;
        ++result;
    }
    return result;
}


template<typename BlueprintFieldType>
std::vector<typename BlueprintFieldType::value_type>
    padding_function(std::vector<typename BlueprintFieldType::value_type> message, std::size_t num_bits) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::vector<value_type> result;
    std::size_t shift = 64 * message.size() - num_bits;

    if (shift > 0) {
        integral_type relay_value = integral_type(message[0].data);
        for (int i = 1; i < message.size(); ++i) {
            integral_type mask = (integral_type(1) << (64 - shift)) - 1;
            integral_type left_part = integral_type(message[i].data >> (64 - shift));
            integral_type right_part = integral_type(message[i].data) & mask;
            result.push_back(value_type((relay_value << shift) + left_part));
            relay_value = right_part;
        }
        relay_value <<= shift;
        relay_value += integral_type(1) << (shift - 8);
        result.push_back(value_type(relay_value));
    } else {
        for (int i = 0; i < message.size(); ++i) {
            result.push_back(message[i]);
        }
        result.push_back(value_type(integral_type(1) << 56));
    }
    while (result.size() % 17 != 0) {
        result.push_back(value_type(0));
    }

    return result;
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows, std::size_t LookupColumns>
auto test_keccak_padding_inner(std::vector<typename BlueprintFieldType::value_type> message,
                               std::vector<typename BlueprintFieldType::value_type> expected_result,
                               const std::size_t num_blocks, const std::size_t num_bits,
                               const bool range_check_input = true, const std::size_t limit_permutation_column = 7) {
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 3;
    constexpr std::size_t SelectorColumns = 20;
    nil::crypto3::zk::snark::plonk_table_description<BlueprintFieldType> desc(WitnessesAmount, PublicInputColumns,
                                                                              ConstantColumns, SelectorColumns);
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using component_type = nil::blueprint::components::keccak_padding<ArithmetizationType>;
    using var = typename component_type::var;

    std::vector<typename BlueprintFieldType::value_type> public_input;
    for (int i = 0; i < num_blocks; ++i) {
        public_input.push_back(message[i]);
    }

    std::vector<var> message_vars;
    for (int i = 0; i < num_blocks; ++i) {
        message_vars.push_back(var(0, i, false, var::column_type::public_input));
    }
    typename component_type::input_type instance_input = {message_vars};

    auto result_check = [expected_result](AssignmentType &assignment, typename component_type::result_type &real_res) {
        assert(expected_result.size() == real_res.padded_message.size());
        for (int i = 0; i < real_res.padded_message.size(); ++i) {
            assert(expected_result[i] == var_value(assignment, real_res.padded_message[i]));
        }
    };

    if (!(WitnessesAmount == 15 || WitnessesAmount == 9)) {
        BOOST_ASSERT_MSG(false, "Please add support for WitnessesAmount that you passed here!");
    }
    std::array<std::uint32_t, WitnessesAmount> witnesses;
    for (std::uint32_t i = 0; i < WitnessesAmount; i++) {
        witnesses[i] = i;
    }
    component_type component_instance =
        component_type(witnesses, std::array<std::uint32_t, 1> {0}, std::array<std::uint32_t, 1> {0}, num_blocks,
                       num_bits, range_check_input, limit_permutation_column);

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input,
        nil::blueprint::connectedness_check_type::type::NONE, num_blocks, num_bits, range_check_input,
        limit_permutation_column);
}

// works
template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows, std::size_t LookupColumns>
void test_keccak_padding_0() {
    using value_type = typename BlueprintFieldType::value_type;

    std::vector<value_type> message = {0};
    const std::size_t num_blocks = 1;
    const std::size_t num_bits = 8;

    std::vector<value_type> expected_result = {281474976710656, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    test_keccak_padding_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns>(message, expected_result,
                                                                                              num_blocks, num_bits);
}
template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows, std::size_t LookupColumns>
void test_keccak_padding_1(std::size_t num_bits) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::vector<value_type> message = {value_type(integral_type(1) << (num_bits - 1) % 64)};
    for (std::size_t i = 0; i < (num_bits - 1) / 64; i++) {
        message.push_back(value_type(0));
    }
    const std::size_t num_blocks = message.size();

    auto expected_result = padding_function<BlueprintFieldType>(message, num_bits);

    test_keccak_padding_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns>(message, expected_result,
                                                                                              num_blocks, num_bits);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows, std::size_t LookupColumns>
void test_keccak_padding_random(std::size_t message_size, bool random_mask_zero = true, bool range_check_input = true,
                                std::size_t limit_permutation_column = 7) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    integral_type mask = (integral_type(1) << 64) - 1;
    std::size_t power_for_mask = 64;
    if (random_mask_zero) {
        power_for_mask = dis(gen) % 63 + 1;
    }
    integral_type mask_zero = (integral_type(1) << power_for_mask) - 1;
    value_type message_zero =
        value_type((integral_type(dis(gen)) & mask_zero) | (integral_type(1) << (power_for_mask - 1)));

    std::vector<value_type> message;
    message.push_back(message_zero);
    for (std::size_t i = 1; i < message_size; i++) {
        message.push_back(value_type(integral_type(dis(gen)) & mask));
    }
    assert(message_size == message.size());
    std::size_t num_bits = 64 * (message_size - 1) + number_bits<BlueprintFieldType>(message[0]);
    std::size_t num_blocks = message_size;

    auto expected_result = padding_function<BlueprintFieldType>(message, num_bits);

    test_keccak_padding_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns>(
        message, expected_result, num_blocks, num_bits, range_check_input, limit_permutation_column);
}

template<typename BlueprintFieldType, std::size_t WitnessesAmount, std::size_t LookupRows, std::size_t LookupColumns>
void test_to_fail_keccak_padding_random(std::size_t message_size, bool more_bits, bool random_mask_zero = true,
                                        bool range_check_input = true, std::size_t limit_permutation_column = 7) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    integral_type mask = (integral_type(1) << 64) - 1;
    std::size_t power_for_mask = 64;
    if (random_mask_zero) {
        power_for_mask = dis(gen) % 63 + 1;
    }
    integral_type mask_zero = (integral_type(1) << power_for_mask) - 1;
    value_type message_zero =
        value_type((integral_type(dis(gen)) & mask_zero) | (integral_type(1) << (power_for_mask - 1)));
    std::vector<value_type> message;
    message.push_back(message_zero);
    for (std::size_t i = 1; i < message_size; i++) {
        message.push_back(value_type(integral_type(dis(gen)) & mask));
    }
    assert(message_size == message.size());
    std::size_t num_bits = 64 * (message_size - 1) + number_bits<BlueprintFieldType>(message[0]);
    std::size_t num_blocks = message_size;

    auto expected_result = padding_function<BlueprintFieldType>(message, num_bits);

    if (more_bits) {
        num_bits -= 1;
    } else {
        num_bits += 1;
    }

    test_keccak_padding_inner<BlueprintFieldType, WitnessesAmount, LookupRows, LookupColumns>(
        message, expected_result, num_blocks, num_bits, range_check_input, limit_permutation_column);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;

    test_keccak_padding_0<field_type, 9, 65536, 10>();
    test_keccak_padding_random<field_type, 9, 65536, 10>(2, true, false);
    for (std::size_t i = 1; i < 100; i++) {
        test_keccak_padding_1<field_type, 9, 65536, 10>(i);
        test_keccak_padding_random<field_type, 9, 65536, 10>(i);
        test_keccak_padding_random<field_type, 9, 65536, 10>(i, false);
        test_keccak_padding_random<field_type, 9, 65536, 10>(i, true, false);
        test_keccak_padding_random<field_type, 9, 65536, 10>(i, false, false);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_pallas_15) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;

    test_keccak_padding_0<field_type, 15, 65536, 10>();
    test_keccak_padding_random<field_type, 15, 65536, 10>(10);
    for (std::size_t i = 80; i < 100; i++) {
        test_keccak_padding_1<field_type, 15, 65536, 10>(i);
        test_keccak_padding_random<field_type, 15, 65536, 10>(i);
        test_keccak_padding_random<field_type, 15, 65536, 10>(i, false);
        test_keccak_padding_random<field_type, 15, 65536, 10>(i, true, false);
        test_keccak_padding_random<field_type, 15, 65536, 10>(i, false, false);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_hashes_keccak_round_to_fail) {
    // test with no result_check asserts
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;

    // test_to_fail_keccak_padding_random<field_type, 9, 65536, 10>(10, false);
    // test_to_fail_keccak_padding_random<field_type, 9, 65536, 10>(16, false, false);
    // test_to_fail_keccak_padding_random<field_type, 9, 65536, 10>(11, false, false, false);
    // test_to_fail_keccak_padding_random<field_type, 9, 65536, 10>(100, true);
    // test_to_fail_keccak_padding_random<field_type, 9, 65536, 10>(150, true, false);
    // test_to_fail_keccak_padding_random<field_type, 9, 65536, 10>(2, true, true, false);
    // test_to_fail_keccak_padding_random<field_type, 9, 65536, 10>(4, true, false, false);

    // test_to_fail_keccak_padding_random<field_type, 15, 65536, 10>(10, false);
    // test_to_fail_keccak_padding_random<field_type, 15, 65536, 10>(16, false, false);
    // test_to_fail_keccak_padding_random<field_type, 15, 65536, 10>(11, false, false, false);
    // test_to_fail_keccak_padding_random<field_type, 15, 65536, 10>(100, true);
    // test_to_fail_keccak_padding_random<field_type, 15, 65536, 10>(150, true, false);
    // test_to_fail_keccak_padding_random<field_type, 15, 65536, 10>(2, true, true, false);
    // test_to_fail_keccak_padding_random<field_type, 15, 65536, 10>(4, true, false, false);

    // this doesn't break, because we switched off range check input
    // test_to_fail_keccak_padding_random<field_type, 9, 65536, 10>(5, false, true, false);
    // test_to_fail_keccak_padding_random<field_type, 15, 65536, 10>(5, false, true, false);

    // test_to_fail_keccak_padding_random<field_type, 9, 65536, 10>(5, false, true);
    // test_to_fail_keccak_padding_random<field_type, 15, 65536, 10>(5, false, true);
}

BOOST_AUTO_TEST_SUITE_END()

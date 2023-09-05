//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE plonk_decomposition_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/hashes/sha2/plonk/decomposition.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_decomposition(std::vector<typename BlueprintFieldType::value_type> public_input,
                        std::vector<typename BlueprintFieldType::value_type> expected_res,
                        const bool expected_to_pass) {

    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using component_type = blueprint::components::decomposition<ArithmetizationType, BlueprintFieldType>;

    std::array<var, 2> input_state_var = {var(0, 0, false, var::column_type::public_input),
                                          var(0, 1, false, var::column_type::public_input)};

    typename component_type::input_type instance_input = {input_state_var};

    auto result_check = [&expected_res](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
            for (std::size_t i = 0; i < real_res.output.size(); i++){
                assert(expected_res[i] == var_value(assignment, real_res.output[i]));
            }
    };
    auto result_check_to_fail = [&expected_res](AssignmentType &assignment,
        typename component_type::result_type &real_res) { };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});

    if (expected_to_pass) {
        crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
    } else {
        crypto3::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check_to_fail, instance_input);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

template<typename FieldType>
std::vector<typename FieldType::value_type> calculate_decomposition(std::vector<typename FieldType::value_type> data_value) {
                std::array<typename FieldType::integral_type, 2> data = {
                    typename FieldType::integral_type(data_value[0].data),
                    typename FieldType::integral_type(data_value[1].data)};
                std::array<typename FieldType::integral_type, 16> range_chunks;
                std::size_t shift = 0;

                for (std::size_t i = 0; i < 8; i++) {
                    range_chunks[i] = (data[0] >> shift) & ((1 << 16) - 1);
                    range_chunks[i + 8] = (data[1] >> shift) & ((1 << 16) - 1);
                    shift += 16;
                }

                std::array<typename FieldType::integral_type, 8> output;

                output[0] = range_chunks[1] * (1 << 16) + range_chunks[0];
                output[1] = range_chunks[3] * (1 << 16) + range_chunks[2];
                output[2] = range_chunks[5] * (1 << 16) + range_chunks[4];
                output[3] = range_chunks[7] * (1 << 16) + range_chunks[6];
                output[4] = range_chunks[9] * (1 << 16) + range_chunks[8];
                output[5] = range_chunks[11] * (1 << 16) + range_chunks[10];
                output[6] = range_chunks[13] * (1 << 16) + range_chunks[12];
                output[7] = range_chunks[15] * (1 << 16) + range_chunks[14];

                std::vector<typename FieldType::value_type> output_value;

                for (std::size_t i = 0; i < output.size(); i++){
                    output_value.push_back(typename FieldType::value_type(output[i]));
                }

                return output_value;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_decomposition_test0) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    test_decomposition<field_type>(
        {0x8d741211e928fdd4d33a13970d0ce7f3_cppui255, 0x92f209334030f9ec8fa8a025e987a5dd_cppui255},
        calculate_decomposition<field_type>({0x8d741211e928fdd4d33a13970d0ce7f3_cppui255, 0x92f209334030f9ec8fa8a025e987a5dd_cppui255}),
        true);

    test_decomposition<field_type>(
        {0, 0},
        calculate_decomposition<field_type>({0, 0}),
        true);

    test_decomposition<field_type>(
        {0xffffffffffffffffffffffffffffffff_cppui255, 0xffffffffffffffffffffffffffffffff_cppui255},
        calculate_decomposition<field_type>({0xffffffffffffffffffffffffffffffff_cppui255, 0xffffffffffffffffffffffffffffffff_cppui255}),
        true);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_decomposition_must_fail) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    typename field_type::value_type bad = 0x100000000000000000000000000000000_cppui255;

    test_decomposition<field_type>(
        {0, bad},
        calculate_decomposition<field_type>({0, bad}),
        false);

    test_decomposition<field_type>(
        {bad, 0},
        calculate_decomposition<field_type>({bad, 0}),
        false);

        bad = 0x4000000000000000000000000000000000000000000000000000000000000000_cppui255;

    test_decomposition<field_type>(
        {0, bad},
        calculate_decomposition<field_type>({0, bad}),
        false);

    test_decomposition<field_type>(
        {bad, 0},
        calculate_decomposition<field_type>({bad, 0}),
        false);
}

BOOST_AUTO_TEST_SUITE_END()
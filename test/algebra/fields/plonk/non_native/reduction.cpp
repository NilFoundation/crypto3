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

#define BOOST_TEST_MODULE blueprint_variable_base_decomposition_edward25519
#include <fstream>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/reduction.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_reduction(std::vector<typename BlueprintFieldType::value_type> public_input,
        typename BlueprintFieldType::value_type expected_res){

    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::reduction<ArithmetizationType, BlueprintFieldType,
        blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::array<var, 8> input_state_var = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    typename component_type::input_type instance_input = {input_state_var};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << std::hex << "___________________________________________________________________________________________________\ninput: ";
            for (std::size_t i = 0; i < 8; i++) {
                std::cout << public_input[7-i].data << " ";
            }
            std::cout << "\nexpected: " << expected_res.data << "\n";
            std::cout << "real    : " << var_value(assignment, real_res.output).data << std::endl;
            #endif
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

constexpr static const crypto3::algebra::curves::ed25519::scalar_field_type::extended_integral_type ed25519_scalar_modulus = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui512;
constexpr static const crypto3::algebra::curves::ed25519::scalar_field_type::extended_integral_type one = 1;
constexpr static const crypto3::algebra::curves::ed25519::scalar_field_type::extended_integral_type max512 = (one<<512)-1;

template<typename FieldType>
std::vector<typename FieldType::value_type> vector_from_extended_integral(typename crypto3::algebra::curves::ed25519::scalar_field_type::extended_integral_type input) {
    std::vector<typename FieldType::value_type> pub_inp;
    for (std::size_t i = 0; i < 8; i++) {
        typename crypto3::algebra::curves::ed25519::scalar_field_type::extended_integral_type mask = 0xffffffffffffffff_cppui512;
        typename FieldType::value_type current = typename FieldType::value_type((input >> (64*i)) & mask);
        pub_inp.push_back(current);
    }
    return pub_inp;
}

template<typename FieldType>
void test_reduction_input_expended_integral_calculate_expected(typename crypto3::algebra::curves::ed25519::scalar_field_type::extended_integral_type input) {
    assert(input <= max512);
    test_reduction<FieldType>(vector_from_extended_integral<FieldType>(input), typename FieldType::value_type(input % ed25519_scalar_modulus));
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_variable_base_decomposition_edward25519) {

    using curve_type = nil::crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;

    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(max512);
    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(0);
    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(1);
    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppui512);
    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(ed25519_scalar_modulus);
    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(ed25519_scalar_modulus * 2);
    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(ed25519_scalar_modulus + 1);
    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(ed25519_scalar_modulus - 1);
    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(ed25519_scalar_modulus << 256);
    test_reduction_input_expended_integral_calculate_expected<BlueprintFieldType>(max512 - 0x399411b7c309a3dceec73d217f5be65d00e1ba768859347a40611e3449c0f00_cppui512);
}

BOOST_AUTO_TEST_SUITE_END()
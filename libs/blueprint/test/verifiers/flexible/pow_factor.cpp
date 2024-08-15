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

#define BOOST_TEST_MODULE blueprint_verifiers_plonk_pow_factor_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/systems/snark/plonk/flexible/pow_factor.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType, std::size_t WitnessColumns>
void test_pow_factor(
        const std::vector<typename BlueprintFieldType::value_type> &coefficients,
        const typename BlueprintFieldType::value_type &theta,
        std::size_t power){
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::pow_factor<ArithmetizationType, BlueprintFieldType>;

    BOOST_ASSERT(coefficients.size() == power + 1);

    typename component_type::input_type instance_input;
    instance_input.theta = var(0, 0, false, var::column_type::public_input);
    instance_input.coefficients.reserve(power + 1);
    for (std::size_t i = 0; i < power + 1; i++) {
        instance_input.coefficients.emplace_back(var(0, i + 1, false, var::column_type::public_input));
    }

    std::vector<value_type> public_input = {theta};
    std::copy(coefficients.begin(), coefficients.end(), std::back_inserter(public_input));
    BOOST_ASSERT(public_input.size() == power + 2);

    auto result_check = [power, &theta, &coefficients](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {

        value_type poly_value = coefficients[0];
        for (std::size_t i = 1; i < power + 1; i++) {
            poly_value = poly_value * theta + coefficients[i];
        }
        BOOST_ASSERT(var_value(assignment, real_res.output) == poly_value);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    std::iota(witnesses.begin(), witnesses.end(), 0);

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, power);
    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input,
         nil::blueprint::connectedness_check_type::type::STRONG, power);
}

template <typename BlueprintFieldType, std::size_t WitnessAmount, std::size_t RandomTestsAmount>
void pow_factor_tests() {
    static boost::random::mt19937 seed_seq(1444);
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);
    static boost::random::uniform_int_distribution<> power_dist(1, 400);
    using value_type = typename BlueprintFieldType::value_type;
    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        const std::size_t power = power_dist(seed_seq);
        std::vector<value_type> coefficients;
        coefficients.reserve(power + 1);
        for (std::size_t i = 0; i < power + 1; i++) {
            coefficients.emplace_back(generate_random());
        }
        value_type theta = generate_random();
        test_pow_factor<BlueprintFieldType, WitnessAmount>(coefficients, theta, power);
    }
    // zero-padding case checked separately
    const std::size_t power = WitnessAmount == 10 ?
        8 :
        8 + (WitnessAmount - 10) / 8 * 7;
    std::vector<value_type> coefficients;
    coefficients.reserve(power + 1);
    for (std::size_t i = 0; i < power + 1; i++) {
        coefficients.emplace_back(generate_random());
    }
    value_type theta = generate_random();
    test_pow_factor<BlueprintFieldType, WitnessAmount>(coefficients, theta, power);
}

constexpr static const std::size_t random_tests_amount = 20;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    pow_factor_tests<field_type, 10, random_tests_amount>();
    pow_factor_tests<field_type, 18, random_tests_amount>();
    pow_factor_tests<field_type, 26, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()

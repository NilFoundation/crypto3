//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#include "nil/blueprint/components/systems/snark/plonk/verifier/final_polynomial_check.hpp"
#include <algorithm>
#include <vector>
#define BOOST_TEST_MODULE plonk_final_polynomial_check_component_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/benchmarks/circuit_generator.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/expression_evaluation_component.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, std::uint32_t WitnessAmount, std::size_t Power, std::size_t Lambda>
void test(std::vector<typename BlueprintFieldType::value_type> &public_input,
          bool expected_to_pass) {

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 3;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t TestLambda = 1;

    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::final_polynomial_check<ArithmetizationType>;

    std::array<std::uint32_t, WitnessColumns> witnesses;
    std::iota(witnesses.begin(), witnesses.end(), 0);
    component_type component_instance(witnesses, std::array<std::uint32_t, 1>(), std::array<std::uint32_t, 0>(),
                                      Power, Lambda);

    typename component_type::input_type instance_input;
    std::size_t rotation = 0;
    for (std::size_t i = 0; i < Lambda; i++) {
        instance_input.points.push_back(var(0, rotation++, false, var::column_type::public_input));
    }
    for (std::size_t i = 0; i < 2 * Lambda; i++) {
        instance_input.values.push_back(var(0, rotation++, false, var::column_type::public_input));
    }
    for (std::size_t i = 0; i < Power + 1; i++) {
        instance_input.coefficients.push_back(var(0, rotation++, false, var::column_type::public_input));
    }

    auto result_check = [](AssignmentType &assignment, typename component_type::result_type &real_res) {};

    if (expected_to_pass) {
        crypto3::test_component<component_type, BlueprintFieldType, hash_type, TestLambda>(
            component_instance, desc, public_input, result_check, instance_input,
            nil::blueprint::connectedness_check_type::type::STRONG,
            Power, Lambda);
    } else {
        crypto3::test_component_to_fail<component_type, BlueprintFieldType, hash_type, TestLambda>(
            component_instance, desc, public_input, result_check, instance_input,
            nil::blueprint::connectedness_check_type::type::STRONG,
            Power, Lambda);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

template<typename BlueprintFieldType, std::uint32_t WitnessAmount, std::size_t Power, std::size_t Lambda>
void test_random_polynomials(boost::random::mt19937 &gen) {
    using value_type = typename BlueprintFieldType::value_type;
    nil::crypto3::random::algebraic_engine<BlueprintFieldType> random_engine(gen);
    boost::random::uniform_int_distribution<> dist(0, 2 * Lambda - 1);
    // test case generation doesn't work otherwise
    BOOST_ASSERT(2 * Lambda == Power + 1);
    for (std::size_t i = 0; i < 15; i++) {
        std::vector<value_type> public_input;
        std::vector<value_type> points_with_m;
        std::vector<value_type> values;
        for (std::size_t j = 0; j < Lambda; j++) {
            value_type point = random_engine();
            public_input.push_back(point);
            points_with_m.push_back(point);
            points_with_m.emplace_back(-point);
        }
        for (std::size_t j = 0; j < 2 * Lambda; j++) {
            value_type value = random_engine();
            public_input.push_back(value);
            values.push_back(value);
        }
        std::vector<std::pair<value_type, value_type>> points_values;
        for (std::size_t j = 0; j < 2 * Lambda; j += 2) {
            points_values.emplace_back(std::make_pair(points_with_m[j], values[j]));
            points_values.emplace_back(std::make_pair(points_with_m[j + 1], values[j + 1]));
        }
        // now we use lagrange interpolation to create a polynomial which would be y at all the (s; -s)
        auto polynomial = nil::crypto3::math::lagrange_interpolation(points_values);
        BOOST_ASSERT(polynomial.size() == 2 * Lambda);
        std::vector<value_type> coefficients;
        for (auto val : polynomial) {
            coefficients.push_back(val);
        }
        BOOST_ASSERT(coefficients.size() == Power + 1);
        std::reverse(coefficients.begin(), coefficients.end());
        public_input.insert(public_input.end(), coefficients.begin(), coefficients.end());
        test<BlueprintFieldType, WitnessAmount, Power, Lambda>(public_input, true);
        // randomly try to break a constraint
        std::size_t rand_index = dist(gen);
        public_input[Lambda + rand_index] = random_engine();
        test<BlueprintFieldType, WitnessAmount, Power, Lambda>(public_input, false);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_final_polynomial_check_component_random_tests) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    boost::random::mt19937 gen(1444);
    test_random_polynomials<field_type, 150, 59, 30>(gen);
}

BOOST_AUTO_TEST_SUITE_END()

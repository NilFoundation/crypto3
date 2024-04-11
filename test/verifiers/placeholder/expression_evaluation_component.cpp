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

#define BOOST_TEST_MODULE plonk_expression_evaluation_component_test

#include <boost/test/unit_test.hpp>

#include <unordered_map>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/benchmarks/circuit_generator.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/detail/expression_evaluation_component.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, std::uint32_t WitnessAmount>
void test(std::vector<typename BlueprintFieldType::value_type> &public_input,
          std::unordered_map<crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>,
                             crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>> var_map,
          crypto3::zk::snark::plonk_constraint<BlueprintFieldType> &constraint) {

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 3;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::detail::expression_evaluation_component<ArithmetizationType>;

    std::array<std::uint32_t, WitnessColumns> witnesses;
    std::iota(witnesses.begin(), witnesses.end(), 0);
    component_type component_instance(witnesses, std::array<std::uint32_t, 1>(), std::array<std::uint32_t, 0>(),
                                      constraint);

    std::function<value_type(const var&)> get_var_value = [&var_map, &public_input](const var &v) {
        BOOST_ASSERT(var_map.count(v) > 0);
        const var input_var = var_map[v];
        BOOST_ASSERT(input_var.type == var::column_type::public_input);
        BOOST_ASSERT(input_var.index == 0);
        return public_input[input_var.rotation];
    };
    expression_evaluator<var> evaluator(constraint, get_var_value);
    value_type expected_res = evaluator.evaluate();

    typename component_type::input_type instance_input = {var_map};

    auto result_check = [&expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        BOOST_ASSERT(var_value(assignment, real_res.output) == expected_res);
    };

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input,
        nil::blueprint::connectedness_check_type::type::STRONG,
        constraint);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_expression_evaluation_component_basic_test) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = field_type::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;
    using constraint_type = crypto3::zk::snark::plonk_constraint<field_type>;

    constraint_type example_constraint = var(0, 0) * var(1, 1) - var(2, 3);
    std::unordered_map<var, var> var_map = {
        {var(0, 0), var(0, 0, false, var::column_type::public_input)},
        {var(1, 1), var(0, 1, false, var::column_type::public_input)},
        {var(2, 3), var(0, 2, false, var::column_type::public_input)}
    };
    std::vector<value_type> public_input = {value_type(2), value_type(3), value_type(4)};
    test<field_type, 15>(public_input, var_map, example_constraint);
    constraint_type example_constraint_2 = var(0, 0).pow(4);
    std::vector<value_type> public_input_2 = {value_type(2)};
    std::unordered_map<var, var> var_map_2 = {
        {var(0, 0), var(0, 0, false, var::column_type::public_input)},
    };
    test<field_type, 11>(public_input_2, var_map_2, example_constraint_2);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_expression_evaluation_component_random_tests) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = field_type::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    boost::random::mt19937 gen(1444);
    nil::crypto3::random::algebraic_engine<field_type> random_engine(gen);

    constexpr std::size_t WitnessAmount = 15;
    blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<field_type>> tmp_assignment(
        WitnessAmount, 0, 1, 0);
    for (std::size_t i = 0; i < 10; i++) {
        auto constraint = nil::blueprint::generate_random_constraint<field_type>(tmp_assignment, 7, 3, gen);
        std::set<var> variable_set;
        std::function<void(var)> variable_extractor =
            [&variable_set](var variable) { variable_set.insert(variable); };
        nil::crypto3::math::expression_for_each_variable_visitor<var> visitor(variable_extractor);
        visitor.visit(constraint);
        std::unordered_map<var, var> var_map;
        std::size_t rotation = 0;
        for (auto &variable : variable_set) {
            var_map[variable] = var(0, rotation++, false, var::column_type::public_input);
        }
        std::vector<value_type> public_input;
        public_input.reserve(variable_set.size());
        for (std::size_t i = 0; i < variable_set.size(); i++) {
            public_input.push_back(random_engine());
        }
        test<field_type, WitnessAmount>(public_input, var_map, constraint);
    }
}

BOOST_AUTO_TEST_SUITE_END()

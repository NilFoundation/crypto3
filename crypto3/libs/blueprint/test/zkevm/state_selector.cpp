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

#define BOOST_TEST_MODULE blueprint_zkevm_state_selector_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks64.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/zkevm/state_selector.hpp>

#include "../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_state_selector(std::size_t options_amount, std::size_t option){
    BOOST_ASSERT(option < options_amount);
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    const std::size_t WitnessColumns = (options_amount + 1) / 2 + 2;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = typename crypto3::zk::snark::plonk_variable<value_type>;
    using component_type = blueprint::components::state_selector<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input)
    };

    std::vector<value_type> public_input = {value_type(option)};
    auto result_check = [](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
        return true;
    };

    std::vector<std::uint32_t> witnesses(WitnessColumns);
    std::iota(witnesses.begin(), witnesses.end(), 0);

    component_type component_instance = component_type(witnesses, std::array<std::uint32_t, 1>{0},
                                                       std::array<std::uint32_t, 1>{0}, options_amount);
    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input,
         nil::blueprint::connectedness_check_type::type::STRONG, options_amount);
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_vesta) {
    using field_type = typename crypto3::algebra::fields::goldilocks64_base_field;
    boost::random::mt19937 gen(1444);

    for (std::size_t i = 1; i < 30; i++) {
        boost::uniform_int<> distrib(0, i - 1);
        test_state_selector<field_type>(i, distrib(gen));
        test_state_selector<field_type>(i, distrib(gen));
        test_state_selector<field_type>(i, distrib(gen));
        test_state_selector<field_type>(i, distrib(gen));
    }
}

BOOST_AUTO_TEST_SUITE_END()

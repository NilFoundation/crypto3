//---------------------------------------------------------------------------//
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_bbf_wrapper_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/bbf/bbf_wrapper.hpp>

#include "../test_plonk_component.hpp"

using namespace nil::crypto3;
using namespace nil::blueprint;

template <typename BlueprintFieldType>
void test_bbf_wrapper(std::vector<typename BlueprintFieldType::value_type> public_input) {
    constexpr std::size_t WitnessColumns = 15;    // TODO
    constexpr std::size_t PublicInputColumns = 1; // TODO
    constexpr std::size_t ConstantColumns = 1;    // TODO
    constexpr std::size_t SelectorColumns = 5;    // TODO

    // table configuration
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);

    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = components::bbf_wrapper<ArithmetizationType, BlueprintFieldType>;

    typename BlueprintFieldType::value_type expected_res = 0; // TODO

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input),
        var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input),
        var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input),
        var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input),
        var(0, 7, false, var::column_type::public_input) };

//    std::vector<typename BlueprintFieldType::value_type> public_input = {input};

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, {0}, {0});

    auto result_check = [&expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        // assert(expected_res == var_value(assignment, real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>
        (component_instance, desc, public_input, result_check, instance_input);
}

static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_bbf_wrapper_test) {
    using field_type = typename algebra::curves::pallas::base_field_type;
    using integral_type = typename field_type::integral_type;
    using value_type = typename field_type::value_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    integral_type base16 = integral_type(1) << 16;

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        auto random_input = value_type(integral_type(generate_random().data) % base16);
        test_bbf_wrapper<field_type>({random_input,1,random_input,random_input,random_input,random_input,random_input,random_input});
    }
}

BOOST_AUTO_TEST_SUITE_END()

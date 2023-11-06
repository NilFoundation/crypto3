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

#define BOOST_TEST_MODULE blueprint_verifiers_plonk_fri_lin_inter_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/fri_lin_inter.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_fri_lin_inter(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    constexpr std::size_t WitnessColumns = 5;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::fri_lin_inter<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};

    value_type s = public_input[0],
               y0 = public_input[1],
               y1 = public_input[2],
               alpha = public_input[3];
    value_type expected_res = y0 + (y1 - y0) * (s - alpha) / (2 * s);

    auto result_check = [&expected_res, &public_input](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {

        BOOST_ASSERT(var_value(assignment, real_res.output) == expected_res);
    };

    component_type component_instance({0, 1, 2, 3, 4}, {}, {});

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>
        (component_instance, public_input, result_check, instance_input);
}

template <typename BlueprintFieldType, std::size_t RandomTestsAmount>
void fri_lin_inter_tests() {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        test_fri_lin_inter<BlueprintFieldType>(
            {generate_random(), generate_random(), generate_random(), generate_random()});
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    fri_lin_inter_tests<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    fri_lin_inter_tests<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;

    fri_lin_inter_tests<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()

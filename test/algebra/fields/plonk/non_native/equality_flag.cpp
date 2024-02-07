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

#define BOOST_TEST_MODULE blueprint_algebra_fields_plonk_non_native_equality_flag_test

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
#include <nil/blueprint/components/algebra/fields/plonk/non_native/equality_flag.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_equality_flag(const std::vector<typename BlueprintFieldType::value_type> &public_input,
                        bool inequality){
    constexpr std::size_t WitnessColumns = 4;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::equality_flag<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)};

    typename BlueprintFieldType::value_type expected_res =
        (public_input[0] == public_input[1]) ?
            BlueprintFieldType::value_type::one()
          : BlueprintFieldType::value_type::zero();

    auto result_check = [&expected_res, &public_input, inequality](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            if (inequality) {
                assert(expected_res != var_value(assignment, real_res.output));
            } else {
                assert(expected_res == var_value(assignment, real_res.output));
            }
    };

    component_type component_instance({0, 1, 2, 3, 4}, {}, {}, inequality);

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>
        (component_instance, public_input, result_check, instance_input,
         nil::blueprint::connectedness_check_type::type::STRONG, inequality);
}

template <typename BlueprintFieldType, std::size_t RandomTestsAmount>
void equality_neq_flag_tests(bool inequality) {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        test_equality_flag<BlueprintFieldType>({generate_random(), generate_random()}, inequality);
    }
}

template <typename BlueprintFieldType, std::size_t RandomTestsAmount>
void equality_eq_flag_tests(bool inequality) {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        auto random_value = generate_random();
        test_equality_flag<BlueprintFieldType>({random_value, random_value}, inequality);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    equality_eq_flag_tests<field_type, random_tests_amount>(true);
    equality_neq_flag_tests<field_type, random_tests_amount>(true);

    equality_eq_flag_tests<field_type, random_tests_amount>(false);
    equality_neq_flag_tests<field_type, random_tests_amount>(false);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    equality_eq_flag_tests<field_type, random_tests_amount>(true);
    equality_neq_flag_tests<field_type, random_tests_amount>(true);

    equality_eq_flag_tests<field_type, random_tests_amount>(false);
    equality_neq_flag_tests<field_type, random_tests_amount>(false);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;

    equality_eq_flag_tests<field_type, random_tests_amount>(true);
    equality_neq_flag_tests<field_type, random_tests_amount>(true);

    equality_eq_flag_tests<field_type, random_tests_amount>(false);
    equality_neq_flag_tests<field_type, random_tests_amount>(false);
}

BOOST_AUTO_TEST_SUITE_END()

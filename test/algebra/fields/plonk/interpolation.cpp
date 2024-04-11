//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunskyn@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_interpolation_coefs_test

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
#include <nil/blueprint/components/algebra/fields/plonk/linear_interpolation.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/quadratic_interpolation.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_linear_inter_coefs(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    constexpr std::size_t WitnessColumns = 7;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::linear_inter_coefs<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};

    value_type x0 = public_input[0],
               z0 = public_input[1],
               x1 = public_input[2],
               z1 = public_input[3];

    const bool expected_to_pass = (x0 != x1);
    std::array<value_type,2> expected_res;

    if (expected_to_pass) {
        expected_res = { (x1*z0 - x0*z1)/(x1-x0), (z1-z0)/(x1-x0) };
    } else {
        expected_res = {0, 0};
    }

    auto result_check = [&expected_res](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {

        BOOST_ASSERT(var_value(assignment, real_res.output[0]) == expected_res[0]);
        BOOST_ASSERT(var_value(assignment, real_res.output[1]) == expected_res[1]);
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6}, {}, {});

    if (expected_to_pass) {
        nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
            (component_instance, desc, public_input, result_check, instance_input);
    } else {
        nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, hash_type, Lambda>
            (component_instance, desc, public_input, result_check, instance_input);
    }
}

using blueprint::components::detail::det3;

template <typename BlueprintFieldType>
void test_quadratic_inter_coefs(const std::vector<typename BlueprintFieldType::value_type> &public_input){
    constexpr std::size_t WitnessColumns = 10;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::quadratic_inter_coefs<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input) };

    value_type x0 = public_input[0],
               z0 = public_input[1],
               x1 = public_input[2],
               z1 = public_input[3],
               x2 = public_input[4],
               z2 = public_input[5];

    value_type d = (x1 - x0)*(x2 - x0)*(x2 - x1),
               one = 1;

    const bool expected_to_pass = (d != 0);
    std::array<value_type,3> expected_res;

    if (expected_to_pass) {
        expected_res = { det3(std::array<value_type,9>{ z0, x0, x0*x0,
                                                       z1, x1, x1*x1,
                                                       z2, x2, x2*x2 }) / d,
                         det3(std::array<value_type,9>{ one, z0, x0*x0,
                                one, z1, x1*x1,
                                one, z2, x2*x2 }) / d,
                         det3(std::array<value_type,9>{ one, x0, z0,
                                one, x1, z1,
                                one, x2, z2 }) / d
                       };
    } else {
        expected_res = {0, 0, 0};
    }

    auto result_check = [&expected_res](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {

        BOOST_ASSERT(var_value(assignment, real_res.output[0]) == expected_res[0]);
        BOOST_ASSERT(var_value(assignment, real_res.output[1]) == expected_res[1]);
        BOOST_ASSERT(var_value(assignment, real_res.output[2]) == expected_res[2]);
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {}, {});

    if (expected_to_pass) {
        nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>
            (component_instance, desc, public_input, result_check, instance_input);
    } else {
        nil::crypto3::test_component_to_fail<component_type, BlueprintFieldType, hash_type, Lambda>
            (component_instance, desc, public_input, result_check, instance_input);
    }
}

template <typename BlueprintFieldType, std::size_t RandomTestsAmount>
void inter_coefs_tests() {
    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        test_linear_inter_coefs<BlueprintFieldType>(
            {generate_random(), generate_random(), generate_random(), generate_random()});
        test_quadratic_inter_coefs<BlueprintFieldType>(
            {generate_random(), generate_random(), generate_random(), generate_random(), generate_random(), generate_random()});
    }
    // one explicitly failing test
    typename BlueprintFieldType::value_type x = generate_random();
    test_linear_inter_coefs<BlueprintFieldType>({x, generate_random(), x, generate_random()});
    test_quadratic_inter_coefs<BlueprintFieldType>({x, generate_random(), x, generate_random(), generate_random(), generate_random()});
    test_quadratic_inter_coefs<BlueprintFieldType>({generate_random(), generate_random(), x, generate_random(), x, generate_random()});
    test_quadratic_inter_coefs<BlueprintFieldType>({x, generate_random(), generate_random(), generate_random(), x, generate_random()});
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;

    inter_coefs_tests<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_field_operations_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    inter_coefs_tests<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_equality_flag_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;

    inter_coefs_tests<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()

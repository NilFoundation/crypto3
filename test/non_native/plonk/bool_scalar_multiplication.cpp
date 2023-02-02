//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_bool_scalar_multiplication_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>
#include <../test/algebra/fields/plonk/non_native/chop_and_glue_non_native.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/bool_scalar_multiplication.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType, typename NonNativeCurveType>
void test_bool_scalar_multiplication(std::vector<typename BlueprintFieldType::value_type> public_input, 
            std::vector<typename BlueprintFieldType::value_type> expected_res){
    
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
    using NonNativeFieldType = typename NonNativeCurveType::base_field_type;

    using var = crypto3::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = blueprint::components::bool_scalar_multiplication<ArithmetizationType,
        NonNativeCurveType, 9, blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::array<var, 4> T_x = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> T_y = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    typename component_type::input_type instance_input = {{T_x, T_y}, var(0, 8, false, var::column_type::public_input)};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment, 
        typename component_type::result_type &real_res) {

        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::array<typename BlueprintFieldType::value_type, 4> x, y, expected_x, expected_y, real_x, real_y;
        for (std::size_t i = 0; i < 4; i++) {
            x[i] = public_input[i];
            y[i] = public_input[i+4];
            expected_x[i] = expected_res[i];
            expected_y[i] = expected_res[i+4];
            real_x[i] = var_value(assignment, real_res.output.x[i]);
            real_y[i] = var_value(assignment, real_res.output.y[i]);
        }

        std::cout << std::hex;

        std::cout << "_________________________________________________________________________________________________________________________________________________\n"; 
        std::cout << "input  x: "; 
        for (std::size_t i = 0; i < 4; i++) {std::cout << x[3-i].data << " ";}
        std::cout << "(" << glue_non_native<BlueprintFieldType, NonNativeFieldType>(x).data << ")\n";

        std::cout << "       y: "; 
        for (std::size_t i = 0; i < 4; i++) {std::cout << y[3-i].data << " ";}
        std::cout << "(" << glue_non_native<BlueprintFieldType, NonNativeFieldType>(y).data << ")\n";

        std::cout << "    bool: " << public_input[8].data << "\n";

        std::cout << "expected: "; 
        for (std::size_t i = 0; i < 4; i++) {std::cout << expected_x[3-i].data << " ";}
        std::cout << "(" << glue_non_native<BlueprintFieldType, NonNativeFieldType>(expected_x).data << ")\n";
        std::cout << "          "; 
        for (std::size_t i = 0; i < 4; i++) {std::cout << expected_y[3-i].data << " ";}
        std::cout << "(" << glue_non_native<BlueprintFieldType, NonNativeFieldType>(expected_y).data << ")\n";


        std::cout << "real    : "; 
        for (std::size_t i = 0; i < 4; i++) {std::cout << real_x[3-i].data << " ";}
        std::cout << "(" << glue_non_native<BlueprintFieldType, NonNativeFieldType>(real_x).data << ")\n";
        std::cout << "          "; 
        for (std::size_t i = 0; i < 4; i++) {std::cout << real_y[3-i].data << " ";}
        // std::cout << "(" << glue_non_native<BlueprintFieldType, NonNativeFieldType>(real_y).data << ")" << std::endl;
        #endif

        for(std::size_t i = 0; i < 4; i++) {
            assert(expected_res[i]   == var_value(assignment, real_res.output.x[i]));
            assert(expected_res[i+4] == var_value(assignment, real_res.output.y[i]));
        }
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FieldType, typename NonNativeCurveType>
void test_bool_scalar_multiplication_usable (typename NonNativeCurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type point, typename FieldType::value_type scalar_bool) {
    
    std::vector<typename FieldType::value_type> public_input = create_public_input<FieldType, typename NonNativeCurveType::base_field_type>(
        chop_non_native<FieldType, typename NonNativeCurveType::base_field_type>(point.X), 
        chop_non_native<FieldType, typename NonNativeCurveType::base_field_type>(point.Y));

    std::vector<typename FieldType::value_type> expected_res;
    if (scalar_bool == 1) {
        expected_res = public_input;
    } else {
        expected_res = {0,0,0,0,1,0,0,0};
    }
    public_input.push_back(scalar_bool);

    test_bool_scalar_multiplication<FieldType, NonNativeCurveType>(public_input, expected_res);
}

constexpr static const std::size_t random_tests_amount = 3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_non_native_bool_scalar_mul_test1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using non_native_curve_type = crypto3::algebra::curves::ed25519;
    using non_native_field_type = non_native_curve_type::base_field_type;

    nil::crypto3::random::algebraic_engine<crypto3::algebra::curves::ed25519::template g1_type<crypto3::algebra::curves::coordinates::affine>> rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>({0,1}, 1);
    test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>({0,1}, 0);

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>(rand(), 1);
        test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>(rand(), 0);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_non_native_bool_scalar_mul_must_fail) { // test should pass if component fails on wrong data, feature is not implemented yet
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using non_native_curve_type = crypto3::algebra::curves::ed25519;
    using non_native_field_type = non_native_curve_type::base_field_type;

    nil::crypto3::random::algebraic_engine<crypto3::algebra::curves::ed25519::template g1_type<crypto3::algebra::curves::coordinates::affine>> rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>({0,1}, 2);
    test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>({0,1}, 10);
    test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>({0,1}, -1);

    test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>(rand(), 2);
    test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>(rand(), 10);
    test_bool_scalar_multiplication_usable<field_type, non_native_curve_type>(rand(), -1);
}

BOOST_AUTO_TEST_SUITE_END()
//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_field_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/addition.hpp>

#include <../test/algebra/fields/plonk/non_native/chop_and_glue_non_native.hpp>

#include "../../../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType, typename NonNativeFieldType>
void test_field_add(const std::vector<typename BlueprintFieldType::value_type> &public_input,
                    const std::array<typename BlueprintFieldType::value_type, 4> &expected_res) {

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

    using component_type = blueprint::components::addition<ArithmetizationType,
        NonNativeFieldType, blueprint::basic_non_native_policy<BlueprintFieldType>>;

    std::array<var, 4> input_var_a = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> input_var_b = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    typename component_type::input_type instance_input = {input_var_a, input_var_b};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {

        for (std::size_t i = 0; i < 4; i++) {
            assert(expected_res[i] == var_value(assignment, real_res.output[i]));
        }
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {}, {});

    crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
    crypto3::test_empty_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template <typename FieldType, typename NonNativeFieldType>
void test_field_add_useable(typename NonNativeFieldType::value_type a, typename NonNativeFieldType::value_type b){
    using chunked_non_native_type = std::array<typename FieldType::value_type, 4>;
    chunked_non_native_type first  = chop_non_native<FieldType, NonNativeFieldType>(a);
    chunked_non_native_type second = chop_non_native<FieldType, NonNativeFieldType>(b);
    chunked_non_native_type expected_result = chop_non_native<FieldType, NonNativeFieldType>(a + b);
    std::vector<typename FieldType::value_type> public_input = create_public_input<FieldType, NonNativeFieldType>(first, second);
    test_field_add<FieldType, NonNativeFieldType>(public_input, expected_result);
}

template <typename FieldType, typename NonNativeFieldType>
void test_field_add_all_cases(){
    nil::crypto3::random::algebraic_engine<NonNativeFieldType> rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    typename NonNativeFieldType::value_type f = 0xf;
    typename NonNativeFieldType::integral_type f_integral;
    for (std::size_t i = 0; i < 63; i++) {
        f_integral = typename NonNativeFieldType::integral_type(f.data);
        f_integral = (f_integral << 4) + 0xf;
        f = typename NonNativeFieldType::value_type(f_integral);
        test_field_add_useable<FieldType, NonNativeFieldType>(f, f);
    }


    test_field_add_useable<FieldType, NonNativeFieldType>(0, 0);
    test_field_add_useable<FieldType, NonNativeFieldType>(1, 1);
    test_field_add_useable<FieldType, NonNativeFieldType>(-1, -1);
    test_field_add_useable<FieldType, NonNativeFieldType>(1, -1);
    test_field_add_useable<FieldType, NonNativeFieldType>(-1, 0);
    test_field_add_useable<FieldType, NonNativeFieldType>(1000, -1000);
    test_field_add_useable<FieldType, NonNativeFieldType>(
        glue_non_native<FieldType, NonNativeFieldType>({45524, 52353, 68769, 5431}),
        glue_non_native<FieldType, NonNativeFieldType>({3724, 342453, 5425, 54222}));

    test_field_add_useable<FieldType, NonNativeFieldType>(
        glue_non_native<FieldType, NonNativeFieldType>({1,1,1,1}),
        glue_non_native<FieldType, NonNativeFieldType>({1,1,1,1}));

    for (std::size_t i = 0; i < 10; i++) {
        test_field_add_useable<FieldType, NonNativeFieldType>(rand(), rand());
    }

}
BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_non_native_addition_pallas) {
    using non_native_field_type = typename crypto3::algebra::fields::curve25519_base_field;
    using field_type = crypto3::algebra::curves::pallas::base_field_type;
    test_field_add_all_cases<field_type, non_native_field_type>();
}

BOOST_AUTO_TEST_SUITE_END()
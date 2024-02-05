//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_exponentiation_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/exponentiation.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include "../../../test_plonk_component.hpp"

template <typename FieldType, std::size_t ExpSize>
void test_exponentiation(std::vector<typename FieldType::value_type> public_input){
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    constexpr std::size_t exp_size = ExpSize;
	using BlueprintFieldType = FieldType;
    using ArithmetizationParams = nil::crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;
	using component_type = nil::blueprint::components::exponentiation<ArithmetizationType, BlueprintFieldType, exp_size>;

	using var = nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    var base(0, 0, false, var::column_type::public_input);
    var exponent(0, 1, false, var::column_type::public_input);

    typename component_type::input_type instance_input = {base, exponent};

    typename BlueprintFieldType::value_type base_value = public_input[0];
    typename BlueprintFieldType::integral_type exponent_value_integral = typename BlueprintFieldType::integral_type(public_input[1].data);
    typename BlueprintFieldType::value_type expected_res = power(base_value, exponent_value_integral);

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "exponentiation test: " << "\n";
            std::cout << "input   : " << public_input[0].data << " " << public_input[1].data << "\n";
            std::cout << "expected: " << expected_res.data    << "\n";
            std::cout << "real    : " << var_value(assignment, real_res.output).data << "\n\n";
            #endif
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},{0},{});


    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (component_instance, public_input, result_check, instance_input);
}

template <typename FieldType, std::size_t RandomTestsAmount>
void exponentiation_tests(){
    for (int i = -2; i < 3; i++){
        for (int j = -2; j < 3; j++){
            test_exponentiation<FieldType, 255>({i, j});
        }
    }

    nil::crypto3::random::algebraic_engine<FieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_exponentiation<FieldType, 255>({generate_random(), generate_random()});
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_exponentiation_one) {
    test_exponentiation<nil::crypto3::algebra::fields::bls12_fr<381>, 1>({1, 1});
    test_exponentiation<nil::crypto3::algebra::curves::vesta::base_field_type, 1>({1, 1});
    test_exponentiation<nil::crypto3::algebra::curves::pallas::base_field_type, 1>({1, 1});
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_exponentiation_b1111) {
    test_exponentiation<nil::crypto3::algebra::fields::bls12_fr<381>, 4>({2379842, 0b1111});
    test_exponentiation<nil::crypto3::algebra::curves::vesta::base_field_type, 4>({2379842, 0b1111});
    test_exponentiation<nil::crypto3::algebra::curves::pallas::base_field_type, 4>({2379842, 0b1111});
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_exponentiation_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::base_field_type;
    exponentiation_tests<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_exponentiation_vesta) {
    using field_type = nil::crypto3::algebra::curves::vesta::base_field_type;
    exponentiation_tests<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_exponentiation_bls12) {
    using field_type = nil::crypto3::algebra::fields::bls12_fr<381>;
    exponentiation_tests<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
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

#define BOOST_TEST_MODULE blueprint_private_input_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>

#include "test_plonk_component.hpp"

using namespace nil;

template <typename FieldType>
void test_add(const typename FieldType::value_type &a, const typename FieldType::value_type &b) {
    using BlueprintFieldType = FieldType;
    constexpr std::size_t WitnessColumns = 3;
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

    using component_type = blueprint::components::addition<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    const std::size_t private_index = AssignmentType::private_storage_index;

    typename component_type::input_type instance_input = {
        var(private_index, 0, false, var::column_type::public_input),
        var(private_index, 1, false, var::column_type::public_input)
    };

    typename BlueprintFieldType::value_type expected_res = a + b;

     std::vector<typename BlueprintFieldType::value_type> public_input = {a, b};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment,
	    typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << "add test: " << "\n";
            std::cout << "input   : " << public_input[0].data << " " << public_input[1].data << "\n";
            std::cout << "expected: " << expected_res.data    << "\n";
            std::cout << "real    : " << var_value(assignment, real_res.output).data << "\n\n";
            #endif
            assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2}, {}, {});

    nil::crypto3::test_component_private_input<
        component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>
            (component_instance, public_input, result_check, instance_input);
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_CASE(blueprint_plonk_private_input_test) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;

    nil::crypto3::random::algebraic_engine<field_type> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        value_type a = generate_random();
        value_type b = generate_random();
        test_add<field_type>(a, b);
    }
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_private_input_copy_constraints) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;

    constexpr std::size_t WitnessColumns = 3;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<field_type, ArithmetizationParams>;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename field_type::value_type>;

    const std::size_t private_index = AssignmentType::private_storage_index;
    blueprint::circuit<ArithmetizationType> bp;

    auto private_1 = var(private_index, 0, false, var::column_type::public_input),
        private_2 = var(private_index, 1, false, var::column_type::public_input),
        public_1 = var(0, 0, false, var::column_type::public_input),
        public_2 = var(0, 1, false, var::column_type::public_input);

    bp.add_copy_constraint({private_1, private_2});
    BOOST_ASSERT(bp.copy_constraints().size() == 0);

    bp.add_copy_constraint({private_1, public_1});
    BOOST_ASSERT(bp.copy_constraints().size() == 0);

    bp.add_copy_constraint({public_2, private_2});
    BOOST_ASSERT(bp.copy_constraints().size() == 0);

    bp.add_copy_constraint({public_1, public_2});
    BOOST_ASSERT(bp.copy_constraints().size() == 1);
}

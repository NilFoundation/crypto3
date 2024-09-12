//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_verifiers_plonk_dfri_linear_check_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/systems/snark/plonk/placeholder/dfri_linear_check.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template<typename BlueprintFieldType, std::size_t WitnessAmount>
void test_dfri_linear_check(const std::vector<typename BlueprintFieldType::value_type> &public_input, typename BlueprintFieldType::value_type expected_res,
                            std::size_t m,
                            std::vector<std::pair<std::size_t, std::size_t>> &eval_map) {

    constexpr std::size_t WitnessColumns = WitnessAmount;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    zk::snark::plonk_table_description<BlueprintFieldType> desc(
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns);
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;

    using component_type = blueprint::components::dfri_linear_check<ArithmetizationType, BlueprintFieldType>;

    std::vector<var> xi;
    std::vector<var> y;
    std::vector<std::vector<var>> z;

    var theta = var(0, 0, false, var::column_type::public_input);
    var x = var(0, 1, false, var::column_type::public_input);


    std::vector<std::size_t> eval_map_ij;
    eval_map_ij.resize(m);
    std::size_t ctr = 0, I = 0, K = 0;

    for(std::size_t l = 0; l < eval_map.size(); l++){
        auto il = eval_map[l].first;
        auto jl = eval_map[l].second;

        eval_map_ij[il - 1]++;
        I = std::max(I, il);
        K = std::max(K, jl);
    }

    for (std::size_t i = 0; i < K; i++){
        xi.push_back(var(0, i + 2, false, var::column_type::public_input));
    }

    for (std::size_t i = 0; i < I; i++){
        y.push_back(var(0, i + 2 + K, false, var::column_type::public_input));
    }

    ctr = I + K + 2;
    for(std::size_t i = 0; i < I; i++){
        std::vector<var> z_i;
        for(std::size_t j = 0; j < eval_map_ij[i]; j++){
            z_i.push_back(var(0, ctr++, false, var::column_type::public_input));
        }
        z.push_back(z_i);
    }

    typename component_type::input_type instance_input = {theta, x, xi, y, z};


    auto result_check = [&expected_res](AssignmentType &assignment, typename component_type::result_type &real_res) {
        std::cout << "expected: " << expected_res.data << std::endl;
        std::cout << "real res: " << var_value(assignment, real_res.output).data << std::endl;
        BOOST_ASSERT(var_value(assignment, real_res.output) == expected_res);
    };

    std::array<std::uint32_t, WitnessColumns> witnesses;
    for (std::uint32_t i = 0; i < WitnessColumns; i++) {
        witnesses[i] = i;
    }
    component_type component_instance(witnesses, std::array<std::uint32_t, 1>(), std::array<std::uint32_t, 1>(), m, eval_map);

    nil::crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input, nil::blueprint::connectedness_check_type::type::STRONG, m);
}

// template<typename BlueprintFieldType, std::size_t RandomTestsAmount>
// void dfri_linear_check_tests() {
//     static boost::random::mt19937 seed_seq;
//     static nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random(seed_seq);

//     for (std::size_t i = 0; i < RandomTestsAmount; i++) {
//         test_dfri_linear_check<BlueprintFieldType>(
//             {generate_random(), generate_random(), generate_random(), generate_random()});
//     }
// }

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_dfri_linear_check_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_dfri_linear_check_test_pallas_m_1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;    

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<field_type> generate_random(seed_seq);

    value_type theta = generate_random();
    value_type x     = generate_random();
    value_type xi = generate_random();
    value_type y  = generate_random();
    value_type z  = generate_random();

    std::vector<value_type> public_inputs = {theta, x, xi, y, z};

    std::vector<std::pair<std::size_t, std::size_t> > eval_map = {std::make_pair(1,1)};
    std::size_t m = 1;
    
    value_type expected_res = (y - z) * ((x - xi).inversed());
    
    test_dfri_linear_check<field_type, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 4>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 5>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 6>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 7>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 8>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 9>(public_inputs, expected_res, m, eval_map);

}

BOOST_AUTO_TEST_CASE(blueprint_plonk_dfri_linear_check_test_pallas_m_2) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    using value_type = typename field_type::value_type;    

    static boost::random::mt19937 seed_seq;
    static nil::crypto3::random::algebraic_engine<field_type> generate_random(seed_seq);

    value_type theta = generate_random();
    value_type x     = generate_random();
    std::array<value_type, 2> xi = {generate_random(), generate_random()};
    value_type y  = generate_random();
    std::array<value_type, 2> z  = {generate_random(), generate_random()};

    std::vector<value_type> public_inputs = {theta, x, xi[0], xi[1], y, z[0], z[1]};

    std::vector<std::pair<std::size_t, std::size_t> > eval_map = {std::make_pair(1,1), std::make_pair(1,2)};
    std::size_t m = 2;
    
    value_type expected_res = (y - z[0]) * ((x - xi[0]).inversed()) + theta * (y - z[1]) * ((x - xi[1]).inversed());
    
    test_dfri_linear_check<field_type, 3>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 4>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 5>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 6>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 7>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 8>(public_inputs, expected_res, m, eval_map);
    test_dfri_linear_check<field_type, 9>(public_inputs, expected_res, m, eval_map);

}

BOOST_AUTO_TEST_SUITE_END()

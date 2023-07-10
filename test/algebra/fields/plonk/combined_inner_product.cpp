//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_combined_inner_product_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/combined_inner_product.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include "../../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_combined_inner_product) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    constexpr std::size_t k = 11;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = zk::components::combined_inner_product<ArithmetizationType, k, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::array<var, k> input_var_zeta1;
    std::array<var, k> input_var_zeta2;
    std::vector<typename BlueprintFieldType::value_type> public_input;
    for (std::size_t i = 0 ; i < k; i++) {
        input_var_zeta1[i] = var(0, 2 * i, false, var::column_type::public_input);
        input_var_zeta2[i] = var(0, 2 * i + 1, false, var::column_type::public_input);
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
        public_input.push_back(algebra::random_element<BlueprintFieldType>());
    }

    var xi = var(0, 2 * k, false, var::column_type::public_input);
    var r = var(0, 2 * k + 1, false, var::column_type::public_input);
    public_input.push_back(algebra::random_element<BlueprintFieldType>());
    public_input.push_back(algebra::random_element<BlueprintFieldType>());

    typename component_type::params_type params = {input_var_zeta1, input_var_zeta2, xi, r};


    auto result_check = [](AssignmentType &assignment, 
        component_type::result_type &real_res) { 
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "combined_inner_product_component: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
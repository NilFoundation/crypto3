//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_details_vanishes_on_last_4_rows

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/constraints/unnormalized_lagrange_basis.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_unnormalized_lagrange_basis_positive_power) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 4;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = zk::components::unnormalized_lagrange_basis<ArithmetizationType, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                                            11, 12, 13, 14>;

    typename BlueprintFieldType::value_type group_gen = 0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui_modular256;
    std::size_t domain_size = 512;
    int ith = 5;
    typename BlueprintFieldType::value_type x = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type group_gen_pow = group_gen.pow(ith);
    typename BlueprintFieldType::value_type expected_res = (x.pow(domain_size) - 1) * (x - group_gen_pow).inversed();

    std::vector<typename BlueprintFieldType::value_type> public_input = {group_gen, x, expected_res};

    typename component_type::params_type params = {
        var(0, 0, false, var::column_type::public_input), domain_size, var(0, 1, false, var::column_type::public_input), ith};

    auto result_check = [&expected_res](AssignmentType &assignment,
        component_type::result_type &real_res) {
        assert(expected_res == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "vanishes_on_last_4_rows: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_unnormalized_lagrange_basis_negative_power) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 4;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = zk::components::unnormalized_lagrange_basis<ArithmetizationType, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                                            11, 12, 13, 14>;

    typename BlueprintFieldType::value_type group_gen = 0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui_modular256;
    std::size_t domain_size = 512;
    int ith = -5;
    typename BlueprintFieldType::value_type x = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type group_gen_pow = group_gen.pow(-ith).inversed();
    typename BlueprintFieldType::value_type expected_res = (x.pow(domain_size) - 1) * (x - group_gen_pow).inversed();

    std::vector<typename BlueprintFieldType::value_type> public_input = {group_gen, x, expected_res};

    typename component_type::params_type params = {
        var(0, 0, false, var::column_type::public_input), domain_size, var(0, 1, false, var::column_type::public_input), ith};

    auto result_check = [&expected_res](AssignmentType &assignment,
        component_type::result_type &real_res) {
        assert(expected_res == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "vanishes_on_last_4_rows: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()

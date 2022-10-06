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

#define BOOST_TEST_MODULE blueprint_plonk_edwards_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/ec_point_edwards25519.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

// BOOST_AUTO_TEST_CASE(blueprint_ec_point_to_fail) {
//     auto start = std::chrono::high_resolution_clock::now();

//     using curve_type = algebra::curves::pallas;
//     using ed25519_type = algebra::curves::ed25519;
//     using BlueprintFieldType = typename curve_type::base_field_type;
//     constexpr std::size_t witness_columns = 9;
//     constexpr std::size_t public_input_columns = 1;
//     constexpr std::size_t constant_columns = 1;
//     constexpr std::size_t selector_columns = 5;
//     using ArithmetizationParams =
//         zk::snark::plonk_arithmetization_params<witness_columns, public_input_columns, constant_columns,
//         selector_columns>;
//     using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 1;

//     using var = zk::snark::plonk_variable<BlueprintFieldType>;

//     using component_type = zk::components::ec_point<ArithmetizationType, curve_type, ed25519_type, 0, 1, 2, 3,
//                                                                           4, 5, 6, 7, 8>;

//     std::vector<typename BlueprintFieldType::value_type> public_input = {0, 1, 2, 3, 4, 5, 6, 7};

//     std::array<var, 4> x = {var(0, 0, false, var::column_type::public_input), var(0, 1, false,
//     var::column_type::public_input),
//         var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
//     std::array<var, 4> y = {var(0, 4, false, var::column_type::public_input), var(0, 5, false,
//     var::column_type::public_input),
//         var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

//     typename component_type::params_type params = {x, y};

//     auto result_check = [](AssignmentType &assignment,
//         component_type::result_type &real_res) {
//     };

//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params,
//     public_input, result_check);

//     auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() -
//     start); std::cout << "Time_execution: " << duration.count() << "ms" << std::endl;
// }

BOOST_AUTO_TEST_CASE(blueprint_ec_point_to_work) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using ed25519_type = algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 5;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type =
        zk::components::ec_point<ArithmetizationType, curve_type, ed25519_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;

    auto value = ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type::one();

    typename ed25519_type::scalar_field_type::integral_type base = 1;
    typename ed25519_type::scalar_field_type::integral_type mask = (base << 66) - 1;

    typename ed25519_type::base_field_type::integral_type val_x =
        typename ed25519_type::base_field_type::integral_type(value.X.data);
    std::array<typename ed25519_type::base_field_type::integral_type, 4> x = {
        val_x & mask, (val_x >> 66) & mask, (val_x >> 132) & mask, (val_x >> 198) & mask};
    typename ed25519_type::base_field_type::integral_type val_y =
        typename ed25519_type::base_field_type::integral_type(value.Y.data);
    std::array<typename ed25519_type::base_field_type::integral_type, 4> y = {
        val_y & mask, (val_y >> 66) & mask, (val_y >> 132) & mask, (val_y >> 198) & mask};

    std::vector<typename BlueprintFieldType::value_type> public_input = {x[0], x[1], x[2], x[3],
                                                                         y[0], y[1], y[2], y[3]};

    std::array<var, 4> xx = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> yy = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    typename component_type::params_type params = {xx, yy};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Time_execution: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
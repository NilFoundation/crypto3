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

#define BOOST_TEST_MODULE plonk_sha512_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/hashes/sha256/plonk/sha512.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>

#include "../../test_plonk_component.hpp"

#include <chrono>

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_sha512) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using FieldType = typename curve_type::base_field_type;

    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 5;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 15;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = zk::components::sha512<ArithmetizationType, curve_type, 0, 1, 2, 3, 4, 5, 6, 7, 8>;

    using ed25519_type = algebra::curves::ed25519;

ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type B =
     ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type::one();
     ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type R = 2*B;
     ed25519_type::scalar_field_type::value_type b = algebra::random_element<ed25519_type::scalar_field_type>();
     ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type T = b*R;
     
    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Rx = ed25519_type::base_field_type::integral_type(R.X.data);
    ed25519_type::base_field_type::integral_type Ry = ed25519_type::base_field_type::integral_type(R.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
    std::vector<typename BlueprintFieldType::value_type> public_input = {
    Tx & mask, (Tx >> 66) & mask, (Tx >> 132) & mask, (Tx >> 198) & (mask >> 9),
    Ty & mask, (Ty >> 66) & mask, (Ty >> 132) & mask, (Ty >> 198) & (mask >> 9),
    Rx & mask, (Rx >> 66) & mask, (Rx >> 132) & mask, (Rx >> 198) & (mask >> 9),
    Ry & mask, (Ry >> 66) & mask, (Ry >> 132) & mask, (Ry >> 198) & (mask >> 9), 
    mask, mask, mask, (mask >> 8)};
    std::array<var, 4> e_R_x = {var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> e_R_y = {var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};
    std::array<var, 4> pk_x = {var(0, 8, false, var::column_type::public_input), var(0, 9, false, var::column_type::public_input),
        var(0, 10, false, var::column_type::public_input), var(0, 11, false, var::column_type::public_input)};
    std::array<var, 4> pk_y = {var(0, 12, false, var::column_type::public_input), var(0, 13, false, var::column_type::public_input),
        var(0, 14, false, var::column_type::public_input), var(0, 15, false, var::column_type::public_input)};
    std::array<var, 4> M = {var(0, 16, false, var::column_type::public_input), var(0, 17, false, var::column_type::public_input), 
        var(0, 18, false, var::column_type::public_input), var(0, 19, false, var::column_type::public_input)};
    typename component_type::params_type params = {{e_R_x, e_R_y}, {pk_x, pk_y}, M};

    /*std::array<typename ArithmetizationType::field_type::value_type, 20> public_input = {1, 1, 1, 1, 1,
    1, 1, 1, 1, 1,
    1, 1, 1, 1, 1,
    1, 1, 1, 1, 1};

    std::array<var, 20> input_state_var = { // 
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input),
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input),
        var(0, 8, false, var::column_type::public_input), var(0, 9, false, var::column_type::public_input),
        var(0, 10, false, var::column_type::public_input), var(0, 11, false, var::column_type::public_input),
        var(0, 12, false, var::column_type::public_input), var(0, 13, false, var::column_type::public_input),
        var(0, 14, false, var::column_type::public_input), var(0, 15, false, var::column_type::public_input),
        var(0, 16, false, var::column_type::public_input), var(0, 17, false, var::column_type::public_input),
        var(0, 18, false, var::column_type::public_input), var(0, 19, false, var::column_type::public_input)};
    



    typename component_type::params_type params =  {
        { {input_state_var[0],input_state_var[1],input_state_var[2],input_state_var[3]}, {input_state_var[4],input_state_var[5],input_state_var[6],input_state_var[7]}},
        { {input_state_var[8],input_state_var[9],input_state_var[10],input_state_var[11]}, {input_state_var[12],input_state_var[13],input_state_var[14],input_state_var[15]}},
        {input_state_var[16],input_state_var[17],input_state_var[18],input_state_var[19]}
    };*/

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Time_execution: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
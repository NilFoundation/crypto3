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

#define BOOST_TEST_MODULE blueprint_plonk_non_native_field_test

#include <chrono>
#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/variable_base_multiplication_per_bit_edwards25519.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_non_native_var_base_mul_per_bit) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using ed25519_type = algebra::curves::ed25519;
    using BlueprintFieldType = typename curve_type::base_field_type;

    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 6;

    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type =
        zk::components::variable_base_multiplication_per_bit<ArithmetizationType, curve_type, ed25519_type, 0, 1, 2, 3,
                                                             4, 5, 6, 7, 8>;

    std::array<var, 4> input_var_Xa = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Xb = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};

    std::array<var, 4> input_var_Ya = {
        var(0, 8, false, var::column_type::public_input), var(0, 9, false, var::column_type::public_input),
        var(0, 10, false, var::column_type::public_input), var(0, 11, false, var::column_type::public_input)};
    std::array<var, 4> input_var_Yb = {
        var(0, 12, false, var::column_type::public_input), var(0, 13, false, var::column_type::public_input),
        var(0, 14, false, var::column_type::public_input), var(0, 15, false, var::column_type::public_input)};

    var b = var(0, 16, false, var::column_type::public_input);

    typename component_type::params_type params = {{input_var_Xa, input_var_Xb}, {input_var_Ya, input_var_Yb}, b};

    ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type T =
        algebra::random_element<ed25519_type::template g1_type<algebra::curves::coordinates::affine>>();
    ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type R = 2 * T;
    ed25519_type::scalar_field_type::value_type b_val = 1;
    ed25519_type::template g1_type<algebra::curves::coordinates::affine>::value_type P = 2 * R + b_val * T;

    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Rx = ed25519_type::base_field_type::integral_type(R.X.data);
    ed25519_type::base_field_type::integral_type Ry = ed25519_type::base_field_type::integral_type(R.Y.data);
    ed25519_type::base_field_type::integral_type Px = ed25519_type::base_field_type::integral_type(P.X.data);
    ed25519_type::base_field_type::integral_type Py = ed25519_type::base_field_type::integral_type(P.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        Tx & mask,
        (Tx >> 66) & mask,
        (Tx >> 132) & mask,
        (Tx >> 198) & mask,
        Ty & mask,
        (Ty >> 66) & mask,
        (Ty >> 132) & mask,
        (Ty >> 198) & mask,
        Rx & mask,
        (Rx >> 66) & mask,
        (Rx >> 132) & mask,
        (Rx >> 198) & mask,
        Ry & mask,
        (Ry >> 66) & mask,
        (Ry >> 132) & mask,
        (Ry >> 198) & mask,
        typename ed25519_type::base_field_type::integral_type(b_val.data)};

    auto result_check = [Px, Py](AssignmentType &assignment, component_type::result_type &real_res) {
        typename ed25519_type::base_field_type::integral_type base = 1;
        typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
        for (std::size_t i = 0; i < 4; i++) {
            assert(typename BlueprintFieldType::value_type((Px >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.x[i]));
            assert(typename BlueprintFieldType::value_type((Py >> 66 * i) & mask) ==
                   assignment.var_value(real_res.output.y[i]));
        }
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "Time_execution: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
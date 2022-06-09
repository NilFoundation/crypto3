//---------------------------------------------------------------------------//
// Copyright (c) 2018-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2022 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE multi_scalar_mul_test

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
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>
#include "test_plonk_component.hpp"

#include "../../../profiling.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_multi_scalar_mul) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using BlueprintScalarType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 3;
    using ArithmetizationParams = zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;
    constexpr std::size_t msm_size = 2;
    using component_type = zk::components::element_g1_multi_scalar_mul<ArithmetizationType, curve_type, msm_size,
                                                            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;
	using var = zk::snark::plonk_variable<BlueprintFieldType>;

    std::vector<typename BlueprintFieldType::value_type> public_input = { };
    typename component_type::params_type assignment_params = {{}, {}};

    curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type sum = 
        curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type::zero();
    for (std::size_t i = 0; i < msm_size; i++) {
        typename curve_type::scalar_field_type::value_type x = algebra::random_element<BlueprintScalarType>();
        typename curve_type::scalar_field_type::value_type shift = 2;
        shift = shift.pow(255) + 1;
        typename curve_type::scalar_field_type::value_type b = (x - shift) / 2;
        typename curve_type::scalar_field_type::integral_type integral_b = typename curve_type::scalar_field_type::integral_type(b.data);
        BlueprintFieldType::value_type b_scalar = integral_b;

        curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type T = algebra::random_element<curve_type::template g1_type<algebra::curves::coordinates::affine>>();
        public_input.push_back(b_scalar);
        public_input.push_back(T.X);
        public_input.push_back(T.Y);
        var scalar_var = {0, (std::int32_t)(3 * i), false, var::column_type::public_input};
        var T_X_var = {0, (std::int32_t)(3 * i + 1), false, var::column_type::public_input};
        var T_Y_var = {0, (std::int32_t)(3 * i + 2), false, var::column_type::public_input};
        assignment_params.scalars[i] = scalar_var;
        assignment_params.bases[i] = {T_X_var, T_Y_var};
        sum = sum + x * T;
    }

    std::cout<<"expected recult: "<<sum.X.data<<" "<<sum.Y.data<<std::endl;

    auto result_check = [&sum](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(sum.X == assignment.var_value(real_res.sum.X));
        assert(sum.Y == assignment.var_value(real_res.sum.Y));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (assignment_params, 
        public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "base_scalar_mul: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
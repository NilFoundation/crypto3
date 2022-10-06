//---------------------------------------------------------------------------//
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_lagrange_denominators_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/lagrange_denominators.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include "../../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_lagrange_denominators) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 2;
    constexpr std::size_t n = 5;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type =
        zk::components::lagrange_denominators<ArithmetizationType, n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    var one(0, 0, false, var::column_type::public_input);
    var zeta(0, 1, false, var::column_type::public_input);
    var zeta_omega(0, 2, false, var::column_type::public_input);
    typename BlueprintFieldType::value_type zeta_value = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type omega_value = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type zeta_omega_value = zeta_value * omega_value;

    std::vector<typename BlueprintFieldType::value_type> public_input = {1, zeta_value, zeta_omega_value};

    std::array<var, n> omega_powers;
    std::array<typename BlueprintFieldType::value_type, n> omega_powers_values;
    for (std::size_t i = 0; i < n; i++) {
        omega_powers_values[i] = power(omega_value, i);
        omega_powers[i] = var(0, 3 + i, false, var::column_type::public_input);
        public_input.push_back(omega_powers_values[i]);
    }

    typename component_type::params_type params = {zeta, zeta_omega, omega_powers, one};

    std::vector<typename BlueprintFieldType::value_type> expected_result(2 * n);
    for (std::size_t i = 0; i < n; i++) {
        expected_result[i] = (zeta_value - omega_powers_values[i]).inversed();
        expected_result[n + i] = (zeta_omega_value - omega_powers_values[i]).inversed();
    }

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < n; i++) {
            assert(expected_result[i] == assignment.var_value(real_res.output[i]));
            assert(expected_result[n + i] == assignment.var_value(real_res.output[n + i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "lagrange_denominators_component: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_lagrange_denominators_real_data) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 2;
    constexpr std::size_t n = 5;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type =
        zk::components::lagrange_denominators<ArithmetizationType, n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    var one(0, 0, false, var::column_type::public_input);
    var zeta(0, 1, false, var::column_type::public_input);
    var zeta_omega(0, 2, false, var::column_type::public_input);
    typename BlueprintFieldType::value_type zeta_value = 0x2F51244846217BCB9DE92C5903AC022FAD29555920E45344407B680D24D550F1_cppui256;
    typename BlueprintFieldType::value_type omega_value = 0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;
    typename BlueprintFieldType::value_type zeta_omega_value = zeta_value * omega_value;

    std::vector<typename BlueprintFieldType::value_type> public_input = {1, zeta_value, zeta_omega_value};

    std::array<var, n> omega_powers;
    std::array<typename BlueprintFieldType::value_type, n> omega_powers_values;
    for (std::size_t i = 0; i < n; i++) {
        omega_powers_values[i] = power(omega_value, i);
        omega_powers[i] = var(0, 3 + i, false, var::column_type::public_input);
        public_input.push_back(omega_powers_values[i]);
    }

    typename component_type::params_type params = {zeta, zeta_omega, omega_powers, one};

    std::vector<typename BlueprintFieldType::value_type> expected_result = {0x04B51DBD555265C26C890F9356AF30F1EC63AFED99D936BDC3D491BA6A06062C_cppui256,
                                                                            0x29E0A0DC50CFA8107324A4C83B2358EFEDBDE840B9C08F5550369CAA41A5A85F_cppui256,
                                                                            0x35AF24EA5A46E07C6C1B50C7522A3DF49CD56EC788096049357C1BD58B97C90A_cppui256,
                                                                            0x2D3A6A9C66D28D2590A2685AA2957BA6E88A0B4261F8CA691283B12CB8400CD2_cppui256,
                                                                            0x0E0ED7C2F3B9C67A4C214B96ADD90D88530FA109C3161B408870B6BB1D585B12_cppui256,
                                                                            0x36A1234D72594664479AE1EB7D5E2DC9CC89CD1CAD0DE2F32829432AE7CD2D9E_cppui256,
                                                                            0x31D2FDE1CDAC87CCC8D10CAE161DD72C5783E200B8C42D8FB3B7E4E7E8DE1CD4_cppui256,
                                                                            0x1031F1E65443D7EE7BF96057030E67B95DE36784C910A58A5B771F0BC9D67FE9_cppui256,
                                                                            0x15A16E2EE8DB03DE98FB82AFBDE4018960F2A0FA1CD257C28E8C4160679CA950_cppui256,
                                                                            0x0F462B51E39AC7A0BAFF4743144FE5F95EF7C60F7571231ADF708CBD007BD581_cppui256};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        for (std::size_t i = 0; i < n; i++) {
            assert(expected_result[i] == assignment.var_value(real_res.output[i]));
            assert(expected_result[n + i] == assignment.var_value(real_res.output[n + i]));
        }
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "lagrange_denominators_component: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
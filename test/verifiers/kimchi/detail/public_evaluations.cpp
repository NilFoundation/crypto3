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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_publuc_evaluations_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/public_evaluations.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include "../../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_publuc_evaluations) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 5;
    constexpr std::size_t n = 5;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type =
        zk::components::public_evaluations<ArithmetizationType, n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    var one(0, 0, false, var::column_type::public_input);
    var zeta_pow_n(0, 1, false, var::column_type::public_input);
    var zeta_omega_pow_n(0, 2, false, var::column_type::public_input);
    typename BlueprintFieldType::value_type zeta_value = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type omega_value = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type zeta_omega_value = zeta_value * omega_value;
    constexpr std::size_t domain = 5;

    std::vector<typename BlueprintFieldType::value_type> public_input = {1, power(zeta_value, domain),
                                                                         power(zeta_omega_value, domain)};

    std::array<var, n> omega_powers;
    std::array<typename BlueprintFieldType::value_type, n> omega_powers_values;
    for (std::size_t i = 0; i < n; i++) {
        omega_powers_values[i] = power(omega_value, i);
        omega_powers[i] = var(0, 3 + i, false, var::column_type::public_input);
        public_input.push_back(omega_powers_values[i]);
    }

    std::array<var, 2 * n> lagrange_base;
    std::vector<typename BlueprintFieldType::value_type> lagrange_base_values(2 * n);
    for (std::size_t i = 0; i < n; i++) {
        lagrange_base_values[i] = (zeta_value - omega_powers_values[i]).inversed();
        lagrange_base_values[n + i] = (zeta_omega_value - omega_powers_values[i]).inversed();
    }

    for (std::size_t i = 0; i < lagrange_base.size(); i++) {
        public_input.push_back(lagrange_base_values[i]);
        lagrange_base[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    std::array<var, n> pi;
    std::array<typename BlueprintFieldType::value_type, n> pi_values;
    for (std::size_t i = 0; i < n; i++) {
        pi_values[i] = algebra::random_element<BlueprintFieldType>();
        public_input.push_back(pi_values[i]);
        pi[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    typename BlueprintFieldType::value_type domain_size_value = 15;
    public_input.push_back(domain_size_value);
    var domain_size(0, public_input.size() - 1, false, var::column_type::public_input);

    typename BlueprintFieldType::value_type zero_value = 0;
    public_input.push_back(zero_value);
    var zero(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {zeta_pow_n,   zeta_omega_pow_n, pi,  lagrange_base,
                                                   omega_powers, domain_size,      one, zero};

    // r[0] = (zeta_pow_n - 1) * domain.size_inv * SUM(-l * p * w)
    // where l from lagrange, p from public, w from omega_powers for l from 0 to PulicInputSize
    // r[1] = (zeta_omega.pow(n) - 1) * index.domain.size_inv * SUM(-l * p * w)
    // where l from lagrange, p from public, w from omega_powers for l from PulicInputSize to 2 * PulicInputSize
    std::array<typename BlueprintFieldType::value_type, 2> expected_result = {0, 0};
    for (std::size_t j = 0; j < 2; j++) {
        for (std::size_t i = 0; i < n; i++) {
            expected_result[j] =
                expected_result[j] + (-lagrange_base_values[j * n + i] * pi_values[i] * omega_powers_values[i]);
        }
        typename BlueprintFieldType::value_type tmp = j == 0 ? power(zeta_value, n) : power(zeta_omega_value, n);
        expected_result[j] = expected_result[j] * domain_size_value.inversed() * (tmp - 1);
    }

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result[0] == assignment.var_value(real_res.output[0]));
        assert(expected_result[1] == assignment.var_value(real_res.output[1]));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "public_evaluations_component: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_real_data) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 5;
    constexpr std::size_t n = 5;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type =
        zk::components::public_evaluations<ArithmetizationType, n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    var one(0, 0, false, var::column_type::public_input);
    var zeta_pow_n(0, 1, false, var::column_type::public_input);
    var zeta_omega_pow_n(0, 2, false, var::column_type::public_input);
    typename BlueprintFieldType::value_type zeta_value = 0x2F51244846217BCB9DE92C5903AC022FAD29555920E45344407B680D24D550F1_cppui256;
    typename BlueprintFieldType::value_type omega_value = 0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;
    typename BlueprintFieldType::value_type zeta_omega_value = zeta_value * omega_value;
    constexpr std::size_t domain = 32;

    std::vector<typename BlueprintFieldType::value_type> public_input = {1, power(zeta_value, domain),
                                                                         power(zeta_omega_value, domain)};
    std::array<var, n> omega_powers;
    std::array<typename BlueprintFieldType::value_type, n> omega_powers_values;
    for (std::size_t i = 0; i < n; i++) {
        omega_powers_values[i] = power(omega_value, i);
        omega_powers[i] = var(0, 3 + i, false, var::column_type::public_input);
        public_input.push_back(omega_powers_values[i]);
    }

    std::array<var, 2 * n> lagrange_base;
    std::vector<typename BlueprintFieldType::value_type> lagrange_base_values(2 * n);
    for (std::size_t i = 0; i < n; i++) {
        lagrange_base_values[i] = (zeta_value - omega_powers_values[i]).inversed();
        lagrange_base_values[n + i] = (zeta_omega_value - omega_powers_values[i]).inversed();
    }

    for (std::size_t i = 0; i < lagrange_base.size(); i++) {
        public_input.push_back(lagrange_base_values[i]);
        lagrange_base[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    std::array<var, n> pi;
    std::array<typename BlueprintFieldType::value_type, n> pi_values;
    for (std::size_t i = 0; i < n; i++) {
        pi_values[i] = 0x0000000000000000000000000000000000000000000000000000000000000003_cppui256;
        public_input.push_back(pi_values[i]);
        pi[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    typename BlueprintFieldType::value_type domain_size_value = 32;
    public_input.push_back(domain_size_value);
    var domain_size(0, public_input.size() - 1, false, var::column_type::public_input);

    typename BlueprintFieldType::value_type zero_value = 0;
    public_input.push_back(zero_value);
    var zero(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {zeta_pow_n,   zeta_omega_pow_n, pi,  lagrange_base,
                                                   omega_powers, domain_size,      one, zero};

    // r[0] = (zeta_pow_n - 1) * domain.size_inv * SUM(-l * p * w)
    // where l from lagrange, p from public, w from omega_powers for l from 0 to PulicInputSize
    // r[1] = (zeta_omega.pow(n) - 1) * index.domain.size_inv * SUM(-l * p * w)
    // where l from lagrange, p from public, w from omega_powers for l from PulicInputSize to 2 * PulicInputSize
    std::array<typename BlueprintFieldType::value_type, 2> expected_result = {0x18D62B16440429CDC5B94B8D9DC8A550535487AA7B64822433AD5E762009BD7C_cppui256,
                                                                                0x32B7DA94FAF98733D833AFE878FA7775452875BCBC8A953CEF1002C7B3D24033_cppui256};


    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result[0] == assignment.var_value(real_res.output[0]));
        assert(expected_result[1] == assignment.var_value(real_res.output[1]));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "public_evaluations_component: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_no_public_input) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 5;
    constexpr std::size_t n = 0;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type =
        zk::components::public_evaluations<ArithmetizationType, n, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    var one(0, 0, false, var::column_type::public_input);
    var zeta_pow_n(0, 1, false, var::column_type::public_input);
    var zeta_omega_pow_n(0, 2, false, var::column_type::public_input);
    typename BlueprintFieldType::value_type zeta_value = 0x2F51244846217BCB9DE92C5903AC022FAD29555920E45344407B680D24D550F1_cppui256;
    typename BlueprintFieldType::value_type omega_value = 0x0CC3380DC616F2E1DAF29AD1560833ED3BAEA3393ECEB7BC8FA36376929B78CC_cppui256;
    typename BlueprintFieldType::value_type zeta_omega_value = zeta_value * omega_value;
    constexpr std::size_t domain = 32;

    std::vector<typename BlueprintFieldType::value_type> public_input = {1, power(zeta_value, domain),
                                                                         power(zeta_omega_value, domain)};

    std::array<var, n> omega_powers;
    std::array<typename BlueprintFieldType::value_type, n> omega_powers_values;
    for (std::size_t i = 0; i < n; i++) {
        omega_powers_values[i] = power(omega_value, i);
        omega_powers[i] = var(0, 3 + i, false, var::column_type::public_input);
        public_input.push_back(omega_powers_values[i]);
    }

    std::array<var, 2 * n> lagrange_base;
    std::vector<typename BlueprintFieldType::value_type> lagrange_base_values(2 * n);
    for (std::size_t i = 0; i < n; i++) {
        lagrange_base_values[i] = (zeta_value - omega_powers_values[i]).inversed();
        lagrange_base_values[n + i] = (zeta_omega_value - omega_powers_values[i]).inversed();
    }

    for (std::size_t i = 0; i < lagrange_base.size(); i++) {
        public_input.push_back(lagrange_base_values[i]);
        lagrange_base[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    std::array<var, n> pi;
    std::array<typename BlueprintFieldType::value_type, n> pi_values;
    for (std::size_t i = 0; i < n; i++) {
        pi_values[i] = 0x0_cppui256;
        public_input.push_back(pi_values[i]);
        pi[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    typename BlueprintFieldType::value_type domain_size_value = 32;
    public_input.push_back(domain_size_value);
    var domain_size(0, public_input.size() - 1, false, var::column_type::public_input);

    typename BlueprintFieldType::value_type zero_value = 0;
    public_input.push_back(zero_value);
    var zero(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {zeta_pow_n,   zeta_omega_pow_n, pi,  lagrange_base,
                                                   omega_powers, domain_size,      one, zero};

    // r[0] = (zeta_pow_n - 1) * domain.size_inv * SUM(-l * p * w)
    // where l from lagrange, p from public, w from omega_powers for l from 0 to PulicInputSize
    // r[1] = (zeta_omega.pow(n) - 1) * index.domain.size_inv * SUM(-l * p * w)
    // where l from lagrange, p from public, w from omega_powers for l from PulicInputSize to 2 * PulicInputSize
    std::array<typename BlueprintFieldType::value_type, 2> expected_result = {0x0_cppui256, 0x0_cppui256};


    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result[0] == assignment.var_value(real_res.output[0]));
        assert(expected_result[1] == assignment.var_value(real_res.output[1]));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "public_evaluations_component: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
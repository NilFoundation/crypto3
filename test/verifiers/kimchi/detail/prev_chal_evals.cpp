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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_prev_chal_evals_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/oracles_scalar/prev_chal_evals.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include "../../../test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

template<typename FieldType, std::size_t ChalAmount>
typename FieldType::value_type b_poly(const std::array<typename FieldType::value_type, ChalAmount> &chals,
                                      typename FieldType::value_type x) {
    std::vector<typename FieldType::value_type> pow_twos;
    pow_twos.push_back(x);
    for (int i = 1; i < ChalAmount; ++i) {
        pow_twos.push_back(pow_twos[i - 1] * pow_twos[i - 1]);
    }
    typename FieldType::value_type res = 1;
    for (int i = 0; i < ChalAmount; ++i) {
        res *= FieldType::value_type::one() + chals[i] * pow_twos[ChalAmount - 1 - i];
    }
    return res;
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_prev_chal_evals) {
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
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t alpha_powers_n = 5;
    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t srs_len = 10;

    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;

    using component_type = zk::components::
        prev_chal_evals<ArithmetizationType, commitment_params, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    std::vector<typename BlueprintFieldType::value_type> public_input = {1, 0};
    var one(0, 0, false, var::column_type::public_input);
    var zero(0, 1, false, var::column_type::public_input);

    // typename BlueprintFieldType::value_type zeta_value = algebra::random_element<BlueprintFieldType>();
    // typename BlueprintFieldType::value_type omega_value = algebra::random_element<BlueprintFieldType>();
    typename BlueprintFieldType::value_type zeta_value = 0x01751A5CCC6A9B9BDF660296AF5F7C80229DC97F3646FFC3729D827E80DF39DF_cppui_modular256;
    //typename BlueprintFieldType::zeta_value * omega_value
    typename BlueprintFieldType::value_type zeta_omega_value = 0x11039196D240AC7CC0D1A88749F716B6B025F6BCA2CBBD0B41D2DA46FCC90558_cppui_modular256;

    public_input.push_back(zeta_value);
    var zeta(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(power(zeta_value, n));
    var zeta_pow_n(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_omega_value);
    var zeta_omega(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(power(zeta_omega_value, n));
    var zeta_omega_pow_n(0, public_input.size() - 1, false, var::column_type::public_input);

    std::array<var, eval_rounds> prev_challenges;
    std::array<typename BlueprintFieldType::value_type, eval_rounds> prev_challenges_values;
    std::array<typename BlueprintFieldType::value_type, 5> prev_challenges_values_from_mina;
    prev_challenges_values_from_mina[0] = 0x2C0AD1A81FAC9BE59890BEA77119393E3E9EC523A44DF600FE2399C01AA76F70_cppui_modular256;
    prev_challenges_values_from_mina[1] = 0x39F31DAAD9FA26835EB1F6ADB2DCE08649061681361B54082C1FA1CD800EEB97_cppui_modular256;
    prev_challenges_values_from_mina[2] = 0x07DB69AD9447B12124D32EB3F4A087CE3126CEE2BE9BB8F3C0EE78EDE57667BD_cppui_modular256;
    prev_challenges_values_from_mina[3] = 0x15C3B5B04E953BBEEAF466BA36642F163B8E2040506916FAEEEA80FB4ADDE3E4_cppui_modular256;
    prev_challenges_values_from_mina[4] = 0x23AC01B308E2C65CB1159EC07827D65E45F5719DE23675021CE68908B045600B_cppui_modular256;
    for (std::size_t i = 0; i < eval_rounds; i++) {
        prev_challenges_values[i] = prev_challenges_values_from_mina[i];
    }


    for (std::size_t i = 0; i < eval_rounds; i++) {
        // prev_challenges_values[i] = algebra::random_element<BlueprintFieldType>(); //
        public_input.push_back(prev_challenges_values[i]);
        prev_challenges[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    std::array<var, 2> evals = {zeta, zeta_omega};
    std::array<var, 2> evals_power = {zeta_pow_n, zeta_omega_pow_n};

    typename component_type::params_type params = {prev_challenges, evals, evals_power, one, zero};

    // r[0] = (zeta_pow_n - 1) * domain.size_inv * SUM(-l * p * w)
    // where l from lagrange, p from public, w from omega_powers for l from 0 to PulicInputSize
    // r[1] = (zeta_omega.pow(n) - 1) * index.domain.size_inv * SUM(-l * p * w)
    // where l from lagrange, p from public, w from omega_powers for l from PulicInputSize to 2 * PulicInputSize
    std::array<typename BlueprintFieldType::value_type, 4> expected_result;
    expected_result[0] = b_poly<BlueprintFieldType, eval_rounds>(prev_challenges_values, zeta_value);
    expected_result[1] = b_poly<BlueprintFieldType, eval_rounds>(prev_challenges_values, zeta_omega_value);
    expected_result[2] = 0x03B060BB64B9D6627C7336873BA524D7B752598E8B3390647BDF6B70B5BB93FF_cppui_modular256; // r[0] from mina, == expected_result[0]
    expected_result[3] = 0x39B7CA68618353B26F521A651FE3F9DD365401BC8B68B07FC6D656EB010A541B_cppui_modular256; // r[1] from mina, == expected_result[1]

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result[0] == assignment.var_value(real_res.output[0][0]));
        assert(expected_result[1] == assignment.var_value(real_res.output[1][0]));
        assert(expected_result[2] == assignment.var_value(real_res.output[0][0]));
        assert(expected_result[3] == assignment.var_value(real_res.output[1][0]));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        params, public_input, result_check);

    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "prev_chal_evals_component: " << duration.count() << "ms" << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_ft_eval_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/ft_eval.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>

#include "test_plonk_component.hpp"
#include "../proof_data.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_ft_eval_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_ft_eval_test) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 10;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t alpha_powers_n = 5;
    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;
    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;
    constexpr static std::size_t lookup_table_size = 1;
    constexpr static bool use_lookup = false;
    constexpr static const std::size_t index_terms = 0;

    constexpr static const std::size_t srs_len = 1;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, 
                                                             commitment_params,
                                                             witness_columns,
                                                             perm_size,
                                                             use_lookup,
                                                             lookup_table_size,
                                                             alpha_powers_n,
                                                             public_input_size,
                                                             index_terms,
                                                             prev_chal_size>;

    zk::components::kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
    typename BlueprintFieldType::value_type omega_value =
        0x1B1A85952300603BBF8DD3068424B64608658ACBB72CA7D2BB9694ADFA504418_cppui256;
    verifier_index.zkpm = {0x2C46205451F6C3BBEA4BABACBEE609ECF1039A903C42BFF639EDC5BA33356332_cppui256,
                           0x1764D9CB4C64EBA9A150920807637D458919CB6948821F4D15EB1994EADF9CE3_cppui256,
                           0x0140117C8BBC4CE4644A58F7007148577782213065BB9699BF5C391FBE1B3E6D_cppui256,
                           0x0000000000000000000000000000000000000000000000000000000000000001_cppui256};
    std::size_t domain_size_value = 128;
    verifier_index.public_input_size = public_input_size;
    verifier_index.alpha_powers = alpha_powers_n;

    using component_type = zk::components::
        ft_eval<ArithmetizationType, curve_type, kimchi_params, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

    zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    typename BlueprintFieldType::value_type joint_combiner_value = 15;
    typename BlueprintFieldType::value_type beta_value = 3;
    typename BlueprintFieldType::value_type gamma_value = 5;
    typename BlueprintFieldType::value_type alpha_value =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_value =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;

    std::vector<typename BlueprintFieldType::value_type> public_input = {
        joint_combiner_value, beta_value, gamma_value, power(zeta_value, domain_size_value),
        // verifier_index
        domain_size_value, omega_value, zeta_value, 1, 0};

    var joint_combiner(0, 0, false, var::column_type::public_input);
    var beta(0, 1, false, var::column_type::public_input);
    var gamma(0, 2, false, var::column_type::public_input);
    var zeta_pow_n(0, 3, false, var::column_type::public_input);
    var domain_size(0, 4, false, var::column_type::public_input);
    var omega(0, 5, false, var::column_type::public_input);
    var zeta(0, 6, false, var::column_type::public_input);
    var one(0, 7, false, var::column_type::public_input);
    var zero(0, 8, false, var::column_type::public_input);
    verifier_index.domain_size = domain_size;
    verifier_index.omega = omega;

    // TODO prepare real data
    std::array<var, alpha_powers_n> alpha_powers;
    for (std::size_t i = 0; i < alpha_powers_n; i++) {
        public_input.push_back(power(alpha_value, i));
        alpha_powers[i] = var(0, public_input.size() - 1, false, var::column_type::public_input);
    }

    zk::components::kimchi_proof_scalar<BlueprintFieldType, kimchi_params, eval_rounds> proof;

    typename component_type::params_type params = {verifier_index,    zeta_pow_n, alpha_powers,
                                                   proof.proof_evals, gamma,      beta,
                                                   proof.proof_evals, zeta,       joint_combiner};

    auto result_check = [](AssignmentType &assignment, component_type::result_type &real_res) {};

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        params, public_input, result_check);
}

BOOST_AUTO_TEST_SUITE_END()
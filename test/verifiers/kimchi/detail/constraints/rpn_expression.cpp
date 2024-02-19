//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_detail_rpn_expression_test

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
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/constraints/rpn_expression.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/constraints/rpn_string_literal.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/binding.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include "verifiers/kimchi/index_terms_instances/ec_index_terms.hpp"
#include "test_plonk_component.hpp"

using namespace nil::crypto3;
BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite)
BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_lagrange) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    typename BlueprintFieldType::value_type result = 0x1E2AE13562C642ED35261EB5927960C75105852F6F962D463BF981EF969050C4_cppui255;
    constexpr const char *s ="UnnormalizedLagrangeBasis(-4);\0";

    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0C0D3C26FCD47AFF64D9055FCE9858335ADE6B0706289AB4019630784E8B7527_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000059E5EE71CFF4B24FA2A3A131F77CFFC8_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000085D434481165E938FEA628354AA5B9E5_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x00_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x35ABB5BAFCAFF26391BB9A23EA996222FD0D4B0F392A78E4AFD5610ECE614E49_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x1421DEB15F5CE205068512B010382353DC0AA1B40386A1C14774C65664BB8182_cppui256;
    std::size_t domain_size = 1024;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val, &result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(assignment.var_value(real_res.output)== result);

    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}
BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_vanishes) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
                                                                           witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
                                                             public_input_size, prev_chal_size>;

    typename BlueprintFieldType::value_type result = 0x2692756edf321604d16f4d2151fbad0a9780c75ebb49f9b56a89adde2f6a1f48_cppui255;
    constexpr const char *s ="Alpha;Pow(24);VanishesOnLast4Rows;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type group_gen = BlueprintFieldType::value_type::one();

    typename BlueprintFieldType::value_type alpha_val =
        0x0C0D3C26FCD47AFF64D9055FCE9858335ADE6B0706289AB4019630784E8B7527_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000059E5EE71CFF4B24FA2A3A131F77CFFC8_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000085D434481165E938FEA628354AA5B9E5_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x00_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x35ABB5BAFCAFF26391BB9A23EA996222FD0D4B0F392A78E4AFD5610ECE614E49_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x1421DEB15F5CE205068512B010382353DC0AA1B40386A1C14774C65664BB8182_cppui256;
    std::size_t domain_size = 1024;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val, &result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(assignment.var_value(real_res.output)== result);

    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_dup) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Dup;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(gamma_val == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_sub) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Sub;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert((beta_val - gamma_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_add) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Add;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert((gamma_val + beta_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}
BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_mul) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Mul;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert((gamma_val * beta_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_pow) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(10), row: Curr });Pow(2);\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;
    evals[0].w[10] = gamma;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert((gamma_val * gamma_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_load) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Store;Beta;Alpha;Pow(20);Add;Alpha;Load(0);Sub;Add;Sub;Literal 0000000000000000000000000000000000000000000000000000000000000001;Add;\0"; // - alpha^20 - beta + alpha + 1
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type alpha_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D5_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8D3_cppui256;
    typename BlueprintFieldType::value_type joint_combiner_val =
        0x0000000000000000000000000000000005321CB83A4BCD5C63F489B5BF95A8DC_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x0000000000000000000000000000000062F9AE3696EA8F0A85043221DE133E32_cppui256;
    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    typename BlueprintFieldType::value_type expected_result = -alpha_val.pow(20) + alpha_val - beta_val + 1;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_complete_add) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Cell(Variable { col: Witness(10), row: Curr });Cell(Variable { col: Witness(2), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Store;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(7), row: Curr });Sub;Sub;Alpha;Pow(1);Cell(Variable { col: Witness(7), row: Curr });Load(0);Mul;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Dup;Add;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Dup;Add;Sub;Load(1);Sub;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(7), row: Curr });Sub;Load(0);Cell(Variable { col: Witness(8), row: Curr });Mul;Cell(Variable { col: Witness(3), row: Curr });Cell(Variable { col: Witness(1), row: Curr });Sub;Store;Sub;Mul;Add;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(2), row: Curr });Add;Cell(Variable { col: Witness(4), row: Curr });Add;Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Mul;Sub;Mul;Add;Alpha;Pow(4);Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(4), row: Curr });Sub;Mul;Cell(Variable { col: Witness(1), row: Curr });Sub;Cell(Variable { col: Witness(5), row: Curr });Sub;Mul;Add;Alpha;Pow(5);Load(2);Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(6), row: Curr });Sub;Mul;Mul;Add;Alpha;Pow(6);Load(2);Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(6), row: Curr });Sub;Mul;Add;\0";
    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type expected_result = 0x0EF5278F0AD55CDE149D4E396A01E9B72A0D73FB4CF033C570B1B7E0C24C5FCE_cppui256;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval0_w = {
            0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui256,
            0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui256,
            0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui256,
            0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui256,
            0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui256,
            0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui256,
            0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui256,
            0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui256,
            0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui256,
            0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui256,
            0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui256,
            0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui256,
            0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui256,
            0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui256,
            0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui256
        };

    typename BlueprintFieldType::value_type eval0_z = 0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256,
        0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui256,
        0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui256,
        0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui256,
        0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui256,
        0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui256
    };

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval1_w = {
            0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui256,
            0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui256,
            0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui256,
            0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui256,
            0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui256,
            0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui256,
            0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui256,
            0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui256,
            0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui256,
            0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui256,
            0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui256,
            0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui256,
            0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui256,
            0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui256,
            0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui256
        };

    typename BlueprintFieldType::value_type eval1_z = 0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
        0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui256,
        0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui256,
        0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui256,
        0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui256,
        0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui256,
        0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui256,
    };

    std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};
    std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};
    std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};

    typename BlueprintFieldType::value_type alpha_val =
        0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;

    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(0);
    var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<
                        BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < witness_columns; j++) {
            public_input.push_back(eval_w[i][j]);
            var w = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].w[j] = w;
        }

        public_input.push_back(eval_z[i]);
        var z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].z = z;

        for (std::size_t j = 0; j < perm_size; j++) {
            public_input.push_back(eval_s[i][j]);
            var s = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].s[j] = s;
        }

        evals[i].poseidon_selector = zero;
        evals[i].generic_selector = zero;
    }

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    var joint_combiner = zero;

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_endo_mul) {

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType>;
    using AssignmentType = blueprint::assignment<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list_ec_test<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list,
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Cell(Variable { col: Witness(11), row: Curr });Dup;Mul;Cell(Variable { col: Witness(11), row: Curr });Sub;Alpha;Pow(1);Cell(Variable { col: Witness(12), row: Curr });Dup;Mul;Cell(Variable { col: Witness(12), row: Curr });Sub;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(13), row: Curr });Dup;Mul;Cell(Variable { col: Witness(13), row: Curr });Sub;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(14), row: Curr });Dup;Mul;Cell(Variable { col: Witness(14), row: Curr });Sub;Mul;Add;Alpha;Pow(4);Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(11), row: Curr });EndoCoefficient;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Mul;Add;Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Cell(Variable { col: Witness(4), row: Curr });Sub;Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(12), row: Curr });Dup;Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(5), row: Curr });Sub;Sub;Mul;Add;Alpha;Pow(5);Cell(Variable { col: Witness(4), row: Curr });Dup;Add;Cell(Variable { col: Witness(9), row: Curr });Dup;Mul;Store;Sub;Load(0);Add;Cell(Variable { col: Witness(4), row: Curr });Cell(Variable { col: Witness(7), row: Curr });Sub;Store;Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(5), row: Curr });Add;Store;Add;Mul;Cell(Variable { col: Witness(5), row: Curr });Dup;Add;Load(2);Mul;Sub;Mul;Add;Alpha;Pow(6);Load(3);Dup;Mul;Load(2);Dup;Mul;Load(1);Load(0);Sub;Cell(Variable { col: Witness(7), row: Curr });Add;Mul;Sub;Mul;Add;Alpha;Pow(7);Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(13), row: Curr });EndoCoefficient;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Mul;Add;Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Cell(Variable { col: Witness(7), row: Curr });Sub;Cell(Variable { col: Witness(10), row: Curr });Mul;Cell(Variable { col: Witness(14), row: Curr });Dup;Add;Literal 0000000000000000000000000000000000000000000000000000000000000001;Sub;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(8), row: Curr });Sub;Sub;Mul;Add;Alpha;Pow(8);Cell(Variable { col: Witness(7), row: Curr });Dup;Add;Cell(Variable { col: Witness(10), row: Curr });Dup;Mul;Store;Sub;Load(4);Add;Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(4), row: Next });Sub;Store;Cell(Variable { col: Witness(10), row: Curr });Mul;Cell(Variable { col: Witness(5), row: Next });Cell(Variable { col: Witness(8), row: Curr });Add;Store;Add;Mul;Cell(Variable { col: Witness(8), row: Curr });Dup;Add;Load(6);Mul;Sub;Mul;Add;Alpha;Pow(9);Load(7);Dup;Mul;Load(6);Dup;Mul;Load(5);Load(4);Sub;Cell(Variable { col: Witness(4), row: Next });Add;Mul;Sub;Mul;Add;Alpha;Pow(10);Cell(Variable { col: Witness(6), row: Curr });Dup;Add;Cell(Variable { col: Witness(11), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(12), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(13), row: Curr });Add;Dup;Add;Cell(Variable { col: Witness(14), row: Curr });Add;Cell(Variable { col: Witness(6), row: Next });Sub;Mul;Add;\0";

    const std::size_t array_size = zk::components::count_delimiters(s);
    const std::size_t N = zk::components::rpn_component_rows<array_size, ArithmetizationType>(s);
    using component_type = zk::components::rpn_expression<ArithmetizationType, kimchi_params, N, 0, 1, 2, 3, 4, 5, 6, 7,
                                                          8, 9, 10, 11, 12, 13, 14>;

    typename BlueprintFieldType::value_type expected_result = 0x259D030170979C4754D0CEBF9E6AE529563BEB3A27C7003F57CCD4F80F875E4B_cppui256;

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval0_w = {
            0x0C2F522FB163AE4A8D2890C57ABF95E55EF7DDD27A928EFAD0D3FA447D40BC29_cppui256,
            0x3F0169364239FF2352BFFEF6D2A206A6DC8FAA526C51EB51FC7610F6E73DFAE5_cppui256,
            0x2BCBED001BA14933A1766C68E09BF19C133AB20B87A9D0DB68321A99C4C7A157_cppui256,
            0x1430DC77EBF0048A4E26DDB817DD34D3F253AA9894C7D442B8BC06C7683D0188_cppui256,
            0x3B79EBE49FAEF6F123C168CF484296A84186EF1FB9FFFA528B0AAC0761F535AD_cppui256,
            0x16C6D43CFFB252215D05E1A05DBA2EEAADB3FAAF88B8AABDBD4E8860B9623530_cppui256,
            0x1C0801C94EA28AAD68CEA9C9524106D39DC1A3491435A23D35EEBE56DB3AB116_cppui256,
            0x21545E083F1282D939751D5E0D4EF173C7528C9E38349FE5E02BAB4686B542D4_cppui256,
            0x2E8F53F919EBB22022424A175A051F6FBDB2B57E06E1AC8A8201FBDD02CEE2FD_cppui256,
            0x1B5A53763A06BFAF8BAAF566FE885CD31355B2AC4F0F04B13F05610DE1EBAB5E_cppui256,
            0x212CC53B694BA1B3ED2D6C514B97325D62BF301F18E76B7DF94F04B7875C7E64_cppui256,
            0x22C1E6932B0336B13262867483DEE4C6B8E798C24F4245051254A64C61EAC604_cppui256,
            0x356428F289E597185A60ED494351FF93B5802480DC375E4B2C6ECAB816B69524_cppui256,
            0x08066B51E8C7F77F825F541E02C51A608FD217435FDF7E75AD5BBE36CB826443_cppui256,
            0x1AA8ADB147AA57E6AA5DBAF2C238352D8C6AA301ECD497BBC775E2A2804E3363_cppui256
        };

    typename BlueprintFieldType::value_type eval0_z = 0x1480D3E4FD095CEC3688F88B105EE6F2365DCFAAA28CCB6B87DAB7E71E58010B_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval0_s = {
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256,
        0x05EDDC1E6C268DF398F068F06C51794D6F672E27FB800DFF6C5C35E5C3D84207_cppui256,
        0x1B03A1DBEA987367FDEF97CC27F7441C4845E93AD1583167DA4A1A9CCFFB1E71_cppui256,
        0x11347E33DF1631D59D66F6149D99DD22FD23B185D7D89CFE0909877C494D7916_cppui256,
        0x0E1372B72364C37883171F80BC89F2AC7043464C8C30E1D2B5D94105035A6C6E_cppui256,
        0x336A5683971A09A68D33D77B41947F8CAFFE3923190B51D443E515761A32889B_cppui256
    };

    std::array<typename BlueprintFieldType::value_type, witness_columns>
        eval1_w = {
            0x144FF7F30B8C75C60E63614EA792F9A41E41C2DBE40F816A602160960C071F56_cppui256,
            0x114768369E43EA7A13DE72AC855AE7D31DC52B34EB45BB96EA1BDFF54FEC4AB8_cppui256,
            0x006259A5F4A9A82296077396D476F9E59392BDDA93E63B9A582EF9BBA452A7A2_cppui256,
            0x3F9EBB3D514729A24B0C87FB434FC043F48195FA45E510BA5817F0ED05DED76B_cppui256,
            0x06F0CA9962E207949F85C22ADCBE8F27E632D14B843F2C65E264752B6100049E_cppui256,
            0x3885B6A574C4B6B89867EE499534E0F4937C7D71BA724A857F5E7F797059E879_cppui256,
            0x0554E97666ABA1659D7D107E3F709F546625481B1A5684BE24EFE9B3CBBC300F_cppui256,
            0x06C748D2C049B08C50633EBF7F7A0C68A03677CE382BF6697B7D285F30215616_cppui256,
            0x0B252004A6768951624E56F1D98B1DDB006B2284FE1C08B258D95B92BF40266F_cppui256,
            0x029236F173E5278B30CB9DAD8C87CEDE865AD1293B9BBF991F1743E8D1FD6638_cppui256,
            0x28C63DB702FFC629457818259603A154886B11D1D1FB7065037F51212E5BE2D3_cppui256,
            0x0219DC4D947F1109C90CD6C0112559A5D04528C2B264062A98DC5E7BBF85F269_cppui256,
            0x246CB73F3BB0A9AC5FA65DED8A1617E0CB8231146F0DF67467ED5E85242DF2B6_cppui256,
            0x06BF9230E2E2424EF63FE51B0306D61BA478A06A226AEDA29DD12DA188D5F302_cppui256,
            0x29126D228A13DAF18CD96C487BF794569FB5A8BBDF14DDEC6CE22DAAED7DF34F_cppui256
        };

    typename BlueprintFieldType::value_type eval1_z = 0x1635A182C3B5623D5E7CF31D244F389FB478B0612B27937A39D48B473DB68931_cppui256;

    std::array<typename BlueprintFieldType::value_type, perm_size> eval1_s = {
        0x069DE7D0EBB1985B05DAB9E13348C12530D374BAD474C76C4AB9FAC8EB557332_cppui256,
        0x177B2B5F39976BE667F5D6768480F1555F52395613AF100529C99844DA28DCC9_cppui256,
        0x2941C2A82AC0067D3DD6A2C47EDD675D5B7BA071414A8324BA4CFAA1816B163F_cppui256,
        0x05EA2B93EF3D2CD3E8DDDA175F2446A8390E35219DFBA39111C8CDBFA3038FCE_cppui256,
        0x15C6FB1ACD775DF5E860906CDDF37C4E6B82CDC1A67F02F129DEAE98A11620D6_cppui256,
        0x338D629CA1F64B37674CA7B5AF91015CA50A5D335E7076E25D9F4C230C99395D_cppui256,
    };

    std::array<std::array<typename BlueprintFieldType::value_type, witness_columns>, 2> eval_w = {eval0_w, eval1_w};
    std::array<typename BlueprintFieldType::value_type, 2> eval_z = {eval0_z, eval1_z};
    std::array<std::array<typename BlueprintFieldType::value_type, perm_size>, 2> eval_s = {eval0_s, eval1_s};

    typename BlueprintFieldType::value_type alpha_val =
        0x322D5D64C86AFB168AC57D2D8AB3512647B4802C8DC4DE07DB2C51E094C4D9B7_cppui256;
    typename BlueprintFieldType::value_type beta_val =
        0x000000000000000000000000000000005D27C70754796C79C9D9958673CF2ABA_cppui256;
    typename BlueprintFieldType::value_type gamma_val =
        0x00000000000000000000000000000000C2278ADB337FA07CDFB689C4651FFD6D_cppui256;
    typename BlueprintFieldType::value_type zeta_val =
        0x03D8C35D2E1466E8514E20A8E658F4E2B1116AB123F7BF53F9A1C7376F788EB1_cppui256;

    typename BlueprintFieldType::value_type omega_val =
        0x0CB8102D0128EBB25343154773101EAF1A9DAEF679667EB4BD1E06B973E985E4_cppui256;
    std::size_t domain_size = 512;

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(0);
    var zero = var(0, public_input.size() - 1, false, var::column_type::public_input);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<
                        BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals;

    for (std::size_t i = 0; i < 2; i++) {
        for (std::size_t j = 0; j < witness_columns; j++) {
            public_input.push_back(eval_w[i][j]);
            var w = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].w[j] = w;
        }

        public_input.push_back(eval_z[i]);
        var z = var(0, public_input.size() - 1, false, var::column_type::public_input);
        evals[i].z = z;

        for (std::size_t j = 0; j < perm_size; j++) {
            public_input.push_back(eval_s[i][j]);
            var s = var(0, public_input.size() - 1, false, var::column_type::public_input);
            evals[i].s[j] = s;
        }

        evals[i].poseidon_selector = zero;
        evals[i].generic_selector = zero;
    }

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);
    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(zeta_val);
    var zeta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    var joint_combiner = zero;

    public_input.push_back(omega_val);
    var omega = var(0, public_input.size() - 1, false, var::column_type::public_input);

    typename component_type::params_type params = {s, zeta, alpha, beta, gamma, joint_combiner, evals, omega, domain_size};

    auto result_check = [&expected_result](AssignmentType &assignment, component_type::result_type &real_res) {
        assert(expected_result == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()
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
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_expression.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/rpn_string_literal.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/kimchi_commitment_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/binding.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/proof_system/circuit_description.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/index_terms_instances/ec_index_terms.hpp>
#include "test_plonk_component.hpp"

using namespace nil::crypto3;
BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite)
BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite_dup) {

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::scalar_field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 30;
    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list<ArithmetizationType>;
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

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
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
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list<ArithmetizationType>;
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
        assert((gamma_val - beta_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
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
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list<ArithmetizationType>;
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

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
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
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list<ArithmetizationType>;
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

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
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
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Pow(2);\0";
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
        assert((gamma_val * gamma_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
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
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using index_terms_list = zk::components::index_terms_scalars_list<ArithmetizationType>;
    using circuit_description = zk::components::kimchi_circuit_description<index_terms_list, 
        witness_columns, perm_size>;
    using kimchi_params = zk::components::kimchi_params_type<curve_type, commitment_params, circuit_description,
        public_input_size, prev_chal_size>;

    constexpr const char *s = "Cell(Variable { col: Witness(10), row: Curr });Cell(Variable { col: Witness(2), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Sub;Store;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(7), row: Curr });Sub;Sub;Alpha;Pow(1);Cell(Variable { col: Witness(7), row: Curr });Load(0);Mul;Mul;Add;Alpha;Pow(2);Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Dup;Add;Cell(Variable { col: Witness(1), row: Curr });Mul;Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Mul;Store;Dup;Add;Sub;Load(1);Sub;Mul;Literal 0000000000000000000000000000000000000000000000000000000000000001;Cell(Variable { col: Witness(7), row: Curr });Sub;Load(0);Cell(Variable { col: Witness(8), row: Curr });Mul;Cell(Variable { col: Witness(3), row: Curr });Cell(Variable { col: Witness(1), row: Curr });Sub;Store;Sub;Mul;Add;Mul;Add;Alpha;Pow(3);Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(2), row: Curr });Add;Cell(Variable { col: Witness(4), row: Curr });Add;Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(8), row: Curr });Mul;Sub;Mul;Add;Alpha;Pow(4);Cell(Variable { col: Witness(8), row: Curr });Cell(Variable { col: Witness(0), row: Curr });Cell(Variable { col: Witness(4), row: Curr });Sub;Mul;Cell(Variable { col: Witness(1), row: Curr });Sub;Cell(Variable { col: Witness(5), row: Curr });Sub;Mul;Add;Alpha;Pow(5);Load(2);Cell(Variable { col: Witness(7), row: Curr });Cell(Variable { col: Witness(6), row: Curr });Sub;Mul;Mul;Add;Alpha;Pow(6);Load(2);Cell(Variable { col: Witness(9), row: Curr });Mul;Cell(Variable { col: Witness(6), row: Curr });Sub;Mul;Add;\0";
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
        
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()
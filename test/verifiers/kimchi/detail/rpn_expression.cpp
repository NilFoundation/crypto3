//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/kimchi_params.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/binding.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_detail_rpn_expression_test_suite) {

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

    constexpr static std::size_t alpha_powers_n = 5;
    constexpr static std::size_t public_input_size = 3;
    constexpr static std::size_t max_poly_size = 32;
    constexpr static std::size_t eval_rounds = 5;

    constexpr static std::size_t witness_columns = 15;
    constexpr static std::size_t perm_size = 7;
    constexpr static std::size_t lookup_table_size = 1;
    constexpr static bool use_lookup = false;

    constexpr static std::size_t srs_len = 10;
    constexpr static const std::size_t index_terms = 0;
    constexpr static const std::size_t prev_chal_size = 1;

    using commitment_params = zk::components::kimchi_commitment_params_type<eval_rounds, max_poly_size, srs_len>;
    using kimchi_params =
        zk::components::kimchi_params_type<curve_type, commitment_params, witness_columns, perm_size, use_lookup, lookup_table_size,
                                           alpha_powers_n, public_input_size, index_terms, prev_chal_size>;

    using component_type =
        zk::components::rpn_expression<ArithmetizationType, kimchi_params, 0, 1, 2,
                                             3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

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

    std::vector<typename BlueprintFieldType::value_type> public_input;

    public_input.push_back(alpha_val);
    var alpha = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(beta_val);
    var beta = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(gamma_val);
    var gamma = var(0, public_input.size() - 1, false, var::column_type::public_input);

    public_input.push_back(joint_combiner_val);
    var joint_combiner = var(0, public_input.size() - 1, false, var::column_type::public_input);

    std::string expression_str = "Alpha;Beta;Cell(Variable { col: Witness(3), row: Curr });Add;";

    auto expression = component_type::rpn_from_string(expression_str);

    using evaluations_type = typename zk::components::kimchi_proof_evaluations<
                        BlueprintFieldType, kimchi_params>;
    std::array<evaluations_type, 2> evals; 
    evals[0].w[3] = gamma;

    typename component_type::params_type params = {expression, 
        alpha, beta, gamma, joint_combiner,
        evals};

    // s: Fp256 "(3BF91D9CBAB4826F2C2A0BFA421A66615BF403C45BB4096846C4326CC0DFF586)"
    // s2: Fp256(BigInteger256([1, 2, 3, 4]))
    typename BlueprintFieldType::value_type s = 0x3BF91D9CBAB4826F2C2A0BFA421A66615BF403C45BB4096846C4326CC0DFF586_cppui256;
    typename BlueprintFieldType::integral_type s_integral = typename BlueprintFieldType::integral_type (s.data);
    std::cout<<"s: "<<s.data<<std::endl;
    std::cout<<"s_integral: "<<s_integral<<std::endl;
    typename BlueprintFieldType::value_type s2 = 0;

    auto result_check = [&gamma_val, &beta_val](AssignmentType &assignment, component_type::result_type &real_res) {
        assert((gamma_val + beta_val) == assignment.var_value(real_res.output));
    };

    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input,
                                                                                                 result_check);
}

BOOST_AUTO_TEST_SUITE_END()
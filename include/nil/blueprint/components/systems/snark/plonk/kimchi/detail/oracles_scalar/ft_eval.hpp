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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_FT_EVAL_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_FT_EVAL_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/zkpm_evaluate.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/zk_w3.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/alpha_argument_type.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // ft polynomial at zeta
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L320-L384
                // Input:
                // Output: ft(zeta)
                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType,
                         std::size_t... WireIndexes>
                class ft_eval;

                template<typename BlueprintFieldType, typename CurveType,
                         typename KimchiParamsType, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9,
                         std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class ft_eval<snark::plonk_constraint_system<BlueprintFieldType>, CurveType,
                              KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using div_component = zk::components::division<ArithmetizationType, W0, W1, W2, W3>;

                    using zkpm_eval_component =
                        zk::components::zkpm_evaluate<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
                                                      W11, W12, W13, W14>;

                    using zk_w3_component = zk::components::zk_w3<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6, W7,
                                                                  W8, W9, W10, W11, W12, W13, W14>;

                    using verifier_index_type = kimchi_verifier_index_scalar<BlueprintFieldType>;

                    using index_terms_list = typename KimchiParamsType::circuit_params::index_terms_list;
                    using constant_term_component =
                        zk::components::rpn_expression<ArithmetizationType, KimchiParamsType,
                                                       index_terms_list::constatnt_term_rows, W0, W1, W2, W3, W4, W5,
                                                       W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t selector_seed = 0x0f22;
                    constexpr static const std::size_t eval_points_amount = 2;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;
                        row += 2; // skip rows for constant in zkpm
                        row += zkpm_eval_component::rows_amount;
                        row += sub_component::rows_amount;

                        row += add_component::rows_amount;
                        row += 3 * mul_component::rows_amount;

                        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                            row += 2 * mul_component::rows_amount;
                            row += 2 * add_component::rows_amount;
                        }

                        if (KimchiParamsType::public_input_size >
                            0) {    // if public input isn't present, then public_eval is empty
                            row += sub_component::rows_amount;
                        }

                        row += 2 * mul_component::rows_amount;

                        for (std::size_t i = 0; i < KimchiParamsType::permut_size; i++) {
                            row += 3 * mul_component::rows_amount;
                            row += 2 * add_component::rows_amount;
                        }
                        row += sub_component::rows_amount;

                        // numerator calculation
                        row += zk_w3_component::rows_amount;
                        row += 3 * sub_component::rows_amount;
                        row += 5 * mul_component::rows_amount;
                        row += add_component::rows_amount;

                        // denominator
                        row += mul_component::rows_amount;
                        row += div_component::rows_amount;

                        row += mul_component::rows_amount;
                        row += add_component::rows_amount;

                        row += constant_term_component::rows_amount;
                        row += sub_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        verifier_index_type &verifier_index;
                        std::array<var, KimchiParamsType::alpha_powers_n> alpha_powers;
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, eval_points_amount>
                            combined_evals;
                        var gamma;
                        var beta;
                        var zeta;
                        var zeta_pow_n;
                        var joint_combiner;
                        std::array<var, eval_points_amount> public_eval;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t component_start_row) {
                            std::size_t row = component_start_row + rows_amount - sub_component::rows_amount;
                            output = typename sub_component::result_type(row).output;
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var zero(0, start_row_index, false, var::column_type::constant);
                        var one(0, start_row_index + 1, false, var::column_type::constant);

                        row += 2; // skip rows for constant in zkpm

                        // zkp = index.zkpm().evaluate(&zeta);
                        var zkp =
                            zkpm_eval_component::generate_circuit(
                                bp, assignment,
                                {params.verifier_index.omega, params.verifier_index.domain_size, params.zeta}, row)
                                .output;
                        row += zkpm_eval_component::rows_amount;

                        // zeta1m1 = zeta_pow_n - ScalarField::<G>::one();
                        var zeta1m1 = zk::components::generate_circuit<sub_component>(bp,
                            assignment, {params.zeta_pow_n, one}, row).output;
                        row += sub_component::rows_amount;

                        // get alpha0, alpha1, alpha2
                        std::pair<std::size_t, std::size_t> alpha_idxs =
                            index_terms_list::alpha_map(argument_type::Permutation);
                        assert(alpha_idxs.second >= 3);
                        var alpha0 = params.alpha_powers[alpha_idxs.first];
                        var alpha1 = params.alpha_powers[alpha_idxs.first + 1];
                        var alpha2 = params.alpha_powers[alpha_idxs.first + 2];

                        // let init = (evals[0].w[PERMUTS - 1] + gamma) * evals[1].z * alpha0 * zkp;
                        var init =
                            zk::components::generate_circuit<add_component>(
                                bp, assignment,
                                {params.combined_evals[0].w[KimchiParamsType::permut_size - 1], params.gamma}, row)
                                .output;
                        row += add_component::rows_amount;
                        init  = zk::components::generate_circuit<mul_component>(bp,
                            assignment, {init, params.combined_evals[1].z}, row).output;
                        row += mul_component::rows_amount;
                        init =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {init, alpha0}, row).output;
                        row += mul_component::rows_amount;
                        init = zk::components::generate_circuit<mul_component>(bp, assignment, {init, zkp}, row).output;
                        row += mul_component::rows_amount;

                        //     let mut ft_eval0 = evals[0]
                        //         .w
                        //         .iter()
                        //         .zip(evals[0].s.iter())
                        //         .map(|(w, s)| (beta * s) + w + gamma)
                        //         .fold(init, |x, y| x * y);
                        var ft_eval0 = init;
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                            var w = params.combined_evals[0].w[i];
                            var s = params.combined_evals[0].s[i];
                            var beta_s =
                                zk::components::generate_circuit<mul_component>(bp, assignment, {params.beta, s}, row)
                                    .output;
                            row += mul_component::rows_amount;
                            var w_beta_s =
                                zk::components::generate_circuit<add_component>(bp, assignment, {w, beta_s}, row)
                                    .output;
                            row += add_component::rows_amount;
                            var w_beta_s_gamma = zk::components::generate_circuit<add_component>(
                                                     bp, assignment, {w_beta_s, params.gamma}, row)
                                                     .output;
                            row += add_component::rows_amount;
                            ft_eval0 = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                       {ft_eval0, w_beta_s_gamma}, row)
                                           .output;
                            row += mul_component::rows_amount;
                        }

                        // ft_eval0 - p_eval[0]
                        if (KimchiParamsType::public_input_size > 0) {
                            var ft_eval0 = zk::components::generate_circuit<sub_component>(bp,
                                assignment, {ft_eval0, params.public_eval[0]}, row).output;
                            row += sub_component::rows_amount;
                        }

                        //     ft_eval0 -= evals[0]
                        //         .w
                        //         .iter()
                        //         .zip(index.shift.iter())
                        //         .map(|(w, s)| gamma + (beta * zeta * s) + w)
                        //         .fold(alpha0 * zkp * evals[0].z, |x, y| x * y);
                        var ft_eval0_sub =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {alpha0, zkp}, row).output;
                        row += mul_component::rows_amount;
                        ft_eval0_sub = zk::components::generate_circuit<mul_component>(
                                           bp, assignment, {ft_eval0_sub, params.combined_evals[0].z}, row)
                                           .output;
                        row += mul_component::rows_amount;

                        for (std::size_t i = 0; i < KimchiParamsType::permut_size; i++) {
                            var w = params.combined_evals[0].w[i];
                            var s = params.verifier_index.shift[i];
                            var beta_s =
                                zk::components::generate_circuit<mul_component>(bp, assignment, {params.beta, s}, row)
                                    .output;
                            row += mul_component::rows_amount;
                            var beta_zeta_s = zk::components::generate_circuit<mul_component>(
                                                  bp, assignment, {params.zeta, beta_s}, row)
                                                  .output;
                            row += mul_component::rows_amount;
                            var gamma_beta_zeta_s = zk::components::generate_circuit<add_component>(
                                                        bp, assignment, {params.gamma, beta_zeta_s}, row)
                                                        .output;
                            row += add_component::rows_amount;
                            var w_gamma_beta_zeta_s = zk::components::generate_circuit<add_component>(
                                                          bp, assignment, {w, gamma_beta_zeta_s}, row)
                                                          .output;
                            row += add_component::rows_amount;

                            ft_eval0_sub = zk::components::generate_circuit<mul_component>(
                                               bp, assignment, {ft_eval0_sub, w_gamma_beta_zeta_s}, row)
                                               .output;
                            row += mul_component::rows_amount;
                        }
                        ft_eval0 = zk::components::generate_circuit<sub_component>(bp, assignment,
                                                                                   {ft_eval0, ft_eval0_sub}, row)
                                       .output;
                        row += sub_component::rows_amount;

                        // numerator calculation

                        var domain_offset_for_zk =
                            zk_w3_component::generate_circuit(bp,    // index.w()
                                                              assignment, {params.verifier_index}, row)
                                .output;
                        row += zk_w3_component::rows_amount;

                        // zeta - index.w()
                        var zeta_minus_w = zk::components::generate_circuit<sub_component>(
                                               bp, assignment, {params.zeta, domain_offset_for_zk}, row)
                                               .output;
                        row += sub_component::rows_amount;

                        // (zeta - ScalarField::<G>::one())
                        var zeta_minus_one =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {params.zeta, one}, row)
                                .output;
                        row += sub_component::rows_amount;

                        // (ScalarField::<G>::one() - evals[0].z)
                        var one_minus_z = zk::components::generate_circuit<sub_component>(
                                              bp, assignment, {one, params.combined_evals[0].z}, row)
                                              .output;
                        row += sub_component::rows_amount;

                        //     let numerator = ((zeta1m1 * alpha1 * (zeta - index.w()))
                        //         + (zeta1m1 * alpha2 * (zeta - ScalarField::<G>::one())))
                        //         * (ScalarField::<G>::one() - evals[0].z);
                        var numerator =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {zeta1m1, alpha1}, row)
                                .output;
                        row += mul_component::rows_amount;

                        numerator = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                    {numerator, zeta_minus_w}, row)
                                        .output;
                        row += mul_component::rows_amount;

                        var numerator_term =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {zeta1m1, alpha2}, row)
                                .output;
                        row += mul_component::rows_amount;
                        numerator_term = zk::components::generate_circuit<mul_component>(
                                             bp, assignment, {numerator_term, zeta_minus_one}, row)
                                             .output;
                        row += mul_component::rows_amount;

                        numerator = zk::components::generate_circuit<add_component>(bp, assignment,
                                                                                    {numerator, numerator_term}, row)
                                        .output;
                        row += add_component::rows_amount;

                        numerator = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                    {numerator, one_minus_z}, row)
                                        .output;
                        row += mul_component::rows_amount;

                        //     let denominator = (zeta - index.w()) * (zeta - ScalarField::<G>::one());
                        //     let denominator = denominator.inverse().expect("negligible probability");
                        var denominator = zk::components::generate_circuit<mul_component>(
                                              bp, assignment, {zeta_minus_w, zeta_minus_one}, row)
                                              .output;
                        row += mul_component::rows_amount;

                        denominator =
                            zk::components::generate_circuit<div_component>(bp, assignment, {one, denominator}, row)
                                .output;
                        row += div_component::rows_amount;

                        //     ft_eval0 += numerator * denominator;
                        var numerator_denominator = zk::components::generate_circuit<mul_component>(
                                                        bp, assignment, {numerator, denominator}, row)
                                                        .output;
                        row += mul_component::rows_amount;
                        ft_eval0 = zk::components::generate_circuit<add_component>(
                                       bp, assignment, {ft_eval0, numerator_denominator}, row)
                                       .output;
                        row += add_component::rows_amount;

                        // evaluate constant term expression
                        var pt = constant_term_component::generate_circuit(
                                     bp, assignment,
                                     {index_terms_list::constant_term_str, params.zeta, params.alpha_powers[1],
                                      params.beta, params.gamma, params.joint_combiner, params.combined_evals,
                                      params.verifier_index.omega, params.verifier_index.domain_size},
                                     row)
                                     .output;
                        row += constant_term_component::rows_amount;

                        ft_eval0 =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {ft_eval0, pt}, row).output;
                        row += sub_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        generate_assignments_constants(assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var zero(0, start_row_index, false, var::column_type::constant);
                        var one(0, start_row_index + 1, false, var::column_type::constant);

                        row += 2; // skip rows for constant in zkpm

                        // zkp = index.zkpm().evaluate(&zeta);
                        var zkp =
                            zkpm_eval_component::generate_assignments(
                                assignment,
                                {params.verifier_index.omega, params.verifier_index.domain_size, params.zeta}, row)
                                .output;
                        row += zkpm_eval_component::rows_amount;

                        // zeta1m1 = zeta_pow_n - ScalarField::<G>::one();
                        var zeta1m1 = sub_component::generate_assignments(
                            assignment, {params.zeta_pow_n, one}, row).output;
                        row += sub_component::rows_amount;

                        // get alpha0, alpha1, alpha2
                        std::pair<std::size_t, std::size_t> alpha_idxs =
                            index_terms_list::alpha_map(argument_type::Permutation);
                        assert(alpha_idxs.second >= 3);
                        var alpha0 = params.alpha_powers[alpha_idxs.first];
                        var alpha1 = params.alpha_powers[alpha_idxs.first + 1];
                        var alpha2 = params.alpha_powers[alpha_idxs.first + 2];

                        // let init = (evals[0].w[PERMUTS - 1] + gamma) * evals[1].z * alpha0 * zkp;
                        var init =
                            add_component::generate_assignments(
                                assignment,
                                {params.combined_evals[0].w[KimchiParamsType::permut_size - 1], params.gamma}, row)
                                .output;
                        row += add_component::rows_amount;
                        init  = mul_component::generate_assignments(
                            assignment, {init, params.combined_evals[1].z}, row).output;
                        row += mul_component::rows_amount;
                        init = mul_component::generate_assignments(assignment, {init, alpha0}, row).output;
                        row += mul_component::rows_amount;
                        init = mul_component::generate_assignments(assignment, {init, zkp}, row).output;
                        row += mul_component::rows_amount;

                        //     let mut ft_eval0 = evals[0]
                        //         .w
                        //         .iter()
                        //         .zip(evals[0].s.iter())
                        //         .map(|(w, s)| (beta * s) + w + gamma)
                        //         .fold(init, |x, y| x * y);
                        var ft_eval0 = init;
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                            var w = params.combined_evals[0].w[i];
                            var s = params.combined_evals[0].s[i];
                            var beta_s = mul_component::generate_assignments(assignment, {params.beta, s}, row).output;
                            row += mul_component::rows_amount;
                            var w_beta_s = add_component::generate_assignments(assignment, {w, beta_s}, row).output;
                            row += add_component::rows_amount;
                            var w_beta_s_gamma =
                                add_component::generate_assignments(assignment, {w_beta_s, params.gamma}, row).output;
                            row += add_component::rows_amount;
                            ft_eval0 =
                                mul_component::generate_assignments(assignment, {ft_eval0, w_beta_s_gamma}, row).output;
                            row += mul_component::rows_amount;
                        }

                        // ft_eval0 - p_eval[0]
                        if (KimchiParamsType::public_input_size > 0) {
                            var ft_eval0 = sub_component::generate_assignments(
                                assignment, {ft_eval0, params.public_eval[0]}, row).output;
                            row += sub_component::rows_amount;
                        }

                        //     ft_eval0 -= evals[0]
                        //         .w
                        //         .iter()
                        //         .zip(index.shift.iter())
                        //         .map(|(w, s)| gamma + (beta * zeta * s) + w)
                        //         .fold(alpha0 * zkp * evals[0].z, |x, y| x * y);
                        var ft_eval0_sub = mul_component::generate_assignments(assignment, {alpha0, zkp}, row).output;
                        row += mul_component::rows_amount;
                        ft_eval0_sub = mul_component::generate_assignments(
                                           assignment, {ft_eval0_sub, params.combined_evals[0].z}, row)
                                           .output;
                        row += mul_component::rows_amount;

                        for (std::size_t i = 0; i < KimchiParamsType::permut_size; i++) {
                            var w = params.combined_evals[0].w[i];
                            var s = params.verifier_index.shift[i];
                            var beta_s = mul_component::generate_assignments(assignment, {params.beta, s}, row).output;
                            row += mul_component::rows_amount;
                            var beta_zeta_s =
                                mul_component::generate_assignments(assignment, {params.zeta, beta_s}, row).output;
                            row += mul_component::rows_amount;
                            var gamma_beta_zeta_s =
                                add_component::generate_assignments(assignment, {params.gamma, beta_zeta_s}, row)
                                    .output;
                            row += add_component::rows_amount;
                            var w_gamma_beta_zeta_s =
                                add_component::generate_assignments(assignment, {w, gamma_beta_zeta_s}, row).output;
                            row += add_component::rows_amount;

                            ft_eval0_sub = mul_component::generate_assignments(assignment,
                                                                               {ft_eval0_sub, w_gamma_beta_zeta_s}, row)
                                               .output;
                            row += mul_component::rows_amount;
                        }
                        ft_eval0 =
                            sub_component::generate_assignments(assignment, {ft_eval0, ft_eval0_sub}, row).output;
                        row += sub_component::rows_amount;

                        // numerator calculation

                        var domain_offset_for_zk = zk_w3_component::generate_assignments(    // index.w()
                                                       assignment, {params.verifier_index}, row)
                                                       .output;
                        row += zk_w3_component::rows_amount;

                        // zeta - index.w()
                        var zeta_minus_w =
                            sub_component::generate_assignments(assignment, {params.zeta, domain_offset_for_zk}, row)
                                .output;
                        row += sub_component::rows_amount;

                        // (zeta - ScalarField::<G>::one())
                        var zeta_minus_one =
                            sub_component::generate_assignments(assignment, {params.zeta, one}, row).output;
                        row += sub_component::rows_amount;

                        // (ScalarField::<G>::one() - evals[0].z)
                        var one_minus_z =
                            sub_component::generate_assignments(assignment, {one, params.combined_evals[0].z}, row)
                                .output;
                        row += sub_component::rows_amount;

                        //     let numerator = ((zeta1m1 * alpha1 * (zeta - index.w()))
                        //         + (zeta1m1 * alpha2 * (zeta - ScalarField::<G>::one())))
                        //         * (ScalarField::<G>::one() - evals[0].z);
                        var numerator = mul_component::generate_assignments(assignment, {zeta1m1, alpha1}, row).output;
                        row += mul_component::rows_amount;

                        numerator =
                            mul_component::generate_assignments(assignment, {numerator, zeta_minus_w}, row).output;
                        row += mul_component::rows_amount;

                        var numerator_term =
                            mul_component::generate_assignments(assignment, {zeta1m1, alpha2}, row).output;
                        row += mul_component::rows_amount;
                        numerator_term =
                            mul_component::generate_assignments(assignment, {numerator_term, zeta_minus_one}, row)
                                .output;
                        row += mul_component::rows_amount;

                        numerator =
                            add_component::generate_assignments(assignment, {numerator, numerator_term}, row).output;
                        row += add_component::rows_amount;

                        numerator =
                            mul_component::generate_assignments(assignment, {numerator, one_minus_z}, row).output;
                        row += mul_component::rows_amount;

                        //     let denominator = (zeta - index.w()) * (zeta - ScalarField::<G>::one());
                        //     let denominator = denominator.inverse().expect("negligible probability");
                        var denominator =
                            mul_component::generate_assignments(assignment, {zeta_minus_w, zeta_minus_one}, row).output;
                        row += mul_component::rows_amount;

                        denominator = div_component::generate_assignments(assignment, {one, denominator}, row).output;
                        row += div_component::rows_amount;

                        //     ft_eval0 += numerator * denominator;
                        var numerator_denominator =
                            mul_component::generate_assignments(assignment, {numerator, denominator}, row).output;
                        row += mul_component::rows_amount;
                        ft_eval0 =
                            add_component::generate_assignments(assignment, {ft_eval0, numerator_denominator}, row)
                                .output;
                        row += add_component::rows_amount;

                        // evaluate constant term expression
                        var pt = constant_term_component::generate_assignments(
                                     assignment,
                                     {index_terms_list::constant_term_str, params.zeta, params.alpha_powers[1],
                                      params.beta, params.gamma, params.joint_combiner, params.combined_evals,
                                      params.verifier_index.omega, params.verifier_index.domain_size},
                                     row)
                                     .output;
                        row += constant_term_component::rows_amount;

                        ft_eval0 = sub_component::generate_assignments(assignment, {ft_eval0, pt}, row).output;
                        row += sub_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                    }

                    static void generate_assignments_constants(
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_FT_EVAL_HPP
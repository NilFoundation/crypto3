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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_FT_EVAL_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_FT_EVAL_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/zkpm_evaluate.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/zk_w3.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // ft polynomial at zeta
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L320-L384
                // Input:
                // Output: ft(zeta)
                template<typename ArithmetizationType,
                    typename CurveType,
                    typename KimchiParamsType,
                    std::size_t... WireIndexes>
                class ft_eval;

                template<typename BlueprintFieldType, 
                         typename ArithmetizationParams,
                         typename CurveType,
                         typename KimchiParamsType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class ft_eval<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    KimchiParamsType,
                    W0,
                    W1,
                    W2,
                    W3,
                    W4,
                    W5,
                    W6,
                    W7,
                    W8,
                    W9,
                    W10,
                    W11,
                    W12,
                    W13,
                    W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;

                    using zkpm_eval_component = zk::components::zkpm_evaluate<ArithmetizationType, 
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using zk_w3_component = zk::components::zk_w3<ArithmetizationType, 
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using verifier_index_type = kimchi_verifier_index_scalar<BlueprintFieldType>;
                    using argument_type = typename verifier_index_type::argument_type;

                    constexpr static const std::size_t selector_seed = 0x0f22;
                    constexpr static const std::size_t eval_points_amount = 2;

                public:
                    constexpr static const std::size_t rows_amount = mul_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        verifier_index_type &verifier_index;
                        var zeta_pow_n;
                        std::array<var, KimchiParamsType::alpha_powers_n> alpha_powers;
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, eval_points_amount> combined_evals;
                        var gamma;
                        var beta;
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, eval_points_amount> evals;
                        var zeta;
                        var joint_combiner;
                        std::array<std::optional<var>, eval_points_amount> public_eval;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            output = typename mul_component::result_type(row).output;
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        zk::components::generate_circuit<mul_component>(bp, assignment, 
                            {params.zeta_pow_n, params.gamma}, row);
                        row += mul_component::rows_amount;


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

                        // zkp = index.zkpm().evaluate(&zeta);
                        var zkp = zkpm_eval_component::generate_assignments(
                            assignment, {params.verifier_index.omega, 
                            params.verifier_index.domain_size, params.zeta},
                            row).output;
                        row += zkpm_eval_component::rows_amount;

                        // zeta1m1 = zeta1 - ScalarField::<G>::one();
                        var zeta1m1 = sub_component::generate_assignments(
                            assignment, {params.zeta, one}, row).output;
                        row += sub_component::rows_amount;

                        // get alpha0, alpha1, alpha2
                        std::pair<std::size_t, std::size_t> alpha_idxs = 
                            params.verifier_index.alpha_map[argument_type::Permutation];
                        assert(alpha_idxs.second >= alpha_idxs.first + 3);
                        var alpha0 = params.alpha_powers[alpha_idxs.first];
                        var alpha1 = params.alpha_powers[alpha_idxs.first + 1];
                        var alpha2 = params.alpha_powers[alpha_idxs.first + 2];

                        // let init = (evals[0].w[PERMUTS - 1] + gamma) * evals[1].z * alpha0 * zkp;
                        var init = add_component::generate_assignments(
                            assignment, {
                            params.combined_evals[0].w[KimchiParamsType::permut_size - 1], 
                            params.gamma}, row).output;
                        row += add_component::rows_amount;
                        init  = mul_component::generate_assignments(
                            assignment, {init, params.combined_evals[0].z}, row).output;
                        row += mul_component::rows_amount;
                        init = mul_component::generate_assignments(
                            assignment, {init, alpha0}, row).output;
                        row += mul_component::rows_amount;
                        init = mul_component::generate_assignments(
                            assignment, {init, zkp}, row).output;
                        row += mul_component::rows_amount;

                        //     let mut ft_eval0 = evals[0]
                        //         .w
                        //         .iter()
                        //         .zip(evals[0].s.iter())
                        //         .map(|(w, s)| (beta * s) + w + gamma)
                        //         .fold(init, |x, y| x * y);
                        var ft_eval0 = zero;
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size; i++) {
                            var w = params.combined_evals[0].w[i];
                            var s = params.combined_evals[0].s[i];
                            var beta_s = mul_component::generate_assignments(
                                assignment, {params.beta, s}, row).output;
                            row += mul_component::rows_amount;
                            var w_beta_s = add_component::generate_assignments(
                                assignment, {w, beta_s}, row).output;
                            row += add_component::rows_amount;
                            var w_beta_s_gamma = add_component::generate_assignments(
                                assignment, {w_beta_s, params.gamma}, row).output;
                            row += add_component::rows_amount;
                            ft_eval0 = mul_component::generate_assignments(
                                assignment, {ft_eval0, w_beta_s_gamma}, row).output;
                            row += mul_component::rows_amount;
                        }

                        // ft_eval0 - p_eval[0]
                        if (params.public_eval[0].has_value()) {
                            var ft_eval0 = sub_component::generate_assignments(
                                assignment, {ft_eval0, params.public_eval[0].value()}, row).output;
                            row += sub_component::rows_amount;
                        }

                        //     ft_eval0 -= evals[0]
                        //         .w
                        //         .iter()
                        //         .zip(index.shift.iter())
                        //         .map(|(w, s)| gamma + (beta * zeta * s) + w)
                        //         .fold(alpha0 * zkp * evals[0].z, |x, y| x * y);
                        var ft_eval0_sub = mul_component::generate_assignments(
                            assignment, {alpha0, zkp}, row).output;
                        row += mul_component::rows_amount;
                        ft_eval0_sub = mul_component::generate_assignments(
                            assignment, {ft_eval0_sub, params.combined_evals[0].z}, row).output;
                        row += mul_component::rows_amount;

                        for (std::size_t i = 0; i < KimchiParamsType::permut_size; i++) {
                            var w = params.combined_evals[0].w[i];
                            var s = params.verifier_index.shift[i];
                            var beta_s = mul_component::generate_assignments(
                                assignment, {params.beta, s}, row).output;
                            row += mul_component::rows_amount;
                            var beta_zeta_s = mul_component::generate_assignments(
                                assignment, {params.zeta, beta_s}, row).output;
                            row += mul_component::rows_amount;
                            var gamma_beta_zeta_s = add_component::generate_assignments(
                                assignment, {params.gamma, beta_zeta_s}, row).output;
                            row += add_component::rows_amount;
                            var w_gamma_beta_zeta_s = add_component::generate_assignments(
                                assignment, {w, gamma_beta_zeta_s}, row).output;
                            row += add_component::rows_amount;

                            ft_eval0_sub = mul_component::generate_assignments(
                                assignment, {ft_eval0_sub, w_gamma_beta_zeta_s}, row).output;
                            row += mul_component::rows_amount;
                        }
                        ft_eval0 = sub_component::generate_assignments(
                            assignment, {ft_eval0, ft_eval0_sub}, row).output;
                        row += sub_component::rows_amount;
                        
                        //     let numerator = ((zeta1m1 * alpha1 * (zeta - index.w()))
                        //         + (zeta1m1 * alpha2 * (zeta - ScalarField::<G>::one())))
                        //         * (ScalarField::<G>::one() - evals[0].z);
                        var numerator = mul_component::generate_assignments(
                            assignment, {zeta1m1, alpha1}, row).output;
                        row += mul_component::rows_amount;

                        var domain_offset_for_zk = zk_w3_component::generate_assignments( // index.w()
                            assignment, {params.verifier_index}, row).output;
                        row += zk_w3_component::rows_amount;
                        //     let denominator = (zeta - index.w()) * (zeta - ScalarField::<G>::one());
                        //     let denominator = denominator.inverse().expect("negligible probability");

                        //     ft_eval0 += numerator * denominator;
                        //     let cs = Constants {
                        //         alpha,
                        //         beta,
                        //         gamma,
                        //         joint_combiner: joint_combiner.map(|j| j.1),
                        //         endo_coefficient: index.endo,
                        //         mds: index.fr_sponge_params.mds.clone(),
                        //     };

                        //     let pt = PolishToken::evaluate(
                        //         &index.linearization.constant_term,
                        //         index.domain,
                        //         zeta,
                        //         &evals,
                        //         &cs,
                        //     )
                        //         .unwrap();
                        //     ft_eval0 -= pt;
                        //     ft_eval0
                        // };

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
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
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_FT_EVAL_HPP
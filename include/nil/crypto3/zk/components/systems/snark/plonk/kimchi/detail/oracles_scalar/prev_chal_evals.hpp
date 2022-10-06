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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_PREV_CHAL_EVALS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_PREV_CHAL_EVALS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly_coefficients.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // evaluate univariate polynomial at points
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L67
                // Input: prev_challenges, zeta, zeta * omega, zeta^n, (zeta * omega)^n,
                // Output: (1 + prev_challenges[-1] x)(1 + prev_challenges[-2] x^2)(1 + prev_challenges[-3] x^4)...
                template<typename ArithmetizationType, typename KimchiCommitmentParamsType, std::size_t... WireIndexes>
                class prev_chal_evals;

                template<typename BlueprintFieldType, typename ArithmetizationParams,
                         typename KimchiCommitmentParamsType, std::size_t W0, std::size_t W1, std::size_t W2,
                         std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8,
                         std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13,
                         std::size_t W14>
                class prev_chal_evals<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                      KimchiCommitmentParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12,
                                      W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;

                    using b_poly_component =
                        zk::components::b_poly<ArithmetizationType, KimchiCommitmentParamsType::eval_rounds, W0, W1, W2,
                                               W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using b_poly_coeff_component =
                        zk::components::b_poly_coefficients<ArithmetizationType,
                                                            KimchiCommitmentParamsType::eval_rounds, W0, W1, W2, W3, W4,
                                                            W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t selector_seed = 0x0f0f;
                    constexpr static const std::size_t eval_points_amount = 2;
                    constexpr static const std::size_t eval_rounds = KimchiCommitmentParamsType::eval_rounds;
                    constexpr static const std::size_t split_poly_eval_size =
                        KimchiCommitmentParamsType::split_poly_eval_size;
                    constexpr static const std::size_t max_poly_size = KimchiCommitmentParamsType::max_poly_size;
                    constexpr static const std::size_t b_len = 1 << eval_rounds;

                public:
                    constexpr static const std::size_t rows_amount =
                        split_poly_eval_size == 1 ?
                            eval_points_amount * b_poly_component::rows_amount :
                            b_poly_coeff_component::rows_amount +
                                eval_points_amount * (b_poly_component::rows_amount +
                                                      (b_len - max_poly_size) *
                                                          (mul_component::rows_amount + mul_component::rows_amount +
                                                           add_component::rows_amount) +
                                                      mul_component::rows_amount + sub_component::rows_amount);
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<var, eval_rounds> &prev_challenges;
                        std::array<var, 2> eval_points;
                        std::array<var, 2> powers_of_eval_points_for_chunks;
                        var one;
                        var zero;
                    };

                    struct result_type {
                        std::array<std::array<var, split_poly_eval_size>, eval_points_amount> output;

                        result_type(std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            for (std::size_t i = 0; i < eval_points_amount; i++) {
                                var full = typename b_poly_component::result_type(row).output;
                                row += b_poly_component::rows_amount;
                                if (split_poly_eval_size == 1) {
                                    output[i][0] = full;
                                    continue;
                                }

                                var diff;
                                for (std::size_t j = max_poly_size; j < b_len; j++) {
                                    if (i == 0 && j == max_poly_size) {
                                        row += b_poly_coeff_component::rows_amount;
                                    }
                                    row += mul_component::rows_amount;
                                    row += mul_component::rows_amount;

                                    diff = typename add_component::result_type(row).output;
                                    row += add_component::rows_amount;
                                }

                                row += mul_component::rows_amount;
                                var res_0 = typename sub_component::result_type(row).output;
                                row += sub_component::rows_amount;
                                output[i][0] = res_0;
                                output[i][1] = diff;
                            }
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::array<var, b_len> b;
                        std::array<std::array<var, split_poly_eval_size>, eval_points_amount> res;
                        for (std::size_t i = 0; i < eval_points_amount; i++) {
                            var full =
                                b_poly_component::generate_circuit(
                                    bp, assignment, {params.prev_challenges, params.eval_points[i], params.one}, row)
                                    .output;
                            row += b_poly_component::rows_amount;
                            if (split_poly_eval_size == 1) {
                                res[i][0] = full;
                                continue;
                            }

                            var betaacc = params.one;
                            var diff = params.zero;
                            for (std::size_t j = max_poly_size; j < b_len; j++) {
                                if (i == 0 && j == max_poly_size) {
                                    b = b_poly_coeff_component::generate_circuit(
                                            bp, assignment, {params.prev_challenges, params.one}, row)
                                            .output;
                                    row += b_poly_coeff_component::rows_amount;
                                }
                                var b_j = b[j];
                                var ret =
                                    zk::components::generate_circuit<mul_component>(bp, assignment, {betaacc, b_j}, row)
                                        .output;
                                row += mul_component::rows_amount;

                                betaacc = zk::components::generate_circuit<mul_component>(
                                              bp, assignment, {betaacc, params.eval_points[i]}, row)
                                              .output;
                                row += mul_component::rows_amount;

                                diff = zk::components::generate_circuit<add_component>(bp, assignment, {diff, ret}, row)
                                           .output;
                                row += add_component::rows_amount;
                            }

                            // [full - (diff * powers_of_eval_points_for_chunks[i]), diff]
                            var res_0 = zk::components::generate_circuit<mul_component>(
                                            bp, assignment, {diff, params.powers_of_eval_points_for_chunks[i]}, row)
                                            .output;
                            row += mul_component::rows_amount;
                            res_0 = zk::components::generate_circuit<sub_component>(bp, assignment, {full, res_0}, row)
                                        .output;
                            row += sub_component::rows_amount;
                            res[i][0] = res_0;
                            res[i][1] = diff;
                        }

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::array<var, b_len> b;
                        std::array<std::array<var, split_poly_eval_size>, eval_points_amount> res;
                        for (std::size_t i = 0; i < eval_points_amount; i++) {
                            var full = b_poly_component::generate_assignments(
                                           assignment, {params.prev_challenges, params.eval_points[i], params.one}, row)
                                           .output;
                            row += b_poly_component::rows_amount;
                            if (split_poly_eval_size == 1) {
                                res[i][0] = full;
                                continue;
                            }

                            var betaacc = params.one;
                            var diff = params.zero;
                            for (std::size_t j = max_poly_size; j < b_len; j++) {
                                if (i == 0 && j == max_poly_size) {
                                    b = b_poly_coeff_component::generate_assignments(
                                            assignment, {params.prev_challenges, params.one}, row)
                                            .output;
                                    row += b_poly_coeff_component::rows_amount;
                                }
                                var b_j = b[j];
                                var ret = mul_component::generate_assignments(assignment, {betaacc, b_j}, row).output;
                                row += mul_component::rows_amount;

                                betaacc = mul_component::generate_assignments(assignment,
                                                                              {betaacc, params.eval_points[i]}, row)
                                              .output;
                                row += mul_component::rows_amount;

                                diff = add_component::generate_assignments(assignment, {diff, ret}, row).output;
                                row += add_component::rows_amount;
                            }

                            // [full - (diff * powers_of_eval_points_for_chunks[i]), diff]
                            var res_0 = mul_component::generate_assignments(
                                            assignment, {diff, params.powers_of_eval_points_for_chunks[i]}, row)
                                            .output;
                            row += mul_component::rows_amount;
                            res_0 = sub_component::generate_assignments(assignment, {full, res_0}, row).output;
                            row += sub_component::rows_amount;
                            res[i][0] = res_0;
                            res[i][1] = diff;
                        }

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
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_PREV_CHAL_EVALS_HPP
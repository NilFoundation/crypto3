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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_B_POLY_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_B_POLY_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // Univariate polynomial at point
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/poly-commitment/src/commitment.rs#L239
                // Input: challenges, x
                // Output: (1 + challenges[-1] x)(1 + challenges[-2] x^2)(1 + challenges[-3] x^4)...
                template<typename ArithmetizationType, std::size_t EvalRounds, std::size_t... WireIndexes>
                class b_poly;

                template<typename BlueprintFieldType, std::size_t EvalRounds,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class b_poly<snark::plonk_constraint_system<BlueprintFieldType>, EvalRounds, W0,
                             W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0xf20;

                public:
                    constexpr static const std::size_t rows_amount = (EvalRounds - 1) * mul_component::rows_amount
                        + EvalRounds * (
                            mul_component::rows_amount + add_component::rows_amount + mul_component::rows_amount
                        );
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<var, EvalRounds> &challenges;
                        var eval_point;
                        var one;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index;

                            for (std::size_t i = 1; i < EvalRounds; i++) {
                                row += mul_component::rows_amount;
                            }
                            var res;
                            for (std::size_t i = 0; i < EvalRounds; i++) {
                                row += mul_component::rows_amount;

                                row += add_component::rows_amount;

                                res = typename mul_component::result_type(row).output;
                                row += mul_component::rows_amount;
                            }

                            output = res;
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::array<var, EvalRounds> pow_twos;
                        pow_twos[0] = params.eval_point;
                        for (std::size_t i = 1; i < EvalRounds; i++) {
                            pow_twos[i] = zk::components::generate_circuit<mul_component>(
                                              bp, assignment, {pow_twos[i - 1], pow_twos[i - 1]}, row)
                                              .output;
                            row += mul_component::rows_amount;
                        }
                        var res = params.one;
                        for (std::size_t i = 0; i < EvalRounds; i++) {
                            var mul_result =
                                zk::components::generate_circuit<mul_component>(
                                    bp, assignment, {params.challenges[i], pow_twos[EvalRounds - 1 - i]}, row)
                                    .output;
                            row += mul_component::rows_amount;

                            var sum_result = zk::components::generate_circuit<add_component>(
                                                 bp, assignment, {params.one, mul_result}, row)
                                                 .output;
                            row += add_component::rows_amount;

                            res =
                                zk::components::generate_circuit<mul_component>(bp, assignment, {res, sum_result}, row)
                                    .output;
                            row += mul_component::rows_amount;
                        }

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::array<var, EvalRounds> pow_twos;
                        pow_twos[0] = params.eval_point;
                        for (std::size_t i = 1; i < EvalRounds; i++) {
                            pow_twos[i] =
                                mul_component::generate_assignments(assignment, {pow_twos[i - 1], pow_twos[i - 1]}, row)
                                    .output;
                            row += mul_component::rows_amount;
                        }
                        var res = params.one;
                        for (std::size_t i = 0; i < EvalRounds; i++) {
                            var mul_result = mul_component::generate_assignments(
                                                 assignment, {params.challenges[i], pow_twos[EvalRounds - 1 - i]}, row)
                                                 .output;
                            row += mul_component::rows_amount;

                            var sum_result =
                                add_component::generate_assignments(assignment, {params.one, mul_result}, row).output;
                            row += add_component::rows_amount;

                            res = mul_component::generate_assignments(assignment, {res, sum_result}, row).output;
                            row += mul_component::rows_amount;
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
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_B_POLY_HPP
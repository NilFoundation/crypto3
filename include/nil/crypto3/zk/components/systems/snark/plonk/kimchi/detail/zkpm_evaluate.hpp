//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ZKPM_EVALUATE_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ZKPM_EVALUATE_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
                // zk-polynomial evaluation
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/circuits/polynomials/permutation.rs#L91
                // Input: group generator (w),
                //        domain size (n),
                //        evaluation point (x)
                // Output: (x - w^{n - 3}) * (x - w^{n - 2}) * (x - w^{n - 1})
                template<typename ArithmetizationType, std::size_t... WireIndexes>
                class zkpm_evaluate;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11,
                         std::size_t W12, std::size_t W13, std::size_t W14>
                class zkpm_evaluate<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using exp_component = zk::components::exponentiation<ArithmetizationType, 60, W0, W1,
                                                                         W2, W3, W4, W5, W6, W7, W8, W9,
                                                                         W10, W11, W12, W13, W14>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0f25;

                    constexpr static const std::size_t zk_rows = 3;

                public:
                    constexpr static const std::size_t rows_amount = 1 + exp_component::rows_amount +
                                                                     4 * mul_component::rows_amount +
                                                                     3 * sub_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var group_gen;
                        std::size_t domain_size;
                        var x;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index;
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constants(bp, assignment, params, start_row_index);

                        var domain_size = var(0, start_row_index, false, var::column_type::constant);

                        std::size_t row = start_row_index;
                        row++;    // skip row for constants in exp_component

                        result_type result(row);

                        var w1 = exp_component::generate_circuit(bp, assignment, {params.group_gen, domain_size}, row)
                                     .output;
                        row += exp_component::rows_amount;
                        var w2 =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {w1, params.group_gen}, row)
                                .output;
                        row += mul_component::rows_amount;
                        var w3 =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {w2, params.group_gen}, row)
                                .output;
                        row += mul_component::rows_amount;

                        var a1 =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {params.x, w1}, row).output;
                        row += sub_component::rows_amount;
                        var a2 =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {params.x, w2}, row).output;
                        row += sub_component::rows_amount;
                        var a3 =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {params.x, w3}, row).output;
                        row += sub_component::rows_amount;

                        var ans1 =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {a1, a2}, row).output;
                        row += mul_component::rows_amount;
                        result.output =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {ans1, a3}, row).output;
                        row += mul_component::rows_amount;

                        return result;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        var domain_size = var(0, start_row_index, false, var::column_type::constant);

                        std::size_t row = start_row_index;
                        row++;    // skip row for constants in exp_component

                        result_type result(row);

                        var w1 = exp_component::generate_assignments(assignment, {params.group_gen, domain_size}, row)
                                     .output;
                        row += exp_component::rows_amount;
                        var w2 = mul_component::generate_assignments(assignment, {w1, params.group_gen}, row).output;
                        row += mul_component::rows_amount;
                        var w3 = mul_component::generate_assignments(assignment, {w2, params.group_gen}, row).output;
                        row += mul_component::rows_amount;

                        var a1 = sub_component::generate_assignments(assignment, {params.x, w1}, row).output;
                        row += sub_component::rows_amount;
                        var a2 = sub_component::generate_assignments(assignment, {params.x, w2}, row).output;
                        row += sub_component::rows_amount;
                        var a3 = sub_component::generate_assignments(assignment, {params.x, w3}, row).output;
                        row += sub_component::rows_amount;

                        var ans1 = mul_component::generate_assignments(assignment, {a1, a2}, row).output;
                        row += mul_component::rows_amount;
                        result.output = mul_component::generate_assignments(assignment, {ans1, a3}, row).output;
                        row += mul_component::rows_amount;

                        return result;
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
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = params.domain_size - zk_rows;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ZKPM_EVALUATE_HPP

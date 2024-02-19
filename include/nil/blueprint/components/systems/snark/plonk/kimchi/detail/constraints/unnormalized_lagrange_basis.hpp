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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_CONSTRAINTS_UNNORMALIZED_LAGRANGE_BASIS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_CONSTRAINTS_UNNORMALIZED_LAGRANGE_BASIS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // Compute the ith unnormalized lagrange basis
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/circuits/expr.rs#L150
                // Input: group generator (w),
                //        i,
                //        domain_size,
                //        evaluation point (x)
                // Output: (x^domain_size - 1) / (x - w^i)
                template<typename ArithmetizationType, std::size_t... WireIndexes>
                class unnormalized_lagrange_basis;

                template<typename BlueprintFieldType, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                         std::size_t W13, std::size_t W14>
                class unnormalized_lagrange_basis<
                    snark::plonk_constraint_system<BlueprintFieldType>, W0, W1, W2, W3, W4, W5,
                    W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using exp_component = zk::components::exponentiation<ArithmetizationType, 64, W0, W1, W2, W3, W4,
                                                                         W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using div_component = zk::components::division<ArithmetizationType, W0, W1, W2, W3>;

                    constexpr static const std::size_t selector_seed = 0x0f25;

                    constexpr static const std::size_t zk_rows = 3;

                public:
                    constexpr static const std::size_t rows_amount = 3 + 2 * exp_component::rows_amount +
                                                                     2 * sub_component::rows_amount +
                                                                     div_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var group_gen;
                        std::size_t domain_size;
                        var x;
                        int i;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index + rows_amount - div_component::rows_amount;
                            output = typename div_component::result_type(row).output;
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constants(bp, assignment, params, start_row_index);

                        var domain_size(0, start_row_index, false, var::column_type::constant);
                        var basis_element(0, start_row_index + 1, false, var::column_type::constant);
                        var one(0, start_row_index + 2, false, var::column_type::constant);

                        std::size_t row = start_row_index;
                        row += 3;    // skip row for constants in exp_component

                        var denominator =
                            exp_component::generate_circuit(bp, assignment, {params.group_gen, basis_element}, row)
                                .output;
                        row += exp_component::rows_amount;

                        denominator = zk::components::generate_circuit<sub_component>(bp, assignment,
                                                                                      {params.x, denominator}, row)
                                          .output;
                        row += sub_component::rows_amount;

                        var numerator =
                            exp_component::generate_circuit(bp, assignment, {params.x, domain_size}, row).output;
                        row += exp_component::rows_amount;
                        numerator =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {numerator, one}, row)
                                .output;
                        row += sub_component::rows_amount;

                        var res = zk::components::generate_circuit<div_component>(bp, assignment,
                                                                                  {numerator, denominator}, row)
                                      .output;
                        row += div_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        var domain_size(0, start_row_index, false, var::column_type::constant);
                        var basis_element(0, start_row_index + 1, false, var::column_type::constant);
                        var one(0, start_row_index + 2, false, var::column_type::constant);

                        std::size_t row = start_row_index;
                        row += 3;    // skip row for constants in exp_component

                        var denominator =
                            exp_component::generate_assignments(assignment, {params.group_gen, basis_element}, row)
                                .output;
                        row += exp_component::rows_amount;

                        denominator =
                            sub_component::generate_assignments(assignment, {params.x, denominator}, row).output;
                        row += sub_component::rows_amount;

                        var numerator =
                            exp_component::generate_assignments(assignment, {params.x, domain_size}, row).output;
                        row += exp_component::rows_amount;
                        numerator = sub_component::generate_assignments(assignment, {numerator, one}, row).output;
                        row += sub_component::rows_amount;

                        var res = div_component::generate_assignments(assignment, {numerator, denominator}, row).output;
                        row += div_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_assignments_constants(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = params.domain_size;
                        row++;
                        assignment.constant(0)[row] =
                            params.i >= 0 ? params.i : params.domain_size - std::size_t(-params.i);
                        row++;
                        assignment.constant(0)[row] = 1;
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_CONSTRAINTS_UNNORMALIZED_LAGRANGE_BASIS_HPP

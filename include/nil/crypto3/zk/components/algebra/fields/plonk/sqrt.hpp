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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_ALGEBRA_FIELDS_SQRT_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_ALGEBRA_FIELDS_SQRT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // square root
                // Input: y
                // Output: x such that x * x = y
                template<typename ArithmetizationType, std::size_t... WireIndexes>
                class sqrt;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                         std::size_t W13, std::size_t W14>
                class sqrt<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, W0, W1, W2, W3,
                           W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using exp_component = zk::components::exponentiation<ArithmetizationType, 256, W0, W1, W2, W3, W4,
                                                                         W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t selector_seed = 0x0ffa;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        row += 3;

                        row += exp_component::rows_amount;

                        row += mul_component::rows_amount;

                        // qr_check * (1 + qr_check) * (y - x_squared) = 0 for y \in QR(q)
                        row += add_component::rows_amount;
                        row += sub_component::rows_amount;
                        row += mul_component::rows_amount;
                        row += mul_component::rows_amount;

                        // qr_check * (1 - qr_check) * (1 + x_squared) = 0 for y \in QNR(q)
                        row += sub_component::rows_amount;
                        row += add_component::rows_amount;
                        row += mul_component::rows_amount;
                        row += mul_component::rows_amount;

                        // (1 - qr_check) * (1 + qr_check) * x_squared = 0 for y = 0
                        row += mul_component::rows_amount;
                        row += mul_component::rows_amount;

                        row += add_component::rows_amount;
                        row += add_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var y;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t component_start_row) {
                            output = var(W0, component_start_row + 3 + exp_component::rows_amount);
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        var exp(0, start_row_index, false, var::column_type::constant);
                        var zero(0, start_row_index + 1, false, var::column_type::constant);
                        var one(0, start_row_index + 2, false, var::column_type::constant);

                        row += 3;

                        // check if y \in QR(q)
                        // qr_check = 1 if y \in QR(q), -1 if y \in QNR(q), 0 if y = 0
                        var qr_check = exp_component::generate_circuit(bp, assignment, {params.y, exp}, row).output;
                        row += exp_component::rows_amount;

                        // x = sqrt(y) if y \in QR(q) or y = 0, -1 otherwise
                        var x(W0, row, false);
                        var x_squared =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {x, x}, row).output;
                        row += mul_component::rows_amount;

                        // qr_check * (1 + qr_check) * (y - x_squared) = 0 for y \in QR(q)
                        var one_plus_qr_check =
                            zk::components::generate_circuit<add_component>(bp, assignment, {qr_check, one}, row)
                                .output;
                        row += add_component::rows_amount;

                        var y_minus_x_squared =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {params.y, x_squared}, row)
                                .output;
                        row += sub_component::rows_amount;

                        var in_qr = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                    {qr_check, one_plus_qr_check}, row)
                                        .output;
                        row += mul_component::rows_amount;
                        in_qr = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                {in_qr, y_minus_x_squared}, row)
                                    .output;
                        row += mul_component::rows_amount;

                        // qr_check * (1 - qr_check) * (1 + x_squared) = 0 for y \in QNR(q)
                        var one_minus_qr_check =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {one, qr_check}, row)
                                .output;
                        row += sub_component::rows_amount;
                        var x_plus_one =
                            zk::components::generate_circuit<add_component>(bp, assignment, {x, one}, row).output;
                        row += add_component::rows_amount;

                        var in_qnr = zk::components::generate_circuit<mul_component>(
                                         bp, assignment, {qr_check, one_minus_qr_check}, row)
                                         .output;
                        row += mul_component::rows_amount;
                        in_qnr =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {in_qnr, x_plus_one}, row)
                                .output;
                        row += mul_component::rows_amount;
                        // (1 - qr_check) * (1 + qr_check) * x_squared = 0 for y = 0

                        var y_eq_zero = zk::components::generate_circuit<mul_component>(
                                            bp, assignment, {one_minus_qr_check, one_plus_qr_check}, row)
                                            .output;
                        row += mul_component::rows_amount;
                        y_eq_zero =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {y_eq_zero, x_squared}, row)
                                .output;
                        row += mul_component::rows_amount;

                        var last_check =
                            zk::components::generate_circuit<add_component>(bp, assignment, {in_qr, in_qnr}, row)
                                .output;
                        row += add_component::rows_amount;
                        last_check = zk::components::generate_circuit<add_component>(bp, assignment,
                                                                                     {last_check, y_eq_zero}, row)
                                         .output;
                        row += add_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        // copy-constarint for last_check and zero

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        generate_assignments_constants(assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var exp(0, start_row_index, false, var::column_type::constant);
                        var zero(0, start_row_index + 1, false, var::column_type::constant);
                        var one(0, start_row_index + 2, false, var::column_type::constant);

                        row += 3;

                        // check if y \in QR(q)
                        // qr_check = 1 if y \in QR(q), -1 if y \in QNR(q), 0 if y = 0
                        var qr_check = exp_component::generate_assignments(assignment, {params.y, exp}, row).output;
                        row += exp_component::rows_amount;
                        // x = sqrt(y) if y \in QR(q) or y = 0, -1 otherwise
                        typename BlueprintFieldType::value_type qr_check_value = assignment.var_value(qr_check).data;
                        if (qr_check_value == BlueprintFieldType::value_type::zero() ||
                            qr_check_value == BlueprintFieldType::value_type::one()) {
                            typename BlueprintFieldType::value_type x_val = assignment.var_value(params.y).sqrt();
                            assignment.witness(0)[row] = x_val;
                        } else if (qr_check_value == -BlueprintFieldType::value_type::one()) {
                            assignment.witness(0)[row] = -1;
                        } else {
                            assert(false);
                        }
                        var x(0, row, false);
                        var x_squared = mul_component::generate_assignments(assignment, {x, x}, row).output;
                        row += mul_component::rows_amount;

                        // qr_check * (1 + qr_check) * (y - x_squared) = 0 for y \in QR(q)
                        var one_plus_qr_check =
                            add_component::generate_assignments(assignment, {qr_check, one}, row).output;
                        row += add_component::rows_amount;

                        var y_minus_x_squared =
                            sub_component::generate_assignments(assignment, {params.y, x_squared}, row).output;
                        row += sub_component::rows_amount;

                        var in_qr =
                            mul_component::generate_assignments(assignment, {qr_check, one_plus_qr_check}, row).output;
                        row += mul_component::rows_amount;
                        in_qr = mul_component::generate_assignments(assignment, {in_qr, y_minus_x_squared}, row).output;
                        row += mul_component::rows_amount;

                        // qr_check * (1 - qr_check) * (1 + x) = 0 for y \in QNR(q)
                        var one_minus_qr_check =
                            sub_component::generate_assignments(assignment, {one, qr_check}, row).output;
                        row += sub_component::rows_amount;
                        var x_plus_one = add_component::generate_assignments(assignment, {x, one}, row).output;
                        row += add_component::rows_amount;

                        var in_qnr =
                            mul_component::generate_assignments(assignment, {qr_check, one_minus_qr_check}, row).output;
                        row += mul_component::rows_amount;
                        in_qnr = mul_component::generate_assignments(assignment, {in_qnr, x_plus_one}, row).output;
                        row += mul_component::rows_amount;

                        // (1 - qr_check) * (1 + qr_check) * x_squared = 0 for y = 0

                        var y_eq_zero = mul_component::generate_assignments(
                                            assignment, {one_minus_qr_check, one_plus_qr_check}, row)
                                            .output;
                        row += mul_component::rows_amount;
                        y_eq_zero = mul_component::generate_assignments(assignment, {y_eq_zero, x_squared}, row).output;
                        row += mul_component::rows_amount;

                        var last_check = add_component::generate_assignments(assignment, {in_qr, in_qnr}, row).output;
                        row += add_component::rows_amount;
                        last_check =
                            add_component::generate_assignments(assignment, {last_check, y_eq_zero}, row).output;
                        row += add_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        // copy-constarint for last_check and zero

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_assignments_constants(
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;    // leave empty cells for exp_component
                        assignment.constant(0)[row] = (BlueprintFieldType::value_type::modulus - 1) / 2;
                        row++;
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {

                        // last_check == zero
                        var zero(0, start_row_index + 1, false, var::column_type::constant);
                        var last_check(W2, start_row_index + rows_amount - 1, false, var::column_type::witness);
                        // bp.add_copy_constraint({zero, last_check});
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_ALGEBRA_FIELDS_SQRT_HPP
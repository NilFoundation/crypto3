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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_TO_GROUP_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_TO_GROUP_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/vesta/base_field.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // generate elliptic curve point from a field element
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/poly-commitment/src/commitment.rs#L370
                // Input: x \in F_q
                // Output: U \in E(F_q)
                template<typename ArithmetizationType, std::size_t... WireIndexes>
                class to_group;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                         std::size_t W13, std::size_t W14>
                class to_group<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, W0, W1, W2,
                               W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using div_component = zk::components::division_or_zero<ArithmetizationType, W0, W1, W2, W3, W4>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0f30;

                    struct curve_params {
                        var u;
                        var fu;
                        var inv_three_u_squared;
                        var sqrt_neg_three_u_squared;
                        var sqrt_neg_three_u_squared_minus_u_over_2;

                        var b;

                        curve_params(std::size_t start_row_index) {
                            u = var(0, start_row_index + 3, false, var::column_type::constant);
                            fu = var(0, start_row_index + 4, false, var::column_type::constant);
                            inv_three_u_squared = var(0, start_row_index + 5, false, var::column_type::constant);
                            sqrt_neg_three_u_squared = var(0, start_row_index + 6, false, var::column_type::constant);
                            sqrt_neg_three_u_squared_minus_u_over_2 =
                                var(0, start_row_index + 7, false, var::column_type::constant);
                            b = var(0, start_row_index + 8, false, var::column_type::constant);
                        }
                    };

                    constexpr static std::size_t potential_xs_rows =
                        mul_component::rows_amount * 9 + add_component::rows_amount * 2 + div_component::rows_amount +
                        sub_component::rows_amount * 4;

                    static std::array<var, 3>
                        potential_xs_assignment(blueprint_assignment_table<ArithmetizationType> &assignment, var t,
                                                curve_params params, var one, var zero, std::size_t row) {
                        var t2 = mul_component::generate_assignments(assignment, {t, t}, row).output;
                        row += mul_component::rows_amount;

                        var alpha = add_component::generate_assignments(assignment, {t2, params.fu}, row).output;
                        row += add_component::rows_amount;
                        alpha = mul_component::generate_assignments(assignment, {alpha, t2}, row).output;
                        row += mul_component::rows_amount;
                        alpha = div_component::generate_assignments(assignment, {one, alpha}, row).output;
                        row += div_component::rows_amount;

                        var x1 = t2;
                        x1 = mul_component::generate_assignments(assignment, {x1, x1}, row).output;    // t2^2
                        row += mul_component::rows_amount;
                        x1 =
                            mul_component::generate_assignments(assignment, {x1, alpha}, row).output;    // t2^2 * alpha
                        row += mul_component::rows_amount;
                        x1 = mul_component::generate_assignments(assignment, {x1, params.sqrt_neg_three_u_squared}, row)
                                 .output;    // t2^2 * alpha * sqrt(-3u^2)
                        row += mul_component::rows_amount;
                        x1 = sub_component::generate_assignments(
                                 assignment, {params.sqrt_neg_three_u_squared_minus_u_over_2, x1}, row)
                                 .output;    // sqrt(-3u^2-u/2) - t2^2 * alpha * sqrt(-3u^2)
                        row += sub_component::rows_amount;

                        var minus_u = sub_component::generate_assignments(assignment, {zero, params.u}, row).output;
                        row += sub_component::rows_amount;

                        var x2 = sub_component::generate_assignments(assignment, {minus_u, x1}, row).output;
                        row += sub_component::rows_amount;

                        var t2_plus_fu = add_component::generate_assignments(assignment, {t2, params.fu}, row).output;
                        row += add_component::rows_amount;
                        var t2_inv = mul_component::generate_assignments(assignment, {t2_plus_fu, alpha}, row).output;
                        row += mul_component::rows_amount;

                        var x3 = mul_component::generate_assignments(assignment, {t2_plus_fu, t2_plus_fu}, row).output;
                        row += mul_component::rows_amount;
                        x3 = mul_component::generate_assignments(assignment, {x3, t2_inv}, row).output;
                        row += mul_component::rows_amount;
                        x3 = mul_component::generate_assignments(assignment, {x3, params.inv_three_u_squared}, row)
                                 .output;
                        row += mul_component::rows_amount;
                        x3 = sub_component::generate_assignments(assignment, {params.u, x3}, row).output;
                        row += sub_component::rows_amount;

                        return {x1, x2, x3};
                    }

                    static std::array<var, 3>
                        potential_xs_circuit(blueprint<ArithmetizationType> &bp,
                                             blueprint_public_assignment_table<ArithmetizationType> &assignment, var t,
                                             curve_params params, var one, var zero, std::size_t row) {
                        var t2 = zk::components::generate_circuit<mul_component>(bp, assignment, {t, t}, row).output;
                        row += mul_component::rows_amount;

                        var alpha =
                            zk::components::generate_circuit<add_component>(bp, assignment, {t2, params.fu}, row)
                                .output;
                        row += add_component::rows_amount;
                        alpha =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {alpha, t2}, row).output;
                        row += mul_component::rows_amount;
                        alpha =
                            zk::components::generate_circuit<div_component>(bp, assignment, {one, alpha}, row).output;
                        row += div_component::rows_amount;

                        var x1 = t2;
                        x1 = zk::components::generate_circuit<mul_component>(bp, assignment, {x1, x1}, row)
                                 .output;    // t2^2
                        row += mul_component::rows_amount;
                        x1 = zk::components::generate_circuit<mul_component>(bp, assignment, {x1, alpha}, row)
                                 .output;    // t2^2 * alpha
                        row += mul_component::rows_amount;
                        x1 = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                             {x1, params.sqrt_neg_three_u_squared}, row)
                                 .output;    // t2^2 * alpha * sqrt(-3u^2)
                        row += mul_component::rows_amount;
                        x1 = zk::components::generate_circuit<sub_component>(
                                 bp, assignment, {params.sqrt_neg_three_u_squared_minus_u_over_2, x1}, row)
                                 .output;    // sqrt(-3u^2-u/2) - t2^2 * alpha * sqrt(-3u^2)
                        row += sub_component::rows_amount;

                        var minus_u =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {zero, params.u}, row)
                                .output;
                        row += sub_component::rows_amount;

                        var x2 =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {minus_u, x1}, row).output;
                        row += sub_component::rows_amount;

                        var t2_plus_fu =
                            zk::components::generate_circuit<add_component>(bp, assignment, {t2, params.fu}, row)
                                .output;
                        row += add_component::rows_amount;
                        var t2_inv =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {t2_plus_fu, alpha}, row)
                                .output;
                        row += mul_component::rows_amount;

                        var x3 = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                 {t2_plus_fu, t2_plus_fu}, row)
                                     .output;
                        row += mul_component::rows_amount;
                        x3 = zk::components::generate_circuit<mul_component>(bp, assignment, {x3, t2_inv}, row).output;
                        row += mul_component::rows_amount;
                        x3 = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                             {x3, params.inv_three_u_squared}, row)
                                 .output;
                        row += mul_component::rows_amount;
                        x3 =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {params.u, x3}, row).output;
                        row += sub_component::rows_amount;

                        return {x1, x2, x3};
                    }

                    constexpr static std::size_t get_y_rows =
                        mul_component::rows_amount * 3 + add_component::rows_amount;

                    static var get_y_assignments(blueprint_assignment_table<ArithmetizationType> &assignment, var x,
                                                 curve_params params, std::size_t row) {
                        // curve_eq
                        var y_squared = mul_component::generate_assignments(assignment, {x, x}, row)
                                            .output;    // x^2 + A (A = 0 for pasta curves)
                        row += mul_component::rows_amount;

                        y_squared =
                            mul_component::generate_assignments(assignment, {y_squared, x}, row).output;    // x^3 + A x
                        row += mul_component::rows_amount;

                        y_squared = add_component::generate_assignments(assignment, {y_squared, params.b}, row)
                                        .output;    // x^3 + A x + B
                        row += add_component::rows_amount;

                        // sqrt
                        typename BlueprintFieldType::value_type y_val = assignment.var_value(y_squared).sqrt();
                        assignment.witness(0)[row] = y_val;
                        var y(0, row);
                        var y_squared_recalculated =
                            mul_component::generate_assignments(assignment, {y, y}, row).output;
                        row += mul_component::rows_amount;

                        // copy constraint

                        return y;
                    }

                    static var get_y_circuit(blueprint<ArithmetizationType> &bp,
                                             blueprint_public_assignment_table<ArithmetizationType> &assignment, var x,
                                             curve_params params, std::size_t row) {
                        // curve_eq
                        var y_squared = zk::components::generate_circuit<mul_component>(bp, assignment, {x, x}, row)
                                            .output;    // x^2 + A (A = 0 for pasta curves)
                        row += mul_component::rows_amount;

                        y_squared = zk::components::generate_circuit<mul_component>(bp, assignment, {y_squared, x}, row)
                                        .output;    // x^3 + A x
                        row += mul_component::rows_amount;

                        y_squared =
                            zk::components::generate_circuit<add_component>(bp, assignment, {y_squared, params.b}, row)
                                .output;    // x^3 + A x + B
                        row += add_component::rows_amount;

                        // sqrt
                        var y(0, row);
                        var y_squared_recalculated =
                            zk::components::generate_circuit<mul_component>(bp, assignment, {y, y}, row).output;
                        row += mul_component::rows_amount;

                        // copy constraint

                        return y;
                    }

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;
                        row += potential_xs_rows;

                        const std::size_t points_size = 3;
                        for (std::size_t i = 0; i < points_size; ++i) {
                            row += get_y_rows;
                        }

                        for (std::size_t i = 0; i < points_size; ++i) {
                            row += sub_component::rows_amount;
                            row += div_component::rows_amount;

                            row += mul_component::rows_amount;
                            row += sub_component::rows_amount;

                            row += add_component::rows_amount;

                            if (i == 0) {
                                continue;
                            }

                            row += div_component::rows_amount;

                            row += mul_component::rows_amount;

                            row += sub_component::rows_amount;

                            row += mul_component::rows_amount;

                            row += mul_component::rows_amount;
                        }

                        for (std::size_t i = 0; i < points_size; ++i) {
                            row += mul_component::rows_amount;
                            row += add_component::rows_amount;

                            row += mul_component::rows_amount;
                            row += add_component::rows_amount;
                        }

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var t;
                    };

                    struct result_type {
                        var_ec_point output;

                        result_type(std::size_t start_row_index) {
                            const std::size_t points_size = 3;

                            std::size_t row = rows_amount - points_size * (2 * mul_component::rows_amount +
                                                                           2 * add_component::rows_amount);

                            var x;
                            var y;

                            for (std::size_t i = 0; i < points_size; ++i) {
                                row += mul_component::rows_amount;
                                x = typename add_component::result_type(row).output;
                                row += add_component::rows_amount;

                                row += mul_component::rows_amount;
                                y = typename add_component::result_type(row).output;
                                row += add_component::rows_amount;
                            }

                            output = {x, y};
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constants(assignment, params, start_row_index);
                        std::size_t row = start_row_index;

                        var zero(0, start_row_index, false, var::column_type::constant);
                        var one(0, start_row_index + 1, false, var::column_type::constant);
                        var minus_one(0, start_row_index + 2, false, var::column_type::constant);

                        curve_params params_curve(start_row_index);

                        std::array<var, 3> xs =
                            potential_xs_circuit(bp, assignment, params.t, params_curve, one, zero, row);
                        row += potential_xs_rows;

                        std::array<var, 3> ys;
                        for (std::size_t i = 0; i < xs.size(); ++i) {
                            ys[i] = get_y_circuit(bp, assignment, xs[i], params_curve, row);
                            row += get_y_rows;
                        }

                        std::array<var, 3> nulifiers;
                        // nulifiers[i] = 1 if ys[i] != -1 AND nulifiers[i - 1] == 0, 0 otherwise
                        // E1: (ys[i] - (-1)) * (ys[i] - (-1))**(-1) -1 = 0 if ys[i] != -1, -1 otherwise
                        // E2: E1 + 1 = 1 if ys[i] != -1, 0 otherwise
                        // E3: nulifiers[i - 1] * nulifiers[i - 1]**(-1) -1 = 0 if nulifiers[i - 1] != 0, -1 otherwise
                        // E4: E3 * (-1) = 0 if nulifiers[i - 1] != 0, 1 otherwise
                        // E5: E2 * E4 = 1 if ys[i] != -1 AND nulifiers[i - 1] = 0, 0 otherwise

                        for (std::size_t i = 0; i < ys.size(); ++i) {
                            var y1 =
                                zk::components::generate_circuit<sub_component>(bp, assignment, {ys[i], minus_one}, row)
                                    .output;
                            row += sub_component::rows_amount;
                            var y1_inversed =
                                zk::components::generate_circuit<div_component>(bp, assignment, {one, y1}, row).output;
                            row += div_component::rows_amount;

                            var e1 =
                                zk::components::generate_circuit<mul_component>(bp, assignment, {y1, y1_inversed}, row)
                                    .output;
                            row += mul_component::rows_amount;
                            e1 = zk::components::generate_circuit<sub_component>(bp, assignment, {e1, one}, row).output;
                            row += sub_component::rows_amount;

                            var e2 =
                                zk::components::generate_circuit<add_component>(bp, assignment, {e1, one}, row).output;
                            row += add_component::rows_amount;

                            if (i == 0) {
                                nulifiers[i] = e2;
                                continue;
                            }

                            var n_inversed = zk::components::generate_circuit<div_component>(
                                                 bp, assignment, {one, nulifiers[i - 1]}, row)
                                                 .output;
                            row += div_component::rows_amount;

                            var e3 = zk::components::generate_circuit<mul_component>(
                                         bp, assignment, {nulifiers[i - 1], n_inversed}, row)
                                         .output;
                            row += mul_component::rows_amount;

                            e3 = zk::components::generate_circuit<sub_component>(bp, assignment, {e3, one}, row).output;
                            row += sub_component::rows_amount;

                            var e4 =
                                zk::components::generate_circuit<mul_component>(bp, assignment, {e3, minus_one}, row)
                                    .output;
                            row += mul_component::rows_amount;

                            var e5 =
                                zk::components::generate_circuit<mul_component>(bp, assignment, {e2, e4}, row).output;
                            row += mul_component::rows_amount;

                            nulifiers[i] = e5;
                        }

                        var x = zero;
                        var y = zero;

                        // res = (xs[0] * nulifiers[0] + xs[1] * nulifiers[1] + xs[2] * nulifiers[2],
                        //      ys[0] * nulifiers[0] + ys[1] * nulifiers[1] + ys[2] * nulifiers[2])
                        for (std::size_t i = 0; i < xs.size(); ++i) {
                            var tmp = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                      {xs[i], nulifiers[i]}, row)
                                          .output;
                            row += mul_component::rows_amount;
                            x = zk::components::generate_circuit<add_component>(bp, assignment, {x, tmp}, row).output;
                            row += add_component::rows_amount;

                            var tmp_y = zk::components::generate_circuit<mul_component>(bp, assignment,
                                                                                        {ys[i], nulifiers[i]}, row)
                                            .output;
                            row += mul_component::rows_amount;
                            y = zk::components::generate_circuit<add_component>(bp, assignment, {y, tmp_y}, row).output;
                            row += add_component::rows_amount;
                        }

                        assert(row == start_row_index + rows_amount);

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        var zero(0, start_row_index, false, var::column_type::constant);
                        var one(0, start_row_index + 1, false, var::column_type::constant);
                        var minus_one(0, start_row_index + 2, false, var::column_type::constant);

                        curve_params params_curve(start_row_index);

                        std::array<var, 3> xs =
                            potential_xs_assignment(assignment, params.t, params_curve, one, zero, row);
                        row += potential_xs_rows;

                        std::array<var, 3> ys;
                        for (std::size_t i = 0; i < xs.size(); ++i) {
                            ys[i] = get_y_assignments(assignment, xs[i], params_curve, row);
                            row += get_y_rows;
                        }

                        std::array<var, 3> nulifiers;
                        // nulifiers[i] = 1 if ys[i] != -1 AND nulifiers[i - 1] == 0, 0 otherwise
                        // E1: (ys[i] - (-1)) * (ys[i] - (-1))**(-1) -1 = 0 if ys[i] != -1, -1 otherwise
                        // E2: E1 + 1 = 1 if ys[i] != -1, 0 otherwise
                        // E3: nulifiers[i - 1] * nulifiers[i - 1]**(-1) -1 = 0 if nulifiers[i - 1] != 0, -1 otherwise
                        // E4: E3 * (-1) = 0 if nulifiers[i - 1] != 0, 1 otherwise
                        // E5: E2 * E4 = 1 if ys[i] != -1 AND nulifiers[i - 1] = 0, 0 otherwise

                        for (std::size_t i = 0; i < ys.size(); ++i) {
                            var y1 = sub_component::generate_assignments(assignment, {ys[i], minus_one}, row).output;
                            row += sub_component::rows_amount;
                            var y1_inversed = div_component::generate_assignments(assignment, {one, y1}, row).output;
                            row += div_component::rows_amount;

                            var e1 = mul_component::generate_assignments(assignment, {y1, y1_inversed}, row).output;
                            row += mul_component::rows_amount;
                            e1 = sub_component::generate_assignments(assignment, {e1, one}, row).output;
                            row += sub_component::rows_amount;

                            var e2 = add_component::generate_assignments(assignment, {e1, one}, row).output;
                            row += add_component::rows_amount;

                            if (i == 0) {
                                nulifiers[i] = e2;
                                continue;
                            }

                            var n_inversed =
                                div_component::generate_assignments(assignment, {one, nulifiers[i - 1]}, row).output;
                            row += div_component::rows_amount;

                            var e3 =
                                mul_component::generate_assignments(assignment, {nulifiers[i - 1], n_inversed}, row)
                                    .output;
                            row += mul_component::rows_amount;

                            e3 = sub_component::generate_assignments(assignment, {e3, one}, row).output;
                            row += sub_component::rows_amount;

                            var e4 = mul_component::generate_assignments(assignment, {e3, minus_one}, row).output;
                            row += mul_component::rows_amount;

                            var e5 = mul_component::generate_assignments(assignment, {e2, e4}, row).output;
                            row += mul_component::rows_amount;

                            nulifiers[i] = e5;
                        }

                        var x = zero;
                        var y = zero;

                        // res = (xs[0] * nulifiers[0] + xs[1] * nulifiers[1] + xs[2] * nulifiers[2],
                        //      ys[0] * nulifiers[0] + ys[1] * nulifiers[1] + ys[2] * nulifiers[2])
                        for (std::size_t i = 0; i < xs.size(); ++i) {
                            var tmp =
                                mul_component::generate_assignments(assignment, {xs[i], nulifiers[i]}, row).output;
                            row += mul_component::rows_amount;
                            x = add_component::generate_assignments(assignment, {x, tmp}, row).output;
                            row += add_component::rows_amount;

                            var tmp_y =
                                mul_component::generate_assignments(assignment, {ys[i], nulifiers[i]}, row).output;
                            row += mul_component::rows_amount;
                            y = add_component::generate_assignments(assignment, {y, tmp_y}, row).output;
                            row += add_component::rows_amount;
                        }

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
                        assignment.constant(0)[row] = -1;
                        row++;

                        // curve_params:
                        typename BlueprintFieldType::value_type u_val;
                        typename BlueprintFieldType::value_type fu_val;
                        typename BlueprintFieldType::value_type inv_three_u_squared_val;
                        typename BlueprintFieldType::value_type sqrt_neg_three_u_squared_val;
                        typename BlueprintFieldType::value_type sqrt_neg_three_u_squared_minus_u_over_2_val;
                        typename BlueprintFieldType::value_type b_val;

                        if (std::is_same<BlueprintFieldType,
                                         typename nil::crypto3::algebra::fields::pallas_base_field>::value) {
                            u_val = 0x0000000000000000000000000000000000000000000000000000000000000001_cppui255;
                            fu_val = 0x0000000000000000000000000000000000000000000000000000000000000006_cppui255;
                            inv_three_u_squared_val =
                                0x2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC18465FD5B88A612661E209E00000001_cppui255;
                            sqrt_neg_three_u_squared_val =
                                0x25999506959B74E25955ABB8AF5563603A3F17A46F5A62923B5ABD7BFBFC9573_cppui255;
                            sqrt_neg_three_u_squared_minus_u_over_2_val =
                                0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                            b_val = 0x0000000000000000000000000000000000000000000000000000000000000005_cppui255;
                        } else {    // vesta
                            u_val = 0x0000000000000000000000000000000000000000000000000000000000000001_cppui255;
                            fu_val = 0x0000000000000000000000000000000000000000000000000000000000000006_cppui255;
                            inv_three_u_squared_val =
                                0x2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC18465FD5BB87093B2D9F21600000001_cppui255;
                            sqrt_neg_three_u_squared_val =
                                0x0D0334B0507CA51CA23B69B039EE1EB41FDA8CFA8F80675E5553A5C0A1541C9F_cppui255;
                            sqrt_neg_three_u_squared_minus_u_over_2_val =
                                0x06819A58283E528E511DB4D81CF70F5A0FED467D47C033AF2AA9D2E050AA0E4F_cppui255;
                            b_val = 0x0000000000000000000000000000000000000000000000000000000000000005_cppui255;
                        }
                        // var u;
                        assignment.constant(0)[row] = u_val;
                        row++;
                        // var fu;
                        assignment.constant(0)[row] = fu_val;
                        row++;
                        // var inv_three_u_squared;
                        assignment.constant(0)[row] = inv_three_u_squared_val;
                        row++;
                        // var sqrt_neg_three_u_squared;
                        assignment.constant(0)[row] = sqrt_neg_three_u_squared_val;
                        row++;
                        // var sqrt_neg_three_u_squared_minus_u_over_2;
                        assignment.constant(0)[row] = sqrt_neg_three_u_squared_minus_u_over_2_val;
                        row++;
                        // var b;
                        assignment.constant(0)[row] = b_val;
                        row++;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_TO_GROUP_HPP
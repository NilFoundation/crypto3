//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_COMPARE_WITH_CONSTANT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_COMPARE_WITH_CONSTANT_HPP

#include <vector>
#include <array>
#include <iostream>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                ///////////////// Compare Value with Constant ////////////////////////////////
                // Constant is pallas base field modulus
                // Return 0, if value >= constant
                // Return 1 otherwise
                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class compare_with_const;

                template<typename BlueprintFieldType,
                         typename CurveType, std::size_t W0,  std::size_t W1, std::size_t W2>
                class compare_with_const<snark::plonk_constraint_system<BlueprintFieldType>,
                                         CurveType,
                                         W0,
                                         W1,
                                         W2> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using div_component = zk::components::division<ArithmetizationType, W0, W1, W2>;
                    using mul_by_const_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    constexpr static const std::size_t selector_seed = 0x0ff8;

                public:
                    constexpr static const std::size_t rows_amount = 15 + 8 * 87;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var value;
                        params_type(var val) : value(val) {
                        }
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t row) {
                            output = var(W2, static_cast<int>(row), false, var::column_type::witness);
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t component_start_row) {

                        generate_assignments_constants(bp, assignment, params, component_start_row);

                        std::size_t row = component_start_row;

                        var k = var(0, component_start_row, false, var::column_type::constant);
                        var power87 = var(0, component_start_row + 1, false, var::column_type::constant);
                        var zero = var(0, component_start_row + 2, false, var::column_type::constant);
                        var one = var(0, component_start_row + 3, false, var::column_type::constant);

                        var c_var =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {zero, params.value}, row)
                                .output;
                        row++;

                        var b_var =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {power87, k}, row).output;
                        row++;
                        b_var =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {b_var, one}, row).output;
                        row++;
                        b_var =
                            zk::components::generate_circuit<add_component>(bp, assignment, {b_var, c_var}, row).output;
                        row++;
                        var c1_var = zero;
                        var b1_var = zero;
                        var bit_var;
                        typename BlueprintFieldType::value_type times = 1;

                        for (int i = 0; i < 87; ++i) {
                            bit_var = var(W1, row, false);
                            var bit_check_c =
                                zk::components::generate_circuit<sub_component>(bp, assignment, {one, bit_var}, row)
                                    .output;
                            row++;
                            bit_check_c = zk::components::generate_circuit<mul_component>(
                                              bp, assignment, {bit_var, bit_check_c}, row)
                                              .output;
                            row++;
                            bit_var = zk::components::generate_circuit<mul_by_const_component>(
                                          bp, assignment, {bit_var, times}, row)
                                          .output;
                            row++;
                            c1_var =
                                zk::components::generate_circuit<add_component>(bp, assignment, {bit_var, c1_var}, row)
                                    .output;
                            row++;
                            bit_var = var(W1, row, false);
                            var bit_check_b =
                                zk::components::generate_circuit<sub_component>(bp, assignment, {one, bit_var}, row)
                                    .output;
                            row++;
                            bit_check_b = zk::components::generate_circuit<mul_component>(
                                              bp, assignment, {bit_var, bit_check_b}, row)
                                              .output;
                            row++;
                            bit_var = zk::components::generate_circuit<mul_by_const_component>(
                                          bp, assignment, {bit_var, times}, row)
                                          .output;
                            row++;
                            b1_var =
                                zk::components::generate_circuit<add_component>(bp, assignment, {bit_var, b1_var}, row)
                                    .output;
                            row++;
                            times *= 2;
                        }

                        var delta_b_var =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {b_var, b1_var}, row)
                                .output;
                        row++;
                        var b1_inv_var = var(W1, row, false);
                        var inv_check_b1 = zk::components::generate_circuit<mul_component>(
                                               bp, assignment, {delta_b_var, b1_inv_var}, row)
                                               .output;
                        row++;
                        var inv_check_one =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {one, inv_check_b1}, row)
                                .output;
                        row++;
                        var inv_check = zk::components::generate_circuit<mul_component>(
                                            bp, assignment, {inv_check_one, delta_b_var}, row)
                                            .output;
                        row++;

                        var delta_c_var =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {c_var, c1_var}, row)
                                .output;
                        row++;
                        var c1_inv_var = var(W1, row, false);
                        var inv_check_c1 = zk::components::generate_circuit<mul_component>(
                                               bp, assignment, {delta_c_var, c1_inv_var}, row)
                                               .output;
                        row++;
                        inv_check_one =
                            zk::components::generate_circuit<sub_component>(bp, assignment, {one, inv_check_c1}, row)
                                .output;
                        row++;
                        inv_check = zk::components::generate_circuit<mul_component>(
                                        bp, assignment, {inv_check_one, delta_c_var}, row)
                                        .output;
                        row++;

                        var result_check_mul = zk::components::generate_circuit<mul_component>(
                                                   bp, assignment, {inv_check_c1, inv_check_b1}, row)
                                                   .output;
                        row++;
                        var result_check_sum = zk::components::generate_circuit<add_component>(
                                                   bp, assignment, {inv_check_c1, inv_check_b1}, row)
                                                   .output;
                        row++;
                        var result_check = zk::components::generate_circuit<sub_component>(
                                               bp, assignment, {result_check_sum, result_check_mul}, row)
                                               .output;
                        return result_type(row);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t component_start_row) {
                        std::size_t row = component_start_row;

                        var k = var(0, component_start_row, false, var::column_type::constant);
                        var power87 = var(0, component_start_row + 1, false, var::column_type::constant);
                        var zero = var(0, component_start_row + 2, false, var::column_type::constant);
                        var one = var(0, component_start_row + 3, false, var::column_type::constant);

                        var c_var = sub_component::generate_assignments(assignment, {zero, params.value}, row).output;
                        row++;

                        var b_var = sub_component::generate_assignments(assignment, {power87, k}, row).output;
                        row++;
                        b_var = sub_component::generate_assignments(assignment, {b_var, one}, row).output;
                        row++;
                        b_var = add_component::generate_assignments(assignment, {b_var, c_var}, row).output;
                        row++;

                        auto b_for_bits = assignment.var_value(b_var).data;
                        auto c_for_bits = assignment.var_value(c_var).data;
                        typename BlueprintFieldType::value_type bit;

                        typename BlueprintFieldType::value_type times = 1;
                        var c1_var = zero;
                        var b1_var = zero;
                        var bit_var;

                        for (int i = 0; i < 87; ++i) {
                            bit.data = c_for_bits - (c_for_bits >> 1 << 1);
                            assignment.witness(W1)[row] = bit;
                            bit_var = var(W1, row, false);
                            var bit_check_c =
                                sub_component::generate_assignments(assignment, {one, bit_var}, row).output;
                            row++;
                            bit_check_c =
                                mul_component::generate_assignments(assignment, {bit_var, bit_check_c}, row).output;
                            row++;
                            c_for_bits = c_for_bits >> 1;
                            bit_var =
                                mul_by_const_component::generate_assignments(assignment, {bit_var, times}, row).output;
                            row++;
                            c1_var = add_component::generate_assignments(assignment, {bit_var, c1_var}, row).output;
                            row++;

                            bit.data = b_for_bits - (b_for_bits >> 1 << 1);
                            assignment.witness(W1)[row] = bit;
                            bit_var = var(W1, row, false);
                            var bit_check_b =
                                sub_component::generate_assignments(assignment, {one, bit_var}, row).output;
                            row++;
                            bit_check_b =
                                mul_component::generate_assignments(assignment, {bit_var, bit_check_b}, row).output;
                            row++;
                            b_for_bits = b_for_bits >> 1;
                            bit_var =
                                mul_by_const_component::generate_assignments(assignment, {bit_var, times}, row).output;
                            row++;
                            b1_var = add_component::generate_assignments(assignment, {bit_var, b1_var}, row).output;
                            row++;
                            times *= 2;
                        }

                        var delta_b_var = sub_component::generate_assignments(assignment, {b_var, b1_var}, row).output;
                        row++;
                        typename BlueprintFieldType::value_type b1_inv;
                        if (assignment.var_value(delta_b_var) != 0) {
                            b1_inv = assignment.var_value(delta_b_var).inversed();
                        } else {
                            b1_inv = 0;
                        }
                        assignment.witness(W1)[row] = b1_inv;
                        var b1_inv_var = var(W1, row, false);
                        var inv_check_b1 =
                            mul_component::generate_assignments(assignment, {delta_b_var, b1_inv_var}, row).output;
                        row++;
                        var inv_check_one =
                            sub_component::generate_assignments(assignment, {one, inv_check_b1}, row).output;
                        row++;
                        var inv_check =
                            mul_component::generate_assignments(assignment, {inv_check_one, delta_b_var}, row).output;
                        row++;

                        var delta_c_var = sub_component::generate_assignments(assignment, {c_var, c1_var}, row).output;
                        row++;
                        typename BlueprintFieldType::value_type c1_inv;
                        if (assignment.var_value(delta_c_var) != 0) {
                            c1_inv = assignment.var_value(delta_c_var).inversed();
                        } else {
                            c1_inv = 0;
                        }
                        assignment.witness(W1)[row] = c1_inv;
                        var c1_inv_var = var(W1, row, false);
                        var inv_check_c1 =
                            mul_component::generate_assignments(assignment, {delta_c_var, c1_inv_var}, row).output;
                        row++;
                        inv_check_one =
                            sub_component::generate_assignments(assignment, {one, inv_check_c1}, row).output;
                        row++;
                        inv_check =
                            mul_component::generate_assignments(assignment, {inv_check_one, delta_c_var}, row).output;
                        row++;

                        var result_check_mul =
                            mul_component::generate_assignments(assignment, {inv_check_c1, inv_check_b1}, row).output;
                        row++;
                        var result_check_sum =
                            add_component::generate_assignments(assignment, {inv_check_c1, inv_check_b1}, row).output;
                        row++;
                        var result_check =
                            sub_component::generate_assignments(assignment, {result_check_sum, result_check_mul}, row)
                                .output;
                        return result_type(row);
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
                                                  std::size_t component_start_row = 0) {

                        var zero = var(0, component_start_row + 2, false, var::column_type::constant);

                        std::size_t row = component_start_row + 5;
                        var bit_check;
                        for (int i = 0; i < 87; ++i) {
                            bit_check = typename mul_component::result_type(row).output;
                            bp.add_copy_constraint({bit_check, zero});
                            row += 4;
                            bit_check = typename mul_component::result_type(row).output;
                            bp.add_copy_constraint({bit_check, zero});
                            row += 4;
                        }
                        row += 2;
                        var inv_check = typename mul_component::result_type(row).output;
                        bp.add_copy_constraint({inv_check, zero});
                        row += 4;
                        inv_check = typename mul_component::result_type(row).output;
                        bp.add_copy_constraint({inv_check, zero});
                    }

                    static void generate_assignments_constants(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        typename BlueprintFieldType::value_type base = 2;
                        assignment.constant(0)[row] =
                            0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui255 -
                            0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255;
                        row++;
                        assignment.constant(0)[row] = base.pow(87);
                        row++;
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                    }
                };

            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP

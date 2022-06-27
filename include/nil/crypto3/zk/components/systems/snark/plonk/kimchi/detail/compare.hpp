//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_COMPARE_WITH_CONSTANT_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_COMPARE_WITH_CONSTANT_HPP

#include <vector>
#include <array>
#include <iostream>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                ///////////////// Compare Value with Constant ////////////////////////////////
                // Constant is pallas base field modulus
                // Return 0, if value >= constant
                // Return 1 otherwise
                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class compare_with_const;

                template<typename BlueprintFieldType, 
                         typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2>
                class compare_with_const<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    W0,
                    W1,
                    W2> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using div_component = zk::components::division<ArithmetizationType, W0, W1, W2>;
                    using mul_by_const_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0ff8;

                public:
                    constexpr static const std::size_t rows_amount = 10 + 5 * 87 + 1; //(+ 5 * 87) if you want to use c_var
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var value = var(0, 0, false);
                        params_type(var val) : value(val) {}
                    };

                    struct result_type {
                        var output = var(0, 0);

                        result_type(std::size_t component_start_row) {
                            output = var(W0, static_cast<int>(component_start_row), false, var::column_type::witness);
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        const std::size_t component_start_row) {

                        generate_assignments_constants(bp, assignment, params, component_start_row);

                        std::size_t row = component_start_row;

                        var k = var(0, component_start_row, false, var::column_type::constant);
                        var power87 = var(0, component_start_row + 1, false, var::column_type::constant);
                        var zero = var(0, component_start_row + 2, false, var::column_type::constant);
                        var one = var(0, component_start_row + 3, false, var::column_type::constant);
                        var two = var(0, component_start_row + 4, false, var::column_type::constant);

                        var c_var = zk::components::generate_circuit<sub_component>(bp, assignment, {zero, params.value}, row).output;
                        row++;

                        var b_var = zk::components::generate_circuit<sub_component>(bp, assignment, {power87, k}, row).output;
                        row++;
                        b_var = zk::components::generate_circuit<sub_component>(bp, assignment, {b_var, one}, row).output;
                        row++;
                        b_var = zk::components::generate_circuit<add_component>(bp, assignment, {b_var, c_var}, row).output;
                        row++;

                        typename BlueprintFieldType::value_type times = 1;
                        // var c1_var = zero;
                        var b1_var = zero;
                        var bit_var;

                        for (int i = 0; i < 87; ++i) {
                            // bit_var = var(W0, row, false);
                            // row++;
                            // var bit_check_c = zk::components::generate_circuit<sub_component>(bp, assignment, {one, bit_var}, row).output;
                            // row++;
                            // bit_check_c = zk::components::generate_circuit<mul_component>(bp, assignment, {bit_var, bit_check_c}, row).output;
                            // row++;
                            // bit_var = zk::components::generate_circuit<mul_by_const_component>(bp, assignment, {bit_var, times}, row).output;
                            // row++;
                            // c1_var = zk::components::generate_circuit<add_component>(bp, assignment, {bit_var, c1_var}, row).output;
                            // row++;

                            bit_var = var(W0, row, false);
                            row++;
                            var bit_check_b = zk::components::generate_circuit<sub_component>(bp, assignment, {one, bit_var}, row).output;
                            row++;
                            bit_check_b = zk::components::generate_circuit<mul_component>(bp, assignment, {bit_var, bit_check_b}, row).output;
                            row++;
                            bit_var = zk::components::generate_circuit<mul_by_const_component>(bp, assignment, {bit_var, times}, row).output;
                            row++;
                            b1_var = zk::components::generate_circuit<add_component>(bp, assignment, {bit_var, b1_var}, row).output;
                            row++;

                            times *= 2;
                        }

                        var res_var(W0, row, false);
                        auto result_row = row;
                        row++;

                        // var delta_c = zk::components::generate_circuit<sub_component>(bp, assignment, {c_var, c1_var}, row).output;
                        // row++;
                        // delta_c = zk::components::generate_circuit<div_component>(bp, assignment, {delta_c, delta_c}, row).output;
                        // row++;
                        // var result_c = zk::components::generate_circuit<sub_component>(bp, assignment, {delta_c, res_var}, row).output;
                        // row++;

                        var delta_b = zk::components::generate_circuit<sub_component>(bp, assignment, {b_var, b1_var}, row).output;
                        row++;
                        delta_b = zk::components::generate_circuit<div_component>(bp, assignment, {delta_b, delta_b}, row).output;
                        row++;
                        var result_b = zk::components::generate_circuit<sub_component>(bp, assignment, {delta_b, res_var}, row).output;
                        row++;

                        generate_copy_constraints(bp, assignment, params, component_start_row);

                        return result_type(result_row);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t component_start_row) {
                        std::size_t row = component_start_row;

                        var k = var(0, component_start_row, false, var::column_type::constant);
                        std::cout << "k: " << assignment.var_value(k).data << '\n';
                        var power87 = var(0, component_start_row + 1, false, var::column_type::constant);
                        var zero = var(0, component_start_row + 2, false, var::column_type::constant);
                        var one = var(0, component_start_row + 3, false, var::column_type::constant);
                        var two = var(0, component_start_row + 4, false, var::column_type::constant);

                        var c_var = sub_component::generate_assignments(assignment, {zero, params.value}, row).output;
                        row++;

                        var b_var = sub_component::generate_assignments(assignment, {power87, k}, row).output;
                        std::cout << "b: " << assignment.var_value(b_var).data << '\n';
                        row++;
                        b_var = sub_component::generate_assignments(assignment, {b_var, one}, row).output;
                        std::cout << "b: " << assignment.var_value(b_var).data << '\n';
                        row++;
                        b_var = add_component::generate_assignments(assignment, {b_var, c_var}, row).output;
                        row++;
                        std::cout << "b: " << assignment.var_value(b_var).data << '\n';

                        auto b_for_bits = assignment.var_value(b_var).data;
                        // auto c_for_bits = assignment.var_value(c_var).data;
                        typename BlueprintFieldType::value_type bit;

                        typename BlueprintFieldType::value_type times = 1;
                        // var c1_var = zero;
                        var b1_var = zero;
                        var bit_var;

                        for (int i = 0; i < 87; ++i) {
                            // bit.data = c_for_bits - (c_for_bits >> 1 << 1);
                            // assignment.witness(W0)[row] = bit;
                            // bit_var = var(W0, row, false);
                            // row++;
                            // var bit_check_c = sub_component::generate_assignments(assignment, {one, bit_var}, row).output;
                            // row++;
                            // bit_check_c = mul_component::generate_assignments(assignment, {bit_var, bit_check_c}, row).output;
                            // row++;
                            // c_for_bits = c_for_bits >> 1;
                            // bit_var = mul_by_const_component::generate_assignments(assignment, {bit_var, times}, row).output;
                            // row++;
                            // c1_var = add_component::generate_assignments(assignment, {bit_var, c1_var}, row).output;
                            // row++;

                            bit.data = b_for_bits - (b_for_bits >> 1 << 1);
                            assignment.witness(W0)[row] = bit;
                            bit_var = var(W0, row, false);
                            row++;
                            var bit_check_b = sub_component::generate_assignments(assignment, {one, bit_var}, row).output;
                            row++;
                            bit_check_b = mul_component::generate_assignments(assignment, {bit_var, bit_check_b}, row).output;
                            row++;
                            b_for_bits = b_for_bits >> 1;
                            bit_var = mul_by_const_component::generate_assignments(assignment, {bit_var, times}, row).output;
                            row++;
                            b1_var = add_component::generate_assignments(assignment, {bit_var, b1_var}, row).output;
                            row++;

                            times *= 2;
                        }

                        typename BlueprintFieldType::value_type res = 0;
                        std::cout << "b1: " << assignment.var_value(b1_var).data << '\n';
                        std::cout << "b: " << assignment.var_value(b_var).data << '\n';
                        // std::cout << "c1: " << assignment.var_value(c1_var).data << '\n';
                        // std::cout << "c: " << assignment.var_value(c_var).data << '\n';
                        if (assignment.var_value(b1_var) != assignment.var_value(b_var)) {
                            res = 1;
                        }
                        assignment.witness(W0)[row] = res;
                        var res_var(W0, row, false);
                        auto result_row = row;
                        row++;

                        // var delta_c = sub_component::generate_assignments(assignment, {c_var, c1_var}, row).output;
                        // row++;
                        // delta_c = div_component::generate_assignments(assignment, {delta_c, delta_c}, row).output;
                        // row++;
                        // var result_c = sub_component::generate_assignments(assignment, {delta_c, res_var}, row).output;
                        // row++;

                        var delta_b = sub_component::generate_assignments(assignment, {b_var, b1_var}, row).output;
                        row++;
                        delta_b = div_component::generate_assignments(assignment, {delta_b, delta_b}, row).output;
                        row++;
                        var result_b = sub_component::generate_assignments(assignment, {delta_b, res_var}, row).output;
                        row++;

                        return result_type(result_row);
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
                                                          std::size_t component_start_row = 0) {

                        var zero = var(0, component_start_row + 2, false, var::column_type::constant);

                        std::size_t row = component_start_row + 6;
                        var bit_check;
                        for (int i = 0; i < 87; ++i) {
                            // bit_check = typename mul_component::result_type(row).output;
                            // row += 5;
                            // bp.add_copy_constraint({bit_check, zero});
                            bit_check = typename mul_component::result_type(row).output;
                            row += 5;
                            bp.add_copy_constraint({bit_check, zero});
                        }
                        row++;
                        // var result_c = typename sub_component::result_type(row).output;
                        // row += 3;
                        var result_b = typename sub_component::result_type(row).output;
                        // bp.add_copy_constraint({result_c, zero});
                        bp.add_copy_constraint({result_b, zero});
                    }

                    static void generate_assignments_constants(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        typename BlueprintFieldType::value_type base = 2;
                        assignment.constant(0)[row] = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001_cppui255 - 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255;
                        row++;
                        assignment.constant(0)[row] = base.pow(87);
                        row++;
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;
                        assignment.constant(0)[row] = 2;
                    }

                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP

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
                class compare_with_const<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
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

                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0ff8;

                public:
                    constexpr static const std::size_t rows_amount = 5 + 5 * 87;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var value = var(0, 0, false);
                        params_type(var val) : value(val) {}
                    };

                    struct result_type {
                        var output = var(0, 0);

                        result_type(std::size_t component_start_row) {
                            output = var(W1, static_cast<int>(component_start_row), false, var::column_type::witness);
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        const std::size_t component_start_row) {

                        generate_assignments_constants(bp, assignment, params, component_start_row);

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, component_start_row);

                        generate_copy_constraints(bp, assignment, params, component_start_row);

                        return result_type(component_start_row);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t component_start_row) {
                        std::size_t row = component_start_row;

                        var constant = var(0, component_start_row, false, var::column_type::constant);
                        var one = var(0, component_start_row + 2, false, var::column_type::constant);
                        var two = var(0, component_start_row + 3, false, var::column_type::constant);

                        var b_var = sub_component::generate_assignments(assignment, {constant, params.value}, row).output;
                        row++;

                        auto b_for_bits = assignment.var_value(b_var).data;
                        typename BlueprintFieldType::value_type bit;
                        assignment.witness(W0)[row] = 1;
                        var times_var(W0, row, false);
                        row++;
                        assignment.witness(W0)[row] = 0;
                        var b1_var(W0, row, false);
                        row++;

                        for (std::size_t i = 0; i < 87; ++i) {
                            bit.data = b_for_bits - (b_for_bits >> 1 << 1);
                            assignment.witness(W2 + i / 7)[i % 7] = bit * (1 - bit);
                            var bit_var(W2 + i / 7, i % 7, false);
                            var bit_check = sub_component::generate_assignments(assignment, {one, bit_var}, row).output;
                            row++;
                            bit_check = mul_component::generate_assignments(assignment, {bit_var, bit_check}, row).output;
                            row++;
                            b_for_bits = b_for_bits >> 1;
                            bit_var = mul_component::generate_assignments(assignment, {bit_var, times_var}, row).output;
                            row++;
                            b1_var = add_component::generate_assignments(assignment, {bit_var, b1_var}, row).output;
                            row++;
                            times_var = mul_component::generate_assignments(assignment, {times_var, two}, row).output;
                            row++;
                        }

                        typename BlueprintFieldType::value_type res = 1;
                        if (assignment.var_value(b1_var) != assignment.var_value(b_var)) {
                            res = 0;
                        }
                        assignment.witness(W1)[component_start_row] = res;
                        var res_var(W1, component_start_row, false);
                        var res_check = sub_component::generate_assignments(assignment, {b1_var, b_var}, row).output;
                        row++;
                        res_check = mul_component::generate_assignments(assignment, {res_check, res_var}, row).output;

                        return result_type(component_start_row);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {}

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                          blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                          const params_type &params,
                                                          std::size_t component_start_row = 0) {

                        var zero = var(0, component_start_row + 1, false, var::column_type::constant);

                        std::size_t row = component_start_row + 4;
                        var bit_check;
                        for (int i = 0; i < 87; ++i) {
                            bit_check = typename mul_component::result_type(row).output;
                            row += 5;
                            bp.add_copy_constraint({bit_check, zero});
                        }
                        row += 4;
                        var res_check = typename mul_component::result_type(row).output;
                        bp.add_copy_constraint({res_check, zero});
                    }

                    static void generate_assignments_constants(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        typename BlueprintFieldType::value_type base = 2;
                        assignment.constant(0)[row] = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255 + base.pow(87) - 1;
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

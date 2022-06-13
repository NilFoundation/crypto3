//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the MERKLE_TREE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_PER_BIT_EDWARD25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_PER_BIT_EDWARD25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/doubling_edwards25519.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/complete_addition_edwards25519.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, typename Ed25519Type,
                         std::size_t... WireIndexes>
                class variable_base_multiplication_per_bit;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                          typename Ed25519Type,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8>
                class variable_base_multiplication_per_bit<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                       CurveType,
                                                        Ed25519Type,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4,
                                                       W5,
                                                       W6,
                                                       W7,
                                                       W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using doubling_component = doubling<ArithmetizationType, CurveType, Ed25519Type,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using complete_addition_component = complete_addition<ArithmetizationType, CurveType, Ed25519Type,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    
                    using var = snark::plonk_variable<BlueprintFieldType>;
                    constexpr static const std::size_t selector_seed = 0xff82;

                public:
                    constexpr static const std::size_t rows_amount =
                        doubling_component::rows_amount + complete_addition_component::rows_amount + 2;

                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        struct var_ec_point {
                            std::array<var, 4> x;
                            std::array<var, 4> y;
                        };

                        var_ec_point T;
                        var_ec_point R;
                        var k;
                    };

                    struct result_type {
                        struct var_ec_point {
                            std::array<var, 4> x;
                            std::array<var, 4> y;
                        };
                        var_ec_point output;

                        /*result_type(std::size_t component_start_row) {
                            output.x = {var(W0, component_start_row, false), var(W1, component_start_row, false),
                             var(W2, component_start_row, false), var(W3, component_start_row, false)};
                            output.y = {var(W0, component_start_row + non_native_range_component::rows_amount, false),
                             var(W1, component_start_row + non_native_range_component::rows_amount, false),
                             var(W2, component_start_row + non_native_range_component::rows_amount, false),
                              var(W3, component_start_row + non_native_range_component::rows_amount, false)};
                        }*/
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        typename Ed25519Type::base_field_type::integral_type b = typename Ed25519Type::base_field_type::integral_type(assignment.var_value(params.k).data);
                        std::array<var, 4> T_x = params.T.x;
                        std::array<var, 4> T_y = params.T.y;
                        std::array<typename CurveType::base_field_type::value_type, 4> T_x_array = {assignment.var_value(params.T.x[0]),
                        assignment.var_value(params.T.x[1]), assignment.var_value(params.T.x[2]), assignment.var_value(params.T.x[3])};
                        std::array<typename CurveType::base_field_type::value_type, 4> T_y_array = {assignment.var_value(params.T.y[0]),
                        assignment.var_value(params.T.y[1]), assignment.var_value(params.T.y[2]), assignment.var_value(params.T.y[3])};

                        std::array<var, 4> R_x = params.R.x;
                        std::array<var, 4> R_y = params.R.y;

                        assignment.witness(W0)[row] = T_y_array[0];
                        assignment.witness(W1)[row] = T_y_array[1];
                        assignment.witness(W2)[row] = T_y_array[2];
                        assignment.witness(W3)[row] = T_y_array[3];
                        assignment.witness(W4)[row] = b;
                        assignment.witness(W5)[row] = b * T_y_array[0] + (1 - b);
                        assignment.witness(W6)[row] = b * T_y_array[1];
                        assignment.witness(W7)[row] = b * T_y_array[2];
                        assignment.witness(W8)[row] = b * T_y_array[3];
                        std::array<var, 4> Q_y = {var(W5, row), var(W6, row), var(W7, row), var(W8, row)};
                        row++;
                        assignment.witness(W0)[row] = T_x_array[0];
                        assignment.witness(W1)[row] = T_x_array[1];
                        assignment.witness(W2)[row] = T_x_array[2];
                        assignment.witness(W3)[row] = T_x_array[3];
                        assignment.witness(W4)[row] = b;
                        assignment.witness(W5)[row] = b * T_x_array[0];
                        assignment.witness(W6)[row] = b * T_x_array[1];
                        assignment.witness(W7)[row] = b * T_x_array[2];
                        assignment.witness(W8)[row] = b * T_x_array[3];
                        std::array<var, 4> Q_x = {var(W5, row), var(W6, row), var(W7, row), var(W8, row)};
                        row++;

                        auto doubling_res = doubling_component::generate_assignments(assignment, typename doubling_component::params_type({R_x, R_y}), row);
                        row+=doubling_component::rows_amount;

                        auto add_res = complete_addition_component::generate_assignments(assignment, typename complete_addition_component::params_type({{doubling_res.output.x, doubling_res.output.y}, {Q_x, Q_y}}), row);
                        row+=complete_addition_component::rows_amount;
                        
                        return {add_res.output.x, add_res.output.y};
                    }

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index){

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;
                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }
                        std::size_t row = start_row_index;
                        std::array<var, 4> T_x = params.T.x;
                        std::array<var, 4> T_y = params.T.y;
                        std::array<var, 4> R_x = params.R.x;
                        std::array<var, 4> R_y = params.R.y;
                        std::array<var, 4> Q_y = {var(W5, row), var(W6, row), var(W7, row), var(W8, row)};
                        row++;
                        std::array<var, 4> Q_x = {var(W5, row), var(W6, row), var(W7, row), var(W8, row)};
                        row++;

                        auto doubling_res = doubling_component::generate_circuit(bp, assignment, typename doubling_component::params_type({R_x, R_y}), row);
                        row+=doubling_component::rows_amount;

                        auto add_res = complete_addition_component::generate_circuit(bp, assignment, typename complete_addition_component::params_type({{doubling_res.output.x, doubling_res.output.y}, {Q_x, Q_y}}), row);
                        row+=complete_addition_component::rows_amount;

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        return {add_res.output.x, add_res.output.y};
                    }

                private:

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const params_type &params,
                        const std::size_t first_selector_index) {
                        auto constraint_1 = bp.add_constraint(
                            var(W5, 0) - var(W0, 0) * var(W4, 0) + (1 - var(W4, 0)));
                        auto constraint_2 = bp.add_constraint(
                            var(W6, 0) - var(W1, 0) * var(W4, 0));
                        auto constraint_3 = bp.add_constraint(
                            var(W7, 0) - var(W2, 0) * var(W4, 0));
                        auto constraint_4 = bp.add_constraint(
                            var(W8, 0) - var(W3, 0) * var(W4, 0));
                        auto constraint_5 = bp.add_constraint(
                            var(W5, +1) - var(W0, +1) * var(W4, +1));
                        auto constraint_6 = bp.add_constraint(
                            var(W6, +1) - var(W1, +1) * var(W4, +1));
                        auto constraint_7 = bp.add_constraint(
                            var(W7, +1) - var(W2, +1) * var(W4, +1));
                        auto constraint_8 = bp.add_constraint(
                            var(W8, +1) - var(W3, +1) * var(W4, +1));

                        bp.add_gate(first_selector_index, 
                            { constraint_1, constraint_2, constraint_3, constraint_4,
                            constraint_5, constraint_6, constraint_7, constraint_8
                            
                        });
                        
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                          blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                                          const params_type &params,
                                                          std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
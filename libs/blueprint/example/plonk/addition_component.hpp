//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_EXAMPLE_PLONK_ADDITION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_EXAMPLE_PLONK_ADDITION_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<typename ArithmetizationType,
                         std::size_t... WireIndexes>
                class addition;

                /// Additiona component takes (x, y, sum) as an input and proves that x + y = sum
                /// We always prove some statement about the data in the table
                /// Table constrains elements of the finite field
                /// Addition Component' table Layout:
                /// W0 | W1 | W2
                ///  x |  y | sum
                /// To prove "something" about the data in the table, we need to define this "something"
                /// We do it via "constraints" - expressions over cells of the table
                /// Constraints:
                /// x + y = sum <=> W0 + W1 = W2
                template<typename BlueprintFieldType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2>
                class addition<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    W0, W1, W2>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                public:
                    // Addition Component takes only one row in the table
                    // More complex components may contain more rows
                    constexpr static const std::size_t rows_amount = 1;

                    // params_type defines input data for the component
                    // it constains either variables allocated on the table (var) or some auxiliary data
                    // Addition Component input contains tree variables:
                    struct params_type {
                        var x;
                        var y;
                        var sum;
                    };

                    // Addition Component doesn't calculate anything, so result_type contains nothing
                    struct result_type {
                        result_type(const params_type &params,
                            std::size_t component_start_row) {

                        }
                    };

                    // allocated_data_type transfers component-related data through the bigger circuits
                    // we don't interested in it for this particular example
                    struct allocated_data_type {
                        allocated_data_type() {
                            previously_allocated = false;
                        }

                        // TODO access modifiers
                        bool previously_allocated;
                        std::size_t add_selector;
                    };

                    // Allocate rows in the table required for Addition Component
                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp,
                        std::size_t components_amount = 1){
                        return bp.allocate_rows(rows_amount *
                            components_amount);
                    }

                    // generate_circuit represents basic interface to put constraints on the table
                    static result_type generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        std::size_t component_start_row) {

                        // generate_gates defines algebraic expressions over cells
                        // for instance, x + y = z or x * y * z - 25 = 0
                        generate_gates(bp, assignment, params, allocated_data, component_start_row);
                        // generate_copy_constraints enforces equality between cells of the table
                        generate_copy_constraints(bp, assignment, params, component_start_row);

                        return result_type(params, component_start_row);
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType>
                                &assignment,
                            const params_type &params,
                            std::size_t component_start_row) {

                        std::size_t row = component_start_row;
                        // variables keeps only data about cells in the table, not the value itself
                        // assignment.var_value resturns value of the cell in the table
                        // here we assign input to the corresponding cells in the table (see table description above)
                        assignment.witness(0)[row] = assignment.var_value(params.x);
                        assignment.witness(1)[row] = assignment.var_value(params.y);
                        assignment.witness(2)[row] = assignment.var_value(params.sum);

                        return result_type(params, component_start_row);
                    }

                    private:
                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t start_row_index) {

                        // selectors define on which rows which constraints are avaiable
                        std::size_t selector_index;
                        if (!allocated_data.previously_allocated) {
                            selector_index = assignment.add_selector(start_row_index);
                            allocated_data.add_selector = selector_index;
                        } else {
                            selector_index = allocated_data.add_selector;
                            assignment.enable_selector(selector_index, start_row_index);
                        }

                        // var(i, 0) defines cell at the column i with rotation 0 (we'll elaborate rotation in the next examples)
                        auto constraint_1 = bp.add_constraint(
                            var(0, 0) + (var(1, 0) - var(2, 0)));

                        if (!allocated_data.previously_allocated) {
                            // gate composes multiple constraints together
                            bp.add_gate(selector_index,
                                { constraint_1
                            });
                            allocated_data.previously_allocated = true;
                        }

                    }

                    static void generate_copy_constraints(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            std::size_t component_start_row){
                        // recall that params contains variables which refers to the cells in the table
                        // these cells can be allocated outside ot the component
                        // however generate_gates enforces contraint only on the rows of the component
                        // thus, we need to enforce equality between the cells from the input and cells of the component
                        std::size_t row = component_start_row;
                        var component_x = var(W0, static_cast<int>(row), false);
                        var component_y = var(W1, static_cast<int>(row), false);
                        var component_sum = var(W2, static_cast<int>(row), false);
                        bp.add_copy_constraint({component_x, params.x});
                        bp.add_copy_constraint({component_y, params.y});
                        bp.add_copy_constraint({component_sum, params.sum});
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_EXAMPLE_PLONK_ADDITION_HPP
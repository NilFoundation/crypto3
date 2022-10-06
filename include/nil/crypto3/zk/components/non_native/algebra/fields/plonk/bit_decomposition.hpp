//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_ZK_BLUEPRINT_BIT_DECOMPOSITION_HPP
#define CRYPTO3_ZK_BLUEPRINT_BIT_DECOMPOSITION_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         typename Ed25519Type,
                         std::size_t... WireIndexes>
                class bit_decomposition;

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
                class bit_decomposition<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    constexpr static const std::size_t selector_seed = 0xf382;

                public:
                    constexpr static const std::size_t rows_amount = 33;

                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var k;
                    };

                    struct result_type {
                        std::array<var, 253> output;
                        result_type(std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            for (std::size_t i = 0; i < 11; i++) {
                                if (i != 0) {
                                    output[25 * i - 22] = var(W0, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 1 - 22] = var(W1, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 2 - 22] = var(W2, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 3 - 22] = var(W3, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 4 - 22] = var(W4, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 5 - 22] = var(W5, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 6 - 22] = var(W6, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 7 - 22] = var(W7, row);
                                }
                                row++;
                                if (i != 0) {
                                    output[25 * i + 8 - 22] = var(W0, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 9 - 22] = var(W1, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 10 - 22] = var(W2, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 11 - 22] = var(W3, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 12 - 22] = var(W4, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 13 - 22] = var(W5, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 14 - 22] = var(W6, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 15 - 22] = var(W7, row);
                                }
                                row++;
                                if (i != 0) {
                                    output[25 * i + 16 - 22] = var(W0, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 17 - 22] = var(W1, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 18 - 22] = var(W2, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 19 - 22] = var(W3, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 20 - 22] = var(W4, row);
                                }
                                if (i != 0) {
                                    output[25 * i + 21 - 22] = var(W5, row);
                                }
                                output[25 * i] = var(W6, row);
                                output[25 * i + 1] = var(W7, row);
                                output[25 * i + 2] = var(W8, row);
                                row++;
                            }
                        }
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row] = ArithmetizationType::field_type::value_type::zero();
                        const std::size_t scalar_size = 275;
                        std::array<bool, scalar_size> b = {false};
                        typename CurveType::scalar_field_type::integral_type integral_k =
                            typename CurveType::scalar_field_type::integral_type(assignment.var_value(params.k).data);
                        for (std::size_t i = 0; i < scalar_size; i++) {
                            b[scalar_size - i - 1] = multiprecision::bit_test(integral_k, i);
                        }
                        typename CurveType::base_field_type::integral_type n = 0;
                        typename CurveType::base_field_type::integral_type t = 0;
                        for (std::size_t i = 0; i < 11; i++) {
                            assignment.witness(W0)[row] = b[25 * i];
                            if (i != 0) {
                                t = t * 2 + b[25 * i];
                            }
                            assignment.witness(W1)[row] = b[25 * i + 1];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 1];
                            }
                            assignment.witness(W2)[row] = b[25 * i + 2];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 2];
                            }
                            assignment.witness(W3)[row] = b[25 * i + 3];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 3];
                            }
                            assignment.witness(W4)[row] = b[25 * i + 4];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 4];
                            }
                            assignment.witness(W5)[row] = b[25 * i + 5];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 5];
                            }
                            assignment.witness(W6)[row] = b[25 * i + 6];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 6];
                            }
                            assignment.witness(W7)[row] = b[25 * i + 7];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 7];
                            }
                            assignment.witness(W8)[row] = n;
                            row++;

                            assignment.witness(W0)[row] = b[25 * i + 8];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 8];
                            }
                            assignment.witness(W1)[row] = b[25 * i + 9];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 9];
                            }
                            assignment.witness(W2)[row] = b[25 * i + 10];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 10];
                            }
                            assignment.witness(W3)[row] = b[25 * i + 11];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 11];
                            }
                            assignment.witness(W4)[row] = b[25 * i + 12];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 12];
                            }
                            assignment.witness(W5)[row] = b[25 * i + 13];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 13];
                            }
                            assignment.witness(W6)[row] = b[25 * i + 14];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 14];
                            }
                            assignment.witness(W7)[row] = b[25 * i + 15];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 15];
                            }
                            row++;

                            assignment.witness(W0)[row] = b[25 * i + 16];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 16];
                            }
                            assignment.witness(W1)[row] = b[25 * i + 17];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 17];
                            }
                            assignment.witness(W2)[row] = b[25 * i + 18];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 18];
                            }
                            assignment.witness(W3)[row] = b[25 * i + 19];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 19];
                            }
                            assignment.witness(W4)[row] = b[25 * i + 20];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 20];
                            }
                            assignment.witness(W5)[row] = b[25 * i + 21];
                            if (i != 0) {
                                t = t * 2 + b[25 * i + 21];
                            }
                            assignment.witness(W6)[row] = b[25 * i + 22];
                            t = t * 2 + b[25 * i + 22];
                            assignment.witness(W7)[row] = b[25 * i + 23];
                            t = t * 2 + b[25 * i + 23];
                            assignment.witness(W8)[row] = b[25 * i + 24];
                            t = t * 2 + b[25 * i + 24];
                            n = t;
                            assignment.witness(W8)[row - 1] = n;
                            row++;
                        }
                        return result_type(component_start_row);
                    }

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;
                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }
                        std::size_t row = start_row_index;
                        assignment.enable_selector(first_selector_index, row + 1, row + rows_amount - 2, 3);

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        return result_type(start_row_index);
                    }

                private:
                    static void
                        generate_gates(blueprint<ArithmetizationType> &bp,
                                       blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                       const params_type &params,
                                       const std::size_t first_selector_index) {
                        snark::plonk_constraint<BlueprintFieldType> t = var(W8, -1);
                        t = t * 2 + var(W0, -1);
                        t = t * 2 + var(W1, -1);
                        t = t * 2 + var(W2, -1);
                        t = t * 2 + var(W3, -1);
                        t = t * 2 + var(W4, -1);
                        t = t * 2 + var(W5, -1);
                        t = t * 2 + var(W6, -1);
                        t = t * 2 + var(W7, -1);
                        t = t * 2 + var(W0, 0);
                        t = t * 2 + var(W1, 0);
                        t = t * 2 + var(W2, 0);
                        t = t * 2 + var(W3, 0);
                        t = t * 2 + var(W4, 0);
                        t = t * 2 + var(W5, 0);
                        t = t * 2 + var(W6, 0);
                        t = t * 2 + var(W7, 0);
                        t = t * 2 + var(W0, 1);
                        t = t * 2 + var(W1, 1);
                        t = t * 2 + var(W2, 1);
                        t = t * 2 + var(W3, 1);
                        t = t * 2 + var(W4, 1);
                        t = t * 2 + var(W5, 1);
                        t = t * 2 + var(W6, 1);
                        t = t * 2 + var(W7, 1);
                        t = t * 2 + var(W8, 1);
                        auto constraint_1 = bp.add_constraint(var(W8, 0) - t);
                        bp.add_gate(first_selector_index,
                                    {constraint_1

                                    });
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const params_type &params,
                        std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        bp.add_copy_constraint({{8, (std::int32_t)(row), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});

                        bp.add_copy_constraint({{0, (std::int32_t)(row), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{1, (std::int32_t)(row), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{2, (std::int32_t)(row), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{3, (std::int32_t)(row), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{4, (std::int32_t)(row), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{5, (std::int32_t)(row), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{6, (std::int32_t)(row), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{7, (std::int32_t)(row), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{0, (std::int32_t)(row + 1), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{1, (std::int32_t)(row + 1), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{2, (std::int32_t)(row + 1), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{3, (std::int32_t)(row + 1), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{4, (std::int32_t)(row + 1), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{5, (std::int32_t)(row + 1), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{6, (std::int32_t)(row + 1), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{7, (std::int32_t)(row + 1), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{0, (std::int32_t)(row + 2), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{1, (std::int32_t)(row + 2), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{2, (std::int32_t)(row + 2), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{3, (std::int32_t)(row + 2), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{4, (std::int32_t)(row + 2), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{5, (std::int32_t)(row + 2), false},
                                                {0, (std::int32_t)(row), false, var::column_type::constant}});
                        bp.add_copy_constraint({{8, (std::int32_t)(row + rows_amount - 2), false}, params.k});
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
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
// @file Declaration of interfaces for auxiliary components for the RANGE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_RANGE_EDWARD25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_RANGE_EDWARD25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class non_native_range;

                /* a0 a1 a2 a3 a'0 a'1 a'2 a'3 xi
                    a'4 a'5 a'6 a'7 a'8 a'9 a'10 a'11 c
                */

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
                         std::size_t W8>
                class non_native_range<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                       CurveType,
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

                    constexpr static const std::size_t selector_seed = 0xff80;

                public:
                    constexpr static const std::size_t rows_amount = 2;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        std::array<var, 4> input;    // 66,66,66,57 bits
                    };

                    struct result_type {
                        result_type(std::size_t component_start_row) {
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         std::size_t start_row_index) {

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;
                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }
                        std::size_t j = start_row_index;
                        assignment.enable_selector(first_selector_index, j);
                        generate_copy_constraints(bp, assignment, params, j);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        typename BlueprintFieldType::integral_type base = 1;
                        std::array<typename BlueprintFieldType::integral_type, 4> ed25519_value = {
                            typename BlueprintFieldType::integral_type(assignment.var_value(params.input[0]).data),
                            typename BlueprintFieldType::integral_type(assignment.var_value(params.input[1]).data),
                            typename BlueprintFieldType::integral_type(assignment.var_value(params.input[2]).data),
                            typename BlueprintFieldType::integral_type(assignment.var_value(params.input[3]).data)};
                        assignment.witness(W0)[row] = ed25519_value[0];
                        assignment.witness(W1)[row] = ed25519_value[1];
                        assignment.witness(W2)[row] = ed25519_value[2];
                        assignment.witness(W3)[row] = ed25519_value[3];
                        std::array<typename BlueprintFieldType::value_type, 12> range_chunks;
                        typename BlueprintFieldType::integral_type mask = 0;
                        typename BlueprintFieldType::value_type xi = 0;
                        for (std::size_t i = 0; i < 4; i++) {
                            for (std::size_t j = 0; j < 3; j++) {
                                if (i == 3) {
                                    if (j == 2) {
                                        mask = (base << 15) - 1;
                                        range_chunks[9 + j] = (ed25519_value[i] >> (21 * j)) & mask;
                                        xi += range_chunks[i * 3 + j] - (base << 15) + 1;
                                    } else {
                                        mask = (base << 21) - 1;
                                        range_chunks[9 + j] = (ed25519_value[i] >> (21 * j)) & mask;
                                        xi += range_chunks[i * 3 + j] - (base << 21) + 1;
                                    }
                                } else {
                                    mask = (1 << 22) - 1;
                                    range_chunks[i * 3 + j] = (ed25519_value[i] >> (22 * j)) & mask;
                                    if (i + j != 0) {
                                        xi += range_chunks[i * 3 + j] - (base << 22) + 1;
                                    }
                                }
                            }
                        }
                        if (xi != 0) {
                            xi = xi.inversed();
                        } else {
                            xi = 0;
                        }
                        assignment.witness(W4)[row] = range_chunks[0];
                        assignment.witness(W5)[row] = range_chunks[1];
                        assignment.witness(W6)[row] = range_chunks[2];
                        assignment.witness(W7)[row] = range_chunks[3];
                        assignment.witness(W8)[row] = xi;
                        row++;
                        assignment.witness(W0)[row] = range_chunks[4];
                        assignment.witness(W1)[row] = range_chunks[5];
                        assignment.witness(W2)[row] = range_chunks[6];
                        assignment.witness(W3)[row] = range_chunks[7];
                        assignment.witness(W4)[row] = range_chunks[8];
                        assignment.witness(W5)[row] = range_chunks[9];
                        assignment.witness(W6)[row] = range_chunks[10];
                        assignment.witness(W7)[row] = range_chunks[11];
                        bool c = 1;
                        if (range_chunks[0] > (base << 22) - 20) {
                            c = 0;
                        }
                        assignment.witness(W8)[row] = c;
                        return result_type(component_start_row);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t first_selector_index) {
                        typename BlueprintFieldType::integral_type base = 1;
                        auto constraint_1 = bp.add_constraint(
                            var(W0, 0) - (var(W4, 0) + var(W5, 0) * (base << 22) + var(W6, 0) * (base << 44)));
                        auto constraint_2 = bp.add_constraint(
                            var(W1, 0) - (var(W7, 0) + var(W0, +1) * (base << 22) + var(W1, +1) * (base << 44)));
                        auto constraint_3 = bp.add_constraint(
                            var(W2, 0) - (var(W2, +1) + var(W3, +1) * (base << 22) + var(W4, +1) * (base << 44)));
                        auto constraint_4 = bp.add_constraint(
                            var(W3, 0) - (var(W5, +1) + var(W6, +1) * (base << 21) + var(W7, +1) * (base << 42)));

                        snark::plonk_constraint<BlueprintFieldType> sum =
                            var(W5, 0) + var(W6, 0) + var(W7, 0) + var(W0, +1) + var(W1, +1) + var(W2, +1) +
                            var(W3, +1) + var(W4, +1) + var(W5, +1) + var(W6, +1) + var(W7, +1) - 2 * (base << 21) -
                            8 * (base << 22) - (base << 15) + 11;
                        auto constraint_5 = bp.add_constraint(sum * (var(W8, 0) * sum - 1));
                        auto constraint_6 =
                            bp.add_constraint(var(W8, 0) * sum + (1 - var(W8, 0) * sum) * var(W8, +1) - 1);

                        bp.add_gate(first_selector_index,
                                    {
                                        constraint_1,
                                        constraint_2,
                                        constraint_3,
                                        constraint_4,
                                        constraint_5,
                                        constraint_6,
                                    });
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        bp.add_copy_constraint({{W0, static_cast<int>(row), false}, params.input[0]});
                        bp.add_copy_constraint({{W1, static_cast<int>(row), false}, params.input[1]});
                        bp.add_copy_constraint({{W2, static_cast<int>(row), false}, params.input[2]});
                        bp.add_copy_constraint({{W3, static_cast<int>(row), false}, params.input[3]});
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_REDUCTION_HPP
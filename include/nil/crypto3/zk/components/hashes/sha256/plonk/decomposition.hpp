//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the DECOMPOSITION component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_DECOMPOSITION_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_DECOMPOSITION_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>
namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class decomposition;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4,
                         std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8>
                class decomposition<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                    CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                public:
                    constexpr static const std::size_t rows_amount = 3;
                    constexpr static const std::size_t selector_seed = 0x0FFE;
                    constexpr static const std::size_t gates_amount = 3;
                    struct params_type {
                        std::array<var, 2> data;
                    };

                    struct result_type {
                        std::array<var, 8> output;

                        result_type(std::size_t start_row_index) {
                            output = {var(W0, start_row_index + 1, false), var(W1, start_row_index + 1, false),
                                      var(W2, start_row_index + 1, false), var(W3, start_row_index + 1, false),
                                      var(W4, start_row_index + 1, false), var(W5, start_row_index + 1, false),
                                      var(W6, start_row_index + 1, false), var(W7, start_row_index + 1, false)};
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         std::size_t start_row_index) {
                        std::size_t j = start_row_index + 1;
                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, j);
                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        std::array<typename ArithmetizationType::field_type::integral_type, 2> data = {
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.data[0]).data),
                            typename ArithmetizationType::field_type::integral_type(
                                assignment.var_value(params.data[1]).data)};
                        std::array<typename ArithmetizationType::field_type::integral_type, 16> range_chunks;
                        std::size_t shift = 0;

                        for (std::size_t i = 0; i < 8; i++) {
                            range_chunks[i] = (data[0] >> shift) & ((1 << 16) - 1);
                            assignment.witness(i)[row] = range_chunks[i];
                            range_chunks[i + 8] = (data[1] >> shift) & ((1 << 16) - 1);
                            assignment.witness(i)[row + 2] = range_chunks[i + 8];
                            shift += 16;
                        }

                        assignment.witness(8)[row] = data[0];
                        assignment.witness(8)[row + 2] = data[1];

                        assignment.witness(0)[row + 1] = range_chunks[1] * (1 << 16) + range_chunks[0];
                        assignment.witness(1)[row + 1] = range_chunks[3] * (1 << 16) + range_chunks[2];
                        assignment.witness(2)[row + 1] = range_chunks[5] * (1 << 16) + range_chunks[4];
                        assignment.witness(3)[row + 1] = range_chunks[7] * (1 << 16) + range_chunks[6];
                        assignment.witness(4)[row + 1] = range_chunks[9] * (1 << 16) + range_chunks[8];
                        assignment.witness(5)[row + 1] = range_chunks[11] * (1 << 16) + range_chunks[10];
                        assignment.witness(6)[row + 1] = range_chunks[13] * (1 << 16) + range_chunks[12];
                        assignment.witness(7)[row + 1] = range_chunks[15] * (1 << 16) + range_chunks[14];

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t first_selector_index) {

                        std::size_t selector_index = first_selector_index;

                        auto constraint_1 =
                            bp.add_constraint(var(W8, -1) - (var(W0, 0) + var(W1, 0) * 0x100000000_cppui255 +
                                                             var(W2, 0) * 0x10000000000000000_cppui255 +
                                                             var(W3, 0) * 0x1000000000000000000000000_cppui255));
                        auto constraint_2 =
                            bp.add_constraint(var(W8, 1) - (var(W4, 0) + var(W5, 0) * 0x100000000_cppui255 +
                                                            var(W6, 0) * 0x10000000000000000_cppui255 +
                                                            var(W7, 0) * 0x1000000000000000000000000_cppui255));
                        auto constraint_3 = bp.add_constraint(var(W0, 0) - (var(W0, -1) + var(W1, -1) * (1 << 16)));
                        auto constraint_4 = bp.add_constraint(var(W1, 0) - (var(W2, -1) + var(W3, -1) * (1 << 16)));
                        auto constraint_5 = bp.add_constraint(var(W2, 0) - (var(W4, -1) + var(W5, -1) * (1 << 16)));
                        auto constraint_6 = bp.add_constraint(var(W3, 0) - (var(W6, -1) + var(W7, -1) * (1 << 16)));
                        auto constraint_7 = bp.add_constraint(var(W4, 0) - (var(W0, +1) + var(W1, +1) * (1 << 16)));
                        auto constraint_8 = bp.add_constraint(var(W5, 0) - (var(W2, +1) + var(W3, +1) * (1 << 16)));
                        auto constraint_9 = bp.add_constraint(var(W6, 0) - (var(W4, +1) + var(W5, +1) * (1 << 16)));
                        auto constraint_10 = bp.add_constraint(var(W7, 0) - (var(W6, +1) + var(W7, +1) * (1 << 16)));
                        bp.add_gate(selector_index,
                                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                                     constraint_7, constraint_8, constraint_9, constraint_10});
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t start_row_index) {
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_DECOMPOSITION_HPP

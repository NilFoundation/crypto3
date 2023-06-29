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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_TREE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_TREE_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/hashes/sha2/plonk/sha256.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
            class merkle_tree;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                     std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                     std::size_t W6, std::size_t W7, std::size_t W8>
            class merkle_tree<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType,
                              W0, W1, W2, W3, W4, W5, W6, W7, W8> {

                typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using var = snark::plonk_variable<BlueprintFieldType>;

                using sha256_component =
                    sha256<ArithmetizationType, BlueprintFieldType, W0, W1, W2, W3, W4, W5, W6, W7, W8>;

            public:
                constexpr static const std::size_t rows_amount = 1023 * sha256_component::rows_amount;

                struct params_type {
                    std::array<var, 2048> data;
                };

                struct allocated_data_type {
                    allocated_data_type() {
                        previously_allocated = false;
                    }

                    // TODO access modifiers
                    bool previously_allocated;
                    std::array<std::size_t, 1> selectors;
                };

                struct result_type {
                    std::array<var, 2> output = {var(0, 0, false), var(0, 0, false)};

                    result_type(std::size_t component_start_row) {
                        std::array<var, 2> output = {var(W0, component_start_row + rows_amount - 1, false),
                                                     var(W1, component_start_row + rows_amount - 1, false)};
                    }
                };

                static std::size_t allocate_rows(blueprint<ArithmetizationType> &bp) {
                    return bp.allocate_rows(rows_amount);
                }

                static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                    blueprint_assignment_table<ArithmetizationType> &assignment,
                                                    const params_type &params,
                                                    allocated_data_type &allocated_data,
                                                    std::size_t component_start_row) {

                    generate_gates(bp, assignment, params, allocated_data, component_start_row);
                    generate_copy_constraints(bp, assignment, params, component_start_row);
                    return result_type(component_start_row);
                }

                static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        std::size_t component_start_row) {
                    std::size_t row = component_start_row;
                    std::array<var, 2048> data;
                    for (std::size_t i = 0; i < 2048; i++) {
                        data[i] = params.data[i];
                    }
                    int k;
                    for (std::size_t i = 11; i > -1; i -= 2) {
                        k = 0;
                        for (std::size_t j = 0; j < (1 << i); j += 4) {
                            std::array<var, 4> sha_blocks = {data[j], data[j + 1], data[j + 2], data[j + 3]};
                            typename sha256_component::params_type sha_params = {sha_blocks};
                            auto sha_output = sha256_component::generate_assignments(assignment, sha_params, row);
                            data[k] = sha_output.output[0];
                            data[k + 1] = sha_output.output[0];
                        }
                        k += 2;
                    }
                    return result_type(component_start_row);
                }

            private:
                static void generate_gates(blueprint<ArithmetizationType> &bp,
                                           blueprint_assignment_table<ArithmetizationType> &assignment,
                                           const params_type &params,
                                           allocated_data_type &allocated_data,
                                           std::size_t component_start_row) {
                    std::size_t row = component_start_row;
                    for (std::size_t i = 11; i > -1; i -= 2) {
                        for (std::size_t j = 0; j < (1 << i); j += 4) {
                            sha256_component::generate_gates(bp, assignment, allocated_data, row);
                        }
                    }
                }

                static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                      blueprint_assignment_table<ArithmetizationType> &assignment,
                                                      const params_type &params,
                                                      std::size_t component_start_row) {
                    std::size_t row = component_start_row;
                    for (std::size_t i = 11; i > -1; i -= 2) {
                        for (std::size_t j = 0; j < (1 << i); j += 4) {
                            sha256_component::generate_copy_constraints(bp, assignment, allocated_data, row);
                        }
                    }
                }
            };

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_MERKLE_TREE_HPP
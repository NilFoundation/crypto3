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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LIMBS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_LIMBS_HPP

#include <vector>
#include <array>
#include <iostream>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                ///////////////// From Limbs ////////////////////////////////
                // Recalculate field element from two 64-bit chunks
                // It's a part of transcript functionality
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L87
                // Input: x1 = [a_0, ..., a_63], x2 = [b_0, ..., b_63]
                // Output: y = [a_0, ...., a_63, b_0, ..., b_63]
                template<typename ArithmetizationType, std::size_t... WireIndexes>
                class from_limbs;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2>
                class from_limbs<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    W0,
                    W1,
                    W2> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0ff0;

                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var first_limb = var(0, 0, false);
                        var second_limb = var(0, 0, false);
                        params_type(std::array<var, 2> input) : first_limb(input[0]), second_limb(input[1]) {}
                        params_type(var first, var second) : first_limb(first), second_limb(second) {}
                    };

                    struct result_type {
                        var result = var(0, 0);

                        result_type(std::size_t component_start_row) {
                            result = var(W2, static_cast<int>(component_start_row), false, var::column_type::witness);
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        const std::size_t component_start_row) {

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
                        typename BlueprintFieldType::value_type first_limb =
                            assignment.var_value(params.first_limb);
                        typename BlueprintFieldType::value_type second_limb =
                            assignment.var_value(params.second_limb);
                        assignment.witness(W0)[row] = first_limb;
                        assignment.witness(W1)[row] = second_limb;
                        typename BlueprintFieldType::value_type scalar = 2;
                        scalar = scalar.pow(64) * second_limb + first_limb;
                        assignment.witness(W2)[row] = scalar;

                        return result_type(component_start_row);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                        typename BlueprintFieldType::value_type scalar = 2;
                        auto constraint_1 = bp.add_constraint(var(W0, 0) + var(W1, 0) * scalar.pow(64) - var(W2, 0));

                        bp.add_gate(first_selector_index, {constraint_1});
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                          blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                          const params_type &params,
                                                          std::size_t component_start_row = 0) {

                        bp.add_copy_constraint({{W0, static_cast<int>(component_start_row), false},
                                                {params.first_limb.index, params.first_limb.rotation,
                                                 false, params.first_limb.type}});
                        bp.add_copy_constraint({{W1, static_cast<int>(component_start_row), false},
                                                {params.second_limb.index, params.second_limb.rotation,
                                                 false, params.second_limb.type}});
                    }
                };

                ///////////////// To Limbs ////////////////////////////////
                // Split field element into four 64-bit chunks
                // It's a part of transcript functionality
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L110
                // Input: x = [a_0, ...., a255]
                // Output: y0 = [a_0, ..., a_63], y1 = [a_64, ..., a_127], y2 = [a_128, ..., a_191], y3 = [a_192, ..., a_255]
                template<typename ArithmetizationType, std::size_t... WireIndexes>
                class to_limbs;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4>
                class to_limbs<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    W0, W1, W2, W3, W4> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0ff1;

                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var param = var(0, 0, false);

                        params_type(var value) : param(value) {}
                    };

                    struct result_type {
                        std::array<var, 4> result;

                        result_type(std::size_t component_start_row) {
                            result = {var(W1, static_cast<int>(component_start_row), false, var::column_type::witness),
                                    var(W2, static_cast<int>(component_start_row), false, var::column_type::witness),
                                    var(W3, static_cast<int>(component_start_row), false, var::column_type::witness),
                                    var(W4, static_cast<int>(component_start_row), false, var::column_type::witness)};
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        const std::size_t component_start_row) {

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
                        typename BlueprintFieldType::value_type value =
                            assignment.var_value(params.param);
                        auto value_data = value.data;
                        auto shifted_data = value_data >> 64 << 64;
                        assignment.witness(W0)[row].data = value_data;
                        assignment.witness(W1)[row].data = value_data - shifted_data;
                        value_data = value_data >> 64;
                        shifted_data = shifted_data >> 64 >> 64 << 64;
                        assignment.witness(W2)[row].data = value_data - shifted_data;
                        value_data = value_data >> 64;
                        shifted_data = shifted_data >> 64 >> 64 << 64;
                        assignment.witness(W3)[row].data = value_data - shifted_data;
                        value_data = value_data >> 64;
                        assignment.witness(W4)[row].data = value_data;

                        return result_type(component_start_row);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                        typename BlueprintFieldType::value_type scalar = 2;
                        auto constraint_1 = bp.add_constraint(var(W1, 0) + var(W2, 0) * scalar.pow(64) +
                                                            var(W3, 0) * scalar.pow(128) + var(W4, 0) * scalar.pow(192) - var(W0, 0));

                        bp.add_gate(first_selector_index, {constraint_1});
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                          blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                          const params_type &params,
                                                          std::size_t component_start_row = 0) {

                        bp.add_copy_constraint({{W0, static_cast<int>(component_start_row), false},
                                                {params.param.index, params.param.rotation, false, params.param.type}});
                    }
                };

            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP

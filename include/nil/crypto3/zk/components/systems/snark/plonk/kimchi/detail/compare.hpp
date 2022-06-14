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

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                ///////////////// Compare Value with Constant ////////////////////////////////
                // Constatnt is pallas base field modulus
                // Return 0, if value >= constant
                // Return 1 otherwise
                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class compare_with_const;

                template<typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1>
                class compare_with_const<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type, ArithmetizationParams>,
                    CurveType,
                    W0,
                    W1> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0ff8;

                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var value = var(0, 0, false);
                        params_type(var val) : value(val) {}
                    };

                    struct result_type {
                        var result = var(0, 0);

                        result_type(std::size_t component_start_row) {
                            result = var(W1, static_cast<int>(component_start_row), false, var::column_type::witness);
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        const std::size_t component_start_row) {

                        generate_assignments_constants(bp, assignment, params, start_row_index);
                        var const = var(0, start_row_index, false, var::column_type::constant);

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
                            assignment.var_value(params.value);
                        assignment.witness(W0)[row] = value;

                        return result_type(component_start_row);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                        auto constraint_1 = bp.add_constraint();

                        bp.add_gate(first_selector_index, {constraint_1});
                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                          blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                          const params_type &params,
                                                          std::size_t component_start_row = 0) {

                        bp.add_copy_constraint({{W0, static_cast<int>(component_start_row), false},
                                                {params.value.index, params.value.rotation,
                                                 false, params.value.type}});
                    }

                    static void generate_assignments_constants(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {

                        assignment.constant(0)[start_row_index] = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255;
                    }

                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP

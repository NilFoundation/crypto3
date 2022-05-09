//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_OPERATIONS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_FIELD_OPERATIONS_HPP

#include <cmath>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         std::size_t... WireIndexes>
                class multiplication;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2>
                class multiplication<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    W0, W1, W2>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0f01;

                    template<typename ComponentType, typename ArithmetizationType>
                    friend typename std::enable_if<
                        (!(has_static_member_function_generate_circuit<ComponentType,
                                typename ComponentType::result_type,
                            boost::mpl::vector<blueprint<ArithmetizationType> &,
                                blueprint_public_assignment_table<ArithmetizationType> &,
                                const typename ComponentType::params_type &,
                                const std::size_t>>::value)),
                            typename ComponentType::result_type>::type
                        generate_circuit(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const typename ComponentType::params_type &params,
                            const std::size_t start_row_index);
                    
                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var x = var(0, 0, false);
                        var y = var(0, 0, false);
                    };

                    struct result_type {
                        var res = var(0, 0, false);
                        result_type(const params_type &params,
                            const std::size_t &start_row_index) {
                            res = var(W2, start_row_index, false, var::column_type::witness);
                        }
                        result_type() {}
                    };

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType>
                                &assignment,
                            const params_type params,
                            const std::size_t start_row_index){

                        const std::size_t j = start_row_index;
                        
                        assignment.witness(W0)[j] = assignment.var_value(params.x);
                        assignment.witness(W1)[j] = assignment.var_value(params.y);
                        assignment.witness(W2)[j] = assignment.var_value(params.x) * assignment.var_value(params.y);

                        return result_type(params, start_row_index);
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment, 
                        const params_type params,
                        const std::size_t first_selector_index) {

                        auto constraint_1 = bp.add_constraint(
                            var(W0, 0) * var(W1, 0) - var(W2, 0));
                        
                        bp.add_gate(first_selector_index, {constraint_1});
                    }

                    static void generate_copy_constraints(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type params,
                            const std::size_t start_row_index){

                        std::size_t public_input_column_index = 0;

                        const std::size_t j = start_row_index;
                        var component_x = var(W0, static_cast<int>(j), false);
                        var component_y = var(W1, static_cast<int>(j), false);
                        bp.add_copy_constraint({component_x, params.x});
                        bp.add_copy_constraint({component_y, params.y});
                    }
                };


                template<typename ArithmetizationType,
                         std::size_t... WireIndexes>
                class addition;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2>
                class addition<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    W0, W1, W2>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0f01;

                    template<typename ComponentType, typename ArithmetizationType>
                    friend typename std::enable_if<
                        (!(has_static_member_function_generate_circuit<ComponentType,
                                typename ComponentType::result_type,
                            boost::mpl::vector<blueprint<ArithmetizationType> &,
                                blueprint_public_assignment_table<ArithmetizationType> &,
                                const typename ComponentType::params_type &,
                                const std::size_t>>::value)),
                            typename ComponentType::result_type>::type
                        generate_circuit(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const typename ComponentType::params_type &params,
                            const std::size_t start_row_index);
                    
                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var x = var(0, 0, false);
                        var y = var(0, 0, false);
                    };

                    struct result_type {
                        var res = var(0, 0, false);
                        result_type(const params_type &params,
                            const std::size_t &start_row_index) {
                            res = var(W2, start_row_index, false, var::column_type::witness);
                        }
                        result_type() {}
                    };

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType>
                                &assignment,
                            const params_type &params,
                            const std::size_t start_row_index){

                        const std::size_t j = start_row_index;
                        
                        assignment.witness(W0)[j] = assignment.var_value(params.x);
                        assignment.witness(W1)[j] = assignment.var_value(params.y);
                        assignment.witness(W2)[j] = assignment.var_value(params.x) + assignment.var_value(params.y);

                        return result_type(params, start_row_index);
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment, 
                        const params_type &params,
                        const std::size_t first_selector_index) {

                        auto constraint_1 = bp.add_constraint(
                            var(W0, 0) + var(W1, 0) - var(W2, 0));
                        
                        bp.add_gate(first_selector_index, {constraint_1});
                    }

                    static void generate_copy_constraints(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t start_row_index){

                        std::size_t public_input_column_index = 0;

                        const std::size_t j = start_row_index;
                        var component_x = var(W0, static_cast<int>(j), false);
                        var component_y = var(W1, static_cast<int>(j), false);
                        bp.add_copy_constraint({component_x, params.x});
                        bp.add_copy_constraint({component_y, params.y});
                    }
                };


                template<typename ArithmetizationType,
                         std::size_t... WireIndexes>
                class division;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2>
                class division<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    W0, W1, W2>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0f01;

                    template<typename ComponentType, typename ArithmetizationType>
                    friend typename std::enable_if<
                        (!(has_static_member_function_generate_circuit<ComponentType,
                                typename ComponentType::result_type,
                            boost::mpl::vector<blueprint<ArithmetizationType> &,
                                blueprint_public_assignment_table<ArithmetizationType> &,
                                const typename ComponentType::params_type &,
                                const std::size_t>>::value)),
                            typename ComponentType::result_type>::type
                        generate_circuit(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const typename ComponentType::params_type &params,
                            const std::size_t start_row_index);
                    
                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var x = var(0, 0, false);
                        var y = var(0, 0, false);
                    };

                    struct result_type {
                        var res = var(0, 0, false);
                        result_type(const params_type &params,
                            const std::size_t &start_row_index) {
                            res = var(W2, start_row_index, false, var::column_type::witness);
                        }
                        result_type() {}
                    };

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType>
                                &assignment,
                            const params_type &params,
                            const std::size_t start_row_index){

                        const std::size_t j = start_row_index;
                        
                        assignment.witness(W0)[j] = assignment.var_value(params.x);
                        assignment.witness(W1)[j] = assignment.var_value(params.y);
                        assignment.witness(W2)[j] = assignment.var_value(params.x) / assignment.var_value(params.y);

                        return result_type(params, start_row_index);
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment, 
                        const params_type &params,
                        const std::size_t first_selector_index) {

                        auto constraint_1 = bp.add_constraint(
                            var(W1, 0) * var(W2, 0) - var(W0, 0));
                        
                        bp.add_gate(first_selector_index, {constraint_1});
                    }

                    static void generate_copy_constraints(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t start_row_index){

                        std::size_t public_input_column_index = 0;

                        const std::size_t j = start_row_index;
                        var component_x = var(W0, static_cast<int>(j), false);
                        var component_y = var(W1, static_cast<int>(j), false);
                        bp.add_copy_constraint({component_x, params.x});
                        bp.add_copy_constraint({component_y, params.y});
                    }
                };


                template<typename ArithmetizationType,
                         std::size_t... WireIndexes>
                class subtraction;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2>
                class subtraction<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    W0, W1, W2>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0f01;

                    template<typename ComponentType, typename ArithmetizationType>
                    friend typename std::enable_if<
                        (!(has_static_member_function_generate_circuit<ComponentType,
                                typename ComponentType::result_type,
                            boost::mpl::vector<blueprint<ArithmetizationType> &,
                                blueprint_public_assignment_table<ArithmetizationType> &,
                                const typename ComponentType::params_type &,
                                const std::size_t>>::value)),
                            typename ComponentType::result_type>::type
                        generate_circuit(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const typename ComponentType::params_type &params,
                            const std::size_t start_row_index);
                    
                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var x = var(0, 0, false);
                        var y = var(0, 0, false);
                    };

                    struct result_type {
                        var res = var(0, 0, false);
                        result_type(const params_type &params,
                            const std::size_t &start_row_index) {
                            res = var(W2, start_row_index, false, var::column_type::witness);
                        }
                        result_type() {}
                    };

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType>
                                &assignment,
                            const params_type params,
                            const std::size_t start_row_index){

                        const std::size_t j = start_row_index;
                        
                        assignment.witness(W0)[j] = assignment.var_value(params.x);
                        assignment.witness(W1)[j] = assignment.var_value(params.y);
                        assignment.witness(W2)[j] = assignment.var_value(params.x) - assignment.var_value(params.y);

                        return result_type(params, start_row_index);
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment, 
                        const params_type params,
                        const std::size_t first_selector_index) {

                        auto constraint_1 = bp.add_constraint(
                            var(W0, 0) - var(W1, 0) - var(W2, 0));
                        
                        bp.add_gate(first_selector_index, {constraint_1});
                    }

                    static void generate_copy_constraints(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type params,
                            const std::size_t start_row_index){

                        std::size_t public_input_column_index = 0;

                        const std::size_t j = start_row_index;
                        var component_x = var(W0, static_cast<int>(j), false);
                        var component_y = var(W1, static_cast<int>(j), false);
                        bp.add_copy_constraint({component_x, params.x});
                        bp.add_copy_constraint({component_y, params.y});
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_UNIFIED_ADDITION_COMPONENT_11_WIRES_HPP

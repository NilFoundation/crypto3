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

#ifndef CRYPTO3_ZK_BLUEPRINT_FIXED_BASE_MULTIPLICATION_EDWARD25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_FIXED_BASE_MULTIPLICATION_EDWARD25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/multiplication.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/addition.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/sum_multiplication.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/c_multiplication.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/multiplication_add_c.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/sum_of_squares.hpp>


namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class fixed_base_multiplication;

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
                class fixed_base_multiplication<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using multiplication_component = multiplication<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using c_multiplication_component = c_multiplication<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using addition_component = addition<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using multiplication_add_c_component = multiplication_add_c<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using sum_multiplication_component = sum_multiplication<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using sum_of_squares_and_c_component = sum_of_squares_and_c<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    

                public:

                    constexpr static const std::size_t required_rows_amount = 10880;

                    struct params_type {
                        struct var_ec_point {
                            var x;
                            var y;
                        };
                        
                        var_ec_point T;
                        var k;
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

                        result_type(const std::size_t &component_start_row) {
                            std::array<var, 2> output = {var(W0, component_start_row + required_rows_amount - 1, false),
                            var(W1, component_start_row + required_rows_amount - 1, false)};
                        }
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(required_rows_amount);
                    }

                    static result_type generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t &component_start_row) {

                        generate_gates(bp, assignment, params, allocated_data, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);
                        return result_type(component_start_row);
                    }

                    static result_type generate_assignments(
                        blueprint_assignment_table<ArithmetizationType>
                            &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        std::array<bool, 253> bits = {false};
                        typename BlueprintFieldType::value_type k = assignment.var_value(params.k);
                        typename CurveType::scalar_field_type::integral_type integral_k = typename CurveType::scalar_field_type::integral_type(k.data);
                        var T_x = params.T.x;
                        var T_y = params.T.y;
                        typename BlueprintFieldType::value_type T_x_value = assignment.var_value(params.T.x);
                        typename BlueprintFieldType::value_type T_y_value = assignment.var_value(params.T.y);
                        typename CurveType::template 
                        g1_type<algebra::curves::coordinates::affine>::value_type T(T_x_value, T_y_value);
                        g1_type<algebra::curves::coordinates::affine>::value_type P = T;
                        for (std::size_t i = 0; i < 253; i++) {
                            b = multiprecision::bit_test(integral_k, i);

                            row+=sum_of_squares_and_c_component::required_rows_amount;

                        }
                        
                        return result_type(component_start_row);
                    }

                private:

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        
                        
                        
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        
                        
                    }

                    
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
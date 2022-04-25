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

#ifndef CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP

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
                class decomposition;

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
                class decomposition<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    constexpr static const std::size_t rows_amount = 50957;

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
                            std::array<var, 2> output = {var(W0, component_start_row + rows_amount - 1, false),
                            var(W1, component_start_row + rows_amount - 1, false)};
                        }
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(rows_amount);
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

                            row+=sum_of_squares_and_c_component::rows_amount;

                            auto t1 = sum_of_squares_and_c_component::generate_assigments(assigment, sum_of_squares_and_c_component::params_type(T_x, T_y), row);
                            row+=sum_of_squares_and_c_component::rows_amount;

                            auto t2 = multiplication_component::generate_assigments(assigment, multiplication_component::params_type(t0.output[0], t1.output[0]), row);
                            row+=multiplication_component::rows_amount;

                            auto t3 = sum_of_squares_and_c_component::generate_assigments(assigment, sum_of_squares_and_c_component::params_type(T_x, T_y), row);
                            row+=sum_of_squares_and_c_component::rows_amount;

                            auto t4 = c_multiplication_component::generate_assigments(assigment, c_multiplication_component::params_type(T_x, T_y), row);
                            row+=c_multiplication_component::rows_amount;

                            P = P * 2;
                            auto t5 = c_multiplication_component::generate_assigments(assigment, c_multiplication_component::params_type(P.X, P.Y), row);
                            row+=c_multiplication_component::rows_amount;

                            auto t6 = multiplication_component::generate_assigments(assigment, multiplication_component::params_type(t3.output[0], t4.output[0]), row);
                            row+=multiplication_component::rows_amount;

                            auto t7 = multiplication_component::generate_assigments(assigment, multiplication_component::params_type(t3.output[0], t6.output[0]), row);
                            row+=multiplication_component::rows_amount;

                            auto t8 = c_multiplication_component::generate_assigments(assigment, c_multiplication_component::params_type(d, t7.output[0]), row);
                            row+=c_multiplication_component::rows_amount;

                            T_y_value = T_y_value * b + (1 - b);

                            Q.X = T.X;
                            Q.Y = T_y_value;

                            auto R = P + Q;

                            auto t9 = sum_multiplication_component::generate_assigments(assigment, sum_multiplication_component::params_type(t8.output[0], t2.output[0], R.X), row);
                            row+=sum_multiplication_component::rows_amount;

                            auto z0 = multiplication_component::generate_assigments(assigment, multiplication_component::params_type(t4.output[0], t1.output[0]), row);
                            row+=multiplication_component::rows_amount;

                            auto z1 = multiplication_add_c_component::generate_assigments(assigment, multiplication_add_c_component::params_type(z0.output[0], P.Y, b), row);
                            row+=multiplication_add_c_component::rows_amount;
                            
                            auto z2 = multiplication_component::generate_assigments(assigment, multiplication_component::params_type(t3.output[0], t0.output[0]), row);
                            row+=multiplication_component::rows_amount;

                            auto z3 = c_multiplication_component::generate_assigments(assigment, c_multiplication_component::params_type(z2.output[0], P.X, b), row);
                            row+=c_multiplication_component::rows_amount;

                            auto z4 = addition_component::generate_assigments(assigment, addition_component::params_type(z3.output[0], z1.output[0]), row);
                            row+=addition_component::rows_amount;

                            auto c0 = sum_multiplication_component::generate_assigments(assigment, sum_multiplication_component::params_type(t2.output[0], t8.output[0], R.Y), row);
                            row+=multiplication_component::rows_amount;

                            auto d0 = c_multiplication_component::generate_assigments(assigment, c_multiplication_component::params_type(z0.output[0], P.X, b), row);
                            row+=c_multiplication_component::rows_amount;

                            auto d1 = sum_multiplication_component::generate_assigments(assigment, sum_multiplication_component::params_type(z2.output[0], P.Y, b), row);
                            row+=sum_multiplication_component::rows_amount;
                            
                            auto res = addition_component::generate_assigments(assigment, addition_component::params_type(d0.output[0], d1.output[0]), row);
                            row+=addition_component::rows_amount;

                            P = R;

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
                        
                        for (std::size_t i = 0; i < 253; i++) {

                            sum_of_squares_and_c_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_of_squares_and_c_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            sum_of_squares_and_c_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_of_squares_and_c_component::rows_amount;

                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            sum_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_multiplication_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            multiplication_add_c_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_add_c_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            addition_component::generate_gates(assigment, allocated_data, row);
                            row+=addition_component::rows_amount;

                            sum_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_multiplication_component::rows_amount;
                            
                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            sum_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_multiplication_component::rows_amount;

                            addition_component::generate_gates(assigment, allocated_data, row);
                            row+=addition_component::rows_amount;

                        }
                        
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        for (std::size_t i = 0; i < 253; i++) {

                            sum_of_squares_and_c_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_of_squares_and_c_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            sum_of_squares_and_c_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_of_squares_and_c_component::rows_amount;

                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            sum_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_multiplication_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            multiplication_add_c_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_add_c_component::rows_amount;

                            multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=multiplication_component::rows_amount;

                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            addition_component::generate_gates(assigment, allocated_data, row);
                            row+=addition_component::rows_amount;

                            sum_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_multiplication_component::rows_amount;
                            
                            c_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=c_multiplication_component::rows_amount;

                            sum_multiplication_component::generate_gates(assigment, allocated_data, row);
                            row+=sum_multiplication_component::rows_amount;

                            addition_component::generate_gates(assigment, allocated_data, row);
                            row+=addition_component::rows_amount;

                        }
                        
                    }

                    
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
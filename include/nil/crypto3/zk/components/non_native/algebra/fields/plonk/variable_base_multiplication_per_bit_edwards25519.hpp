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

#ifndef CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_PER_BIT_EDWARD25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_PER_BIT_EDWARD25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/multiplication.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/addition.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/subtraction.hpp>


namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                          typename Ed25519Type,
                         std::size_t... WireIndexes>
                class variable_base_multiplication_per_bit;

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
                class variable_base_multiplication_per_bit<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using non_native_range_component = zk::components::non_native_range<ArithmetizationType, CurveType, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8>;    
                    using multiplication_component = non_native_field_element_multiplication<ArithmetizationType, CurveType, Ed25519Type,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using addition_component = non_native_field_element_addition<ArithmetizationType, CurveType, Ed25519Type,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using subtraction_component = non_native_field_element_subtraction<ArithmetizationType, CurveType, Ed25519Type,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    constexpr static const std::size_t selector_seed = 0xff82;
                    

                public:

                    constexpr static const std::size_t rows_amount = 2 * non_native_range_component::rows_amount + 
                    16 * multiplication_component::rows_amount + 6 * addition_component::rows_amount +
                    3 * subtraction_component::rows_amount;

                    constexpr static const std::size_t gates_amount = 2;

                    struct params_type {
                        struct var_ec_point {
                            std::array<var, 4> x;
                            std::array<var, 4> y;
                        };
                        
                        var_ec_point T;
                        var_ec_point R;
                        var k;
                    };

                    struct result_type {
                        std::array<var, 2> output = {var(0, 0, false), var(0, 0, false)};

                        result_type(const std::size_t &component_start_row) {
                            std::array<var, 2> output = {var(W0, component_start_row + rows_amount - 1, false),
                            var(W1, component_start_row + rows_amount - 1, false)};
                        }
                    };

                    static result_type generate_assignments(
                        blueprint_assignment_table<ArithmetizationType>
                            &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                        typename Ed25519Type::base_field_type::integral_type base = 1;
                        typename Ed25519Type::base_field_type::integral_type b = typename Ed25519Type::base_field_type::integral_type(assignment.var_value(params.k).data);
                        std::array<var, 4> T_x = params.T.x;
                        std::array<var, 4> T_y = params.T.y;
                        std::array<typename CurveType::base_field_type::value_type, 4> T_x_array = {assignment.var_value(params.T.x[0]),
                        assignment.var_value(params.T.x[1]), assignment.var_value(params.T.x[2]), assignment.var_value(params.T.x[3])};
                        std::array<typename CurveType::base_field_type::value_type, 4> T_y_array = {assignment.var_value(params.T.y[0]),
                        assignment.var_value(params.T.y[1]), assignment.var_value(params.T.y[2]), assignment.var_value(params.T.y[3])};

                        std::array<var, 4> R_x = params.R.x;
                        std::array<var, 4> R_y = params.R.y;
                        std::array<typename CurveType::base_field_type::value_type, 4> R_x_array = {assignment.var_value(params.R.x[0]),
                        assignment.var_value(params.R.x[1]), assignment.var_value(params.R.x[2]), assignment.var_value(params.R.x[3])};
                        std::array<typename CurveType::base_field_type::value_type, 4> R_y_array = {assignment.var_value(params.R.y[0]),
                        assignment.var_value(params.R.y[1]), assignment.var_value(params.R.y[2]), assignment.var_value(params.R.y[3])};

                        typename Ed25519Type::template 
                        g1_type<algebra::curves::coordinates::affine>::value_type T((typename Ed25519Type::base_field_type::integral_type(T_x_array[0].data)
                         + typename Ed25519Type::base_field_type::integral_type(T_x_array[1].data) * (base << 66) +
                        typename Ed25519Type::base_field_type::integral_type(T_x_array[2].data) * (base << 132) +
                         typename Ed25519Type::base_field_type::integral_type(T_x_array[3].data) * (base << 198)),
                          (typename Ed25519Type::base_field_type::integral_type(T_y_array[0].data) + 
                          typename Ed25519Type::base_field_type::integral_type(T_y_array[1].data) * (base << 66) +
                        typename Ed25519Type::base_field_type::integral_type(T_y_array[2].data) * (base << 132) + 
                        typename Ed25519Type::base_field_type::integral_type(T_y_array[3].data) * (base << 198)));
                        typename Ed25519Type::template 
                        g1_type<algebra::curves::coordinates::affine>::value_type R((typename Ed25519Type::base_field_type::integral_type(R_x_array[0].data)
                         + typename Ed25519Type::base_field_type::integral_type(R_x_array[1].data) * (base << 66) +
                        typename Ed25519Type::base_field_type::integral_type(R_x_array[2].data) * (base << 132) +
                         typename Ed25519Type::base_field_type::integral_type(R_x_array[3].data) * (base << 198)),
                          (typename Ed25519Type::base_field_type::integral_type(R_y_array[0].data) + 
                          typename Ed25519Type::base_field_type::integral_type(R_y_array[1].data) * (base << 66) +
                        typename Ed25519Type::base_field_type::integral_type(R_y_array[2].data) * (base << 132) + 
                        typename Ed25519Type::base_field_type::integral_type(R_y_array[3].data) * (base << 198)));

                        typename Ed25519Type::template 
                        g1_type<algebra::curves::coordinates::affine>::value_type Q(T.X* b, (T.Y*b + (1 - b)));

                        typename Ed25519Type::template 
                        g1_type<algebra::curves::coordinates::affine>::value_type P = 2*R + Q;

                        typename Ed25519Type::base_field_type::integral_type mask = (base << 66) - 1;

                        typename Ed25519Type::base_field_type::integral_type Px_integral = typename Ed25519Type::base_field_type::integral_type(P.X.data);
                        std::array<typename Ed25519Type::base_field_type::integral_type, 4> x3 = {Px_integral & mask, (Px_integral >>66) & mask, (Px_integral >>132) & mask, (Px_integral >>198) & mask};
                        

                        typename Ed25519Type::base_field_type::integral_type Py_integral = typename Ed25519Type::base_field_type::integral_type(P.Y.data);
                        std::array<typename Ed25519Type::base_field_type::integral_type, 4> y3 = {Py_integral & mask, (Py_integral >>66) & mask, (Py_integral >>132) & mask, (Py_integral >>198) & mask};

                        assignment.witness(W0)[row] = x3[0];
                        assignment.witness(W1)[row] = x3[1];
                        assignment.witness(W2)[row] = x3[2];
                        assignment.witness(W3)[row] = x3[3];
                        std::array<var, 4>  P_x = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};

                        typename non_native_range_component::params_type range_params_x3 = {P_x};
                        non_native_range_component::generate_assignments(assignment, range_params_x3, row);
                        row+=non_native_range_component::rows_amount;

                        assignment.witness(W0)[row] = y3[0];
                        assignment.witness(W1)[row] = y3[1];
                        assignment.witness(W2)[row] = y3[2];
                        assignment.witness(W3)[row] = y3[3];
                        std::array<var, 4>  P_y = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};
                        typename non_native_range_component::params_type range_params_y3 = {P_y};
                        non_native_range_component::generate_assignments(assignment, range_params_y3, row);
                        row+=non_native_range_component::rows_amount;

                        std::cout<<"Rx: "<<assignment.var_value(R_x[0]).data<<" "<<assignment.var_value(R_x[1]).data<<" "<<assignment.var_value(R_x[2]).data<<" "
                        <<assignment.var_value(R_x[3]).data<<std::endl;

                        auto s0 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({R_x, R_x}), row);
                        row+=multiplication_component::rows_amount;

                        std::cout<<"so: "<<assignment.var_value(s0.output[0]).data<<" "<<assignment.var_value(s0.output[1]).data<<" "<<assignment.var_value(s0.output[2]).data<<" "
                        <<assignment.var_value(s0.output[3]).data<<std::endl;

                        auto s1 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({R_y, R_y}), row);
                        row+=multiplication_component::rows_amount;

                        std::cout<<"s1: "<<assignment.var_value(s1.output[0]).data<<" "<<assignment.var_value(s1.output[1]).data<<" "<<assignment.var_value(s1.output[2]).data<<" "
                        <<assignment.var_value(s1.output[3]).data<<std::endl;

                        auto s2 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({R_x, R_y}), row);
                        row+=multiplication_component::rows_amount;

                        std::cout<<"s2: "<<assignment.var_value(s2.output[0]).data<<" "<<assignment.var_value(s2.output[1]).data<<" "<<assignment.var_value(s2.output[2]).data<<" "
                        <<assignment.var_value(s2.output[3]).data<<std::endl;

                        assignment.witness(W0)[row] = T_y_array[0];
                        assignment.witness(W1)[row] = T_y_array[1];
                        assignment.witness(W2)[row] = T_y_array[2];
                        assignment.witness(W3)[row] = T_y_array[3];
                        assignment.witness(W4)[row] = b;
                        assignment.witness(W5)[row] = b * T_y_array[0];
                        assignment.witness(W6)[row] = b * T_y_array[1];
                        assignment.witness(W7)[row] = b * T_y_array[2];
                        assignment.witness(W8)[row] = b * T_y_array[3];
                        std::array<var, 4> s3 = {var(W5, row), var(W6, row), var(W7, row), var(W8, row)};
                        row++;
                        assignment.witness(W0)[row] = T_x_array[0];
                        assignment.witness(W1)[row] = T_x_array[1];
                        assignment.witness(W2)[row] = T_x_array[2];
                        assignment.witness(W3)[row] = T_x_array[3];
                        assignment.witness(W4)[row] = b;
                        assignment.witness(W5)[row] = b * T_x_array[0];
                        assignment.witness(W6)[row] = b * T_x_array[1];
                        assignment.witness(W7)[row] = b * T_x_array[2];
                        assignment.witness(W8)[row] = b * T_x_array[3];
                        std::array<var, 4> s4 = {var(W5, row), var(W6, row), var(W7, row), var(W8, row)};
                        row++;

                        auto t0 = addition_component::generate_assignments(assignment, typename addition_component::params_type({s0.output, s1.output}), row);
                        row+=addition_component::rows_amount;

                        auto t1 = subtraction_component::generate_assignments(assignment, typename subtraction_component::params_type({s1.output, s0.output}), row);
                        row+=subtraction_component::rows_amount;

                        auto t2 = subtraction_component::generate_assignments(assignment, typename subtraction_component::params_type({s0.output, s1.output}), row);
                        row+=subtraction_component::rows_amount;

                        auto t3 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({s3, R_x}), row);
                        row+=multiplication_component::rows_amount;

                        typename BlueprintFieldType::value_type two = 2;
                        assignment.constant(0)[row] = two;
                        assignment.constant(0)[row + 1] = 0;
                        assignment.constant(0)[row + 2] = 0;
                        assignment.constant(0)[row + 3] = 0;
                        std::array<var, 4> two_var_array = {var(0, 0, false, var::column_type::constant), var(0, 1, false, var::column_type::constant),
                        var(0, 2, false, var::column_type::constant), var(0, 3, false, var::column_type::constant)};

                        auto t4 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({s2.output, two_var_array}), row);
                        row+=multiplication_component::rows_amount;

                        
                        typename BlueprintFieldType::integral_type d = typename BlueprintFieldType::integral_type((typename BlueprintFieldType::value_type(121665/121666)).data);
                        assignment.constant(0)[row + 4] = d & mask;
                        assignment.constant(0)[row + 5] = (d >> 66) & mask;
                        assignment.constant(0)[row + 6] = (d >> 132) & mask;
                        assignment.constant(0)[row + 7] = (d >> 192) & mask;
                        std::array<var, 4> d_var_array = {var(0, 4, false, var::column_type::constant), var(0, 5, false, var::column_type::constant),
                        var(0, 6, false, var::column_type::constant), var(0, 7, false, var::column_type::constant)};

                        auto t5 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({t4.output, d_var_array}), row);
                        row+=multiplication_component::rows_amount;

                        auto l0 = addition_component::generate_assignments(assignment, typename addition_component::params_type({two_var_array, t2.output}), row);
                        row+=addition_component::rows_amount;

                        std::cout<<"lo: "<<assignment.var_value(l0.output[0]).data<<" "<<assignment.var_value(l0.output[1]).data<<" "<<assignment.var_value(l0.output[2]).data<<" "
                        <<assignment.var_value(l0.output[3]).data<<std::endl;

                        std::cout<<"t1: "<<assignment.var_value(t1.output[0]).data<<" "<<assignment.var_value(t1.output[1]).data<<" "<<assignment.var_value(t1.output[2]).data<<" "
                        <<assignment.var_value(t1.output[3]).data<<std::endl;

                        auto l1 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({l0.output, t1.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto l2 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({t5.output, t0.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto l3 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({l2.output, t3.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto r0 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({l0.output, t4.output}), row);
                        row+=multiplication_component::rows_amount;

                        assignment.witness(W0)[row] = b;
                        assignment.witness(W1)[row] = (1 - b);
                        assignment.witness(W2)[row] = 0;
                        assignment.witness(W3)[row] = 0;
                        assignment.witness(W4)[row] = 0;
                        std::array<var, 4> b_var_array = {var(1, row), var(2, row),
                        var(3, row), var(4, row)};
                        row++;

                        auto r1 = addition_component::generate_assignments(assignment, typename addition_component::params_type({s3, b_var_array}), row);
                        row+=addition_component::rows_amount;

                        auto r2 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({r1.output, r0.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto r3 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({t0.output, t1.output}), row);
                        row+=multiplication_component::rows_amount;
                        
                        auto r4 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({r3.output, s4}), row);
                        row+=multiplication_component::rows_amount;

                        auto p0 = addition_component::generate_assignments(assignment, typename addition_component::params_type({l1.output, l3.output}), row);
                        row+=addition_component::rows_amount;

                        auto p1 = subtraction_component::generate_assignments(assignment, typename subtraction_component::params_type({l1.output, l3.output}), row);
                        row+=subtraction_component::rows_amount;

                        auto p2 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({p0.output, P_x}), row);
                        row+=multiplication_component::rows_amount;

                        auto p3 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({p0.output, P_y}), row);
                        row+=multiplication_component::rows_amount;

                        auto z0 = addition_component::generate_assignments(assignment, typename addition_component::params_type({r4.output, r2.output}), row);
                        row+=addition_component::rows_amount;

                        auto z1 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({r0.output, s4}), row);
                        row+=multiplication_component::rows_amount;

                        auto z2 = multiplication_component::generate_assignments(assignment, typename multiplication_component::params_type({r3.output, r1.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto z3 = addition_component::generate_assignments(assignment, typename addition_component::params_type({z1.output, z2.output}), row);
                        row+=addition_component::rows_amount;
                        
                        return result_type(component_start_row);
                    }

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index){

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;
                        if (selector_iterator == assignment.selectors_end()){
                            first_selector_index = assignment.allocate_selector(selector_seed,
                                gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second; 
                        }
                        std::size_t row = start_row_index;
                        std::array<var, 4>  P_x = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};

                        typename non_native_range_component::params_type range_params_x3 = {P_x};
                        non_native_range_component::generate_circuit(bp, assignment, range_params_x3, row);
                        row+=non_native_range_component::rows_amount;

                        std::array<var, 4>  P_y = {var(W0, row), var(W1, row), var(W2, row), var(W3, row)};
                        typename non_native_range_component::params_type range_params_y3 = {P_y};
                        non_native_range_component::generate_circuit(bp, assignment, range_params_y3, row);
                        row+=non_native_range_component::rows_amount;

                        std::array<var, 4> R_x = params.R.x;
                        std::array<var, 4> R_y = params.R.y;
                        std::array<var, 4> T_x = params.T.x;
                        std::array<var, 4> T_y = params.T.y;

                        auto s0 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({R_x, R_x}), row);
                        row+=multiplication_component::rows_amount;

                        auto s1 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({R_y, R_y}), row);
                        row+=multiplication_component::rows_amount;

                        auto s2 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({R_x, R_y}), row);
                        row+=multiplication_component::rows_amount;

                        assignment.enable_selector(first_selector_index, row, row + 2);
                        std::array<var, 4> s3 = {var(W5, row), var(W6, row), var(W7, row), var(W8, row)};
                        row++;
                        std::array<var, 4> s4 = {var(W5, row), var(W6, row), var(W7, row), var(W8, row)};
                        row++;

                        auto t0 = addition_component::generate_circuit(bp, assignment, typename addition_component::params_type({s0.output, s1.output}), row);
                        row+=addition_component::rows_amount;

                        auto t1 = subtraction_component::generate_circuit(bp, assignment, typename subtraction_component::params_type({s1.output, s0.output}), row);
                        row+=subtraction_component::rows_amount;

                        auto t2 = subtraction_component::generate_circuit(bp, assignment, typename subtraction_component::params_type({s0.output, s1.output}), row);
                        row+=subtraction_component::rows_amount;

                        auto t3 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({s3, R_x}), row);
                        row+=multiplication_component::rows_amount;

                        std::array<var, 4> two_var_array = {var(0, 0, false, var::column_type::constant), var(0, 1, false, var::column_type::constant),
                        var(0, 2, false, var::column_type::constant), var(0, 3, false, var::column_type::constant)};

                        auto t4 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({s2.output, two_var_array}), row);
                        row+=multiplication_component::rows_amount;

                        std::array<var, 4> d_var_array = {var(0, 4, false, var::column_type::constant), var(0, 5, false, var::column_type::constant),
                        var(0, 6, false, var::column_type::constant), var(0, 7, false, var::column_type::constant)};

                        auto t5 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({t4.output, d_var_array}), row);
                        row+=multiplication_component::rows_amount;

                        auto l0 = addition_component::generate_circuit(bp, assignment, typename addition_component::params_type({two_var_array, t2.output}), row);
                        row+=addition_component::rows_amount;

                        auto l1 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({l0.output, t1.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto l2 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({t5.output, t0.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto l3 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({l2.output, t3.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto r0 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({l0.output, t4.output}), row);
                        row+=multiplication_component::rows_amount;

                        std::array<var, 4> b_var_array = {var(1, row), var(2, row),
                        var(3, row), var(4, row)};
                        assignment.enable_selector(first_selector_index + 1, row);
                        row++;

                        auto r1 = addition_component::generate_circuit(bp, assignment, typename addition_component::params_type({s3, b_var_array}), row);
                        row+=addition_component::rows_amount;

                        auto r2 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({r1.output, r0.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto r3 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({t0.output, t1.output}), row);
                        row+=multiplication_component::rows_amount;
                        
                        auto r4 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({r3.output, s4}), row);
                        row+=multiplication_component::rows_amount;

                        auto p0 = addition_component::generate_circuit(bp, assignment, typename addition_component::params_type({l1.output, l3.output}), row);
                        row+=addition_component::rows_amount;

                        auto p1 = subtraction_component::generate_circuit(bp, assignment, typename subtraction_component::params_type({l1.output, l3.output}), row);
                        row+=subtraction_component::rows_amount;

                        auto p2 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({p0.output, P_x}), row);
                        row+=multiplication_component::rows_amount;

                        auto p3 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({p0.output, P_y}), row);
                        row+=multiplication_component::rows_amount;

                        auto z0 = addition_component::generate_circuit(bp, assignment, typename addition_component::params_type({r4.output, r2.output}), row);
                        row+=addition_component::rows_amount;

                        auto z1 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({r0.output, s4}), row);
                        row+=multiplication_component::rows_amount;

                        auto z2 = multiplication_component::generate_circuit(bp, assignment, typename multiplication_component::params_type({r3.output, r1.output}), row);
                        row+=multiplication_component::rows_amount;

                        auto z3 = addition_component::generate_circuit(bp, assignment, typename addition_component::params_type({z1.output, z2.output}), row);
                        row+=addition_component::rows_amount;

                        //generate_copy_constraints(bp, assignment, params, j);


                        return result_type(start_row_index);
                    }

                private:

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const params_type &params,
                        const std::size_t first_selector_index) {
                        auto constraint_1 = bp.add_constraint(
                            var(W5, 0) - var(W0, 0) * var(W4, 0));
                        auto constraint_2 = bp.add_constraint(
                            var(W6, 0) - var(W1, 0) * var(W4, 0));
                        auto constraint_3 = bp.add_constraint(
                            var(W7, 0) - var(W2, 0) * var(W4, 0));
                        auto constraint_4 = bp.add_constraint(
                            var(W8, 0) - var(W3, 0) * var(W4, 0));

                        auto constraint_5 = bp.add_constraint(
                            var(W1, 0) + var(W2, 0) + var(W3, 0) + var(W4, 0) - 1 + var(W0, 0));

                        bp.add_gate(first_selector_index, 
                            { constraint_1, constraint_2, constraint_3, constraint_4
                            
                        });
                        bp.add_gate(first_selector_index + 1, 
                            { constraint_5
                            
                        });
                        
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
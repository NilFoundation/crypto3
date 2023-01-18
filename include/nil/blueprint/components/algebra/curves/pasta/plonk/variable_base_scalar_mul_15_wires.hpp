//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>

namespace nil {
    namespace blueprint {
            namespace components {

                // Using results from https://arxiv.org/pdf/math/0208038.pdf
                // Input: x \in F_p, P \in E(F_p)
                // Output: y * P, where x = (y - 2^255 - 1) / 2 (if x is not -1, 0, 1)
                // Output: y * P, where x = (y - 2^255)         (on vesta curve if x is -1, 0, 1)

                // clang-format off
// _____________________________________________________________________________________________________________________________________________________
// |        |   W0   |   W1   |   W2    |   W3    |   W4    |   W5    |   W6    |   W7   |   W8   |   W9   |  W10   |  W11   |  W12   |  W13   |  W14   |
// |‾row‾0‾‾|‾‾ calculating 2T ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|
// | row 1  |  T.X   |  T.Y   | P[0].X  | p[0].Y  |  n      | n_next  |         | P[1].X | P[1].Y | P[2].X | P[2].Y | P[3].X | P[3].Y | P[4].X | P[4].Y |
// | row 2  | P[5].X | P[5].Y | bits[0] | bits[1] | bits[2] | bits[3] | bits[4] |   s0   |   s1   |   s2   |  s3    |  s4    |        |        |        | 
// | row 3  |  T.X   |  T.Y   | P[0].X  | p[0].Y  |  n      | n_next  |         | P[1].X | P[1].Y | P[2].X | P[2].Y | P[3].X | P[3].Y | P[4].X | P[4].Y |
// | row 4  | P[5].X | P[5].Y | bits[5] | bits[6] | bits[7] | bits[8] | bits[9] |   s0   |   s1   |   s2   |  s3    |  s4    |        |        |        |
// |        | ...                                                                                                                                       |
// |last row|    x   |    y   |   t0    |   t1    |   t2    |  n_next |   T.X   |  T.Y   |   m    |        |        |        |        |        |        |
//  ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
                // clang-format on

                ////////////////////////////////
                template<typename ConstFieldType>
                struct variable_base_scalar_mul_shifted_consts;

                template<>
                struct variable_base_scalar_mul_shifted_consts<typename nil::crypto3::algebra::curves::pallas> {
                    using FieldType = nil::crypto3::algebra::fields::pallas_base_field;

                    constexpr static const typename FieldType::value_type shifted_minus_one = 0x224698fc0994a8dd8c46eb2100000000_cppui255;
                    constexpr static const typename FieldType::value_type shifted_zero = 0x200000000000000000000000000000003369e57a0e5efd4c526a60b180000001_cppui255;
                    constexpr static const typename FieldType::value_type shifted_one = 0x224698fc0994a8dd8c46eb2100000001_cppui255;
                };

                template<>
                struct variable_base_scalar_mul_shifted_consts<typename nil::crypto3::algebra::curves::vesta> {
                    using FieldType = nil::crypto3::algebra::fields::vesta_base_field;

                    constexpr static const typename FieldType::value_type shifted_minus_one = 0x448d31f81299f237325a61da00000001_cppui255;
                    constexpr static const typename FieldType::value_type shifted_zero =      0x448d31f81299f237325a61da00000002_cppui255;
                    constexpr static const typename FieldType::value_type shifted_one =       0x448d31f81299f237325a61da00000003_cppui255;
                };
                ////////////////////////////////

                template<typename ArithmetizationType, typename CurveType, std::uint32_t WitnessesAmount>
                class curve_element_variable_base_scalar_mul;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                class curve_element_variable_base_scalar_mul<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    15
                >: public plonk_component<BlueprintFieldType, ArithmetizationParams, 15, 1, 0> {

                    using add_component =
                        nil::blueprint::components::unified_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType, 11>;

                    using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 15, 1, 0>;

                public:
                    using var = typename component_type::var;
                    constexpr static const std::size_t mul_rows_amount = 102;
                    constexpr static const std::size_t add_component_rows_amount = add_component::rows_amount;
                    constexpr static const std::size_t rows_amount = add_component_rows_amount + mul_rows_amount + 1;
                    constexpr static const std::size_t gates_amount = 2;

                    constexpr static const typename BlueprintFieldType::value_type shifted_minus_one = variable_base_scalar_mul_shifted_consts<CurveType>::shifted_minus_one;
                    constexpr static const typename BlueprintFieldType::value_type shifted_zero = variable_base_scalar_mul_shifted_consts<CurveType>::shifted_zero;
                    constexpr static const typename BlueprintFieldType::value_type shifted_one = variable_base_scalar_mul_shifted_consts<CurveType>::shifted_one;

                    struct input_type {
                        struct var_ec_point {
                            var x;
                            var y;
                        };

                        var_ec_point T;
                        var b;
                    };

                    struct result_type {
                        var X;
                        var Y;
                        result_type(const curve_element_variable_base_scalar_mul &component, input_type &params, std::size_t start_row_index) {
                            X = var(component.W(0), start_row_index + component.rows_amount - 1, false, var::column_type::witness);
                            Y = var(component.W(1), start_row_index + component.rows_amount - 1, false, var::column_type::witness);
                        }
                        result_type(const curve_element_variable_base_scalar_mul &component, std::size_t start_row_index) {
                            X = var(component.W(0), start_row_index + component.rows_amount - 1, false, var::column_type::witness);
                            Y = var(component.W(1), start_row_index + component.rows_amount - 1, false, var::column_type::witness);
                        }
                    };

                    template <typename ContainerType>
                    curve_element_variable_base_scalar_mul(ContainerType witness):
                        component_type(witness, {}, {}){};

                    template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                    curve_element_variable_base_scalar_mul(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input):
                        component_type(witness, constant, public_input){};

                    curve_element_variable_base_scalar_mul(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                                   std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                                   std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                        component_type(witnesses, constants, public_inputs){};
                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                using plonk_curve_element_variable_base_scalar_mul =
                    curve_element_variable_base_scalar_mul<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        CurveType,
                        15
                    >;

                    template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                    typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type 
                        generate_assignments(
                            const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                            const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                            const std::uint32_t start_row_index) {

                        typename BlueprintFieldType::value_type b = var_value(assignment, instance_input.b);
                        typename BlueprintFieldType::value_type T_x = var_value(assignment, instance_input.T.x);
                        typename BlueprintFieldType::value_type T_y = var_value(assignment, instance_input.T.y);
                        typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type T(T_x,
                                                                                                                 T_y);

                        std::array<
                            typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type, 6>
                            P;
                        typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type Q;

                        typename CurveType::scalar_field_type::integral_type integral_b =
                            typename CurveType::scalar_field_type::integral_type(b.data);
                        const std::size_t scalar_size = 255;
                        nil::marshalling::status_type status;
                        std::array<bool, scalar_size> bits =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_b, status);

                        typename BlueprintFieldType::value_type n = 0;
                        typename BlueprintFieldType::value_type n_next = 0;

                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        unified_addition<ArithmetizationType, CurveType, 11> unified_addition_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8), component.W(9), 
                                        component.W(10)},{},{});

                        typename unified_addition<ArithmetizationType, CurveType, 11>::input_type addition_input = {{instance_input.T.x, instance_input.T.y},
                                                                               {instance_input.T.x, instance_input.T.y}};

                        typename unified_addition<ArithmetizationType, CurveType, 11>::result_type addition_res = 
                            generate_assignments(unified_addition_instance, assignment, addition_input, start_row_index);


                        typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type
                            T_doubled(var_value(assignment, addition_res.X), var_value(assignment, addition_res.Y));

                        std::size_t j = start_row_index + component.add_component_rows_amount;

                        for (std::size_t i = j; i < j + component.mul_rows_amount; i = i + 2) {
                            assignment.witness(component.W(0), i) = T.X;
                            assignment.witness(component.W(1), i) = T.Y;
                            if (i == j) {
                                P[0] = T_doubled;
                            } else {
                                P[0] = P[5];
                                n = n_next;
                            }
                            assignment.witness(component.W(2), i) = P[0].X;
                            assignment.witness(component.W(3), i) = P[0].Y;
                            assignment.witness(component.W(4), i) = n;
                            n_next = 32 * n + 16 * bits[((i - j) / 2) * 5] + 8 * bits[((i - j) / 2) * 5 + 1] +
                                     4 * bits[((i - j) / 2) * 5 + 2] + 2 * bits[((i - j) / 2) * 5 + 3] +
                                     bits[((i - j) / 2) * 5 + 4];
                            assignment.witness(component.W(5), i) = n_next;
                            Q.X = T.X;
                            Q.Y = (2 * bits[((i - j) / 2) * 5] - 1) * T.Y;
                            P[1] = (P[0] + Q) + P[0];
                            assignment.witness(component.W(7), i) = P[1].X;
                            assignment.witness(component.W(8), i) = P[1].Y;
                            assignment.witness(component.W(7), i + 1) = (P[0].Y - Q.Y) * (P[0].X - Q.X).inversed();
                            Q.Y = (2 * bits[((i - j) / 2) * 5 + 1] - 1) * T.Y;
                            P[2] = (P[1] + Q) + P[1];
                            assignment.witness(component.W(9), i) = P[2].X;
                            assignment.witness(component.W(10), i) = P[2].Y;
                            assignment.witness(component.W(8), i + 1) = (P[1].Y - Q.Y) * (P[1].X - Q.X).inversed();
                            Q.Y = (2 * bits[((i - j) / 2) * 5 + 2] - 1) * T.Y;
                            P[3] = (P[2] + Q) + P[2];
                            assignment.witness(component.W(11), i) = P[3].X;
                            assignment.witness(component.W(12), i) = P[3].Y;
                            assignment.witness(component.W(9), i + 1) = (P[2].Y - Q.Y) * (P[2].X - Q.X).inversed();
                            Q.Y = (2 * bits[((i - j) / 2) * 5 + 3] - 1) * T.Y;
                            P[4] = (P[3] + Q) + P[3];
                            assignment.witness(component.W(13), i) = P[4].X;
                            assignment.witness(component.W(14), i) = P[4].Y;
                            assignment.witness(component.W(10), i + 1) = (P[3].Y - Q.Y) * (P[3].X - Q.X).inversed();
                            Q.Y = (2 * bits[((i - j) / 2) * 5 + 4] - 1) * T.Y;
                            P[5] = (P[4] + Q) + P[4];
                            assignment.witness(component.W(0), i + 1) = P[5].X;
                            assignment.witness(component.W(1), i + 1) = P[5].Y;
                            assignment.witness(component.W(11), i + 1) = (P[4].Y - Q.Y) * (P[4].X - Q.X).inversed();
                            assignment.witness(component.W(2), i + 1) = bits[((i - j) / 2) * 5];
                            assignment.witness(component.W(3), i + 1) = bits[((i - j) / 2) * 5 + 1];
                            assignment.witness(component.W(4), i + 1) = bits[((i - j) / 2) * 5 + 2];
                            assignment.witness(component.W(5), i + 1) = bits[((i - j) / 2) * 5 + 3];
                            assignment.witness(component.W(6), i + 1) = bits[((i - j) / 2) * 5 + 4];
                        }
                        typename BlueprintFieldType::value_type m = ((n_next - component.shifted_minus_one)*
                        (n_next - component.shifted_zero)*(n_next - component.shifted_one));
                        typename BlueprintFieldType::value_type t0 = ( m == 0 ? 0 : m.inversed());
                        typename BlueprintFieldType::value_type t1 = ((n_next - component.shifted_minus_one) == 0) ? 0 : (n_next - component.shifted_minus_one).inversed();
                        typename BlueprintFieldType::value_type t2 = ((n_next - component.shifted_one)       == 0) ? 0 : (n_next - component.shifted_one).inversed();
                        typename BlueprintFieldType::value_type x;
                        typename BlueprintFieldType::value_type y;
                        if (n_next == component.shifted_minus_one) {
                            x = T.X;
                            y = -T.Y;
                        } else  {
                            if (n_next == component.shifted_zero) {
                                x = 0;
                                y = 0;
                            } else {
                                if (n_next == component.shifted_one) {
                                    x = T.X;
                                    y = T.Y;
                                } else {
                                    x = P[5].X;
                                    y = P[5].Y;
                                }
                            }
                        }
                        assignment.witness(component.W(2), start_row_index + component.rows_amount - 1) = t0;
                        assignment.witness(component.W(3), start_row_index + component.rows_amount - 1) = t1;
                        assignment.witness(component.W(4), start_row_index + component.rows_amount - 1) = t2;
                        assignment.witness(component.W(5), start_row_index + component.rows_amount - 1) = n_next;
                        assignment.witness(component.W(6), start_row_index + component.rows_amount - 1) = T.X;
                        assignment.witness(component.W(7), start_row_index + component.rows_amount - 1) = T.Y;
                        assignment.witness(component.W(8), start_row_index + component.rows_amount - 1) = m;
                        assignment.witness(component.W(0), start_row_index + component.rows_amount - 1) = x;
                        assignment.witness(component.W(1), start_row_index + component.rows_amount - 1) = y;

                        return typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                    typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type 
                        generate_circuit(
                            const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                            const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type &instance_input,
                            const std::uint32_t start_row_index) {

                        generate_assignments_constants(component, bp, assignment, instance_input, start_row_index);

                        auto selector_iterator = assignment.find_selector(component);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()){
                            first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                            generate_gates(component, bp, assignment, instance_input, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, start_row_index + component.add_component_rows_amount,
                                                   start_row_index + component.rows_amount - 4, 2);
                        assignment.enable_selector(first_selector_index + 1, start_row_index + component.rows_amount - 2);

                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        typename unified_addition<ArithmetizationType, CurveType, 11>::input_type addition_input = {{instance_input.T.x, instance_input.T.y},
                                                                               {instance_input.T.x, instance_input.T.y}};

                        unified_addition<ArithmetizationType, CurveType, 11> unified_addition_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8), component.W(9), 
                                        component.W(10)},{},{});

                        generate_circuit(unified_addition_instance, bp, assignment, addition_input, start_row_index);

                        generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                        return typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                        void generate_gates(
                            const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                            const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                            const std::size_t first_selector_index) {

                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        using var = typename curve_element_variable_base_scalar_mul<ArithmetizationType,  CurveType, 15>::var;

                        auto bit_check_1 = bp.add_bit_check(var(component.W(2), +1));
                        auto bit_check_2 = bp.add_bit_check(var(component.W(3), +1));
                        auto bit_check_3 = bp.add_bit_check(var(component.W(4), +1));
                        auto bit_check_4 = bp.add_bit_check(var(component.W(5), +1));
                        auto bit_check_5 = bp.add_bit_check(var(component.W(6), +1));

                        auto constraint_1 = bp.add_constraint((var(component.W(2), 0) - var(component.W(0), 0)) * var(component.W(7), +1) -
                                                              (var(component.W(3), 0) - (2 * var(component.W(2), +1) - 1) * var(component.W(1), 0)));
                        auto constraint_2 = bp.add_constraint((var(component.W(7), 0) - var(component.W(0), 0)) * var(component.W(8), +1) -
                                                              (var(component.W(8), 0) - (2 * var(component.W(3), +1) - 1) * var(component.W(1), 0)));
                        auto constraint_3 = bp.add_constraint((var(component.W(9), 0) - var(component.W(0), 0)) * var(component.W(9), +1) -
                                                              (var(component.W(10), 0) - (2 * var(component.W(4), +1) - 1) * var(component.W(1), 0)));
                        auto constraint_4 = bp.add_constraint((var(component.W(11), 0) - var(component.W(0), 0)) * var(component.W(10), +1) -
                                                              (var(component.W(12), 0) - (2 * var(component.W(5), +1) - 1) * var(component.W(1), 0)));
                        auto constraint_5 = bp.add_constraint((var(component.W(13), 0) - var(component.W(0), 0)) * var(component.W(11), +1) -
                                                              (var(component.W(14), 0) - (2 * var(component.W(6), +1) - 1) * var(component.W(1), 0)));

                        auto constraint_6 = bp.add_constraint(
                            (2 * var(component.W(3), 0) - var(component.W(7), 1) * (2 * var(component.W(2), 0) - var(component.W(7), 1).pow(2) + var(component.W(0), 0))) *
                                (2 * var(component.W(3), 0) - var(component.W(7), 1) * (2 * var(component.W(2), 0) - var(component.W(7), 1).pow(2) + var(component.W(0), 0))) -
                            ((2 * var(component.W(2), 0) - var(component.W(7), 1).pow(2) + var(component.W(0), 0)) *
                             (2 * var(component.W(2), 0) - var(component.W(7), 1).pow(2) + var(component.W(0), 0)) *
                             (var(component.W(7), 0) - var(component.W(0), 0) + var(component.W(7), 1).pow(2))));
                        auto constraint_7 = bp.add_constraint(
                            (2 * var(component.W(8), 0) - var(component.W(8), 1) * (2 * var(component.W(7), 0) - var(component.W(8), 1).pow(2) + var(component.W(0), 0))) *
                                (2 * var(component.W(8), 0) - var(component.W(8), 1) * (2 * var(component.W(7), 0) - var(component.W(8), 1).pow(2) + var(component.W(0), 0))) -
                            ((2 * var(component.W(7), 0) - var(component.W(8), 1).pow(2) + var(component.W(0), 0)) *
                             (2 * var(component.W(7), 0) - var(component.W(8), 1).pow(2) + var(component.W(0), 0)) *
                             (var(component.W(9), 0) - var(component.W(0), 0) + var(component.W(8), 1).pow(2))));
                        auto constraint_8 = bp.add_constraint(
                            (2 * var(component.W(10), 0) - var(component.W(9), 1) * (2 * var(component.W(9), 0) - var(component.W(9), 1).pow(2) + var(component.W(0), 0))) *
                                (2 * var(component.W(10), 0) - var(component.W(9), 1) * (2 * var(component.W(9), 0) - var(component.W(9), 1).pow(2) + var(component.W(0), 0))) -
                            ((2 * var(component.W(9), 0) - var(component.W(9), 1).pow(2) + var(component.W(0), 0)) *
                             (2 * var(component.W(9), 0) - var(component.W(9), 1).pow(2) + var(component.W(0), 0)) *
                             (var(component.W(11), 0) - var(component.W(0), 0) + var(component.W(9), 1).pow(2))));
                        auto constraint_9 = bp.add_constraint(
                            (2 * var(component.W(12), 0) - var(component.W(10), +1) * (2 * var(component.W(11), 0) - var(component.W(10), +1).pow(2) + var(component.W(0), 0))) *
                                (2 * var(component.W(12), 0) -
                                 var(component.W(10), +1) * (2 * var(component.W(11), 0) - var(component.W(10), +1).pow(2) + var(component.W(0), 0))) -
                            ((2 * var(component.W(11), 0) - var(component.W(10), +1).pow(2) + var(component.W(0), 0)) *
                             (2 * var(component.W(11), 0) - var(component.W(10), +1).pow(2) + var(component.W(0), 0)) *
                             (var(component.W(13), 0) - var(component.W(0), 0) + var(component.W(10), +1).pow(2))));
                        auto constraint_10 = bp.add_constraint(
                            (2 * var(component.W(14), 0) - var(component.W(11), +1) * (2 * var(component.W(13), 0) - var(component.W(11), +1).pow(2) + var(component.W(0), 0))) *
                                (2 * var(component.W(14), 0) -
                                 var(component.W(11), +1) * (2 * var(component.W(13), 0) - var(component.W(11), +1).pow(2) + var(component.W(0), 0))) -
                            ((2 * var(component.W(13), 0) - var(component.W(11), +1).pow(2) + var(component.W(0), 0)) *
                             (2 * var(component.W(13), 0) - var(component.W(11), +1).pow(2) + var(component.W(0), 0)) *
                             (var(component.W(0), 1) - var(component.W(0), 0) + var(component.W(11), +1).pow(2))));

                        auto constraint_11 = bp.add_constraint(
                            (var(component.W(8), 0) + var(component.W(3), 0)) * (2 * var(component.W(2), 0) - var(component.W(7), +1).pow(2) + var(component.W(0), 0)) -
                            ((var(component.W(2), 0) - var(component.W(7), 0)) *
                             (2 * var(component.W(3), 0) - var(component.W(7), +1) * (2 * var(component.W(2), 0) - var(component.W(7), +1).pow(2) + var(component.W(0), 0)))));
                        auto constraint_12 = bp.add_constraint(
                            (var(component.W(10), 0) + var(component.W(8), 0)) * (2 * var(component.W(7), 0) - var(component.W(8), +1).pow(2) + var(component.W(0), 0)) -
                            ((var(component.W(7), 0) - var(component.W(9), 0)) *
                             (2 * var(component.W(8), 0) - var(component.W(8), +1) * (2 * var(component.W(7), 0) - var(component.W(8), +1).pow(2) + var(component.W(0), 0)))));
                        auto constraint_13 = bp.add_constraint(
                            (var(component.W(12), 0) + var(component.W(10), 0)) * (2 * var(component.W(9), 0) - var(component.W(9), +1).pow(2) + var(component.W(0), 0)) -
                            ((var(component.W(9), 0) - var(component.W(11), 0)) *
                             (2 * var(component.W(10), 0) - var(component.W(9), +1) * (2 * var(component.W(9), 0) - var(component.W(9), +1).pow(2) + var(component.W(0), 0)))));
                        auto constraint_14 = bp.add_constraint(
                            (var(component.W(14), 0) + var(component.W(12), 0)) * (2 * var(component.W(11), 0) - var(component.W(10), +1).pow(2) + var(component.W(0), 0)) -
                            ((var(component.W(11), 0) - var(component.W(13), 0)) *
                             (2 * var(component.W(12), 0) - var(component.W(10), +1) * (2 * var(component.W(11), 0) - var(component.W(10), +1).pow(2) + var(component.W(0), 0)))));
                        auto constraint_15 = bp.add_constraint(
                            (var(component.W(1), +1) + var(component.W(14), 0)) * (2 * var(component.W(13), 0) - var(component.W(11), +1).pow(2) + var(component.W(0), 0)) -
                            ((var(component.W(13), 0) - var(component.W(0), +1)) *
                             (2 * var(component.W(14), 0) - var(component.W(11), +1) * (2 * var(component.W(13), 0) - var(component.W(11), +1).pow(2) + var(component.W(0), 0)))));

                        auto constraint_16 =
                            bp.add_constraint(var(component.W(5), 0) - (32 * (var(component.W(4), 0)) + 16 * var(component.W(2), +1) + 8 * var(component.W(3), +1) +
                                                            4 * var(component.W(4), +1) + 2 * var(component.W(5), +1) + var(component.W(6), +1)));

                        bp.add_gate(first_selector_index,
                                    {bit_check_1,   bit_check_2,   bit_check_3,   bit_check_4,   bit_check_5,
                                     constraint_1,  constraint_2,  constraint_3,  constraint_4,  constraint_5,
                                     constraint_6,  constraint_7,  constraint_8,  constraint_9,  constraint_10,
                                     constraint_11, constraint_12, constraint_13, constraint_14, constraint_15,
                                     constraint_16});
                        std::size_t selector_index_2 = first_selector_index + 1;
                        bit_check_1 = bp.add_bit_check(var(component.W(2), 0));
                        bit_check_2 = bp.add_bit_check(var(component.W(3), 0));
                        bit_check_3 = bp.add_bit_check(var(component.W(4), 0));
                        bit_check_4 = bp.add_bit_check(var(component.W(5), 0));
                        bit_check_5 = bp.add_bit_check(var(component.W(6), 0));

                        constraint_1 = bp.add_constraint((var(component.W(2), -1) - var(component.W(0), -1)) * var(component.W(7), 0) -
                                                         (var(component.W(3), -1) - (2 * var(component.W(2), 0) - 1) * var(component.W(1), -1)));
                        constraint_2 = bp.add_constraint((var(component.W(7), -1) - var(component.W(0), -1)) * var(component.W(8), 0) -
                                                         (var(component.W(8), -1) - (2 * var(component.W(3), 0) - 1) * var(component.W(1), -1)));
                        constraint_3 = bp.add_constraint((var(component.W(9), -1) - var(component.W(0), -1)) * var(component.W(9), 0) -
                                                         (var(component.W(10), -1) - (2 * var(component.W(4), 0) - 1) * var(component.W(1), -1)));
                        constraint_4 = bp.add_constraint((var(component.W(11), -1) - var(component.W(0), -1)) * var(component.W(10), 0) -
                                                         (var(component.W(12), -1) - (2 * var(component.W(5), 0) - 1) * var(component.W(1), -1)));
                        constraint_5 = bp.add_constraint((var(component.W(13), -1) - var(component.W(0), -1)) * var(component.W(11), 0) -
                                                         (var(component.W(14), -1) - (2 * var(component.W(6), 0) - 1) * var(component.W(1), -1)));

                        constraint_6 = bp.add_constraint(
                            (2 * var(component.W(3), -1) - var(component.W(7), 0) * (2 * var(component.W(2), -1) - var(component.W(7), 0).pow(2) + var(component.W(0), -1))) *
                                (2 * var(component.W(3), -1) - var(component.W(7), 0) * (2 * var(component.W(2), -1) - var(component.W(7), 0).pow(2) + var(component.W(0), -1))) -
                            ((2 * var(component.W(2), -1) - var(component.W(7), 0).pow(2) + var(component.W(0), -1)) *
                             (2 * var(component.W(2), -1) - var(component.W(7), 0).pow(2) + var(component.W(0), -1)) *
                             (var(component.W(7), -1) - var(component.W(0), -1) + var(component.W(7), 0).pow(2))));
                        constraint_7 = bp.add_constraint(
                            (2 * var(component.W(8), -1) - var(component.W(8), 0) * (2 * var(component.W(7), -1) - var(component.W(8), 0).pow(2) + var(component.W(0), -1))) *
                                (2 * var(component.W(8), -1) - var(component.W(8), 0) * (2 * var(component.W(7), -1) - var(component.W(8), 0).pow(2) + var(component.W(0), -1))) -
                            ((2 * var(component.W(7), -1) - var(component.W(8), 0).pow(2) + var(component.W(0), -1)) *
                             (2 * var(component.W(7), -1) - var(component.W(8), 0).pow(2) + var(component.W(0), -1)) *
                             (var(component.W(9), -1) - var(component.W(0), -1) + var(component.W(8), 0).pow(2))));
                        constraint_8 = bp.add_constraint(
                            (2 * var(component.W(10), -1) - var(component.W(9), 0) * (2 * var(component.W(9), -1) - var(component.W(9), 0).pow(2) + var(component.W(0), -1))) *
                                (2 * var(component.W(10), -1) - var(component.W(9), 0) * (2 * var(component.W(9), -1) - var(component.W(9), 0).pow(2) + var(component.W(0), -1))) -
                            ((2 * var(component.W(9), -1) - var(component.W(9), 0).pow(2) + var(component.W(0), -1)) *
                             (2 * var(component.W(9), -1) - var(component.W(9), 0).pow(2) + var(component.W(0), -1)) *
                             (var(component.W(11), -1) - var(component.W(0), -1) + var(component.W(9), 0).pow(2))));
                        constraint_9 = bp.add_constraint(
                            ((2 * var(component.W(12), -1) - var(component.W(10), 0) * (2 * var(component.W(11), -1) - var(component.W(10), 0).pow(2) + var(component.W(0), -1))) *
                                 (2 * var(component.W(12), -1) -
                                  var(component.W(10), 0) * (2 * var(component.W(11), -1) - var(component.W(10), 0).pow(2) + var(component.W(0), -1))) -
                             ((2 * var(component.W(11), -1) - var(component.W(10), 0).pow(2) + var(component.W(0), -1)) *
                              (2 * var(component.W(11), -1) - var(component.W(10), 0).pow(2) + var(component.W(0), -1)) *
                              (var(component.W(13), -1) - var(component.W(0), -1) + var(component.W(10), 0).pow(2)))) *
                            var(component.W(8), +1) * var(component.W(2), +1));
                        constraint_10 = bp.add_constraint(
                            ((2 * var(component.W(14), -1) - var(component.W(11), 0) * (2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1))) *
                                 (2 * var(component.W(14), -1) -
                                  var(component.W(11), 0) * (2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1))) -
                             ((2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1)) *
                              (2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1)) *
                              (var(component.W(0), 0) - var(component.W(0), -1) + var(component.W(11), 0).pow(2)))) *
                            var(component.W(8), +1) * var(component.W(2), +1));

                        constraint_11 = bp.add_constraint(
                            (var(component.W(8), -1) + var(component.W(3), -1)) * (2 * var(component.W(2), -1) - var(component.W(7), 0).pow(2) + var(component.W(0), -1)) -
                            ((var(component.W(2), -1) - var(component.W(7), -1)) *
                             (2 * var(component.W(3), -1) - var(component.W(7), 0) * (2 * var(component.W(2), -1) - var(component.W(7), 0).pow(2) + var(component.W(0), -1)))));
                        constraint_12 = bp.add_constraint(
                            (var(component.W(10), -1) + var(component.W(8), -1)) * (2 * var(component.W(7), -1) - var(component.W(8), 0).pow(2) + var(component.W(0), -1)) -
                            ((var(component.W(7), -1) - var(component.W(9), -1)) *
                             (2 * var(component.W(8), -1) - var(component.W(8), 0) * (2 * var(component.W(7), -1) - var(component.W(8), 0).pow(2) + var(component.W(0), -1)))));
                        constraint_13 = bp.add_constraint(
                            (var(component.W(12), -1) + var(component.W(10), -1)) * (2 * var(component.W(9), -1) - var(component.W(9), 0).pow(2) + var(component.W(0), -1)) -
                            ((var(component.W(9), -1) - var(component.W(11), -1)) *
                             (2 * var(component.W(10), -1) - var(component.W(9), 0) * (2 * var(component.W(9), -1) - var(component.W(9), 0).pow(2) + var(component.W(0), -1)))));
                        constraint_14 = bp.add_constraint(
                            ((var(component.W(14), -1) + var(component.W(12), -1)) * (2 * var(component.W(11), -1) - var(component.W(10), 0).pow(2) + var(component.W(0), -1)) -
                             ((var(component.W(11), -1) - var(component.W(13), -1)) *
                              (2 * var(component.W(12), -1) -
                               var(component.W(10), 0) * (2 * var(component.W(11), -1) - var(component.W(10), 0).pow(2) + var(component.W(0), -1))))) *
                            var(component.W(8), +1) * var(component.W(2), +1));
                        constraint_15 = bp.add_constraint(
                            ((var(component.W(1), 0) + var(component.W(14), -1)) * (2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1)) -
                             ((var(component.W(13), -1) - var(component.W(0), 0)) *
                              (2 * var(component.W(14), -1) -
                               var(component.W(11), 0) * (2 * var(component.W(13), -1) - var(component.W(11), 0).pow(2) + var(component.W(0), -1))))) *
                            var(component.W(8), +1) * var(component.W(2), +1));

                        constraint_16 =
                            bp.add_constraint(var(component.W(5), -1) - (32 * (var(component.W(4), -1)) + 16 * var(component.W(2), 0) + 8 * var(component.W(3), 0) +
                                                            4 * var(component.W(4), 0) + 2 * var(component.W(5), 0) + var(component.W(6), 0)));

                        auto constraint_17 = bp.add_constraint((var(component.W(8), +1)*var(component.W(2), +1) - 1) * var(component.W(8), +1));
                        auto constraint_18 = bp.add_constraint(((var(component.W(5), +1) - component.shifted_minus_one)
                        *var(component.W(3), +1) - 1) * (var(component.W(5), +1) - component.shifted_minus_one));
                        auto constraint_19 = bp.add_constraint(((var(component.W(5), +1) - component.shifted_one)
                        *var(component.W(4), +1) - 1) * (var(component.W(5), +1) - component.shifted_one));
                        auto constraint_20 = bp.add_constraint((var(component.W(8), +1)*var(component.W(2), +1)*var(component.W(0), 0)) + 
                        ((var(component.W(5), +1) - component.shifted_minus_one)
                        *var(component.W(3), +1) - (var(component.W(5), +1) - component.shifted_one)
                        *var(component.W(4), +1))* ((var(component.W(5), +1) - component.shifted_minus_one)
                        *var(component.W(3), +1) - (var(component.W(5), +1) - component.shifted_one)
                        *var(component.W(4), +1)) * var(component.W(6), +1) - var(component.W(0), +1));
                        auto constraint_21 = bp.add_constraint((var(component.W(8), +1)*var(component.W(2), +1)*var(component.W(1), 0)) + 
                        ((var(component.W(5), +1) - component.shifted_minus_one)
                        *var(component.W(3), +1) - (var(component.W(5), +1) - component.shifted_one)
                        *var(component.W(4), +1)) * var(component.W(7), +1) - var(component.W(1), +1));
                        auto constraint_22 = bp.add_constraint(var(component.W(8), +1) - ((var(component.W(5), +1) - component.shifted_minus_one)
                        *(var(component.W(5), +1) - component.shifted_zero)*
                        (var(component.W(5), +1) - component.shifted_one)));
                        bp.add_gate(selector_index_2,
                                    {bit_check_1,   bit_check_2,   bit_check_3,   bit_check_4,   bit_check_5,
                                     constraint_1,  constraint_2,  constraint_3,  constraint_4,  constraint_5,
                                     constraint_6,  constraint_7,  constraint_8,  constraint_9,  constraint_10,
                                     constraint_11, constraint_12, constraint_13, constraint_14, constraint_15,
                                     constraint_16, constraint_17, constraint_18, constraint_19, constraint_20,
                                     constraint_21, constraint_22});
                    }

                        template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                            void generate_copy_constraints(
                                const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                                const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                                const std::uint32_t start_row_index) {

                        std::size_t j = start_row_index + component.add_component_rows_amount;
                        using var = typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::var;

                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        
                        unified_addition<ArithmetizationType, CurveType, 11> unified_addition_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8), component.W(9), 
                                        component.W(10)},{},{});

                        typename unified_addition<ArithmetizationType, CurveType, 11>::result_type addition_res(unified_addition_instance, start_row_index);

                        bp.add_copy_constraint({{component.W(2), (std::int32_t)(j), false}, addition_res.X});
                        bp.add_copy_constraint({{component.W(3), (std::int32_t)(j), false}, addition_res.Y});

                        // main algorithm

                        for (int z = 0; z < component.mul_rows_amount - 2; z += 2) {
                            bp.add_copy_constraint(
                                {{component.W(0), (std::int32_t)(j + z), false}, {component.W(0), (std::int32_t)(j + z + 2), false}});
                            bp.add_copy_constraint(
                                {{component.W(1), (std::int32_t)(j + z), false}, {component.W(1), (std::int32_t)(j + z + 2), false}});
                        }

                        for (int z = 2; z < component.mul_rows_amount; z += 2) {
                            bp.add_copy_constraint(
                                {{component.W(2), (std::int32_t)(j + z), false}, {component.W(0), (std::int32_t)(j + z - 1), false}});
                            bp.add_copy_constraint(
                                {{component.W(3), (std::int32_t)(j + z), false}, {component.W(1), (std::int32_t)(j + z - 1), false}});
                        }

                        for (int z = 2; z < component.mul_rows_amount; z += 2) {
                            bp.add_copy_constraint(
                                {{component.W(4), (std::int32_t)(j + z), false}, {component.W(5), (std::int32_t)(j + z - 2), false}});
                        }
                        bp.add_copy_constraint({{component.W(5), (std::int32_t)(start_row_index + component.rows_amount - 1), false},
                                                {component.W(5), (std::int32_t)(start_row_index + component.rows_amount - 3), false}});
                        bp.add_copy_constraint({{component.W(6), (std::int32_t)(start_row_index + component.rows_amount - 1), false},
                                                {component.W(0), (std::int32_t)(start_row_index + component.rows_amount - 3), false}});
                        bp.add_copy_constraint({{component.W(7), (std::int32_t)(start_row_index + component.rows_amount - 1), false},
                                                {component.W(1), (std::int32_t)(start_row_index + component.rows_amount - 3), false}});

                        bp.add_copy_constraint({{component.W(4), (std::int32_t)(j), false},
                                                {component.W(0), (std::int32_t)(j), false, var::column_type::constant}});

                        bp.add_copy_constraint(
                            {instance_input.b, {component.W(5), (std::int32_t)(j + component.rows_amount - 4), false}});    // scalar value check
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                            void generate_assignments_constants(
                                const plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                                const typename plonk_curve_element_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                                const std::uint32_t start_row_index) {
                        std::size_t row = start_row_index + component.add_component_rows_amount;

                        assignment.constant(component.C(0), row) = BlueprintFieldType::value_type::zero();
                    }
            }    // namespace components
    }   // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_DECOMPOSED_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_DECOMPOSED_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>
#include <nil/blueprint/components/algebra/curves/pasta/plonk/variable_base_scalar_mul_15_wires.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>

namespace nil {
        namespace blueprint {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::uint32_t WitnessesAmount>
                class curve_element_decomposed_variable_base_scalar_mul;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                class curve_element_decomposed_variable_base_scalar_mul<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType, 15>:
                    public plonk_component<BlueprintFieldType, ArithmetizationParams, 15, 1, 0> {

                    using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 15, 1, 0>;
                    using ArithmetizationType = nil::crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                    using add_component = nil::blueprint::components::unified_addition<ArithmetizationType, CurveType, 11>;
                    using mul_component = nil::blueprint::components::curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, 15>;
                    using mul_field_component = nil::blueprint::components::multiplication<ArithmetizationType, BlueprintFieldType, 3, basic_non_native_policy<BlueprintFieldType>>;

                public:
                    using var = typename component_type::var;
                    constexpr static const std::size_t rows_amount_without_addition = 2 * mul_component::rows_amount +
                                                                     2 * mul_field_component::rows_amount;
                    constexpr static const std::size_t rows_amount = rows_amount_without_addition + add_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;
                    // TODO: component is  not finished, add gates

                    struct input_type {
                        struct var_ec_point {
                            var x;
                            var y;
                        };

                        var_ec_point T;
                        var b1;
                        var b2;
                    };

                    struct result_type {
                        var X;
                        var Y;
                        result_type(const curve_element_decomposed_variable_base_scalar_mul &component, std::size_t start_row_index) {
                            // TODO: use result type of add_component
                            X = var(component.W(4), start_row_index + component.rows_amount_without_addition, false, var::column_type::witness);
                            Y = var(component.W(5), start_row_index + component.rows_amount_without_addition, false, var::column_type::witness);

                        //     auto res = typename add_component::result_type(unified_addition_instance,
                        //         start_row_index + 2 * mul_component::rows_amount +
                        //             2 * mul_field_component::rows_amount);
                        //     X = res.X;
                        //     Y = res.Y;
                        }
                    };
                    template <typename ContainerType>
                    curve_element_decomposed_variable_base_scalar_mul(ContainerType witness):
                        component_type(witness, {}, {}){};

                    template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                    curve_element_decomposed_variable_base_scalar_mul(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input):
                        component_type(witness, constant, public_input){};

                    curve_element_decomposed_variable_base_scalar_mul(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                                   std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                                   std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                        component_type(witnesses, constants, public_inputs){};
                };

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                using plonk_curve_element_decomposed_variable_base_scalar_mul =
                    curve_element_decomposed_variable_base_scalar_mul<
                        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        CurveType,
                        15
                    >;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                    typename plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type 
                        generate_assignments(
                            const plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                            const typename plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                            const std::uint32_t start_row_index) {

                        std::size_t row = start_row_index;

                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        using vbsm_component = curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, 15>; // Variable Base Scalar Multiplication 
                        using mul_field_component = multiplication<ArithmetizationType, BlueprintFieldType, 3, basic_non_native_policy<BlueprintFieldType>>;
                        using add_component = unified_addition<ArithmetizationType, CurveType, 11>;
                        using var = typename curve_element_decomposed_variable_base_scalar_mul<ArithmetizationType,  CurveType, 15>::var;

                        add_component unified_addition_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8), component.W(9), 
                                        component.W(10)},{},{});

                        vbsm_component vbsm_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8), component.W(9), 
                                        component.W(10), component.W(11), component.W(12), component.W(13), component.W(14)},{component.C(0)},{});

                        mul_field_component mul_field_instance(
                                {component.W(0), component.W(1), component.W(2)},{},{});


                        typename vbsm_component::input_type vbsm_input = {{instance_input.T.x, instance_input.T.y}, instance_input.b1};
                        typename vbsm_component::result_type vbsm_res = generate_assignments(vbsm_instance, assignment, vbsm_input, row);
                        row += vbsm_component::rows_amount;

                        typename vbsm_component::input_type vbsm_input_2 = {{instance_input.T.x, instance_input.T.y}, var(component.C(0), start_row_index, false, var::column_type::constant)};
                        typename vbsm_component::result_type const_vbsm_res = generate_assignments(vbsm_instance, assignment, vbsm_input_2, row);
                        row += vbsm_component::rows_amount;

                        typename mul_field_component::input_type x_input = {const_vbsm_res.X, instance_input.b2};
                        typename mul_field_component::result_type x = generate_assignments(mul_field_instance, assignment, x_input, row);
                        row += mul_field_component::rows_amount;

                        typename mul_field_component::input_type y_input = {const_vbsm_res.Y, instance_input.b2};
                        typename mul_field_component::result_type y = generate_assignments(mul_field_instance, assignment, y_input, row);
                        row += mul_field_component::rows_amount;

                        typename add_component::input_type add_input = {{x.output, y.output}, {vbsm_res.X, vbsm_res.Y}};
                        typename add_component::result_type final_res = generate_assignments(unified_addition_instance, assignment, add_input, row);
                        row += add_component::rows_amount;

                        return typename plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                   }

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                    typename plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type 
                        generate_circuit(
                            const plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                            const typename plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type &instance_input,
                            const std::uint32_t start_row_index) {

                        std::size_t row = start_row_index;

                        // TODO: add generate_gates and copy constraints

                        using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        using vbsm_component = curve_element_variable_base_scalar_mul<ArithmetizationType, CurveType, 15>; // Variable Base Scalar Multiplication 
                        using mul_field_component = multiplication<ArithmetizationType, BlueprintFieldType, 3, basic_non_native_policy<BlueprintFieldType>>;
                        using add_component = unified_addition<ArithmetizationType, CurveType, 11>;
                        using var = typename curve_element_decomposed_variable_base_scalar_mul<ArithmetizationType,  CurveType, 15>::var;

                        add_component unified_addition_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8), component.W(9), 
                                        component.W(10)},{},{});

                        vbsm_component vbsm_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8), component.W(9), 
                                        component.W(10), component.W(11), component.W(12), component.W(13), component.W(14)},{component.C(0)},{});

                        mul_field_component mul_field_instance(
                                {component.W(0), component.W(1), component.W(2)},{},{});


                        typename vbsm_component::input_type vbsm_input = {{instance_input.T.x, instance_input.T.y}, instance_input.b1};
                        typename vbsm_component::result_type vbsm_res = generate_circuit(vbsm_instance, bp, assignment, vbsm_input, row);
                        row += vbsm_component::rows_amount;

                        typename vbsm_component::input_type vbsm_input_2 = {{instance_input.T.x, instance_input.T.y}, var(component.C(0), start_row_index, false, var::column_type::constant)};
                        typename vbsm_component::result_type const_vbsm_res = generate_circuit(vbsm_instance, bp, assignment, vbsm_input_2, row);
                        row += vbsm_component::rows_amount;

                        typename mul_field_component::input_type x_input = {const_vbsm_res.X, instance_input.b2};
                        typename mul_field_component::result_type x = generate_circuit(mul_field_instance, bp, assignment, x_input, row);
                        row += mul_field_component::rows_amount;

                        typename mul_field_component::input_type y_input = {const_vbsm_res.Y, instance_input.b2};
                        typename mul_field_component::result_type y = generate_circuit(mul_field_instance, bp, assignment, y_input, row);
                        row += mul_field_component::rows_amount;

                        typename add_component::input_type add_input = {{x.output, y.output}, {vbsm_res.X, vbsm_res.Y}};
                        typename add_component::result_type final_res = generate_circuit(unified_addition_instance, bp, assignment, add_input, row);
                        row += add_component::rows_amount;

                        return typename plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                    }

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                        void generate_gates(
                            const plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                            circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                            assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                            const typename plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type &instance_input,
                            const std::size_t first_selector_index) {
                                // TODO
                    }

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                    void generate_copy_constraints(
                        const plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type &instance_input,
                        const std::uint32_t start_row_index) {
                            //TODO
                    }

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
                    void generate_assignments_constant(
                        const plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                        circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_curve_element_decomposed_variable_base_scalar_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type &instance_input,
                        const std::uint32_t start_row_index) {
                        std::size_t row = start_row_index;
                        typename BlueprintFieldType::integral_type one = 1;
                        assignment.constant(component.C(0), row) = (one << 254);
                    }
            }    // namespace components
        }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

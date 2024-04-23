//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for auxiliary components for the VARIABLE_BASE_MULTIPLICATION component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP

#include "nil/blueprint/components/algebra/fields/plonk/non_native/detail/bit_builder_component.hpp"
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/variable_base_multiplication_per_bit.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/bool_scalar_multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/bit_shift_constant.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename CurveType, typename Ed25519Type,
                     typename NonNativePolicyType>
            class variable_base_multiplication;

            template<typename BlueprintFieldType,
                     typename CurveType, typename Ed25519Type>
            class variable_base_multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                    CurveType,
                    Ed25519Type,
                    basic_non_native_policy<BlueprintFieldType>>:
                public plonk_component<BlueprintFieldType> {

                constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount,
                                                                        std::size_t bits_amount) {
                        return
                            decomposition_component_type::get_rows_amount(witness_amount, bits_amount,
                                                                          bit_composition_mode::MSB) +
                            252 * mul_per_bit_component::get_rows_amount(witness_amount) +
                            bool_scalar_mul_component::get_rows_amount(witness_amount);
                }

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = typename component_type::manifest_type;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>
                    ArithmetizationType;

                using mul_per_bit_component = variable_base_multiplication_per_bit<
                    ArithmetizationType, CurveType, Ed25519Type, non_native_policy_type>;

                using decomposition_component_type = bit_decomposition<ArithmetizationType>;

                using bool_scalar_mul_component = bool_scalar_multiplication<
                    ArithmetizationType, Ed25519Type, non_native_policy_type>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return variable_base_multiplication::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t bits_amount, bit_composition_mode mode) {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(
                            bool_scalar_mul_component::get_gate_manifest(witness_amount))
                        .merge_with(mul_per_bit_component::get_gate_manifest(witness_amount))
                        .merge_with(
                            decomposition_component_type::get_gate_manifest(witness_amount, bits_amount, mode));

                    return manifest;
                }

                static manifest_type get_manifest(std::size_t bits_amount, bit_composition_mode mode) {
                    manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(9)),
                        false
                    ).merge_with(mul_per_bit_component::get_manifest())
                     .merge_with(decomposition_component_type::get_manifest(bits_amount, mode))
                     .merge_with(bool_scalar_mul_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t bits_amount, bit_composition_mode mode) {
                    return rows_amount_internal(witness_amount, bits_amount);
                }

                // We use bits_amount from decomposition subcomponent to initialize rows_amount
                // CRITICAL: do not move decomposition_subcomponent below rows_amount
                const decomposition_component_type decomposition_subcomponent;
                // CRITICAL: do not move decomposition_subcomponent below rows_amount
                const mul_per_bit_component mul_per_bit_subcomponent;
                const bool_scalar_mul_component bool_scalar_mul_subcomponent;

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), decomposition_subcomponent.bits_amount);
                constexpr static const std::size_t gates_amount = 0;
                const std::string component_name = "non-native curve multiplication";

                struct input_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };

                    var_ec_point T;
                    var k;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {T.x[0], T.x[1], T.x[2], T.x[3], T.y[0], T.y[1], T.y[2], T.y[3], k};
                    }
                };

                struct result_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };
                    var_ec_point output;

                    result_type(const variable_base_multiplication &component, std::uint32_t start_row_index) {
                        using mul_per_bit_component =
                            components::variable_base_multiplication_per_bit<ArithmetizationType,
                                CurveType, Ed25519Type, non_native_policy_type>;
                        mul_per_bit_component component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

                        auto final_mul_per_bit_res = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, CurveType>::result_type(
                            component_instance, start_row_index + component.rows_amount - component.mul_per_bit_subcomponent.rows_amount);


                        output.x = {final_mul_per_bit_res.output.x[0],
                                    final_mul_per_bit_res.output.x[1],
                                    final_mul_per_bit_res.output.x[2],
                                    final_mul_per_bit_res.output.x[3]};
                        output.y = {final_mul_per_bit_res.output.y[0],
                                    final_mul_per_bit_res.output.y[1],
                                    final_mul_per_bit_res.output.y[2],
                                    final_mul_per_bit_res.output.y[3]};
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {output.x[0], output.x[1], output.x[2], output.x[3],
                                output.y[0], output.y[1], output.y[2], output.y[3]};
                    }
                };

                template<typename ContainerType>
                explicit variable_base_multiplication(ContainerType witness, std::uint32_t bits_amount,
                                                      bit_composition_mode mode_) :
                    component_type(witness, {}, {}, get_manifest(bits_amount, mode_)),
                    decomposition_subcomponent(witness, bits_amount, mode_),
                    mul_per_bit_subcomponent(witness),
                    bool_scalar_mul_subcomponent(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                variable_base_multiplication(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input, std::uint32_t bits_amount = 253,
                                   bit_composition_mode mode_ = bit_composition_mode::MSB) :
                    component_type(witness, constant, public_input, get_manifest(bits_amount, mode_)),
                    decomposition_subcomponent(witness, constant, public_input,
                                               bits_amount, mode_),
                    mul_per_bit_subcomponent(witness, constant, public_input),
                    bool_scalar_mul_subcomponent(witness, constant, public_input) {};

                variable_base_multiplication(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::uint32_t bits_amount = 253, bit_composition_mode mode_ = bit_composition_mode::MSB) :
                        component_type(witnesses, constants, public_inputs, get_manifest(bits_amount, mode_)),
                        decomposition_subcomponent(witnesses, constants, public_inputs,
                                                   bits_amount, mode_),
                        mul_per_bit_subcomponent(witnesses, constants, public_inputs),
                        bool_scalar_mul_subcomponent(witnesses, constants, public_inputs) {};
            };

            template<typename BlueprintFieldType, typename CurveType>
            using plonk_ed25519_var_base_mul = variable_base_multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                CurveType,
                typename crypto3::algebra::curves::ed25519,
                basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename CurveType>
            typename plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>::result_type
                generate_assignments(
                    const plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using component_type =
                        plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>;
                    using var = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, CurveType>::var;

                    using mul_per_bit_component = typename component_type::mul_per_bit_component;
                    using decomposition_component_type = typename component_type::decomposition_component_type;
                    using bool_scalar_mul_component = typename component_type::bool_scalar_mul_component;

                    std::size_t row = start_row_index;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;

                    typename decomposition_component_type::result_type bits =
                        generate_assignments(component.decomposition_subcomponent,
                            assignment, {instance_input.k}, row);
                    row += component.decomposition_subcomponent.rows_amount;

                    typename bool_scalar_mul_component::result_type bool_mul_res =
                        generate_assignments(component.bool_scalar_mul_subcomponent, assignment,
                        typename bool_scalar_mul_component::input_type({{T_x, T_y}, bits.output[0]}), row);
                    row += component.bool_scalar_mul_subcomponent.rows_amount;

                    typename mul_per_bit_component::result_type res_per_bit =
                        generate_assignments(component.mul_per_bit_subcomponent, assignment,
                        typename mul_per_bit_component::input_type({{T_x, T_y},
                            {bool_mul_res.output.x, bool_mul_res.output.y}, bits.output[1]}),
                        row);
                    row += component.mul_per_bit_subcomponent.rows_amount;

                    for (std::size_t i = 2; i < 253; i++) {
                        res_per_bit = generate_assignments(component.mul_per_bit_subcomponent, assignment,
                        typename mul_per_bit_component::input_type({{T_x, T_y},
                            {res_per_bit.output.x, res_per_bit.output.y}, bits.output[i]}), row);
                        row += component.mul_per_bit_subcomponent.rows_amount;
                    }

                    return typename plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>::result_type(component, start_row_index);
                }

            template<typename BlueprintFieldType, typename CurveType>
            typename plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>::result_type
                generate_circuit(
                    const plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                    const typename plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using component_type =
                        plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>;
                    using var = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, CurveType>::var;

                    using mul_per_bit_component = typename component_type::mul_per_bit_component;
                    using decomposition_component_type = typename component_type::decomposition_component_type;
                    using bool_scalar_mul_component = typename component_type::bool_scalar_mul_component;


                    std::size_t row = start_row_index;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;

                    typename decomposition_component_type::result_type bits =
                    generate_circuit(component.decomposition_subcomponent, bp, assignment, {instance_input.k},
                                     row);
                    row += component.decomposition_subcomponent.rows_amount;

                    typename bool_scalar_mul_component::result_type bool_mul_res =
                        generate_circuit(component.bool_scalar_mul_subcomponent, bp, assignment,
                        typename bool_scalar_mul_component::input_type({{T_x, T_y}, bits.output[0]}), row);
                    row += component.bool_scalar_mul_subcomponent.rows_amount;

                    typename mul_per_bit_component::result_type res_per_bit =
                        generate_circuit(component.mul_per_bit_subcomponent, bp, assignment,
                        typename mul_per_bit_component::input_type({{T_x, T_y},
                            {bool_mul_res.output.x, bool_mul_res.output.y}, bits.output[1]}),
                        row);
                    row += component.mul_per_bit_subcomponent.rows_amount;

                    for (std::size_t i = 2; i < 253; i++) {
                        res_per_bit = generate_circuit(component.mul_per_bit_subcomponent, bp, assignment,
                        typename mul_per_bit_component::input_type({{T_x, T_y},
                            {res_per_bit.output.x, res_per_bit.output.y}, bits.output[i]}), row);
                        row += component.mul_per_bit_subcomponent.rows_amount;
                    }

                    return typename plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>::result_type(component, start_row_index);
                }

            template<typename ComponentType>
            class input_type_converter;

            template<typename ComponentType>
            class result_type_converter;

            template<typename BlueprintFieldType, typename CurveType>
            class input_type_converter<
                plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>> {

                using component_type =
                    plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>;
                using input_type = typename component_type::input_type;
                using var = typename nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            public:
                static input_type convert(
                    const input_type &input,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &tmp_assignment) {

                    input_type new_input;
                    for (std::size_t i = 0; i < input.T.x.size(); i++) {
                        tmp_assignment.public_input(0, i) = var_value(assignment, input.T.x[i]);
                        new_input.T.x[i] = var(0, i, false, var::column_type::public_input);
                    }
                    for (std::size_t i = 0; i < input.T.y.size(); i++) {
                        std::size_t new_idx = input.T.x.size() + i;
                        tmp_assignment.public_input(0, new_idx) = var_value(assignment, input.T.y[i]);
                        new_input.T.y[i] = var(0, new_idx, false, var::column_type::public_input);
                    }
                    tmp_assignment.public_input(0, input.T.x.size() + input.T.y.size()) =
                        var_value(assignment, input.k);
                    new_input.k = var(0, input.T.x.size() + input.T.y.size(),
                                      false, var::column_type::public_input);

                    return new_input;
                }

                static var deconvert_var(const input_type &input,
                                         var variable) {
                    BOOST_ASSERT(variable.type == var::column_type::public_input);
                    if (std::size_t(variable.rotation) < input.T.x.size()) {
                        return input.T.x[variable.rotation];
                    } else if (std::size_t(variable.rotation) < input.T.x.size() + input.T.y.size()) {
                        return input.T.y[variable.rotation - input.T.x.size()];
                    } else {
                        return input.k;
                    }
                }
            };

            template<typename BlueprintFieldType, typename CurveType>
            class result_type_converter<
                plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>> {

                using component_type =
                    plonk_ed25519_var_base_mul<BlueprintFieldType, CurveType>;
                using input_type = typename component_type::input_type;
                using result_type = typename component_type::result_type;
                using stretcher_type = component_stretcher<BlueprintFieldType, component_type>;
            public:
                static result_type convert(const stretcher_type &component, const result_type old_result,
                                           const input_type &instance_input, std::size_t start_row_index) {
                    result_type new_result(component.component, start_row_index);

                    for (std::size_t i = 0; i < 4; i++) {
                        new_result.output.x[i] = component.move_var(
                            old_result.output.x[i],
                            start_row_index + component.line_mapping[old_result.output.x[i].rotation],
                            instance_input
                        );
                        new_result.output.y[i] = component.move_var(
                            old_result.output.y[i],
                            start_row_index + component.line_mapping[old_result.output.y[i].rotation],
                            instance_input
                        );
                    }

                    return new_result;
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP

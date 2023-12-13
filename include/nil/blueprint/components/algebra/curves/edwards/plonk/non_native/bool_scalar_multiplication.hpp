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
// @file Declaration of interfaces for auxiliary components for the MERKLE_TREE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BOOL_SCALAR_MULTIPLICATION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BOOL_SCALAR_MULTIPLICATION_HPP

#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename Ed25519Type, typename NonNativePolicyType>
            class bool_scalar_multiplication;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class bool_scalar_multiplication<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                typename crypto3::algebra::curves::ed25519, basic_non_native_policy<BlueprintFieldType>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

                using operating_field_type = typename crypto3::algebra::fields::curve25519_base_field;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return bool_scalar_multiplication::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_single_value_param(9)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 2;
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<operating_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<operating_field_type>::non_native_var_type y;
                    };

                    var_ec_point T;
                    var k;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {T.x[0], T.x[1], T.x[2], T.x[3],
                                T.y[0], T.y[1], T.y[2], T.y[3],
                                k};
                    }
                };

                struct result_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<operating_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<operating_field_type>::non_native_var_type y;
                    };
                    var_ec_point output;

                    result_type(const bool_scalar_multiplication &component, std::uint32_t start_row_index) {
                        output.y = {
                            var(component.W(5), start_row_index, false),
                            var(component.W(6), start_row_index, false),
                            var(component.W(7), start_row_index, false),
                            var(component.W(8), start_row_index, false)};
                        output.x = {
                            var(component.W(5), start_row_index + 1, false),
                            var(component.W(6), start_row_index + 1, false),
                            var(component.W(7), start_row_index + 1, false),
                            var(component.W(8), start_row_index + 1, false)};
                    }

                    std::vector<var> all_vars() const {
                        return {output.x[0], output.x[1], output.x[2], output.x[3],
                                output.y[0], output.y[1], output.y[2], output.y[3]};
                    }
                };

                template <typename ContainerType>
                explicit bool_scalar_multiplication(ContainerType witness):
                    component_type(witness, {}, {}, get_manifest()){};

                template <typename WitnessContainerType, typename ConstantContainerType,
                    typename PublicInputContainerType>
                bool_scalar_multiplication(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input):
                    component_type(witness, constant, public_input, get_manifest()){};

                bool_scalar_multiplication(std::initializer_list<
                        typename component_type::witness_container_type::value_type> witnesses,
                               std::initializer_list<
                        typename component_type::constant_container_type::value_type> constants,
                               std::initializer_list<
                        typename component_type::public_input_container_type::value_type> public_inputs):
                    component_type(witnesses, constants, public_inputs, get_manifest()){};

            };

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            using plonk_bool_scalar_multiplication =
                bool_scalar_multiplication<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                typename crypto3::algebra::curves::ed25519,
                basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bool_scalar_multiplication<BlueprintFieldType,
                        ArithmetizationParams>::input_type &instance_input,
                    const std::uint32_t start_row_index) {
                using Ed25519Type = typename crypto3::algebra::curves::ed25519;
                using var = typename plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams>::var;

                std::size_t row = start_row_index;
                typename Ed25519Type::base_field_type::integral_type b = typename Ed25519Type::base_field_type::integral_type(var_value(assignment, instance_input.k).data);
                std::array<var, 4> T_x = instance_input.T.x;
                std::array<var, 4> T_y = instance_input.T.y;
                std::array<typename BlueprintFieldType::value_type, 4> T_x_array = {var_value(assignment, instance_input.T.x[0]),
                var_value(assignment, instance_input.T.x[1]), var_value(assignment, instance_input.T.x[2]), var_value(assignment, instance_input.T.x[3])};
                std::array<typename BlueprintFieldType::value_type, 4> T_y_array = {var_value(assignment, instance_input.T.y[0]),
                var_value(assignment, instance_input.T.y[1]), var_value(assignment, instance_input.T.y[2]), var_value(assignment, instance_input.T.y[3])};

                assignment.witness(component.W(0), row) = T_y_array[0];
                assignment.witness(component.W(1), row) = T_y_array[1];
                assignment.witness(component.W(2), row) = T_y_array[2];
                assignment.witness(component.W(3), row) = T_y_array[3];
                assignment.witness(component.W(4), row) = b;
                assignment.witness(component.W(5), row) = b * T_y_array[0] + (1 - b);
                assignment.witness(component.W(6), row) = b * T_y_array[1];
                assignment.witness(component.W(7), row) = b * T_y_array[2];
                assignment.witness(component.W(8), row) = b * T_y_array[3];
                row++;
                assignment.witness(component.W(0), row) = T_x_array[0];
                assignment.witness(component.W(1), row) = T_x_array[1];
                assignment.witness(component.W(2), row) = T_x_array[2];
                assignment.witness(component.W(3), row) = T_x_array[3];
                assignment.witness(component.W(4), row) = b;
                assignment.witness(component.W(5), row) = b * T_x_array[0];
                assignment.witness(component.W(6), row) = b * T_x_array[1];
                assignment.witness(component.W(7), row) = b * T_x_array[2];
                assignment.witness(component.W(8), row) = b * T_x_array[3];

                return typename plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams>::result_type
                    (component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                using var = typename plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams>::var;

                auto constraint_9 =
                    var(component.W(4), 0) * ( var(component.W(4), 0) - 1);
                auto constraint_10 =
                    var(component.W(4), 0) - var(component.W(4), +1);
                auto constraint_1 =
                    var(component.W(5), 0) - (var(component.W(0), 0) * var(component.W(4), 0) + (1 - var(component.W(4), 0)));
                auto constraint_2 =
                    var(component.W(6), 0) - var(component.W(1), 0) * var(component.W(4), 0);
                auto constraint_3 =
                    var(component.W(7), 0) - var(component.W(2), 0) * var(component.W(4), 0);
                auto constraint_4 =
                    var(component.W(8), 0) - var(component.W(3), 0) * var(component.W(4), 0);
                auto constraint_5 =
                    var(component.W(5), +1) - var(component.W(0), +1) * var(component.W(4), +1);
                auto constraint_6 =
                    var(component.W(6), +1) - var(component.W(1), +1) * var(component.W(4), +1);
                auto constraint_7 =
                    var(component.W(7), +1) - var(component.W(2), +1) * var(component.W(4), +1);
                auto constraint_8 =
                    var(component.W(8), +1) - var(component.W(3), +1) * var(component.W(4), +1);

                return bp.add_gate(
                    {constraint_9, constraint_10,
                    constraint_1, constraint_2, constraint_3, constraint_4,
                    constraint_5, constraint_6, constraint_7, constraint_8});

            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                using var = typename plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams>::var;

                std::size_t row = start_row_index;

                bp.add_copy_constraint({var(component.W(0), row + 1, false), instance_input.T.x[0]});
                bp.add_copy_constraint({var(component.W(1), row + 1, false), instance_input.T.x[1]});
                bp.add_copy_constraint({var(component.W(2), row + 1, false), instance_input.T.x[2]});
                bp.add_copy_constraint({var(component.W(3), row + 1, false), instance_input.T.x[3]});
                bp.add_copy_constraint({var(component.W(4), row + 1, false), instance_input.k});
                bp.add_copy_constraint({var(component.W(0), row, false), instance_input.T.y[0]});
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input.T.y[1]});
                bp.add_copy_constraint({var(component.W(2), row, false), instance_input.T.y[2]});
                bp.add_copy_constraint({var(component.W(3), row, false), instance_input.T.y[3]});
                bp.add_copy_constraint({var(component.W(4), row, false), instance_input.k});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_bool_scalar_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index){

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                std::size_t row = start_row_index;
                assignment.enable_selector(selector_index, row);

                generate_copy_constraints(component, bp, assignment, instance_input, row);

                return typename plonk_bool_scalar_multiplication<BlueprintFieldType,
                                                                 ArithmetizationParams>::result_type
                            (component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
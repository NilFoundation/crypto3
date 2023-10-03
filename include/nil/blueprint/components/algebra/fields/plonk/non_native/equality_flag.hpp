//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_EQUALITY_FLAG_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_EQUALITY_FLAG_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x, y \in Fp
            // Output: 1 iff x == y, 0 otherwise
            // Output is reversed if inequality = true.
            // Basically runs a slightly optimized copy of division-or-zero component on [x - y].
            template<typename ArithmetizationType, typename BlueprintFieldType>
            class equality_flag;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class equality_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    bool inequality;

                    gate_manifest_type(bool inequality_) :inequality(inequality_) {}

                    std::uint32_t gates_amount() const override {
                        return equality_flag::gates_amount;
                    }

                    bool operator<(gate_manifest_type const& other) const {
                        return inequality < other.inequality;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       bool inequality) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(inequality));
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             bool inequality) {
                    return 1;
                }

                bool inequality;
                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, inequality);

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(4)),
                        false
                    );
                    return manifest;
                }

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const equality_flag &component, std::uint32_t start_row_index) {
                        output = var(component.W(3), start_row_index, false, var::column_type::witness);
                    }

                    result_type(const equality_flag &component, std::size_t start_row_index) {
                        output = var(component.W(3), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };


                template <typename ContainerType>
                equality_flag(ContainerType witness, bool inequality_):
                    component_type(witness, {}, {}, get_manifest()),
                    inequality(inequality_)
                    {};

                template <typename WitnessContainerType, typename ConstantContainerType,
                    typename PublicInputContainerType>
                equality_flag(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, bool inequality_):
                    component_type(witness, constant, public_input, get_manifest()),
                    inequality(inequality_)
                    {};

                equality_flag(std::initializer_list<
                        typename component_type::witness_container_type::value_type> witnesses,
                               std::initializer_list<
                        typename component_type::constant_container_type::value_type> constants,
                               std::initializer_list<
                        typename component_type::public_input_container_type::value_type> public_inputs,
                        bool inequality_):
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    inequality(inequality_)
                    {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_equality_flag =
                equality_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType>;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_equality_flag<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);
                assignment.witness(component.W(0), j) = x_val;
                assignment.witness(component.W(1), j) = y_val;
                if (x_val == y_val) {
                    assignment.witness(component.W(2), j) = 0;
                } else {
                    assignment.witness(component.W(2), j) = 1 / (x_val - y_val);
                }
                assignment.witness(component.W(3), j) = x_val == y_val ? !component.inequality : component.inequality;

                return typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_equality_flag<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input) {

                using var = typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                var x_var = var(component.W(0), 0),
                    y_var = var(component.W(1), 0),
                    inv_or_zero = var(component.W(2), 0),
                    result = var(component.W(3), 0);

                auto constraint_1 = result * (result - 1);
                auto constraint_2 = (x_var - y_var) * inv_or_zero +
                    (component.inequality ? constraint_type(-result) : constraint_type(result - 1));
                auto constraint_3 = (inv_or_zero - (x_var - y_var)) *
                    (component.inequality ? constraint_type(result - 1) : constraint_type(result));

                return bp.add_gate({constraint_1, constraint_2, constraint_3});
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_equality_flag<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                const typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                var component_y = var(component.W(1), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
                bp.add_copy_constraint({instance_input.y, component_y});
            }

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams>
            typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_equality_flag<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index){

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_equality_flag<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELD_EQUALITY_FLAG_HPP

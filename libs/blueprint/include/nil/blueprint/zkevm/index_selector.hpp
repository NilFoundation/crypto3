//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#pragma once

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/zkevm/state.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // activates a witness column based on an input value
            // is used to achieve dynamic selector behavior
            // actual implementation
            template<typename ArithmetizationType, typename FieldType>
            class index_selector;

            template<typename BlueprintFieldType>
            class index_selector<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using state_var = state_var<BlueprintFieldType>;

                std::size_t options_amount;

                class gate_manifest_type : public component_gate_manifest {
                private:
                    std::size_t options_amount;

                public:
                    gate_manifest_type(std::size_t options_amount_) :
                        options_amount(options_amount_) {};

                    bool operator<(gate_manifest_type const& other) const {
                        return (options_amount < other.options_amount);
                    }

                    std::uint32_t gates_amount() const override {
                        return index_selector::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t options_amount
                ) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(options_amount));
                    return manifest;
                }

                static manifest_type get_manifest(std::size_t options_amount) {
                    manifest_type manifest = manifest_type(
                        // TODO: make the manifest depend on options_amount
                        // this requires the manifest rework
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(
                            options_amount
                        )),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(
                    std::size_t options_amount
                ) {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(options_amount);
                const std::string component_name = "index selector component";

                struct input_type {
                    std::size_t index;
                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                struct result_type {
                    result_type(const index_selector &component, std::size_t start_row_index) {}
                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                template<typename ContainerType>
                explicit index_selector(ContainerType witness, std::size_t options_amount_) :
                    component_type(witness, {}, {}, get_manifest(options_amount_)),
                    options_amount(options_amount_){
                    BOOST_ASSERT(this->witness_amount() >= options_amount);
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                index_selector(
                    WitnessContainerType witness, ConstantContainerType constant,
                    PublicInputContainerType public_input, std::size_t options_amount_) :
                    component_type(witness, constant, public_input, get_manifest(options_amount_)),
                    options_amount(options_amount_){
                    BOOST_ASSERT(this->witness_amount() >= options_amount);
                };

                index_selector(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t options_amount_, bool is_compressed_ = false) :
                    component_type(witnesses, constants, public_inputs, get_manifest(options_amount_)),
                    options_amount(options_amount_){
                    BOOST_ASSERT(this->witness_amount() >= this->options_amount);
                };


                // Here we only check that all variables are zeroes and ones, and their sum is 1
                std::vector<constraint_type> generate_constraints() const {
                    std::cout << "Index selector generate_constraints options_amount = " << this->options_amount << std::endl;
                    std::vector<constraint_type> constraints;

                    std::size_t option_cells_amount = (this->options_amount + 1)/2,
                                option_WA = this->witness_amount() - 1;
                    for (std::size_t i = 0; i < options_amount; i++) {
                        var curr_var = var(this->W(i),0);
                        constraints.push_back(curr_var * (curr_var - 1));
                    }
                    return constraints;
                }

                // Allows conveniently connect sum_constraints from different areas;
                constraint_type sum_constraint(std::size_t rotation = 0){
                    constraint_type sum_to_one;
                    for (std::size_t i = 0; i < options_amount; i++) {
                        var curr_var = var(this->W(i), rotation);
                        sum_to_one += curr_var;
                    }
                    return sum_to_one;
                }

                constraint_type index_constraint(std::size_t rotation = 0){
                    constraint_type compose_constraint;
                    for (std::size_t i = 0; i < options_amount; i++){
                        var curr_var = var(this->W(i),rotation);
                        compose_constraint += i * curr_var;
                    }
                    return compose_constraint;
                }

                state_var index(std::size_t i){
                    return state_var(this->W(i));
                }
            };

            template<typename BlueprintFieldType>
            using plonk_index_selector =
                index_selector<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                               BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_index_selector<BlueprintFieldType>::result_type generate_assignments(
                const plonk_index_selector<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_index_selector<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_index_selector<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                std::size_t index = instance_input.index;
                //if( index >= component.options_amount ) std::cout << index << ">=" << component.options_amount << std::endl;
                BOOST_ASSERT(index < component.options_amount);

                // calculating this is somehow very unintuitive
                std::size_t option_WA = component.witness_amount() - 1;

                const integral_type parity = index & 1; // index%2

                for (std::size_t i = 1; i < component.witness_amount() - 1; i++) {          // zerofy all
                    assignment.witness(component.W(i), start_row_index) = 0;
                }
                assignment.witness(component.W(index), start_row_index) = 1;

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_index_selector<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_index_selector<BlueprintFieldType>::input_type
                    &instance_input) {

                return bp.add_gate(component.generate_constraints());
            }

            template<typename BlueprintFieldType>
            typename plonk_index_selector<BlueprintFieldType>::result_type generate_circuit(
                const plonk_index_selector<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_index_selector<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_index_selector<BlueprintFieldType>;
                using state_var = state_var<BlueprintFieldType>;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

        }   // namespace components
    }       // namespace blueprint
}    // namespace nil

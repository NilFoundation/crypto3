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

namespace nil {
    namespace blueprint {
        namespace components {
            // activates a witness column based on an input value
            // is used to achive dynamic selector behavior
            // actual implementation
            template<typename ArithmetizationType, typename FieldType>
            class state_selector;

            template<typename BlueprintFieldType>
            class state_selector<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                std::size_t options_amount;
                bool is_compressed;

                class gate_manifest_type : public component_gate_manifest {
                private:
                    std::size_t witness_amount;
                    std::size_t options_amount;
                    bool is_compressed;

                public:
                    gate_manifest_type(std::size_t witness_amount_, std::size_t options_amount_, bool is_compressed_) :
                        witness_amount(witness_amount_), options_amount(options_amount_), is_compressed(is_compressed_) {};

                    bool operator<(gate_manifest_type const& other) const {
                        return witness_amount < other.witness_amount ||
                               (witness_amount == other.witness_amount && options_amount < other.options_amount) ||
                               (witness_amount == other.witness_amount && options_amount == other.options_amount &&
                                is_compressed < other.is_compressed);
                    }

                    std::uint32_t gates_amount() const override {
                        return state_selector::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t options_amount,
                                                       bool is_compressed) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, options_amount, is_compressed));
                    return manifest;
                }

                static manifest_type get_manifest(std::size_t options_amount, bool is_compressed) {
                    manifest_type manifest = manifest_type(
                        // TODO: make the manifest depend on options_amount
                        // this requires the manifest rework
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(
                            is_compressed ? (options_amount + 1) / 4 + 2 : (options_amount + 1) / 2 + 2
                            )
                        ),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t options_amount,
                                                             bool is_compressed) {
                    return 1 + is_compressed;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), options_amount, is_compressed);
                const std::string component_name = "state selector component";

                struct input_type {
                    var item_index;
                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {item_index};
                    }
                };

                struct result_type {
                    result_type(const state_selector &component, std::size_t start_row_index) {}
                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {};
                    }
                };

                template<typename ContainerType>
                explicit state_selector(ContainerType witness, std::size_t options_amount_, bool is_compressed_ = false) :
                    component_type(witness, {}, {}, get_manifest(options_amount_, is_compressed_)),
                    options_amount(options_amount_),
                    is_compressed(is_compressed_) {

                    BOOST_ASSERT(this->witness_amount() ==
                            this->is_compressed ? (this->options_amount + 1) / 4 + 2 : (this->options_amount + 1) / 2 + 2);
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                state_selector(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, std::size_t options_amount_, bool is_compressed_ = false) :
                    component_type(witness, constant, public_input, get_manifest(options_amount_,is_compressed_)),
                    options_amount(options_amount_),
                    is_compressed(is_compressed_) {

                    BOOST_ASSERT(this->witness_amount() ==
                            this->is_compressed ? (this->options_amount + 1) / 4 + 2 : (this->options_amount + 1) / 2 + 2);
                };

                state_selector(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t options_amount_, bool is_compressed_ = false) :
                    component_type(witnesses, constants, public_inputs, get_manifest(options_amount_, is_compressed_)),
                    options_amount(options_amount_),
                    is_compressed(is_compressed_) {

                    BOOST_ASSERT(this->witness_amount() ==
                            this->is_compressed ? (this->options_amount + 1) / 4 + 2 : (this->options_amount + 1) / 2 + 2);
                };

                std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> generate_constraints() const {
                    using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                    std::vector<constraint_type> constraints;

                    constraint_type sum_to_one;
                    constraint_type idx_decompose;
                    std::size_t option_cells_amount = (this->options_amount + 1)/2,
                                option_WA = this->witness_amount() - 1;
                    std::size_t idx = 0;
                    for (std::size_t i = 0; i < option_cells_amount; i++) {
                        var curr_var = var(this->W(1 + (i % option_WA)), 0 + is_compressed*(i / option_WA), true, var::column_type::witness);
                        sum_to_one += curr_var;
                        idx_decompose += idx * curr_var;
                        idx += 2;
                        constraints.push_back(curr_var * (curr_var - 1));
                    }
                    sum_to_one -= 1;
                    constraints.push_back(sum_to_one);

                    var pairing_var = var(this->W(this->witness_amount() - 1), 0 + is_compressed, true, var::column_type::witness);
                    idx_decompose += pairing_var;
                    idx_decompose -= var(this->W(0), 0, true, var::column_type::witness);
                    constraints.push_back(idx_decompose);

                    if (is_compressed) {
                        constraints.push_back(var(this->W(0), 0, true, var::column_type::witness) -
                                              var(this->W(0), +1, true, var::column_type::witness));
                    }

                    constraints.push_back(pairing_var * (pairing_var - 1));
                    if (options_amount % 2 != 0) {
                        var last_pair = var(this->W(1 + ((option_cells_amount - 1) % option_WA)),
                                            0 + is_compressed*((option_cells_amount - 1) / option_WA), true, var::column_type::witness);
                        constraints.push_back(last_pair * pairing_var);
                    }

                    return constraints;
                }

                constraint_type option_constraint(std::size_t option, bool shift = false) const {
                    BOOST_ASSERT(option < options_amount);

                    std::size_t option_cells_amount = (this->options_amount + 1)/2,
                                option_WA = this->witness_amount() - 1;

                    var option_var = var(this->W(1 + ((option / 2) % option_WA)),
                                         0 + is_compressed*((option/2 / option_WA) - shift),
                                         true, var::column_type::witness),
                        parity_var = var(this->W(this->witness_amount() - 1), 0+is_compressed*(1 - shift), true, var::column_type::witness);

                    if (option % 2 == 0) {
                        return option_var * (1 - parity_var);
                    } else {
                        return option_var * parity_var;
                    }
                }

                constraint_type option_constraint_even(std::size_t option) const {
                    return option_constraint(option,true);
                }

                constraint_type option_constraint_odd(std::size_t option) const {
                    return option_constraint(option,false);
                }

                var option_variable(std::int32_t offset = 0) const {
                    return var(this->W(0), offset, true, var::column_type::witness);
                }
                var parity_variable(std::int32_t offset = 0) const {
                    return var(this->W(this->witness_amount() - 1), offset, true, var::column_type::witness);
                }

            };

            template<typename BlueprintFieldType>
            using plonk_state_selector =
                state_selector<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                               BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_state_selector<BlueprintFieldType>::result_type generate_assignments(
                const plonk_state_selector<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_state_selector<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_state_selector<BlueprintFieldType>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;

                value_type index = var_value(assignment, instance_input.item_index);
                BOOST_ASSERT(index < component.options_amount);

                // calculating this is somehow very unintuitive
                std::size_t option_WA = component.witness_amount() - 1;
                const std::size_t pair_index = std::size_t(integral_type(index.data >> 1));
                const integral_type parity = integral_type(index.data & value_type(1).data);
                assignment.witness(component.W(0), start_row_index) = index;
                if (component.is_compressed) {
                    assignment.witness(component.W(0), start_row_index + 1) = index;
                }
                for (std::size_t i = 1; i < component.witness_amount() - 1; i++) {
                    assignment.witness(component.W(i), start_row_index) = 0;
                    if (component.is_compressed) {
                        assignment.witness(component.W(i), start_row_index + 1) = 0;
                    }
                }
                assignment.witness(component.W(1 + (pair_index % option_WA)),
                                   start_row_index + component.is_compressed*(pair_index / option_WA)) = 1;
                assignment.witness(component.W(component.witness_amount() - 1),
                                   start_row_index + component.is_compressed) = value_type(parity);

                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::size_t generate_gates(
                const plonk_state_selector<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_state_selector<BlueprintFieldType>::input_type
                    &instance_input) {

                return bp.add_gate(component.generate_constraints());
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_state_selector<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_state_selector<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_state_selector<BlueprintFieldType>;
                using var = typename component_type::var;

                bp.add_copy_constraint(
                    {instance_input.item_index,
                     var(component.W(0), start_row_index, false, var::column_type::witness)});
            }

            template<typename BlueprintFieldType>
            typename plonk_state_selector<BlueprintFieldType>::result_type generate_circuit(
                const plonk_state_selector<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_state_selector<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using component_type = plonk_state_selector<BlueprintFieldType>;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

        }   // namespace components
    }       // namespace blueprint
}    // namespace nil

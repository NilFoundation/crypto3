//---------------------------------------------------------------------------//
// Copyright (c) 2023 Alexey Yashunsky <a.yashunsky@nil.foundation>
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
// @file Declaration of interfaces for FRI verification array swapping component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_POSEIDON_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_POSEIDON_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon_constants.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Input: t, array <a1, b1, a2, b2, ..., an, bn>
            // Output: <a1,b1,a2,b2,....,an,bn> if t == 0, <b1,a1,b2,a2,....,bn,an> if t == 1
            // Does NOT check that t is really a bit.
            // Configuration is suboptimal: we do rows of the form
            // t, a1, b1, o11, o12, a2, b2, o21, o22, ...
            // We could reuse t among multiple different rows for a better configuration, but that would be
            // more complex than what we can quickly implement now.
            template<typename ArithmetizationType, typename FieldType>
            class flexible_poseidon;

            template<typename BlueprintFieldType>
            class flexible_poseidon<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using FieldType = BlueprintFieldType;

                constexpr static const std::uint32_t state_size = 3;
                constexpr static const std::uint32_t rounds_amount = 55;
                constexpr static const std::size_t sbox_alpha = 7;

                constexpr static const std::array<std::array<typename FieldType::value_type, state_size>, state_size>
                    mds = detail::poseidon_constants<FieldType, state_size, rounds_amount>::mds;
                constexpr static const std::array<std::array<typename FieldType::value_type, state_size>, rounds_amount>
                    round_constant = detail::poseidon_constants<FieldType, state_size, rounds_amount>::round_constant;

                constexpr static const std::size_t rate = 2;
                constexpr static const std::size_t constraints_amount = rounds_amount * state_size;
                constexpr static const std::size_t cells_amount = (rounds_amount + 1) * state_size;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());

                class gate_manifest_type : public component_gate_manifest {
                private:
                    std::size_t witness_amount;
                public:
                    gate_manifest_type(std::size_t _witness_amount) :
                        witness_amount(_witness_amount) {};

                    bool operator<(gate_manifest_type const& other) const {
                        return witness_amount < other.witness_amount;
                    }

                    std::uint32_t gates_amount() const override {
                        std::size_t blocks = flexible_poseidon::rounds_amount + 1;
                        std::size_t row_capacity = witness_amount/flexible_poseidon::state_size;
                        std::cout << "Poseidon gates amount: " << ((blocks-1)%row_capacity == 0? (blocks-1)/row_capacity : (blocks-1)/row_capacity + 1) << std::endl;
                        return (blocks-1)%row_capacity == 0? (blocks-1)/row_capacity : (blocks-1)/row_capacity + 1;
                    }
                };

                static gate_manifest get_gate_manifest(
                    std::size_t witness_amount
                ) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(3, 168, 3)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(
                    std::size_t witness_amount
                ) {
                    std::size_t blocks = flexible_poseidon::rounds_amount + 1;
                    std::size_t row_capacity = witness_amount/flexible_poseidon::state_size;
                    return blocks%row_capacity == 0? blocks/row_capacity : blocks/row_capacity + 1;
                }

                //constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    std::array<var, state_size> input_state;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.insert(result.end(), input_state.begin(), input_state.end());
                        return result;
                    }
                };

                struct result_type {
                    std::array<var, state_size> output_state = {var(0, 0, false), var(0, 0, false), var(0, 0, false)};

                    result_type(const flexible_poseidon &component, std::uint32_t start_row_index) {
                        std::size_t blocks = rounds_amount + 1;
                        std::size_t row_capacity = component.witness_amount()/state_size;
                        std::size_t last_column_id = blocks % row_capacity == 0? row_capacity * state_size: (blocks %row_capacity) * state_size;
                        last_column_id = last_column_id - 1;

                        output_state = {
                            var(component.W(last_column_id - 2), start_row_index + component.rows_amount - 1, false),
                            var(component.W(last_column_id - 1), start_row_index + component.rows_amount - 1, false),
                            var(component.W(last_column_id), start_row_index + component.rows_amount - 1, false)
                        };
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> result;
                        result.insert(result.end(), output_state.begin(), output_state.end());
                        return result;
                    }
                };

                template<typename ContainerType>
                explicit flexible_poseidon(ContainerType witness) :
                    component_type(witness, {}, {}, get_manifest())
                    {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                flexible_poseidon(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) : component_type(witness, constant, public_input, get_manifest())
                    {};

/*              flexible_poseidon(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs
                ) : component_type(witnesses, constants, public_inputs, get_manifest())
                    {};*/
            };

            template<typename BlueprintFieldType>
            using plonk_flexible_poseidon =
                flexible_poseidon<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                               BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_flexible_poseidon<BlueprintFieldType>::result_type generate_assignments(
                const plonk_flexible_poseidon<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_poseidon<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index
            ) {
                using component_type = plonk_flexible_poseidon<BlueprintFieldType>;

                constexpr static const std::uint32_t state_size = component_type::state_size;

                std::array<typename BlueprintFieldType::value_type, state_size> state = {
                    var_value(assignment, instance_input.input_state[0]),
                    var_value(assignment, instance_input.input_state[1]),
                    var_value(assignment, instance_input.input_state[2])};
                std::array<typename BlueprintFieldType::value_type, state_size> next_state;

                assignment.witness(component.W(0), start_row_index) = state[0];
                assignment.witness(component.W(1), start_row_index) = state[1];
                assignment.witness(component.W(2), start_row_index) = state[2];

                static_assert(state_size == 3);
                std::size_t row = 0;
                std::size_t column = 0;

                for (std::size_t i = 0; i < component.rounds_amount; i++) {
                    for (std::size_t j = 0; j < state_size; j++) {
                        next_state[j] = state[0].pow(component_type::sbox_alpha) * component_type::mds[j][0] +
                                        state[1].pow(component_type::sbox_alpha) * component_type::mds[j][1] +
                                        state[2].pow(component_type::sbox_alpha) * component_type::mds[j][2] +
                                        component_type::round_constant[i][j];
                    }
                    column += 3;
                    if( column + 3 > component.witness_amount() ){
                        row++;
                        column = 0;
                    }
                    assignment.witness(component.W(column), start_row_index + row) = next_state[0];
                    assignment.witness(component.W(column+1), start_row_index + row) = next_state[1];
                    assignment.witness(component.W(column+2), start_row_index + row) = next_state[2];
                    state = next_state;
                }
                return typename component_type::result_type(component, start_row_index);
	        }

            template<typename BlueprintFieldType>
            std::vector<std::size_t>
            generate_gates(
                const plonk_flexible_poseidon<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_poseidon<BlueprintFieldType>::input_type
                    &instance_input) {

                using component_type = plonk_flexible_poseidon<BlueprintFieldType>;
                using var = typename component_type::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;

                std::vector<std::size_t> selectors;

                std::size_t start_column = 0;
                std::vector<std::vector<constraint_type>> constraints;
                std::size_t gate_id = 0;
                for (std::size_t round = 0; round < component_type::rounds_amount; round++) {
                    if(start_column == 0) constraints.push_back(std::vector<constraint_type>());
                    var input_var1 = var(component.W(start_column), 0);
                    var input_var2 = var(component.W(start_column+1), 0);
                    var input_var3 = var(component.W(start_column+2), 0);
                    var output_var1;
                    var output_var2;
                    var output_var3;
                    if( start_column + 5 < component.witness_amount() ){
                        output_var1 = var(component.W(start_column+3), 0);
                        output_var2 = var(component.W(start_column+4), 0);
                        output_var3 = var(component.W(start_column+5), 0);
                    } else {
                        output_var1 = var(component.W(0), 1);
                        output_var2 = var(component.W(1), 1);
                        output_var3 = var(component.W(2), 1);
                    }
                    auto constraint1 =
                        output_var1 -
                        (input_var1.pow(component_type::sbox_alpha) * component_type::mds[0][0] +
                         input_var2.pow(component_type::sbox_alpha) * component_type::mds[0][1] +
                         input_var3.pow(component_type::sbox_alpha) * component_type::mds[0][2] +
                         component_type::round_constant[round][0]);
                    auto constraint2 =
                        output_var2 -
                        (input_var1.pow(component_type::sbox_alpha) * component_type::mds[1][0] +
                         input_var2.pow(component_type::sbox_alpha) * component_type::mds[1][1] +
                         input_var3.pow(component_type::sbox_alpha) * component_type::mds[1][2] +
                         component_type::round_constant[round][1]);
                    auto constraint3 =
                        output_var3 -
                        (input_var1.pow(component_type::sbox_alpha) * component_type::mds[2][0] +
                         input_var2.pow(component_type::sbox_alpha) * component_type::mds[2][1] +
                         input_var3.pow(component_type::sbox_alpha) * component_type::mds[2][2] +
                         component_type::round_constant[round][2]);
                    constraints[gate_id].push_back(constraint1);
                    constraints[gate_id].push_back(constraint2);
                    constraints[gate_id].push_back(constraint3);
                    if( start_column + 5 > component.witness_amount() ){
                        selectors.push_back(bp.add_gate(constraints[gate_id]));
                        gate_id++;
                        start_column = 0;
                    } else {
                        start_column+= 3;
                    }
                }
                if(selectors.size() != constraints.size()){
                    selectors.push_back(bp.add_gate(constraints[gate_id]));
                }
                return selectors;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_flexible_poseidon<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_poseidon<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // CRITICAL: these copy constraints might not be sufficient, but are definitely required.
                // I've added copy constraints for the inputs, but internal ones might be missing
                // Proceed with care
                using var = typename plonk_flexible_poseidon<BlueprintFieldType>::var;
                for (std::size_t i = 0; i < 3; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.input_state[i]});
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_flexible_poseidon<BlueprintFieldType>::result_type generate_circuit(
                const plonk_flexible_poseidon<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_flexible_poseidon<BlueprintFieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                using component_type = plonk_flexible_poseidon<BlueprintFieldType>;

                auto selector_indices = generate_gates(component, bp, assignment, instance_input);
                for( std::size_t i = 0; i < selector_indices.size(); i++){
                    assignment.enable_selector(i, start_row_index+i);
                }
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FLEXIBLE_POSEIDON_HPP
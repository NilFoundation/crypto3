//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_PLONK_POSEIDON_HPP
#define CRYPTO3_BLUEPRINT_PLONK_POSEIDON_HPP

#include <string>

#include <nil/crypto3/algebra/matrix/matrix.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/vesta/base_field.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon_constants.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: [x_0, x_1, x_2] \in Fp
            // Output: [y_0, y_1, y_2] - Poseidon permutation of [x_0, x_1, x_2]
            template<typename ArithmetizationType, typename FieldType>
            class poseidon;

            template<typename BlueprintFieldType, typename FieldType>
            class poseidon<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                           FieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                constexpr static const std::uint32_t state_size = 3;
                constexpr static const std::uint32_t rounds_amount = 55;

                constexpr static const std::size_t rounds_per_row = 5;

                constexpr static const std::size_t sbox_alpha = 7;

                constexpr static const std::array<std::array<typename FieldType::value_type, state_size>, state_size>
                    mds = detail::poseidon_constants<FieldType, state_size, rounds_amount>::mds;
                constexpr static const std::array<std::array<typename FieldType::value_type, state_size>, rounds_amount>
                    round_constant = detail::poseidon_constants<FieldType, state_size, rounds_amount>::round_constant;

                constexpr static const std::size_t rate = 2;
                constexpr static const std::size_t gates_amount = 11;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount());
                const std::string component_name = "poseidon hash";

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return poseidon::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }


                static manifest_type get_manifest() {
                    using manifest_param = nil::blueprint::manifest_param;
                    using manifest_single_value_param = nil::blueprint::manifest_single_value_param;
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(15)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return rounds_amount / rounds_per_row + 1;
                }

                struct input_type {
                    std::array<var, state_size> input_state;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {input_state[0], input_state[1], input_state[2]};
                    }
                };

                struct result_type {
                    std::array<var, state_size> output_state = {var(0, 0, false), var(0, 0, false), var(0, 0, false)};

                    result_type(const poseidon<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                               FieldType> &component,
                                std::uint32_t start_row_index) {

                        output_state = {var(component.W(0), start_row_index + component.rows_amount - 1, false),
                                        var(component.W(1), start_row_index + component.rows_amount - 1, false),
                                        var(component.W(2), start_row_index + component.rows_amount - 1, false)};
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {output_state[0], output_state[1], output_state[2]};
                    }
                };

                constexpr static std::array<std::array<typename FieldType::value_type, state_size>, state_size>
                    mds_constants() {
                    return mds;
                }

                template<typename ContainerType>
                explicit poseidon(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                poseidon(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                poseidon(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type>
                             constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename FieldType>
            using plonk_poseidon =
                poseidon<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                         FieldType>;

            template<typename BlueprintFieldType, typename FieldType>
            typename plonk_poseidon<BlueprintFieldType, FieldType>::result_type
                generate_assignments(
                    const plonk_poseidon<BlueprintFieldType, FieldType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_poseidon<BlueprintFieldType, FieldType>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using component_type = plonk_poseidon<BlueprintFieldType, FieldType>;

                constexpr static const std::uint32_t state_size = component_type::state_size;

                std::array<typename BlueprintFieldType::value_type, state_size> state = {
                    var_value(assignment, instance_input.input_state[0]),
                    var_value(assignment, instance_input.input_state[1]),
                    var_value(assignment, instance_input.input_state[2])};
                std::array<typename BlueprintFieldType::value_type, state_size> next_state;

                std::size_t row = start_row_index;
                assignment.witness(component.W(0), row) = state[0];
                assignment.witness(component.W(1), row) = state[1];
                assignment.witness(component.W(2), row) = state[2];

                static_assert(state_size == 3);

                for (std::size_t i = row; i < row + component.rows_amount - 1; i++) {
                    for (std::size_t j = 0; j < state_size; j++) {
                        next_state[j] = state[0].pow(component_type::sbox_alpha) * component_type::mds[j][0] +
                                        state[1].pow(component_type::sbox_alpha) * component_type::mds[j][1] +
                                        state[2].pow(component_type::sbox_alpha) * component_type::mds[j][2] +
                                        component_type::round_constant[(i - row) * 5][j];
                    }

                    assignment.witness(component.W(3), i) = next_state[0];
                    assignment.witness(component.W(4), i) = next_state[1];
                    assignment.witness(component.W(5), i) = next_state[2];
                    state = next_state;
                    for (std::uint32_t j = 0; j < state_size; j++) {
                        next_state[j] = state[0].pow(component_type::sbox_alpha) * component_type::mds[j][0] +
                                        state[1].pow(component_type::sbox_alpha) * component_type::mds[j][1] +
                                        state[2].pow(component_type::sbox_alpha) * component_type::mds[j][2] +
                                        component_type::round_constant[(i - row) * 5 + 1][j];
                    }
                    assignment.witness(component.W(6), i) = next_state[0];
                    assignment.witness(component.W(7), i) = next_state[1];
                    assignment.witness(component.W(8), i) = next_state[2];
                    state = next_state;
                    for (std::uint32_t j = 0; j < state_size; j++) {
                        next_state[j] = state[0].pow(component_type::sbox_alpha) * component_type::mds[j][0] +
                                        state[1].pow(component_type::sbox_alpha) * component_type::mds[j][1] +
                                        state[2].pow(component_type::sbox_alpha) * component_type::mds[j][2] +
                                        component_type::round_constant[(i - row) * 5 + 2][j];
                    }
                    assignment.witness(component.W(9), i) = next_state[0];
                    assignment.witness(component.W(10), i) = next_state[1];
                    assignment.witness(component.W(11), i) = next_state[2];
                    state = next_state;
                    for (std::uint32_t j = 0; j < state_size; j++) {
                        next_state[j] = state[0].pow(component_type::sbox_alpha) * component_type::mds[j][0] +
                                        state[1].pow(component_type::sbox_alpha) * component_type::mds[j][1] +
                                        state[2].pow(component_type::sbox_alpha) * component_type::mds[j][2] +
                                        component_type::round_constant[(i - row) * 5 + 3][j];
                    }
                    assignment.witness(component.W(12), i) = next_state[0];
                    assignment.witness(component.W(13), i) = next_state[1];
                    assignment.witness(component.W(14), i) = next_state[2];
                    state = next_state;
                    for (std::uint32_t j = 0; j < state_size; j++) {
                        next_state[j] = state[0].pow(component_type::sbox_alpha) * component_type::mds[j][0] +
                                        state[1].pow(component_type::sbox_alpha) * component_type::mds[j][1] +
                                        state[2].pow(component_type::sbox_alpha) * component_type::mds[j][2] +
                                        component_type::round_constant[(i - row) * 5 + 4][j];
                    }
                    assignment.witness(component.W(0), i + 1) = next_state[0];
                    assignment.witness(component.W(1), i + 1) = next_state[1];
                    assignment.witness(component.W(2), i + 1) = next_state[2];
                    state = next_state;
                }

                return typename plonk_poseidon<BlueprintFieldType, FieldType>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename FieldType>
            std::array<std::size_t,
                plonk_poseidon<BlueprintFieldType, FieldType>::rounds_amount /
                plonk_poseidon<BlueprintFieldType, FieldType>::rounds_per_row>
            generate_gates(
                const plonk_poseidon<BlueprintFieldType, FieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_poseidon<BlueprintFieldType, FieldType>::input_type
                    &instance_input) {

                using component_type = plonk_poseidon<BlueprintFieldType, FieldType>;
                using var = typename component_type::var;

                std::array<std::size_t, component_type::rounds_amount / component_type::rounds_per_row> selectors;

                std::size_t j = 0;
                for (std::size_t z = 0; z < component_type::rounds_amount; z += component_type::rounds_per_row) {
                    auto constraint_1 =
                        var(component.W(3), 0) -
                        (var(component.W(0), 0).pow(component_type::sbox_alpha) * component_type::mds[0][0] +
                         var(component.W(1), 0).pow(component_type::sbox_alpha) * component_type::mds[0][1] +
                         var(component.W(2), 0).pow(component_type::sbox_alpha) * component_type::mds[0][2] +
                         component_type::round_constant[z][0]);
                    auto constraint_2 =
                        var(component.W(4), 0) -
                        (var(component.W(0), 0).pow(component_type::sbox_alpha) * component_type::mds[1][0] +
                         var(component.W(1), 0).pow(component_type::sbox_alpha) * component_type::mds[1][1] +
                         var(component.W(2), 0).pow(component_type::sbox_alpha) * component_type::mds[1][2] +
                         component_type::round_constant[z][1]);
                    auto constraint_3 =
                        var(component.W(5), 0) -
                        (var(component.W(0), 0).pow(component_type::sbox_alpha) * component_type::mds[2][0] +
                         var(component.W(1), 0).pow(component_type::sbox_alpha) * component_type::mds[2][1] +
                         var(component.W(2), 0).pow(component_type::sbox_alpha) * component_type::mds[2][2] +
                         component_type::round_constant[z][2]);

                    auto constraint_4 =
                        var(component.W(6), 0) -
                        (var(component.W(3), 0).pow(component_type::sbox_alpha) * component_type::mds[0][0] +
                         var(component.W(4), 0).pow(component_type::sbox_alpha) * component_type::mds[0][1] +
                         var(component.W(5), 0).pow(component_type::sbox_alpha) * component_type::mds[0][2] +
                         component_type::round_constant[z + 1][0]);
                    auto constraint_5 =
                        var(component.W(7), 0) -
                        (var(component.W(3), 0).pow(component_type::sbox_alpha) * component_type::mds[1][0] +
                         var(component.W(4), 0).pow(component_type::sbox_alpha) * component_type::mds[1][1] +
                         var(component.W(5), 0).pow(component_type::sbox_alpha) * component_type::mds[1][2] +
                         component_type::round_constant[z + 1][1]);
                    auto constraint_6 =
                        var(component.W(8), 0) -
                        (var(component.W(3), 0).pow(component_type::sbox_alpha) * component_type::mds[2][0] +
                         var(component.W(4), 0).pow(component_type::sbox_alpha) * component_type::mds[2][1] +
                         var(component.W(5), 0).pow(component_type::sbox_alpha) * component_type::mds[2][2] +
                         component_type::round_constant[z + 1][2]);

                    auto constraint_7 =
                        var(component.W(9), 0) -
                        (var(component.W(6), 0).pow(component_type::sbox_alpha) * component_type::mds[0][0] +
                         var(component.W(7), 0).pow(component_type::sbox_alpha) * component_type::mds[0][1] +
                         var(component.W(8), 0).pow(component_type::sbox_alpha) * component_type::mds[0][2] +
                         component_type::round_constant[z + 2][0]);

                    auto constraint_8 =
                        var(component.W(10), 0) -
                        (var(component.W(6), 0).pow(component_type::sbox_alpha) * component_type::mds[1][0] +
                         var(component.W(7), 0).pow(component_type::sbox_alpha) * component_type::mds[1][1] +
                         var(component.W(8), 0).pow(component_type::sbox_alpha) * component_type::mds[1][2] +
                         component_type::round_constant[z + 2][1]);
                    auto constraint_9 =
                        var(component.W(11), 0) -
                        (var(component.W(6), 0).pow(component_type::sbox_alpha) * component_type::mds[2][0] +
                         var(component.W(7), 0).pow(component_type::sbox_alpha) * component_type::mds[2][1] +
                         var(component.W(8), 0).pow(component_type::sbox_alpha) * component_type::mds[2][2] +
                         component_type::round_constant[z + 2][2]);

                    auto constraint_10 =
                        var(component.W(12), 0) -
                        (var(component.W(9), 0).pow(component_type::sbox_alpha) * component_type::mds[0][0] +
                         var(component.W(10), 0).pow(component_type::sbox_alpha) * component_type::mds[0][1] +
                         var(component.W(11), 0).pow(component_type::sbox_alpha) * component_type::mds[0][2] +
                         component_type::round_constant[z + 3][0]);
                    auto constraint_11 =
                        var(component.W(13), 0) -
                        (var(component.W(9), 0).pow(component_type::sbox_alpha) * component_type::mds[1][0] +
                         var(component.W(10), 0).pow(component_type::sbox_alpha) * component_type::mds[1][1] +
                         var(component.W(11), 0).pow(component_type::sbox_alpha) * component_type::mds[1][2] +
                         component_type::round_constant[z + 3][1]);
                    auto constraint_12 =
                        var(component.W(14), 0) -
                        (var(component.W(9), 0).pow(component_type::sbox_alpha) * component_type::mds[2][0] +
                         var(component.W(10), 0).pow(component_type::sbox_alpha) * component_type::mds[2][1] +
                         var(component.W(11), 0).pow(component_type::sbox_alpha) * component_type::mds[2][2] +
                         component_type::round_constant[z + 3][2]);

                    auto constraint_13 =
                        var(component.W(0), +1) -
                        (var(component.W(12), 0).pow(component_type::sbox_alpha) * component_type::mds[0][0] +
                         var(component.W(13), 0).pow(component_type::sbox_alpha) * component_type::mds[0][1] +
                         var(component.W(14), 0).pow(component_type::sbox_alpha) * component_type::mds[0][2] +
                         component_type::round_constant[z + 4][0]);
                    auto constraint_14 =
                        var(component.W(1), +1) -
                        (var(component.W(12), 0).pow(component_type::sbox_alpha) * component_type::mds[1][0] +
                         var(component.W(13), 0).pow(component_type::sbox_alpha) * component_type::mds[1][1] +
                         var(component.W(14), 0).pow(component_type::sbox_alpha) * component_type::mds[1][2] +
                         component_type::round_constant[z + 4][1]);
                    auto constraint_15 =
                        var(component.W(2), +1) -
                        (var(component.W(12), 0).pow(component_type::sbox_alpha) * component_type::mds[2][0] +
                         var(component.W(13), 0).pow(component_type::sbox_alpha) * component_type::mds[2][1] +
                         var(component.W(14), 0).pow(component_type::sbox_alpha) * component_type::mds[2][2] +
                         component_type::round_constant[z + 4][2]);
                    selectors[j] = bp.add_gate(
                        {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                         constraint_7, constraint_8, constraint_9, constraint_10, constraint_11, constraint_12,
                         constraint_13, constraint_14, constraint_15});
                    j++;
                }
                return selectors;
            }

            template<typename BlueprintFieldType, typename FieldType>
            void generate_copy_constraints(
                const plonk_poseidon<BlueprintFieldType, FieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_poseidon<BlueprintFieldType, FieldType>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // CRITICAL: these copy constraints might not be sufficient, but are definitely required.
                // I've added copy constraints for the inputs, but internal ones might be missing
                // Proceed with care
                using var = typename plonk_poseidon<BlueprintFieldType, FieldType>::var;
                for (std::size_t i = 0; i < 3; i++) {
                    bp.add_copy_constraint({var(component.W(i), start_row_index, false), instance_input.input_state[i]});
                }
            }

            template<typename BlueprintFieldType, typename FieldType>
            typename plonk_poseidon<BlueprintFieldType, FieldType>::result_type
                generate_circuit(
                    const plonk_poseidon<BlueprintFieldType, FieldType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_poseidon<BlueprintFieldType, FieldType>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                auto selector_indices = generate_gates(component, bp, assignment, instance_input);
                for (std::size_t z = 0, i = 0;
                     z < plonk_poseidon<BlueprintFieldType, FieldType>::rounds_amount;
                     z += plonk_poseidon<BlueprintFieldType, FieldType>::rounds_per_row,
                     i++) {
                    assignment.enable_selector(selector_indices[i], start_row_index + i);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                return typename plonk_poseidon<BlueprintFieldType, FieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_POSEIDON_HPP

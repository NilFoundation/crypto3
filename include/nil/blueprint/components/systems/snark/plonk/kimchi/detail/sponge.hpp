//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_SPONGE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_SPONGE_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/crypto3/zk/algorithms/allocate.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/blueprint/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // Poseidon sponge construction
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/poseidon.rs#L64
                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class kimchi_sponge;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class kimchi_sponge<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                    CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using poseidon_component =
                        typename zk::components::poseidon<ArithmetizationType, BlueprintFieldType, W0, W1, W2, W3, W4,
                                                          W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using add_component = typename zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    std::size_t state_count = 0;
                    bool state_absorbed = true;

                    std::array<var, poseidon_component::state_size> state = {var(W0, 0), var(W1, 0), var(W2, 0)};

                    void permute_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                            const std::size_t &component_start_row) {

                        typename poseidon_component::result_type poseidon_res =
                            poseidon_component::generate_assignments(assignment, {state}, component_start_row);

                        for (std::size_t i = 0; i < poseidon_component::state_size; i++) {
                            state[i] = poseidon_res.output_state[i];
                        }
                    }

                    void add_input_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                              var &input,
                                              std::size_t state_index,
                                              const std::size_t component_start_row) {

                        auto addition_result = add_component::generate_assignments(
                            assignment, {input, state[state_index]}, component_start_row);
                        state[state_index] = addition_result.output;
                    }

                    void permute_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const std::size_t component_start_row) {

                        typename poseidon_component::result_type poseidon_res =
                            poseidon_component::generate_circuit(bp, assignment, {state}, component_start_row);

                        for (std::size_t i = 0; i < poseidon_component::state_size; i++) {
                            state[i] = poseidon_res.output_state[i];
                        }
                    }

                    void add_input_circuit(blueprint<ArithmetizationType> &bp,
                                           blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                           const var &input,
                                           std::size_t state_index,
                                           const std::size_t component_start_row) {

                        auto addition_result = zk::components::generate_circuit<add_component>(
                            bp, assignment, {input, state[state_index]}, component_start_row);
                        state[state_index] = addition_result.output;
                    }

                    constexpr static const std::size_t permute_rows = poseidon_component::rows_amount;
                    constexpr static const std::size_t add_input_rows = add_component::rows_amount;

                public:
                    constexpr static const std::size_t init_rows = 0;
                    constexpr static const std::size_t absorb_rows = permute_rows + add_input_rows;
                    constexpr static const std::size_t squeeze_rows = permute_rows;
                    constexpr static const std::size_t gates_amount = 0;

                    constexpr static const std::size_t state_size = poseidon_component::state_size;

                    std::array<var, state_size> _inner_state() {
                        return state;
                    }

                    void init_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                         var zero,
                                         const std::size_t component_start_row) {

                        for (std::size_t i = 0; i < poseidon_component::state_size; i++) {
                            state[i] = zero;
                        }
                    }

                    void init_circuit(blueprint<ArithmetizationType> &bp,
                                      blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                      const var zero,
                                      const std::size_t component_start_row) {

                        for (std::size_t i = 0; i < poseidon_component::state_size; i++) {
                            state[i] = zero;
                        }
                    }

                    void absorb_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                           var absorbing_value,
                                           const std::size_t component_start_row) {

                        std::size_t row = component_start_row;

                        if (this->state_absorbed) {
                            if (this->state_count == poseidon_component::rate) {
                                permute_assignment(assignment, component_start_row);
                                row += permute_rows;

                                add_input_assignment(assignment, absorbing_value, 0, row);

                                this->state_count = 1;
                            } else {
                                add_input_assignment(assignment, absorbing_value, this->state_count,
                                                     component_start_row);

                                this->state_count++;
                            }
                        } else {
                            add_input_assignment(assignment, absorbing_value, 0, component_start_row);

                            this->state_absorbed = true;
                            this->state_count = 1;
                        }
                    }

                    void absorb_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        const var &absorbing_value,
                                        const std::size_t component_start_row) {

                        std::size_t row = component_start_row;

                        if (this->state_absorbed) {
                            if (this->state_count == poseidon_component::rate) {
                                permute_circuit(bp, assignment, component_start_row);

                                row += permute_rows;

                                add_input_circuit(bp, assignment, absorbing_value, 0, row);

                                this->state_count = 1;
                            } else {
                                add_input_circuit(bp, assignment, absorbing_value, this->state_count,
                                                  component_start_row);

                                this->state_count++;
                            }
                        } else {
                            add_input_circuit(bp, assignment, absorbing_value, 0, component_start_row);

                            this->state_absorbed = true;
                            this->state_count = 1;
                        }
                    }

                    var squeeze_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                           const std::size_t component_start_row) {
                        if (!this->state_absorbed) {    // state = squeezed
                            if (this->state_count == poseidon_component::rate) {
                                permute_assignment(assignment, component_start_row);
                                this->state_count = 1;
                                return this->state[0];
                            } else {
                                return this->state[this->state_count++];
                            }
                        } else {
                            permute_assignment(assignment, component_start_row);

                            this->state_absorbed = false;
                            this->state_count = 1;

                            return this->state[0];
                        }
                    }

                    var squeeze_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        const std::size_t component_start_row) {

                        if (!this->state_absorbed) {    // state = squeezed
                            if (this->state_count == poseidon_component::rate) {
                                permute_circuit(bp, assignment, component_start_row);
                                this->state_count = 1;
                                return this->state[0];
                            } else {
                                return this->state[this->state_count++];
                            }
                        } else {
                            permute_circuit(bp, assignment, component_start_row);

                            this->state_absorbed = false;
                            this->state_count = 1;

                            return this->state[0];
                        }
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_SPONGE_HPP

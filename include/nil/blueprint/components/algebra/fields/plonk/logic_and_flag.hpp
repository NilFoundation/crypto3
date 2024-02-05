//---------------------------------------------------------------------------//
// Copyright (c) 2023 Valeh Farzaliyev <estoniaa@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_LOGIC_AND_FLAG_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_LOGIC_AND_FLAG_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            /** && component
             *  Input: x, y
             *  Output: f = 0 if xy=0, f=1 otherwise
             *
             *  Constraints:
             *      p = xy
             *      pv = f
             *      f(f-1) = 0
             *      (v-p)(f-1) = 0
             *  Let p = xy; Then there exists v such that vp=f.
             *  If p=0, then v=0, so f. Otherwise, v = p.inverse() and f = 1
             * */
            template<typename ArithmetizationType>
            class logic_and_flag;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class logic_and_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

                using value_type = typename BlueprintFieldType::value_type;

                constexpr static std::size_t rows_amount_internal(std::size_t witness_amount) {
                    return witness_amount == 2 ? 3 : (witness_amount < 5 ? 2 : 1);
                }
            public:
                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    static const constexpr std::size_t clamp_val = 5;
                    std::size_t witness_amount;

                    gate_manifest_type(std::size_t witness_amount_)
                        : witness_amount(std::min(witness_amount_, clamp_val)) {}

                    std::uint32_t gates_amount() const override {
                        return logic_and_flag::gates_amount;
                    }

                    bool operator<(const component_gate_manifest *other) const override {
                        return witness_amount < dynamic_cast<const gate_manifest_type*>(other)->witness_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_range_param(2, 6)),
                        false
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return rows_amount_internal(witness_amount);
                }
                constexpr static std::size_t get_empty_rows_amount() {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = rows_amount_internal(component_type::witness_amount());
                const std::size_t empty_rows_amount = get_empty_rows_amount();

                struct input_type {
                    var x;
                    var y;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x, y};
                    }
                };

                struct result_type {
                    var output;

                    result_type(const logic_and_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                                 ArithmetizationParams>
                                                    > &component,
                                std::uint32_t start_row_index) {
                        output =
                            var(component.W(component.witness_amount() - 1),
                                            start_row_index + component.rows_amount - 1, false);
                    }
                    result_type(const logic_and_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                                 ArithmetizationParams>
                                                    > &component,
                                std::uint32_t start_row_index, bool skip) {
                        output = var(component.W(0), start_row_index, false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit logic_and_flag(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                logic_and_flag(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                logic_and_flag(std::initializer_list<typename component_type::witness_container_type::value_type>
                                   witnesses,
                               std::initializer_list<typename component_type::constant_container_type::value_type>
                                   constants,
                               std::initializer_list<typename component_type::public_input_container_type::value_type>
                                   public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};

                static typename BlueprintFieldType::value_type calculate(typename BlueprintFieldType::value_type x,
                                                                         typename BlueprintFieldType::value_type y) {

                    std::array<typename BlueprintFieldType::value_type, 5> t;
                    t[0] = x;
                    t[1] = y;
                    t[2] = t[0] * t[1];                                // p
                    t[3] = t[2].is_zero() ? t[2] : t[2].inversed();    // v
                    t[4] = t[3] * t[2];                                // f

                    return t[4];
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_logic_and_flag_component =
                logic_and_flag<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_logic_and_flag_component<BlueprintFieldType,
                                                                  ArithmetizationParams>::input_type &instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                std::array<typename BlueprintFieldType::value_type, 5> t;
                t[0] = var_value(assignment, instance_input.x);
                t[1] = var_value(assignment, instance_input.y);
                t[2] = t[0] * t[1];                                // p
                t[3] = t[2].is_zero() ? t[2] : t[2].inversed();    // v
                t[4] = t[3] * t[2];                                // f

                std::size_t _idx;
                for (std::size_t i = 0; i < component.rows_amount; i++) {
                    for (std::size_t j = 0; j < witness_amount; j++) {
                        _idx = i * witness_amount + j;
                        if (_idx < 5) {
                            assignment.witness(component.W(j), row + i) = t[_idx];
                        }
                    }
                }
                // store the output in last column, last row
                assignment.witness(component.W(witness_amount - 1), row + component.rows_amount - 1) = t[4];

                return
                    typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>::result_type
                        (component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_empty_assignments(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_logic_and_flag_component<BlueprintFieldType,
                                                                  ArithmetizationParams>::input_type &instance_input,
                    const std::uint32_t start_row_index) {
                using component_type = plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>;

                assignment.witness(component.W(0), start_row_index) = component_type::calculate(var_value(assignment, instance_input.x),
                                                                                                var_value(assignment, instance_input.y));

                return
                    typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>::result_type
                        (component, start_row_index, true);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_logic_and_flag_component<BlueprintFieldType,
                                                              ArithmetizationParams>::input_type &instance_input) {

                using var = typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>::var;

                std::size_t offset = component.rows_amount == 3 ? -1 : 0;
                std::size_t witness_amount = component.witness_amount();

                std::array<std::pair<std::size_t, std::size_t>, 4> wl;

                int _idx;
                for (std::size_t i = 0; i < component.rows_amount; i++) {
                    for (std::size_t j = 0; j < witness_amount; j++) {
                        _idx = i * witness_amount + j;
                        if (_idx < 4) {
                            wl[_idx] = std::make_pair(j, i + offset);
                        }
                    }
                }

                auto _x = var(component.W(wl[0].first), wl[0].second);
                auto _y = var(component.W(wl[1].first), wl[1].second);
                auto _p = var(component.W(wl[2].first), wl[2].second);
                auto _v = var(component.W(wl[3].first), wl[3].second);
                auto _f = var(component.W(witness_amount - 1), offset + component.rows_amount - 1);

                auto constraint_1 = _p - _x * _y;            // p =x*y
                auto constraint_2 = _f * (_f - 1);           // f(f-1)=0
                auto constraint_3 = _f - _p * _v;            // f = pv
                auto constraint_4 = (_v - _p) * (_f - 1);    // (v-p)(f-1)=0

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                using var = typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>::var;

                bp.add_copy_constraint({var(component.W(0), row, false), instance_input.x});
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input.y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>
                        &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_logic_and_flag_component<BlueprintFieldType,
                                                                  ArithmetizationParams>::input_type &instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index + (component.rows_amount == 3 ? 1 : 0));

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return
                    typename plonk_logic_and_flag_component<BlueprintFieldType, ArithmetizationParams>::result_type
                        (component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_FIELDS_LOGIC_AND_FLAG_HPP
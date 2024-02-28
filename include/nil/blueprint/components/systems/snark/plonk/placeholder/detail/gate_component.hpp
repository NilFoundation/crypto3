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
// @file Declaration of interfaces for auxiliary components for the GATE_COMPONENT component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_COMPONENT_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {

                /**
                 * Description: Polynomial evaluation component for non-constant polynomials using Horner's methods
                 * Input: theta, C_0, C_1, ..., C_{d-1}, q.
                 * Output: G = q*(C_0 + theta * C_1 + theta^2 * C_2 + ... + theta^{d-1} * C_{d-1}) % p
                 */
                template<typename ArithmetizationType>
                class gate_component;

                template<typename BlueprintFieldType>
                class gate_component<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    : public plonk_component<BlueprintFieldType> {

                    constexpr static const std::uint32_t ConstantsAmount = 0;

                    constexpr static std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t degree) {

                        assert(degree != 0);
                        std::size_t r = std::ceil(2.0 * degree / (witness_amount - 1));
                        if ((2 * degree - 1) % (witness_amount - 1) + 1 >= witness_amount - 3) {
                            r++;
                        }
                        return r;
                    }

                    static std::size_t gates_amount_internal(std::size_t witness_amount) {
                        return 2 * witness_amount;
                    }

                public:
                    using component_type = plonk_component<BlueprintFieldType>;

                    using var = typename component_type::var;
                    using manifest_type = nil::blueprint::plonk_component_manifest;

                    constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                                 std::size_t lookup_column_amount,
                                                                 std::size_t degree) {
                        return rows_amount_internal(witness_amount, degree);
                    }

                    const std::size_t _d;
                    bool need_extra_row = false;

                    const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), _d);
                    const std::size_t gates_amount = gates_amount_internal(this->witness_amount());

                    class gate_manifest_type : public component_gate_manifest {
                    public:
                        std::size_t witness_amount;

                        gate_manifest_type(std::size_t witness_amount_) : witness_amount(witness_amount_) {
                        }

                        std::uint32_t gates_amount() const override {
                            return gate_component::gates_amount_internal(witness_amount);
                        }

                        bool operator<(const component_gate_manifest *other) const override {
                            std::size_t other_witness_amount =
                                dynamic_cast<const gate_manifest_type *>(other)->witness_amount;
                            return witness_amount < other_witness_amount;
                        }
                    };

                    static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                           std::size_t lookup_column_amount,
                                                           std::size_t degree) {
                        gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount));
                        return manifest;
                    }

                    static manifest_type get_manifest() {
                        static manifest_type manifest =
                            manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(3, 15)), false);
                        return manifest;
                    }

                    struct input_type {
                        var theta;
                        std::vector<var> constraints;
                        var selector;

                        std::vector<std::reference_wrapper<var>> all_vars() {
                            std::vector<std::reference_wrapper<var>> vars;
                            vars.push_back(theta);
                            vars.insert(vars.begin() + 1, constraints.begin(), constraints.end());
                            vars.push_back(selector);
                            return vars;
                        }
                    };

                    struct result_type {
                        var output;

                        result_type(const gate_component &component, std::uint32_t start_row_index) {
                            output = var(component.W(component.witness_amount() - 1),
                                         start_row_index + component.rows_amount - 1, false);
                        }

                        std::vector<std::reference_wrapper<var>> all_vars() {
                            return {output};
                        }
                    };

                    template<typename ContainerType>
                    gate_component(ContainerType witness, std::size_t _d_) :
                        component_type(witness, {}, {}, get_manifest()), _d(_d_) {
                        std::size_t WitnessesAmount = this->witness_amount();
                        if ((2 * _d - 1) % (WitnessesAmount - 1) + 1 >= WitnessesAmount - 3) {
                            need_extra_row = true;
                        }
                    };

                    template<typename WitnessContainerType, typename ConstantContainerType,
                             typename PublicInputContainerType>
                    gate_component(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input, std::size_t _d_) :
                        component_type(witness, constant, public_input, get_manifest()),
                        _d(_d_) {
                        std::size_t WitnessesAmount = this->witness_amount();
                        if ((2 * _d - 1) % (WitnessesAmount - 1) + 1 >= WitnessesAmount - 3) {
                            need_extra_row = true;
                        }
                    };

                    gate_component(
                        std::initializer_list<typename component_type::witness_container_type::value_type>
                            witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type>
                            constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        std::size_t _d_) :
                        component_type(witnesses, constants, public_inputs, get_manifest()),
                        _d(_d_) {
                        std::size_t WitnessesAmount = this->witness_amount();
                        if ((2 * _d - 1) % (WitnessesAmount - 1) + 1 >= WitnessesAmount - 3) {
                            need_extra_row = true;
                        }
                    };
                };

            }    // namespace detail

            template<typename BlueprintFieldType>
            using plonk_gate_component = detail::gate_component<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_gate_component<BlueprintFieldType>::result_type generate_assignments(
                const plonk_gate_component<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_gate_component<BlueprintFieldType>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                typename BlueprintFieldType::value_type q = var_value(assignment, instance_input.selector);
                typename BlueprintFieldType::value_type theta = var_value(assignment, instance_input.theta);

                std::vector<typename BlueprintFieldType::value_type> assignments;
                typename BlueprintFieldType::value_type G = BlueprintFieldType::value_type::zero();

                typename BlueprintFieldType::value_type tmp;
                for (std::size_t i = 1; i <= component._d; i++) {
                    tmp = var_value(assignment, instance_input.constraints[component._d - i + 1]);
                    assignments.push_back(tmp);
                    G = theta * (G + tmp);
                    assignments.push_back(G);
                }
                G = q * (G + var_value(assignment, instance_input.constraints[0]));

                std::size_t r = 0, j = 0, i = 0;
                for (i = 0; i < assignments.size(); i++) {
                    r = i / (witness_amount - 1);
                    j = i % (witness_amount - 1) + 1;
                    assignment.witness(component.W(j), row + r) = assignments[i];
                }
                row += r;

                for (r = start_row_index; r <= row; r++) {
                    assignment.witness(component.W(0), r) = theta;
                }
                j = (assignments.size() % (witness_amount - 1)) + 1;
                if (component.need_extra_row) {
                    j = 0;
                    row++;
                }

                assignment.witness(component.W(j), row) = var_value(assignment, instance_input.constraints[0]);
                assignment.witness(component.W(j + 1), row) = q;
                assignment.witness(component.W(witness_amount - 1), row) = G;

                return typename plonk_gate_component<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const plonk_gate_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_gate_component<BlueprintFieldType>::input_type
                    instance_input) {

                std::size_t witness_amount = component.witness_amount();
                using var = typename plonk_gate_component<BlueprintFieldType>::var;

                std::vector<std::size_t> selectors;

                auto constraint_1 =
                    var(component.W(2), 0) - var(component.W(1), 0) * var(component.W(0), 0);    // G = theta * C_d
                selectors.push_back(bp.add_gate({constraint_1}));

                auto constraint_2 =
                    var(component.W(1), 0) - var(component.W(0), 0) * (var(component.W(witness_amount - 1), -1) +
                                                                       var(component.W(witness_amount - 2), -1));
                selectors.push_back(bp.add_gate({constraint_2}));

                auto constraint_3 =
                    var(component.W(2), 0) -
                    var(component.W(0), 0) * (var(component.W(1), 0) + var(component.W(witness_amount - 1), -1));
                selectors.push_back(bp.add_gate({constraint_3}));

                for (std::size_t i = 3; i < witness_amount; i++) {
                    auto constraint_i = var(component.W(i), 0) - var(component.W(0), 0) * (var(component.W(i - 1), 0) +
                                                                                           var(component.W(i - 2), 0));
                    selectors.push_back(bp.add_gate({constraint_i}));
                }

                auto constraint_5 =
                    var(component.W(witness_amount - 1), 0) -
                    var(component.W(1), 0) * (var(component.W(0), 0) + var(component.W(witness_amount - 3), -1));
                selectors.push_back(bp.add_gate({constraint_5}));

                auto constraint_6 =
                    var(component.W(witness_amount - 1), 0) -
                    var(component.W(1), 0) * (var(component.W(0), 0) + var(component.W(witness_amount - 2), -1));
                selectors.push_back(bp.add_gate({constraint_6}));

                auto constraint_7 =
                    var(component.W(witness_amount - 1), 0) -
                    var(component.W(1), 0) * (var(component.W(0), 0) + var(component.W(witness_amount - 1), -1));
                selectors.push_back(bp.add_gate({constraint_7}));

                for (std::size_t i = 2; i < witness_amount - 1; i++) {
                    auto constraint_i =
                        var(component.W(witness_amount - 1), 0) -
                        var(component.W(i), 0) * (var(component.W(i - 1), 0) + var(component.W(i - 2), 0));
                    selectors.push_back(bp.add_gate({constraint_i}));
                }

                return selectors;
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_gate_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_gate_component<BlueprintFieldType>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_gate_component<BlueprintFieldType>::var;

                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                std::size_t r = 0, j = 0;

                for (std::size_t i = 0; i < component.rows_amount - 1; i++) {
                    bp.add_copy_constraint({var(component.W(0), row + i, false), instance_input.theta});
                }
                if (!component.need_extra_row) {
                    bp.add_copy_constraint(
                        {var(component.W(0), row + component.rows_amount - 1, false), instance_input.theta});
                }

                for (std::size_t i = 0; i < component._d; i++) {
                    r = (2 * i) / (witness_amount - 1);
                    j = (2 * i) % (witness_amount - 1) + 1;
                    bp.add_copy_constraint(
                        {var(component.W(j), row + r, false), instance_input.constraints[component._d - i]});
                }
                row = start_row_index + component.rows_amount - 1;
                j = 2 * component._d % (witness_amount - 1) + 1;
                if (component.need_extra_row) {
                    j = 0;
                }

                bp.add_copy_constraint({var(component.W(j), row, false), instance_input.constraints[0]});
                bp.add_copy_constraint({var(component.W(j + 1), row, false), instance_input.selector});
            }

            template<typename BlueprintFieldType>
            typename plonk_gate_component<BlueprintFieldType>::result_type generate_circuit(
                const plonk_gate_component<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_gate_component<BlueprintFieldType>::input_type
                    instance_input,
                const std::size_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                std::vector<std::size_t> selector_indices = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_indices[0], row);

                // first row gates
                std::size_t last_gate = (2 * component._d - 1) % (witness_amount - 1) + 1;
                std::size_t first_row_last_gate = witness_amount - 1;

                if (component.rows_amount == 1 || (component.rows_amount == 2 && component.need_extra_row)) {
                    first_row_last_gate = last_gate;
                }

                for (std::size_t i = 4; i <= first_row_last_gate; i = i + 2) {
                    assignment.enable_selector(selector_indices[i], row);
                }

                if (component.rows_amount > 1) {
                    // middle row gates
                    std::size_t r;
                    std::size_t tmp = 2;
                    for (r = 1; r < component.rows_amount - 2; r++) {
                        tmp = 2 - ((witness_amount - 1) % 2) * (r % 2);
                        for (std::size_t i = tmp; i < witness_amount; i = i + 2) {
                            assignment.enable_selector(selector_indices[i], row + r);
                        }
                    }

                    tmp = 2 - ((witness_amount - 1) % 2) * (r % 2);
                    if (component.need_extra_row && r == component.rows_amount - 2) {
                        for (std::size_t i = tmp; i <= last_gate; i = i + 2) {
                            assignment.enable_selector(selector_indices[i], row + r);
                        }
                        r++;
                    }
                    if( !component.need_extra_row && r == component.rows_amount - 2) {
                        for (std::size_t i = tmp; i < witness_amount; i = i + 2) {
                            assignment.enable_selector(selector_indices[i], row + r);
                        }
                        r++;
                    }

                    // last row gates
                    tmp = 2 - (r % 2) * ((witness_amount - 1) % 2);
                    if (component.need_extra_row) {
                        assignment.enable_selector(selector_indices[last_gate + 3], row + r);
                    } else {
                        for (std::size_t i = tmp; i <= last_gate; i = i + 2) {
                            assignment.enable_selector(selector_indices[i], row + r);
                        }
                        assignment.enable_selector(selector_indices[witness_amount + last_gate + 3], row + r);
                    }
                } else {
                    assignment.enable_selector(selector_indices[witness_amount + last_gate + 3], row);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_gate_component<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_GATE_COMPONENT_HPP
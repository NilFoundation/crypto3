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
// @file Declaration of interfaces for auxiliary components for the LOOKUP_ARGUMENT_VERIFIER component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_F3_LOOP_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_F3_LOOP_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            namespace detail {
                template<typename ArithmetizationType>
                class f3_loop;

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                class f3_loop<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 1> {

                    constexpr static const std::uint32_t ConstantsAmount = 0;

                    constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t n) {

                        std::size_t r = std::ceil(4.0 * n / witness_amount);
                        return r;
                    }

                    constexpr static std::size_t gates_amount_internal(std::size_t witness_amount, std::size_t degree) {
                        if (witness_amount % 4 == 0) {
                            return witness_amount / 4 + 1;
                        }
                        if (witness_amount % 4 == 2) {
                            return witness_amount / 2 + 1;
                        }
                        return witness_amount + 1;
                    }

                public:
                    using component_type =
                        plonk_component<BlueprintFieldType, ArithmetizationParams, ConstantsAmount, 1>;
                    using var = typename component_type::var;
                    using manifest_type = nil::blueprint::plonk_component_manifest;

                    constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                                 std::size_t lookup_column_amount, std::size_t m) {
                        return rows_amount_internal(witness_amount, m);
                    }

                    const std::size_t m;

                    const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), m);
                    const std::size_t gates_amount = gates_amount_internal(this->witness_amount(), m);

                    class gate_manifest_type : public component_gate_manifest {
                    public:
                        std::size_t witness_amount;
                        std::size_t degree;

                        gate_manifest_type(std::size_t witness_amount_, std::size_t degree_) :
                            witness_amount(witness_amount_), degree(degree_) {
                        }

                        std::uint32_t gates_amount() const override {
                            return f3_loop::gates_amount_internal(witness_amount, degree);
                        }

                        bool operator<(const component_gate_manifest *other) const override {
                            return this->witness_amount <
                                   dynamic_cast<const gate_manifest_type *>(other)->witness_amount;
                        }
                    };

                    static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                           std::size_t lookup_column_amount,
                                                           std::size_t degree) {
                        gate_manifest manifest = gate_manifest(gate_manifest_type(witness_amount, degree));
                        return manifest;
                    }

                    static manifest_type get_manifest() {
                        static manifest_type manifest =
                            manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(4, 15)), false);
                        return manifest;
                    }

                    struct input_type {
                        std::vector<var> alphas;
                        std::vector<var> s;
                        std::vector<var> t;

                        std::vector<var> all_vars() const {
                            std::vector<var> vars;
                            vars.insert(vars.end(), alphas.begin(), alphas.end());
                            vars.insert(vars.end(), s.begin(), s.end());
                            vars.insert(vars.end(), t.begin(), t.end());
                            return vars;
                        }
                    };

                    struct result_type {
                        var output;

                        result_type(const f3_loop &component, std::uint32_t start_row_index) {
                            std::size_t WitnessesAmount = component.witness_amount();
                            std::size_t l = 4 * component.m % WitnessesAmount;
                            if (l == 0) {
                                l = WitnessesAmount;
                            }
                            output = var(component.W(l - 1), start_row_index + component.rows_amount - 1, false);
                        }

                        std::vector<var> all_vars() const {
                            return {output};
                        }
                    };

                    template<typename ContainerType>
                    f3_loop(ContainerType witness, std::size_t m_) :
                        component_type(witness, {}, {}, get_manifest()), m(m_) {};

                    template<typename WitnessContainerType, typename ConstantContainerType,
                             typename PublicInputContainerType>
                    f3_loop(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input, std::size_t m_) :
                        component_type(witness, constant, public_input, get_manifest()),
                        m(m_) {};

                    f3_loop(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs,
                            std::size_t m_) :
                        component_type(witnesses, constants, public_inputs, get_manifest()),
                        m(m_) {};
                };
            }    // namespace detail

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_f3_loop =
                detail::f3_loop<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_f3_loop<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                assert(instance_input.s.size() == instance_input.t.size());
                assert(instance_input.s.size() == instance_input.alphas.size());
                assert(instance_input.s.size() == component.m);

                using var = typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::var;

                typename BlueprintFieldType::value_type f3 = BlueprintFieldType::value_type::zero();
                std::vector<typename BlueprintFieldType::value_type> assignments;
                for (std::size_t i = 0; i < component.m; i++) {
                    typename BlueprintFieldType::value_type s_i = var_value(assignment, instance_input.s[i]);
                    typename BlueprintFieldType::value_type t_i = var_value(assignment, instance_input.t[i]);
                    typename BlueprintFieldType::value_type alpha_i = var_value(assignment, instance_input.alphas[i]);
                    f3 = f3 + (s_i - t_i) * alpha_i;
                    assignments.push_back(alpha_i);
                    assignments.push_back(s_i);
                    assignments.push_back(t_i);
                    assignments.push_back(f3);
                }

                std::size_t r = 0, j = 0, i = 0;
                for (i = 0; i < assignments.size(); i++) {
                    r = i / (witness_amount);
                    j = i % witness_amount;
                    assignment.witness(component.W(j), row + r) = assignments[i];
                }
                row += r;

                return typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::result_type(component,
                                                                                                      start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<std::size_t> generate_gates(
                const plonk_f3_loop<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::input_type instance_input) {

                using var = typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::var;
                std::size_t witness_amount = component.witness_amount();

                std::vector<std::size_t> selectors;

                auto constraint_1 =
                    var(component.W(3), 0) - (var(component.W(1), 0) - var(component.W(2), 0)) * var(component.W(0), 0);
                selectors.push_back(bp.add_gate({constraint_1}));

                if (witness_amount % 4 == 0) {
                    auto constraint_2 = var(component.W(3), 0) - var(component.W(witness_amount - 1), -1) -
                                        (var(component.W(1), 0) - var(component.W(2), 0)) * var(component.W(0), 0);
                    selectors.push_back(bp.add_gate({constraint_2}));

                    for (std::size_t j = 7; j < witness_amount; j = j + 4) {
                        auto constraint_ =
                            var(component.W(j), 0) - var(component.W(j - 4), 0) -
                            (var(component.W(j - 2), 0) - var(component.W(j - 1), 0)) * var(component.W(j - 3), 0);
                        selectors.push_back(bp.add_gate({constraint_2}));
                    }
                } else if (witness_amount % 4 == 2) {
                    auto constraint_2 = var(component.W(1), 0) - var(component.W(witness_amount - 3), -1) -
                                        (var(component.W(witness_amount - 1), -1) - var(component.W(0), 0)) *
                                            var(component.W(witness_amount - 2), -1);
                    selectors.push_back(bp.add_gate({constraint_2}));

                    auto constraint_3 = var(component.W(3), 0) - var(component.W(witness_amount - 1), -1) -
                                        (var(component.W(1), 0) - var(component.W(2), 0)) * var(component.W(0), 0);
                    selectors.push_back(bp.add_gate({constraint_3}));

                    for (std::size_t j = 5; j < witness_amount; j = j + 2) {
                        auto constraint_ =
                            var(component.W(j), 0) - var(component.W(j - 4), 0) -
                            (var(component.W(j - 2), 0) - var(component.W(j - 1), 0)) * var(component.W(j - 3), 0);
                        selectors.push_back(bp.add_gate({constraint_}));
                    }

                } else {
                    auto constraint_2 =
                        var(component.W(0), 0) - var(component.W(witness_amount - 4), -1) -
                        (var(component.W(witness_amount - 2), -1) - var(component.W(witness_amount - 1), -1)) *
                            var(component.W(witness_amount - 3), -1);
                    selectors.push_back(bp.add_gate({constraint_2}));

                    auto constraint_3 = var(component.W(1), 0) - var(component.W(witness_amount - 3), -1) -
                                        (var(component.W(witness_amount - 1), -1) - var(component.W(0), 0)) *
                                            var(component.W(witness_amount - 2), -1);
                    selectors.push_back(bp.add_gate({constraint_3}));

                    auto constraint_4 =
                        var(component.W(2), 0) - var(component.W(witness_amount - 2), -1) -
                        (var(component.W(0), 0) - var(component.W(1), 0)) * var(component.W(witness_amount - 1), -1);
                    selectors.push_back(bp.add_gate({constraint_4}));

                    auto constraint_5 = var(component.W(3), 0) - var(component.W(witness_amount - 1), -1) -
                                        (var(component.W(1), 0) - var(component.W(2), 0)) * var(component.W(0), 0);
                    selectors.push_back(bp.add_gate({constraint_5}));

                    for (std::size_t j = 4; j < witness_amount; j++) {
                        auto constraint_ =
                            var(component.W(j), 0) - var(component.W(j - 4), 0) -
                            (var(component.W(j - 2), 0) - var(component.W(j - 1), 0)) * var(component.W(j - 3), 0);
                        selectors.push_back(bp.add_gate({constraint_}));
                    }
                }

                return selectors;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_f3_loop<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::var;
                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                std::size_t tmp;

                std::size_t last_col = 4 * component.m % witness_amount;
                if (last_col == 0) {
                    last_col = witness_amount;
                }
                for (std::size_t r = 0; r < component.rows_amount; r++) {
                    std::size_t last_j = (r == component.rows_amount - 1) ? last_col : witness_amount;
                    for (std::size_t j = 0; j < last_j; j++) {
                        tmp = r * witness_amount + j;
                        if (tmp % 4 == 0) {
                            bp.add_copy_constraint(
                                {var(component.W(j), row + r, false), instance_input.alphas[tmp / 4]});
                        } else if (tmp % 4 == 1) {
                            bp.add_copy_constraint({var(component.W(j), row + r, false), instance_input.s[tmp / 4]});
                        } else if (tmp % 4 == 2) {
                            bp.add_copy_constraint({var(component.W(j), row + r, false), instance_input.t[tmp / 4]});
                        }
                    }
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_f3_loop<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t witness_amount = component.witness_amount();

                assert(instance_input.s.size() == instance_input.t.size());
                assert(instance_input.s.size() == component.m);

                std::vector<std::size_t> selectors = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selectors[0], row);

                std::size_t last_col = 4 * component.m % witness_amount;
                if (last_col == 0) {
                    last_col = witness_amount;
                }

                std::size_t start_j, x = witness_amount % 4;
                std::size_t r;
                if (witness_amount % 4 == 0) {
                    start_j = 3;
                    for (r = 0; r < component.rows_amount - 1; r++) {
                        for (std::size_t j = start_j; j < witness_amount; j = j + 4) {
                            if (r == 0 && j == 3)
                                continue;
                            assignment.enable_selector(selectors[(j / 4 + 1)], row + r);
                        }
                    }
                    r = component.rows_amount - 1;
                    for (std::size_t j = start_j; j < last_col; j = j + 4) {
                        assignment.enable_selector(selectors[(j / 4 + 1)], row + r);
                    }
                } else if (witness_amount % 4 == 2) {
                    for (r = 0; r < component.rows_amount - 1; r++) {
                        start_j = 3 - 2 * (r % 2);
                        for (std::size_t j = start_j; j < witness_amount; j = j + 4) {
                            if (r == 0 && j == 3)
                                continue;
                            assignment.enable_selector(selectors[(j / 2 + 1)], row + r);
                        }
                    }

                    r = component.rows_amount - 1;
                    start_j = 3 - 2 * (r % 2);
                    for (std::size_t j = start_j; j < last_col; j = j + 4) {
                        assignment.enable_selector(selectors[(j / 2 + 1)], row + r);
                    }
                } else {
                    for (r = 0; r < component.rows_amount - 1; r++) {
                        if (r % 4 == 0) {
                            start_j = 3;
                        } else {
                            start_j = (3 - x) + (x - 2) * (r % 4 - 1);
                        }
                        for (std::size_t j = start_j; j < witness_amount; j = j + 4) {
                            if (r == 0 && j == 3)
                                continue;
                            assignment.enable_selector(selectors[j + 1], row + r);
                        }
                    }

                    r = component.rows_amount - 1;
                    if (r % 4 == 0) {
                        start_j = 3;
                    } else {
                        start_j = (3 - x) + (x - 2) * (r % 4 - 1);
                    }
                    for (std::size_t j = start_j; j < last_col; j = j + 4) {
                        assignment.enable_selector(selectors[j + 1], row + r);
                    }
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_f3_loop<BlueprintFieldType, ArithmetizationParams>::result_type(component,
                                                                                                      start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_F3_LOOP_HPP
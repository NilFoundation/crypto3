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
// @file Declaration of interfaces for auxiliary components for the PERMUTATION_ARGUMENT_VERIFIER component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERMUTATION_ARGUMENT_VERIFIER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERMUTATION_ARGUMENT_VERIFIER_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType>
            class permutation_verifier;

            template<typename BlueprintFieldType>
            class permutation_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType> {

                constexpr static const std::uint32_t ConstantsAmount = 0;

                constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t m) {
                    return m + 2;
                }

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                const std::size_t m;

                std::size_t rows_amount = rows_amount_internal(this->witness_amount(), m);
                constexpr static const std::size_t gates_amount = 4;
                const std::string component_name = "permutation argument verifier component";

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t m) {
                    return rows_amount_internal(witness_amount, m);
                }

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return permutation_verifier::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t m) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(std::size_t m) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(6)), false);
                    return manifest;
                }

                struct input_type {
                    std::vector<var> f;
                    std::vector<var> Se;
                    std::vector<var> Ssigma;
                    var L0;
                    var V;
                    var V_zeta;
                    var q_last;
                    var q_pad;
                    std::array<var, 2> thetas;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> vars;
                        vars.insert(vars.end(), f.begin(), f.end());
                        vars.insert(vars.end(), Se.begin(), Se.end());
                        vars.insert(vars.end(), Ssigma.begin(), Ssigma.end());
                        vars.push_back(L0);
                        vars.push_back(V);
                        vars.push_back(V_zeta);
                        vars.push_back(q_last);
                        vars.push_back(q_pad);
                        vars.push_back(thetas[0]);
                        vars.push_back(thetas[1]);
                        return vars;
                    }
                };

                struct result_type {
                    std::array<var, 3> output;

                    result_type(const permutation_verifier &component, std::uint32_t start_row_index) {
                        output = {var(component.W(0), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(4), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(0), start_row_index + component.rows_amount - 1, false)};
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {output[0], output[1], output[2]};
                    }
                };

                template<typename ContainerType>
                permutation_verifier(ContainerType witness, std::size_t m_) :
                    component_type(witness, {}, {}, get_manifest(m_)), m(m_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                permutation_verifier(WitnessContainerType witness, ConstantContainerType constant,
                                     PublicInputContainerType public_input, std::size_t m_) :
                    component_type(witness, constant, public_input, get_manifest(m_)),
                    m(m_) {};

                permutation_verifier(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t m_) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m_)),
                    m(m_) {};
            };

            template<typename BlueprintFieldType>
            using plonk_permutation_verifier = permutation_verifier<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>;

            template<typename BlueprintFieldType>
            typename plonk_permutation_verifier<BlueprintFieldType>::result_type
                generate_assignments(
                    const plonk_permutation_verifier<BlueprintFieldType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_permutation_verifier<BlueprintFieldType>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                assert(instance_input.f.size() == component.m);

                std::size_t m = component.m;

                std::vector<typename BlueprintFieldType::value_type> f, Se, Ssigma;
                for (std::size_t i = 0; i < m; i++) {
                    f.push_back(var_value(assignment, instance_input.f[i]));
                    Se.push_back(var_value(assignment, instance_input.Se[i]));
                    Ssigma.push_back(var_value(assignment, instance_input.Ssigma[i]));
                }
                typename BlueprintFieldType::value_type one = BlueprintFieldType::value_type::one();
                typename BlueprintFieldType::value_type fe = one;
                typename BlueprintFieldType::value_type fsigma = one;

                typename BlueprintFieldType::value_type theta_1 = var_value(assignment, instance_input.thetas[0]);
                typename BlueprintFieldType::value_type theta_2 = var_value(assignment, instance_input.thetas[1]);

                typename BlueprintFieldType::value_type L0_y = var_value(assignment, instance_input.L0);
                typename BlueprintFieldType::value_type Vsigma_y = var_value(assignment, instance_input.V);
                typename BlueprintFieldType::value_type Vsigma_zetay = var_value(assignment, instance_input.V_zeta);
                typename BlueprintFieldType::value_type q_last_y = var_value(assignment, instance_input.q_last);
                typename BlueprintFieldType::value_type q_pad_y = var_value(assignment, instance_input.q_pad);

                for (std::size_t i = 0; i < m; i++) {
                    fe = fe * (f[i] + theta_1 * Se[i] + theta_2);
                    fsigma = fsigma * (f[i] + theta_1 * Ssigma[i] + theta_2);
                    assignment.witness(component.W(0), row + i) = fe;
                    assignment.witness(component.W(1), row + i) = f[i];
                    assignment.witness(component.W(2), row + i) = Se[i];
                    assignment.witness(component.W(4), row + i) = Ssigma[i];
                    assignment.witness(component.W(5), row + i) = fsigma;

                    if (i & 1) {
                        assignment.witness(component.W(3), row + i) = theta_2;
                    } else {
                        assignment.witness(component.W(3), row + i) = theta_1;
                    }
                }
                row += component.m;

                assignment.witness(component.W(0), row) = L0_y * (one - Vsigma_y);
                assignment.witness(component.W(1), row) = q_last_y;
                assignment.witness(component.W(2), row) = q_pad_y;
                assignment.witness(component.W(3), row) = L0_y;
                assignment.witness(component.W(4), row) =
                    (1 - (q_last_y + q_pad_y)) * (Vsigma_zetay * fsigma - Vsigma_y * fe);

                row++;

                assignment.witness(component.W(0), row) = q_last_y * (Vsigma_y * Vsigma_y - Vsigma_y);
                assignment.witness(component.W(1), row) = Vsigma_y;
                assignment.witness(component.W(2), row) = Vsigma_y * Vsigma_y;
                assignment.witness(component.W(3), row) = Vsigma_zetay;

                return typename plonk_permutation_verifier<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::vector<std::size_t> generate_gates(
                const plonk_permutation_verifier<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_permutation_verifier<BlueprintFieldType>::input_type
                    instance_input) {

                using var = typename plonk_permutation_verifier<BlueprintFieldType>::var;

                auto constraint_1 = var(component.W(0), 0) - var(component.W(1), 0) -
                                    var(component.W(2), 0) * var(component.W(3), 0) - var(component.W(3), +1);
                auto constraint_2 = var(component.W(5), 0) - var(component.W(1), 0) -
                                    var(component.W(4), 0) * var(component.W(3), 0) - var(component.W(3), +1);

                auto constraint_3 = var(component.W(0), +1) -
                                    var(component.W(0), 0) *
                                        (var(component.W(1), +1) + var(component.W(2), +1) * var(component.W(3), 0) +
                                         var(component.W(3), +1));
                auto constraint_4 = var(component.W(5), +1) -
                                    var(component.W(5), 0) *
                                        (var(component.W(1), +1) + var(component.W(4), +1) * var(component.W(3), 0) +
                                         var(component.W(3), +1));

                std::size_t first_selector_index =
                    bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4});

                auto constraint_5 = var(component.W(0), 0) -
                                    var(component.W(0), -1) *
                                        (var(component.W(1), 0) + var(component.W(2), 0) * var(component.W(3), 0) +
                                         var(component.W(3), +1));
                auto constraint_6 = var(component.W(5), 0) -
                                    var(component.W(5), -1) *
                                        (var(component.W(1), 0) + var(component.W(4), 0) * var(component.W(3), 0) +
                                         var(component.W(3), +1));

                std::size_t second_selector_index =
                    bp.add_gate({constraint_3, constraint_4, constraint_5, constraint_6});

                auto constraint_7 = var(component.W(0), 0) -
                                    var(component.W(0), -1) *
                                        (var(component.W(1), 0) + var(component.W(2), 0) * var(component.W(3), 0) +
                                         var(component.W(3), -1));
                auto constraint_8 = var(component.W(5), 0) -
                                    var(component.W(5), -1) *
                                        (var(component.W(1), 0) + var(component.W(4), 0) * var(component.W(3), 0) +
                                         var(component.W(3), -1));
                std::size_t third_selector_index = bp.add_gate({constraint_7, constraint_8});

                auto constraint_9 = var(component.W(0), 0) - var(component.W(3), 0) * (1 - var(component.W(1), +1));
                auto constraint_10 = var(component.W(4), 0) - (1 - var(component.W(1), 0) - var(component.W(2), 0)) *
                                                                  (var(component.W(3), +1) * var(component.W(5), -1) -
                                                                   var(component.W(1), +1) * var(component.W(0), -1));

                auto constraint_11 = var(component.W(2), +1) - var(component.W(1), +1) * var(component.W(1), +1);
                auto constraint_12 = var(component.W(0), +1) -
                                     var(component.W(1), 0) * (var(component.W(2), +1) - var(component.W(1), +1));

                std::size_t fourth_selector_index =
                    bp.add_gate({constraint_9, constraint_10, constraint_11, constraint_12});

                return {first_selector_index, second_selector_index, third_selector_index, fourth_selector_index};
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_permutation_verifier<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_permutation_verifier<BlueprintFieldType>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                std::size_t m = component.m;

                using var = typename plonk_permutation_verifier<BlueprintFieldType>::var;

                for (std::size_t i = 0; i < m; i++) {
                    bp.add_copy_constraint({var(component.W(1), row, false), instance_input.f[i]});
                    bp.add_copy_constraint({var(component.W(2), row, false), instance_input.Se[i]});
                    bp.add_copy_constraint({var(component.W(3), row, false), instance_input.thetas[(i & 1)]});
                    bp.add_copy_constraint({var(component.W(4), row, false), instance_input.Ssigma[i]});
                    row++;
                }
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input.q_last});
                bp.add_copy_constraint({var(component.W(2), row, false), instance_input.q_pad});
                bp.add_copy_constraint({var(component.W(3), row, false), instance_input.L0});
                row++;
                bp.add_copy_constraint({var(component.W(1), row, false), instance_input.V});
                bp.add_copy_constraint({var(component.W(3), row, false), instance_input.V_zeta});
            }

            template<typename BlueprintFieldType>
            typename plonk_permutation_verifier<BlueprintFieldType>::result_type
                generate_circuit(
                    const plonk_permutation_verifier<BlueprintFieldType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_permutation_verifier<BlueprintFieldType>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                std::vector<std::size_t> selectors = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selectors[0], row);

                for (row = start_row_index + 2; row < start_row_index + component.m - (component.m & 1); row += 2) {
                    assignment.enable_selector(selectors[1], row);
                }

                row = start_row_index + component.m;
                if (component.m & 1) {
                    assignment.enable_selector(selectors[2], row - 1);
                }
                assignment.enable_selector(selectors[3], row);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_permutation_verifier<BlueprintFieldType>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_PERMUTATION_ARGUMENT_VERIFIER_HPP
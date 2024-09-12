//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
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
// @file Declaration of interfaces for FRI verification linear interpolation component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DFRI_LINEAR_CHECK_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DFRI_LINEAR_CHECK_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            // Linear check with points (s,y0), (-s,y1) at point alpha
            // Input: s, y0, y1, alpha
            // Output: y = y0 + (y1 - y0)*(s - alpha)/(2s)
            // DOES NOT CHECK THAT s != 0
            template<typename ArithmetizationType, typename BlueprintFieldType>
            class dfri_linear_check;

            template<typename BlueprintFieldType>
            class dfri_linear_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>
                : public plonk_component<BlueprintFieldType> {

            public:
                using component_type = plonk_component<BlueprintFieldType>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::size_t m;
                    std::uint32_t gates_amount() const override {
                        return dfri_linear_check::gates_amount;
                    }

                    gate_manifest_type(std::size_t m_) :m(m_) {};
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t m) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type(m));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(3, 15)), false);
                    return manifest;
                }

                const std::size_t m;
                const std::vector<std::pair<std::size_t, std::size_t>> eval_map;

                const std::vector<std::array<std::pair<std::size_t, std::size_t>, 9>> fullconfig =
                    full_configuration(this->witness_amount(), 0, m);

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t m) {
                    return m * std::ceil(9.0 / witness_amount);
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), m);
                const std::string component_name = "dfri linear check component";

                struct input_type {
                    var theta;
                    var x;
                    std::vector<var> xi;
                    std::vector<var> y;
                    std::vector<std::vector<var>> z;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        std::vector<std::reference_wrapper<var>> vars;

                        vars.push_back(theta);
                        vars.push_back(x);
                        vars.insert(vars.end(), xi.begin(), xi.end());
                        vars.insert(vars.end(), y.begin(), y.end());
                        for (std::size_t i = 0; i < z.size(); i++) {
                            vars.insert(vars.end(), z[i].begin(), z[i].end());
                        }

                        return vars;
                    }
                };

                struct result_type {
                    var output;

                    result_type(const dfri_linear_check &component, std::uint32_t start_row_index) {

                        output = var(component.W(component.fullconfig[component.m-1][8].first),
                                     start_row_index + component.fullconfig[component.m-1][8].second, false, var::column_type::witness);
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {output};
                    }
                };

                static std::array<std::pair<std::size_t, std::size_t>, 9> configure_blocks(std::size_t witness_amount,
                                                                                           std::size_t row) {

                    std::array<std::pair<std::size_t, std::size_t>, 9> locations;

                    std::size_t r = 0, c = 0;
                    for (std::size_t i = 0; i < 9; i++) {
                        r = row + i / witness_amount;
                        c = i % witness_amount;
                        locations[i] = std::make_pair(c, r);
                    }

                    return locations;
                }

                static std::vector<std::array<std::pair<std::size_t, std::size_t>, 9>>
                    full_configuration(std::size_t witness_amount, std::size_t row, std::size_t m) {

                    std::vector<std::array<std::pair<std::size_t, std::size_t>, 9>> configs;
                    std::size_t single_block_rows = std::ceil(9.0 / witness_amount);

                    for (std::size_t i = 0; i < m; i++) {
                        configs.push_back(configure_blocks(witness_amount, row + i * single_block_rows));
                    }

                    return configs;
                }

                template<typename ContainerType>
                dfri_linear_check(ContainerType witness, std::size_t m_,
                                  std::vector<std::pair<std::size_t, std::size_t>> eval_map_) :
                    component_type(witness, {}, {}, get_manifest()), m(m_), eval_map(eval_map_) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                dfri_linear_check(WitnessContainerType witness, ConstantContainerType constant,
                                  PublicInputContainerType public_input, std::size_t m_,
                                  std::vector<std::pair<std::size_t, std::size_t>> eval_map_) :
                    component_type(witness, constant, public_input, get_manifest()), m(m_), eval_map(eval_map_) {};

                dfri_linear_check(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t m_, std::vector<std::pair<std::size_t, std::size_t>> eval_map_) :
                    component_type(witnesses, constants, public_inputs, get_manifest()), m(m_), eval_map(eval_map_) {};
            };

            template<typename BlueprintFieldType>
            using plonk_dfri_linear_check =
                dfri_linear_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_dfri_linear_check<BlueprintFieldType>::result_type generate_assignments(
                const plonk_dfri_linear_check<BlueprintFieldType> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                BOOST_ASSERT(component.fullconfig.size() == component.m);

                std::size_t il, jl;
                value_type x, xi, xsubxiinv, y, z, q, q_new;
                value_type q_last = value_type::zero();
                value_type theta = var_value(assignment, instance_input.theta);
                for (std::size_t l = 0; l < component.m; l++) {
                    il = component.eval_map[component.m - l - 1].first - 1;
                    jl = component.eval_map[component.m - l - 1].second - 1;
                    x = var_value(assignment, instance_input.x);
                    xi = var_value(assignment, instance_input.xi[jl]);
                    xsubxiinv = (x - xi).inversed();
                    y = var_value(assignment, instance_input.y[il]);
                    z = var_value(assignment, instance_input.z[il][jl]);
                    q = (y - z) * xsubxiinv;
                    q_new = q + theta * q_last;

                    assignment.witness(component.W(component.fullconfig[l][0].first),
                                       start_row_index + component.fullconfig[l][0].second) = x;
                    assignment.witness(component.W(component.fullconfig[l][1].first),
                                       start_row_index + component.fullconfig[l][1].second) = xi;
                    assignment.witness(component.W(component.fullconfig[l][2].first),
                                       start_row_index + component.fullconfig[l][2].second) = xsubxiinv;
                    assignment.witness(component.W(component.fullconfig[l][3].first),
                                       start_row_index + component.fullconfig[l][3].second) = y;
                    assignment.witness(component.W(component.fullconfig[l][4].first),
                                       start_row_index + component.fullconfig[l][4].second) = z;
                    assignment.witness(component.W(component.fullconfig[l][5].first),
                                       start_row_index + component.fullconfig[l][5].second) = q;
                    assignment.witness(component.W(component.fullconfig[l][6].first),
                                       start_row_index + component.fullconfig[l][6].second) = theta;
                    assignment.witness(component.W(component.fullconfig[l][7].first),
                                       start_row_index + component.fullconfig[l][7].second) = q_last;
                    assignment.witness(component.W(component.fullconfig[l][8].first),
                                       start_row_index + component.fullconfig[l][8].second) = q_new;

                    q_last = q_new;
                }

                return typename plonk_dfri_linear_check<BlueprintFieldType>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            std::size_t
                generate_gates(const plonk_dfri_linear_check<BlueprintFieldType> &component,
                               circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                               assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                               const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input) {

                using var = typename plonk_dfri_linear_check<BlueprintFieldType>::var;

                int shift = (component.witness_amount() > 4) ? 0 : -1;

                auto single_block = component.fullconfig[0];
                var x = var(component.W(single_block[0].first), static_cast<int>(single_block[0].second + shift));
                var xi = var(component.W(single_block[1].first), static_cast<int>(single_block[1].second + shift));
                var xsubxiinv =
                    var(component.W(single_block[2].first), static_cast<int>(single_block[2].second + shift));
                var y = var(component.W(single_block[3].first), static_cast<int>(single_block[3].second + shift));
                var z = var(component.W(single_block[4].first), static_cast<int>(single_block[4].second + shift));
                var q = var(component.W(single_block[5].first), static_cast<int>(single_block[5].second + shift));
                var theta = var(component.W(single_block[6].first), static_cast<int>(single_block[6].second + shift));
                var q_last = var(component.W(single_block[7].first), static_cast<int>(single_block[7].second + shift));
                var q_new = var(component.W(single_block[8].first), static_cast<int>(single_block[8].second + shift));

                auto constraint_1 = (x - xi) * xsubxiinv - 1;
                auto constraint_2 = q * (x - xi) - (y - z);
                auto constraint_3 = q_new - (q_last * theta + q);
                return bp.add_gate({constraint_1, constraint_2, constraint_3});
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_dfri_linear_check<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_dfri_linear_check<BlueprintFieldType>::var;

                std::size_t il, jl;
                for (std::size_t l = 0; l < component.m; l++) {
                    il = component.eval_map[component.m - l - 1].first - 1;
                    jl = component.eval_map[component.m - l - 1].second - 1;

                    var x = var(component.W(component.fullconfig[l][0].first),
                                static_cast<int>(component.fullconfig[l][0].second + start_row_index), false);
                    var xi = var(component.W(component.fullconfig[l][1].first),
                                 static_cast<int>(component.fullconfig[l][1].second + start_row_index), false);
                    var y = var(component.W(component.fullconfig[l][3].first),
                                static_cast<int>(component.fullconfig[l][3].second + start_row_index), false);
                    var z = var(component.W(component.fullconfig[l][4].first),
                                static_cast<int>(component.fullconfig[l][4].second + start_row_index), false);
                    var theta = var(component.W(component.fullconfig[l][6].first),
                                    static_cast<int>(component.fullconfig[l][6].second + start_row_index), false);
                    var q_last = var(component.W(component.fullconfig[l][7].first),
                                     static_cast<int>(component.fullconfig[l][7].second + start_row_index), false);

                    bp.add_copy_constraint({instance_input.x, x});
                    bp.add_copy_constraint({instance_input.xi[jl], xi});
                    bp.add_copy_constraint({instance_input.y[il], y});
                    bp.add_copy_constraint({instance_input.z[il][jl], z});
                    bp.add_copy_constraint({instance_input.theta, theta});

                    if (l >= 1) {
                        var q_new_old =
                            var(component.W(component.fullconfig[l - 1][8].first),
                                static_cast<int>(component.fullconfig[l - 1][8].second + start_row_index), false);
                        bp.add_copy_constraint({q_last, q_new_old});
                    } else {
                        bp.add_copy_constraint(
                            {q_last, var(component.C(0), start_row_index, false, var::column_type::constant)});
                    }
                }
            }

            template<typename BlueprintFieldType>
            typename plonk_dfri_linear_check<BlueprintFieldType>::result_type generate_circuit(
                const plonk_dfri_linear_check<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input,
                const std::size_t start_row_index) {

                generate_assignments_constant(component, bp, assignment, instance_input, start_row_index);

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                std::size_t single_block_rows = std::ceil(9.0 / component.witness_amount());
                std::size_t shift = (component.witness_amount() > 4) ? 0 : 1;

                for (std::size_t l = 0; l < component.m; l++) {
                    assignment.enable_selector(selector_index, start_row_index + l * single_block_rows + shift);
                }

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_dfri_linear_check<BlueprintFieldType>::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constant(
                const plonk_dfri_linear_check<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>> &assignment,
                const typename plonk_dfri_linear_check<BlueprintFieldType>::input_type &instance_input,
                const std::uint32_t start_row_index) {

                using value_type = typename BlueprintFieldType::value_type;

                assignment.constant(component.C(0), start_row_index) = 0;
            }

        }    // namespace components
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_DFRI_LINEAR_CHECK_HPP

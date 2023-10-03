//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_DIVISION_REMAINDER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_DIVISION_REMAINDER_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/range_check.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

#include <type_traits>
#include <utility>
#include <sstream>
#include <string>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename ArithmetizationType>
            class division_remainder;

            /*
                For x, y < 2^{bits_amount} bits, where bits_amount < modulus_bits / 2, we divide x by y:
                x = qy + r, r < y,
                outputting q and r.
                If check_inputs = true, this checks that x and y satisfy x, y < 2^{bits_amount}.
            */
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class division_remainder<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>> :
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                using value_type = typename BlueprintFieldType::value_type;

                static std::size_t range_check_amount_internal(bool check_inputs) {
                    return 2 + 2 * check_inputs;
                }

                static bool needs_bonus_row_internal(std::size_t witness_amount) {
                    return witness_amount < 5;
                }

                static std::size_t rows_amount_internal(std::size_t witness_amount, std::size_t bits_amount,
                                                        bool check_inputs) {
                    return range_check_amount_internal(check_inputs) *
                           range_check_component_type::get_rows_amount(witness_amount, 0, bits_amount) +
                            1 + needs_bonus_row_internal(witness_amount);
                }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;

                using range_check_component_type =
                    range_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>>;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t witness_amount;
                    static const std::size_t clamp = 5;

                    gate_manifest_type(std::size_t witness_amount_)
                        : witness_amount(std::min(witness_amount_, clamp)) {}

                    std::uint32_t gates_amount() const override {
                        return division_remainder::gates_amount;
                    }

                    bool operator<(const component_gate_manifest *other) {
                        const gate_manifest_type *other_casted =
                            dynamic_cast<const gate_manifest_type*>(other);
                        return witness_amount < other_casted->witness_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t bits_amount,
                                                       bool check_inputs) {
                    gate_manifest manifest =
                        gate_manifest(gate_manifest_type(witness_amount))
                        .merge_with(range_check_component_type::get_gate_manifest(witness_amount,
                                                                                  lookup_column_amount,
                                                                                  bits_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(
                            new manifest_range_param(3, 6)),
                        true
                    ).merge_with(range_check_component_type::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::size_t bits_amount,
                                                             bool check_inputs) {
                    return rows_amount_internal(witness_amount, bits_amount, check_inputs);
                }

                /*
                   It's CRITICAL that these two variables remain on top
                   Otherwise initialization goes in wrong order, leading to arbitrary values.
                */
                const std::size_t bits_amount;
                const bool check_inputs;
                /* Do NOT move the above variables! */

                const std::size_t range_check_amount = range_check_amount_internal(check_inputs);

                std::vector<range_check_component_type> range_checks;

                const bool needs_bonus_row = needs_bonus_row_internal(this->witness_amount());
                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), bits_amount, check_inputs);
                constexpr static const std::size_t gates_amount = 1;

                enum var_address {
                    X, Y, Q, R_, Y_MINUS_R
                };

                std::pair<std::size_t, std::size_t> get_var_address(
                        var_address var_ad, std::size_t start_row_index) const{
                    std::size_t row = start_row_index + var_ad / this->witness_amount(),
                                column = var_ad % this->witness_amount();
                    return std::make_pair(row, column);
                }

                var get_var_for_gate(var_address var_ad) const {
                    auto address = get_var_address(var_ad, 0);
                    return var(this->W(address.second), address.first, true);
                }

                struct input_type {
                    var x, y;

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct result_type {
                    var quotient, remainder;

                    result_type(const division_remainder &component, std::size_t start_row_index) {
                        std::pair<std::size_t, std::size_t>
                            r_address = component.get_var_address(var_address::R_, start_row_index),
                            q_address = component.get_var_address(var_address::Q, start_row_index);

                        quotient = var(component.W(q_address.second), q_address.first);
                        remainder = var(component.W(r_address.second), r_address.first);
                    }

                    std::vector<var> all_vars() const {
                        return {quotient, remainder};
                    }
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                division_remainder(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input,
                                   std::size_t bits_amount_, bool check_inputs_):
                    component_type(witness, constant, public_input, get_manifest()),
                    bits_amount(bits_amount_),
                    check_inputs(check_inputs_),
                    range_checks(range_check_amount, range_check_component_type(witness, constant,
                                                                                public_input, bits_amount_))
                {};

                division_remainder(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::size_t bits_amount_, bool check_inputs_) :
                        component_type(witnesses, constants, public_inputs, get_manifest()),
                        bits_amount(bits_amount_),
                        check_inputs(check_inputs_),
                        range_checks(range_check_amount, range_check_component_type(witnesses, constants,
                                                                                    public_inputs, bits_amount_))
                {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_division_remainder =
                division_remainder<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                               ArithmetizationParams>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using component_type = plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
                using value_type = typename BlueprintFieldType::value_type;

                var x = component.get_var_for_gate(var_address::X),
                    y = component.get_var_for_gate(var_address::Y),
                    r = component.get_var_for_gate(var_address::R_),
                    q = component.get_var_for_gate(var_address::Q),
                    y_minus_r = component.get_var_for_gate(var_address::Y_MINUS_R);

                std::vector<constraint_type> constraints;
                constraint_type division_constraint = x - y * q - r;
                constraints.push_back(division_constraint);
                constraint_type y_minus_r_constraint = y - r - y_minus_r;
                constraints.push_back(y_minus_r_constraint);

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using component_type = plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;
                std::uint32_t row = start_row_index;

                std::pair<std::size_t, std::size_t>
                    x_address = component.get_var_address(var_address::X, start_row_index),
                    y_address = component.get_var_address(var_address::Y, start_row_index);

                bp.add_copy_constraint({instance_input.x, var(component.W(x_address.second), x_address.first, false)});
                bp.add_copy_constraint({instance_input.y, var(component.W(y_address.second), y_address.first, false)});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>::result_type
            generate_circuit(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;

                std::pair<std::size_t, std::size_t>
                    x_address = component.get_var_address(var_address::X, start_row_index),
                    y_address = component.get_var_address(var_address::Y, start_row_index),
                    r_address = component.get_var_address(var_address::R_, start_row_index),
                    q_address = component.get_var_address(var_address::Q, start_row_index),
                    y_minus_r_address = component.get_var_address(var_address::Y_MINUS_R, start_row_index);

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);
                row += 1 + component.needs_bonus_row;

                generate_circuit(component.range_checks[0], bp, assignment,
                                 {var(component.W(y_minus_r_address.second), y_minus_r_address.first, false)}, row);
                row += component.range_checks[0].rows_amount;

                generate_circuit(component.range_checks[1], bp, assignment,
                                 {var(component.W(q_address.second), q_address.first, false)}, row);
                row += component.range_checks[1].rows_amount;

                if (component.check_inputs) {
                    generate_circuit(component.range_checks[2], bp, assignment,
                                     {var(component.W(x_address.second), x_address.first, false)}, row);
                    row += component.range_checks[2].rows_amount;

                    generate_circuit(component.range_checks[3], bp, assignment,
                                     {var(component.W(y_address.second), y_address.first, false)}, row);
                    row += component.range_checks[3].rows_amount;
                }

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>::result_type
            generate_assignments(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_division_remainder<BlueprintFieldType, ArithmetizationParams>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;

                value_type x = var_value(assignment, instance_input.x),
                           y = var_value(assignment, instance_input.y);
                integral_type x_integral = integral_type(x.data),
                              y_integral = integral_type(y.data);
                integral_type q_integral = y_integral != 0 ? x_integral / y_integral : 0,
                              r_integral = y_integral != 0 ? x_integral % y_integral : 0;
                value_type q = value_type(q_integral),
                           r = value_type(r_integral);

                std::pair<std::size_t, std::size_t>
                    x_address = component.get_var_address(var_address::X, start_row_index),
                    y_address = component.get_var_address(var_address::Y, start_row_index),
                    r_address = component.get_var_address(var_address::R_, start_row_index),
                    q_address = component.get_var_address(var_address::Q, start_row_index),
                    y_minus_r_address = component.get_var_address(var_address::Y_MINUS_R, start_row_index);

                assignment.witness(component.W(x_address.second), x_address.first) = x;
                assignment.witness(component.W(y_address.second), y_address.first) = y;
                assignment.witness(component.W(r_address.second), r_address.first) = r;
                assignment.witness(component.W(q_address.second), q_address.first) = q;
                assignment.witness(component.W(y_minus_r_address.second), y_minus_r_address.first) = y - r;
                row += 1 + component.needs_bonus_row;

                generate_assignments(component.range_checks[0], assignment,
                                    {var(component.W(y_minus_r_address.second), y_minus_r_address.first, false)}, row);
                row += component.range_checks[0].rows_amount;

                generate_assignments(component.range_checks[1], assignment,
                                     {var(component.W(q_address.second), q_address.first, false)}, row);
                row += component.range_checks[1].rows_amount;

                if (component.check_inputs) {
                    generate_assignments(component.range_checks[2], assignment,
                                         {var(component.W(x_address.second), x_address.first, false)}, row);
                    row += component.range_checks[2].rows_amount;

                    generate_assignments(component.range_checks[3], assignment,
                                         {var(component.W(y_address.second), y_address.first, false)}, row);
                    row += component.range_checks[3].rows_amount;
                }

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif  // CRYPTO3_BLUEPRINT_COMPONENTS_NON_NATIVE_DIVISION_REMAINDER_HPP

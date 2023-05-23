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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_DIVISION_REMAINDER_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_DIVISION_REMAINDER_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/non_native/comparsion.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/range_check.hpp>

#include <nil/crypto3/random/algebraic_engine.hpp>

#include <type_traits>
#include <utility>

namespace nil {
    namespace blueprint {
        namespace components {
            using nil::blueprint::components::detail::comparsion_mode;

            template<typename ArithmetizationType, std::uint32_t WitnessesAmount, std::size_t R>
            class division_remainder;

            /*
                For x, y < 2^{R} bits, where R < modulus_bits - 1, we divide x by y:
                x = qy + r, r < y.
                Note that this component doesn't always check that x,y < 2^{R} bits; if the division can be preformed
                with no overflow, sometimes bigger inputs can work. This DOES NOT allow incorrect division,
                only meaning that the input bounds are not exact.
                If that is undesirable, you should perform the range checks beforehand.
                Because of how it's comparsion subcomponents function, if R is divisible by their chunk_size, this
                compononent will take less gates if R is divisible by (what currently is, please check!) 2.

                Strategy:
                We first find the greatest n, which is divisible by 2 and n <= modulus_bits - 1.
                Such n is always within 2 bits of modulus_bits.
                1) Check that r < y via comparsion component
                2) Check that multiplication qy does not overflow (and is less than) 2^{n}
                2.a) Note that if we do not overflow, one of q/y would be < 2^{n/2}.
                     We leave it up to assigner to decide which one it is going to be.
                2.b) The remaining one is decomposed into the following number system:
                     a_2 b_2 + b_1,
                     with digits b1, b2 < 2^{n/2}, and a_2 = 2^{n/2}.
                     Decomposition is done by range_check-ing b_1, b_2 against 2^{n/2} and checking that
                     the sum equals the decomposed number.
                     Note that the other number is already in this form with b'_2 = 0 and b'_1 being the number.
                2.c) We multiply qy by:
                    (a_2 b_2 + b_1) * b'_1 = a_2 b_2 b'_1 + b_1 b'_1.
                    We check that the first term does not overflow via range_checking b_2 b'_1 against 2^{n/2}.
                    Note that the multiplications of b cannot overflow 2^{n}.
                    We also check that the sum does not overflow 2^{n} by comparing
                    a_2 b_2 b'_1 + b_1 b'_1 and b_1 b'_1.
                    Without overflow, the sum would be more than each of it's terms; this breaks when an overflow
                    occurs.
                3) Check that x = qy + r. Note that because n < modulus_bits, qy < 2^{n},
                   and r < y, this cannot overflow the field. At worst, x < 2^{modulus_bits}.
                In order to save gates, all the checks which do not call a separate component are done
                at the start of this component.
            */
            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R>
            class division_remainder<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                 ArithmetizationParams>,
                                     WitnessesAmount, R> :
                public plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 1, 0> {

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                       WitnessesAmount, 1, 0>;
                using value_type = typename BlueprintFieldType::value_type;

            public:
                using var = typename component_type::var;

                constexpr static const std::size_t n = R % 2 ? R + 1 : R;

                using comparsion_ge_component_type = comparsion<
                                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                ArithmetizationParams>,
                                                                WitnessesAmount, R, comparsion_mode::GREATER_EQUAL>;
                using comparsion_less_component_type = comparsion<
                                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                ArithmetizationParams>,
                                                                WitnessesAmount, R, comparsion_mode::LESS_THAN>;
                using range_check_type_component_type =
                    range_check<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                            ArithmetizationParams>,
                                WitnessesAmount, n / 2>;

                comparsion_ge_component_type comparsion_ge;
                comparsion_less_component_type comparsion_less;
                std::array<range_check_type_component_type, 4> range_check;

                enum var_address {
                    B_2_F, B_1_F, A_2_B_2_F, F, G, B_2, B_1, QY, Q, X, Y, R_
                };

                // Need to move this to static constexpr, but unsure how to do static constexpr random generation
                const value_type non_residue_calc() {
                    value_type result = -1,
                               sqrt = result.sqrt();
                    nil::crypto3::random::algebraic_engine<BlueprintFieldType> generate_random;
                    generate_random.seed(404);

                    while (sqrt * sqrt == result) {
                        result = generate_random();
                        sqrt = result.sqrt();
                    }
                    return result;
                }

                const value_type non_residue = non_residue_calc();

                constexpr static const std::pair<std::size_t, std::size_t> get_variable_assignment(
                        var_address v, std::size_t start_row_index) {
                    std::size_t row = v / WitnessesAmount,
                                column = v % WitnessesAmount;
                    return std::make_pair(start_row_index + row, column);
                }

                /*constexpr static const std::pair<std::size_t, std::size_t> get_variable_top_gate(var_address v) {

                }

                constexpr static const std::pair<std::size_t, std::size_t> get_variable_bot_gate(var_address v) {

                }*/

                constexpr static const var get_variable_single_gate(var_address v) {
                    std::pair<std::size_t, std::size_t> address = get_variable_assignment(v, 0);
                    return var(address.second, address.first - 1, true);
                }

                constexpr static const std::size_t added_rows_amount = (12 + WitnessesAmount - 1) / WitnessesAmount;
                constexpr static const bool needs_bonus_row = added_rows_amount > 3;

                constexpr static const std::size_t rows_amount =
                    added_rows_amount +  4 * range_check_type_component_type::rows_amount +
                    comparsion_less_component_type::rows_amount + comparsion_ge_component_type::rows_amount;
                constexpr static const std::size_t gates_amount = 1 + needs_bonus_row;

                struct input_type {
                    var x, y;
                };

                struct result_type {
                    var quotient, remainder;

                    result_type(const division_remainder &component, std::size_t start_row_index) {
                        std::pair<std::size_t, std::size_t>
                            q_var_ad = component.get_variable_assignment(var_address::Q, start_row_index),
                            r_var_ad = component.get_variable_assignment(var_address::R_, start_row_index);
                        quotient = var(component.W(q_var_ad.second), q_var_ad.first);
                        remainder = var(component.W(r_var_ad.second), r_var_ad.first);
                    }
                };

                template <typename ContainerType>
                division_remainder(ContainerType witness):
                    component_type(witness, {}, {}), comparsion_ge(witness), comparsion_less(witness),
                    range_check({range_check_type_component_type(witness), range_check_type_component_type(witness),
                                 range_check_type_component_type(witness), range_check_type_component_type(witness)})
                {};

                template <typename WitnessContainerType, typename ConstantContainerType,
                          typename PublicInputContainerType>
                division_remainder(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input):
                    component_type(witness, constant, public_input),
                    comparsion_ge(witness, constant, public_input),
                    comparsion_less(witness, constant, public_input),
                    range_check({range_check_type_component_type(witness, constant, public_input),
                                 range_check_type_component_type(witness, constant, public_input),
                                 range_check_type_component_type(witness, constant, public_input),
                                 range_check_type_component_type(witness, constant, public_input)})
                {};

                division_remainder(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs) :
                            component_type(witnesses, constants, public_inputs),
                            comparsion_ge(witnesses, constants, public_inputs),
                            comparsion_less(witnesses, constants, public_inputs),
                            range_check({range_check_type_component_type(witnesses, constants, public_inputs),
                                         range_check_type_component_type(witnesses, constants, public_inputs),
                                         range_check_type_component_type(witnesses, constants, public_inputs),
                                         range_check_type_component_type(witnesses, constants, public_inputs)})
                {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R>
            using plonk_division_remainder =
                division_remainder<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                               ArithmetizationParams>,
                                   WitnessesAmount, R>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits - 1, bool> = true>
            void generate_gates(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {

                using var = typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessesAmount, R>::var;
                using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
                using gate_type = typename crypto3::zk::snark::plonk_gate<BlueprintFieldType, constraint_type>;
                using var_address = typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                                      WitnessesAmount, R>::var_address;
                using value_type = typename BlueprintFieldType::value_type;

                var x_var = component.get_variable_single_gate(var_address::X),
                    y_var = component.get_variable_single_gate(var_address::Y),
                    q_var = component.get_variable_single_gate(var_address::Q),
                    r_var = component.get_variable_single_gate(var_address::R_),
                    f_var = component.get_variable_single_gate(var_address::F),
                    g_var = component.get_variable_single_gate(var_address::G),
                    qy_var = component.get_variable_single_gate(var_address::QY),
                    b_2_var = component.get_variable_single_gate(var_address::B_2),
                    b_1_var = component.get_variable_single_gate(var_address::B_1),
                    b_2_f_var = component.get_variable_single_gate(var_address::B_2_F),
                    b_1_f_var = component.get_variable_single_gate(var_address::B_1_F),
                    a_2_b_2_f_var = component.get_variable_single_gate(var_address::A_2_B_2_F);

                std::vector<constraint_type> constraints;
                constraints.reserve(4);

                constraint_type division_constraint = x_var - qy_var - r_var;
                constraints.push_back(division_constraint);

                constraint_type decomposition_constraint =
                    b_2_var * value_type(2).pow(component.n / 2) + b_1_var - g_var;
                constraints.push_back(decomposition_constraint);

                constraint_type multiplication_constraint = qy_var - a_2_b_2_f_var - b_1_f_var;
                constraints.push_back(multiplication_constraint);

                value_type non_residue = component.non_residue;
                constraint_type option_select_constraint =
                    ((f_var - q_var) * (f_var - q_var) - non_residue * (g_var - y_var) * (g_var - y_var)) *
                    ((f_var - y_var) * (f_var - y_var) - non_residue * (g_var - q_var) * (g_var - q_var));
                constraints.push_back(option_select_constraint);

                gate_type gate = gate_type(first_selector_index, constraints);
                bp.add_gate(gate);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits - 1, bool> = true>
            void generate_copy_constraints(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessesAmount, R>::var;
                using var_address = typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                                      WitnessesAmount, R>::var_address;
                std::uint32_t row = start_row_index;

                std::pair<std::size_t, std::size_t>
                    x_var_ad = component.get_variable_assignment(var_address::X, start_row_index),
                    y_var_ad = component.get_variable_assignment(var_address::Y, start_row_index);

                bp.add_copy_constraint({instance_input.x, var(component.W(x_var_ad.second), x_var_ad.first)});
                bp.add_copy_constraint({instance_input.y, var(component.W(y_var_ad.second), y_var_ad.first)});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits - 1, bool> = true>
            typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount, R>::result_type
            generate_circuit(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R>
                    &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                    ArithmetizationParams>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using var_address = typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                                      WitnessesAmount, R>::var_address;

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;
                std::size_t row = start_row_index;

                using var = typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                              WitnessesAmount, R>::var;
                using var_address = typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                                      WitnessesAmount, R>::var_address;

                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }

                assignment.enable_selector(first_selector_index, start_row_index + 1);
                row += component.added_rows_amount;

                std::pair<std::size_t, std::size_t>
                    r_var_ad = component.get_variable_assignment(var_address::R_, start_row_index),
                    qy_var_ad = component.get_variable_assignment(var_address::QY, start_row_index),
                    f_var_ad = component.get_variable_assignment(var_address::F, start_row_index),
                    b_2_var_ad = component.get_variable_assignment(var_address::B_2, start_row_index),
                    b_1_var_ad = component.get_variable_assignment(var_address::B_1, start_row_index),
                    b_2_f_var_ad = component.get_variable_assignment(var_address::B_2_F, start_row_index),
                    b_1_f_var_ad = component.get_variable_assignment(var_address::B_1_F, start_row_index);

                generate_circuit(component.range_check[0], bp, assignment,
                                 {var(b_1_var_ad.second, b_1_var_ad.first)}, row);
                row += component.range_check[0].rows_amount;
                std::cout << "Component 1\n";
                generate_circuit(component.range_check[1], bp, assignment,
                                 {var(b_2_var_ad.second, b_2_var_ad.first)}, row);
                row += component.range_check[1].rows_amount;
                std::cout << "Component 2\n";
                generate_circuit(component.range_check[2], bp, assignment,
                                 {var(f_var_ad.second, f_var_ad.first)}, row);
                row += component.range_check[2].rows_amount;
                std::cout << "Component 3\n";
                generate_circuit(component.range_check[3], bp, assignment,
                                 {var(b_2_f_var_ad.second, b_2_f_var_ad.first)}, row);
                row += component.range_check[3].rows_amount;
                std::cout << "Component 4\n";

                generate_circuit(component.comparsion_less, bp, assignment,
                                 {var(r_var_ad.second, r_var_ad.first), instance_input.y}, row);
                row += component.comparsion_less.rows_amount;
                std::cout << "Component 5\n";
                generate_circuit(component.comparsion_ge, bp, assignment,
                                 {var(qy_var_ad.second, qy_var_ad.first),
                                  var(b_1_f_var_ad.second, b_1_f_var_ad.first)}, row);
                row += component.comparsion_ge.rows_amount;
                std::cout << "Component 6\n";

                std::cout << "Component n: " << component.n << "\n";

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                         WitnessesAmount, R>::result_type(
                                        component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::uint32_t WitnessesAmount,
                     std::size_t R,
                     std::enable_if_t<R < BlueprintFieldType::modulus_bits - 1, bool> = true>
            typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                              WitnessesAmount, R>::result_type
            generate_assignments(
                const plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                               WitnessesAmount, R>
                    &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                       ArithmetizationParams>>
                    &assignment,
                const typename plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                        WitnessesAmount, R>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;

                using component_type = plonk_division_remainder<BlueprintFieldType, ArithmetizationParams,
                                                                WitnessesAmount, R>;
                using value_type = typename BlueprintFieldType::value_type;
                using integral_type = typename BlueprintFieldType::integral_type;
                using var = typename component_type::var;
                using var_address = typename component_type::var_address;

                integral_type x_integral = integral_type(var_value(assignment, instance_input.x).data),
                              y_integral = integral_type(var_value(assignment, instance_input.y).data);
                integral_type q_integral = y_integral != 0 ? x_integral / y_integral : 0,
                              r_integral = y_integral != 0 ? x_integral % y_integral : 0;

                value_type x = value_type(x_integral),
                           y = value_type(y_integral),
                           q = value_type(q_integral),
                           r = value_type(r_integral);
                std::pair<std::size_t, std::size_t>
                    x_var_ad = component.get_variable_assignment(var_address::X, start_row_index),
                    y_var_ad = component.get_variable_assignment(var_address::Y, start_row_index),
                    q_var_ad = component.get_variable_assignment(var_address::Q, start_row_index),
                    r_var_ad = component.get_variable_assignment(var_address::R_, start_row_index),
                    f_var_ad = component.get_variable_assignment(var_address::F, start_row_index),
                    g_var_ad = component.get_variable_assignment(var_address::G, start_row_index),
                    qy_var_ad = component.get_variable_assignment(var_address::QY, start_row_index),
                    b_2_var_ad = component.get_variable_assignment(var_address::B_2, start_row_index),
                    b_1_var_ad = component.get_variable_assignment(var_address::B_1, start_row_index),
                    b_2_f_var_ad = component.get_variable_assignment(var_address::B_2_F, start_row_index),
                    b_1_f_var_ad = component.get_variable_assignment(var_address::B_1_F, start_row_index),
                    a_2_b_2_f_var_ad = component.get_variable_assignment(var_address::A_2_B_2_F, start_row_index);

                assignment.witness(component.W(x_var_ad.second), x_var_ad.first) = x;
                assignment.witness(component.W(y_var_ad.second), y_var_ad.first) = y;
                assignment.witness(component.W(q_var_ad.second), q_var_ad.first) = q;
                assignment.witness(component.W(r_var_ad.second), r_var_ad.first) = r;
                assignment.witness(component.W(qy_var_ad.second), qy_var_ad.first) = q * y;
                std::cout << "q * y: " << (q * y).data << "\n";

                integral_type f_integral = y < q ? y_integral : q_integral,
                              g_integral = y < q ? q_integral : y_integral;
                std::cout << "f: " << f_integral << "\n";
                std::cout << "q: " << q_integral << "\n";

                value_type f = value_type(f_integral),
                           g = value_type(g_integral);

                assignment.witness(component.W(f_var_ad.second), f_var_ad.first) = f;
                assignment.witness(component.W(g_var_ad.second), g_var_ad.first) = g;

                value_type two_n_2 = value_type(2).pow(component.n / 2);
                integral_type two_n_2_integral = integral_type(two_n_2.data);
                integral_type b_1_integral = g_integral % two_n_2_integral,
                              b_2_integral = g_integral / two_n_2_integral;
                integral_type b_2_f_integral = b_2_integral * f_integral;
                value_type b_1 = value_type(b_1_integral),
                           b_2 = value_type(b_2_integral),
                           b_1_f = value_type(b_1_integral * f_integral),
                           b_2_f = value_type(b_2_f_integral),
                           a_2_b_2_f = value_type(two_n_2_integral * b_2_f_integral);

                assignment.witness(component.W(b_1_var_ad.second), b_1_var_ad.first) = b_1;
                assignment.witness(component.W(b_2_var_ad.second), b_2_var_ad.first) = b_2;
                assignment.witness(component.W(b_1_f_var_ad.second), b_1_f_var_ad.first) = b_1_f;
                std::cout << "b_2_f: " << std::hex << b_2_f.data << std::dec << "\n";
                std::cout << "comp_check: " << bool(b_2_f < two_n_2) << "\n";
                assignment.witness(component.W(b_2_f_var_ad.second), b_2_f_var_ad.first) = b_2_f;
                assignment.witness(component.W(a_2_b_2_f_var_ad.second), a_2_b_2_f_var_ad.first) = a_2_b_2_f;

                row += component.added_rows_amount;

                generate_assignments(component.range_check[0], assignment,
                                     {var(b_1_var_ad.second, b_1_var_ad.first)}, row);
                row += component.range_check[0].rows_amount;
                generate_assignments(component.range_check[1], assignment,
                                     {var(b_2_var_ad.second, b_2_var_ad.first)}, row);
                row += component.range_check[1].rows_amount;
                generate_assignments(component.range_check[2], assignment,
                                     {var(f_var_ad.second, f_var_ad.first)}, row);
                row += component.range_check[2].rows_amount;
                generate_assignments(component.range_check[3], assignment,
                                     {var(b_2_f_var_ad.second, b_2_f_var_ad.first)}, row);
                row += component.range_check[3].rows_amount;

                generate_assignments(component.comparsion_less, assignment,
                                     {var(r_var_ad.second, r_var_ad.first), instance_input.y}, row);
                row += component.comparsion_less.rows_amount;
                generate_assignments(component.comparsion_ge, assignment,
                                     {var(qy_var_ad.second, qy_var_ad.first),
                                      var(b_1_f_var_ad.second, b_1_f_var_ad.first)}, row);
                row += component.comparsion_ge.rows_amount;

                BOOST_ASSERT(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}   // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_DIVISION_REMAINDER_HPP

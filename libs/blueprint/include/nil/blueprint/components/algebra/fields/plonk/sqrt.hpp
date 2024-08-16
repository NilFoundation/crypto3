//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ALGEBRA_FIELDS_SQRT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ALGEBRA_FIELDS_SQRT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/addition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/subtraction.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/exponentiation.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // square root
            // Input: y
            // Output: x such that x * x = y
            template<typename ArithmetizationType, typename BlueprintFieldType>
            class sqrt;

            template<typename BlueprintFieldType>
            class sqrt<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                       BlueprintFieldType> : public plonk_component<BlueprintFieldType> {

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>
                    ArithmetizationType;


                constexpr static std::size_t rows() {
                    std::size_t row = 0;
                    const std::size_t exp_rows_amount = exp_component::get_rows_amount(15);
                    const std::size_t mul_rows_amount = mul_component::get_rows_amount(3);
                    const std::size_t sub_rows_amount = sub_component::get_rows_amount(3);
                    const std::size_t add_rows_amount = add_component::get_rows_amount(3);

                    row += 3; // leave empty cells for exp_component's constants

                    row += exp_rows_amount;

                    row += mul_rows_amount;

                    // qr_check * (1 + qr_check) * (y - x_squared) = 0 for y \in QR(q)
                    row += add_rows_amount;
                    row += sub_rows_amount;
                    row += mul_rows_amount;
                    row += mul_rows_amount;

                    // qr_check * (1 - qr_check) * (1 + x_squared) = 0 for y \in QNR(q)
                    row += sub_rows_amount;
                    row += add_rows_amount;
                    row += mul_rows_amount;
                    row += mul_rows_amount;

                    // (1 - qr_check) * (1 + qr_check) * x_squared = 0 for y = 0
                    row += mul_rows_amount;
                    row += mul_rows_amount;

                    row += add_rows_amount;
                    row += add_rows_amount;

                    return row;
                }

            public:
                using component_type = plonk_component<BlueprintFieldType>;
                using mul_component = multiplication<ArithmetizationType, BlueprintFieldType,
                                                     basic_non_native_policy<BlueprintFieldType>>;
                using add_component = addition<ArithmetizationType, BlueprintFieldType,
                                                     basic_non_native_policy<BlueprintFieldType>>;
                using sub_component = subtraction<ArithmetizationType, BlueprintFieldType,
                                                     basic_non_native_policy<BlueprintFieldType>>;
                using exp_component = exponentiation<ArithmetizationType, BlueprintFieldType, 256>;

                using manifest_type = plonk_component_manifest;
                using var = typename component_type::var;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return sqrt::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount) {
                    static gate_manifest manifest = \
                        gate_manifest(gate_manifest_type())
                        .merge_with(mul_component::get_gate_manifest(witness_amount))
                        .merge_with(add_component::get_gate_manifest(witness_amount))
                        .merge_with(sub_component::get_gate_manifest(witness_amount))
                        .merge_with(exp_component::get_gate_manifest(witness_amount));
                    return manifest;
                }


                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(15)),
                        true
                    );
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount) {
                    return rows();
                }

                const std::size_t rows_amount = rows();
                constexpr static const std::size_t gates_amount = 0;

                struct input_type {
                    var y;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {y};
                    }
                };

                struct result_type {
                    var output;

                    result_type(const sqrt &component, std::size_t component_start_row) {
                        output = var(
                            component.W(0),
                            component_start_row + 3 + exp_component::get_rows_amount(15),
                            false
                        );
                    }

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {output};
                    }
                };

                template <typename WitnessContainerType, typename ConstantContainerType,
                          typename PublicInputContainerType>
                    sqrt(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input):
                            component_type(witness, constant, public_input, get_manifest()){};

                    sqrt(
                        std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                            component_type(witnesses, constants, public_inputs, get_manifest()){};
            };

            template<typename BlueprintFieldType>
                using plonk_sqrt =
                    sqrt<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                         BlueprintFieldType>;

            template<typename BlueprintFieldType>
            typename plonk_sqrt<BlueprintFieldType>::result_type
                generate_circuit(
                    const plonk_sqrt<BlueprintFieldType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_sqrt<BlueprintFieldType>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                using component_type = plonk_sqrt<BlueprintFieldType>;
                using var = typename component_type::var;
                using exp_component = typename component_type::exp_component;
                using mul_component = typename component_type::mul_component;
                using add_component = typename component_type::add_component;
                using sub_component = typename component_type::sub_component;
                std::size_t row = start_row_index;

                var exp(0, start_row_index, false, var::column_type::constant);
                var zero(0, start_row_index + 1, false, var::column_type::constant);
                var one(0, start_row_index + 2, false, var::column_type::constant);

                row += 3; // leave empty cells for exp_component's constants

                // check if y \in QR(q)
                auto exp_instance =
                // qr_check = 1 if y \in QR(q), -1 if y \in QNR(q), 0 if y = 0
                exp_component({
                    component.W(0), component.W(1), component.W(2), component.W(3),
                    component.W(4), component.W(5), component.W(6), component.W(7),
                    component.W(8), component.W(9), component.W(10), component.W(11),
                    component.W(12), component.W(13), component.W(14)}, {component.C(0)},
                    {}
                );
                var qr_check = generate_circuit(exp_instance, bp, assignment, {instance_input.y, exp}, row).output;
                row += exp_instance.rows_amount;
                // x = sqrt(y) if y \in QR(q) or y = 0, -1 otherwise
                auto mul_instance = mul_component({component.W(0), component.W(1), component.W(2)}, {}, {});
                var x(component.W(0), row, false);
                var x_squared = generate_circuit(mul_instance, bp, assignment, {x, x}, row).output;
                row += mul_instance.rows_amount;

                // qr_check * (1 + qr_check) * (y - x_squared) = 0 for y \in QR(q)
                auto add_instance = add_component({component.W(0), component.W(1), component.W(2)}, {}, {});
                var one_plus_qr_check = generate_circuit(
                    add_instance, bp, assignment, {qr_check, one}, row).output;
                row += add_instance.rows_amount;

                auto sub_instance = sub_component({component.W(0), component.W(1), component.W(2)}, {}, {});
                var y_minus_x_squared = generate_circuit(
                    sub_instance, bp, assignment, {instance_input.y, x_squared}, row).output;
                row += sub_instance.rows_amount;

                var in_qr = generate_circuit(mul_instance, bp, assignment, {qr_check, one_plus_qr_check}, row).output;
                row += mul_instance.rows_amount;
                in_qr = generate_circuit(mul_instance, bp, assignment, {in_qr, y_minus_x_squared}, row).output;
                row += mul_instance.rows_amount;

                // qr_check * (1 - qr_check) * (1 + x_squared) = 0 for y \in QNR(q)
                var one_minus_qr_check = generate_circuit(sub_instance, bp, assignment, {one, qr_check}, row).output;
                row += sub_instance.rows_amount;
                var x_plus_one = generate_circuit(add_instance, bp, assignment, {x, one}, row).output;
                row += add_instance.rows_amount;

                var in_qnr = generate_circuit(mul_instance, bp, assignment, {qr_check, one_minus_qr_check}, row).output;
                row += mul_instance.rows_amount;
                in_qnr = generate_circuit(mul_instance, bp, assignment, {in_qnr, x_plus_one}, row).output;
                row += mul_instance.rows_amount;

                // (1 - qr_check) * (1 + qr_check) * x_squared = 0 for y = 0
                var y_eq_zero = generate_circuit(
                    mul_instance, bp, assignment, {one_minus_qr_check, one_plus_qr_check}, row).output;
                row += mul_instance.rows_amount;
                y_eq_zero = generate_circuit(mul_instance, bp, assignment, {y_eq_zero, x_squared}, row).output;
                row += mul_instance.rows_amount;

                var last_check = generate_circuit(add_instance, bp, assignment, {in_qr, in_qnr}, row).output;
                row += add_instance.rows_amount;
                last_check = generate_circuit(add_instance, bp, assignment, {last_check, y_eq_zero}, row).output;
                row += add_instance.rows_amount;

                assert(row == start_row_index + component.rows_amount);

                // copy-constarint for last_check and zero
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constants(component, assignment, instance_input, start_row_index);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            typename plonk_sqrt<BlueprintFieldType>::result_type
                generate_assignments(
                    const plonk_sqrt<BlueprintFieldType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                        &assignment,
                    const typename plonk_sqrt<BlueprintFieldType>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                using component_type = plonk_sqrt<BlueprintFieldType>;
                using var = typename component_type::var;
                using exp_component = typename component_type::exp_component;
                using mul_component = typename component_type::mul_component;
                using add_component = typename component_type::add_component;
                using sub_component = typename component_type::sub_component;
                std::size_t row = start_row_index;

                var exp(0, start_row_index, false, var::column_type::constant);
                var zero(0, start_row_index + 1, false, var::column_type::constant);
                var one(0, start_row_index + 2, false, var::column_type::constant);

                row += 3; // leave empty cells for exp_component's constants

                // check if y \in QR(q)
                // qr_check = 1 if y \in QR(q), -1 if y \in QNR(q), 0 if y = 0
                auto exp_instance =
                    exp_component({component.W(0), component.W(1), component.W(2), component.W(3),
                                   component.W(4), component.W(5), component.W(6), component.W(7),
                                   component.W(8), component.W(9), component.W(10), component.W(11),
                                   component.W(12), component.W(13), component.W(14)}, {component.C(0)},
                                  {});
                var qr_check = generate_assignments(exp_instance, assignment, {instance_input.y, exp}, row).output;
                row += exp_instance.rows_amount;
                // x = sqrt(y) if y \in QR(q) or y = 0, -1 otherwise
                typename BlueprintFieldType::value_type qr_check_value = var_value(assignment, qr_check).data;
                if (qr_check_value == BlueprintFieldType::value_type::zero() ||
                    qr_check_value == BlueprintFieldType::value_type::one()){
                        typename BlueprintFieldType::value_type x_val = var_value(assignment, instance_input.y).sqrt();
                        assignment.witness(component.W(0), row) = x_val;
                } else if (qr_check_value == -BlueprintFieldType::value_type::one()) {
                    assignment.witness(component.W(0), row) = -1;
                } else {
                    assert(false);
                }

                auto mul_instance = mul_component({component.W(0), component.W(1), component.W(2)}, {}, {});
                var x(0, row, false);
                var x_squared = generate_assignments(mul_instance, assignment, {x, x}, row).output;
                row += mul_instance.rows_amount;

                // qr_check * (1 + qr_check) * (y - x_squared) = 0 for y \in QR(q)
                auto add_instance = add_component({component.W(0), component.W(1), component.W(2)}, {}, {});
                var one_plus_qr_check = generate_assignments(add_instance, assignment, {qr_check, one}, row).output;
                row += add_instance.rows_amount;

                auto sub_instance = sub_component({component.W(0), component.W(1), component.W(2)}, {}, {});
                var y_minus_x_squared = generate_assignments(
                    sub_instance, assignment, {instance_input.y, x_squared}, row).output;
                row += sub_instance.rows_amount;

                var in_qr = generate_assignments(mul_instance, assignment, {qr_check, one_plus_qr_check}, row).output;
                row += mul_instance.rows_amount;
                in_qr = generate_assignments(mul_instance, assignment,{in_qr, y_minus_x_squared}, row).output;
                row += mul_instance.rows_amount;

                // qr_check * (1 - qr_check) * (1 + x) = 0 for y \in QNR(q)
                var one_minus_qr_check = generate_assignments(sub_instance, assignment, {one, qr_check}, row).output;
                row += sub_instance.rows_amount;
                var x_plus_one = generate_assignments(add_instance, assignment, {x, one}, row).output;
                row += add_instance.rows_amount;

                var in_qnr = generate_assignments(mul_instance, assignment, {qr_check, one_minus_qr_check}, row).output;
                row += mul_instance.rows_amount;
                in_qnr = generate_assignments(mul_instance, assignment, {in_qnr, x_plus_one}, row).output;
                row += mul_instance.rows_amount;

                // (1 - qr_check) * (1 + qr_check) * x_squared = 0 for y = 0
                var y_eq_zero = generate_assignments(mul_instance, assignment, {one_minus_qr_check, one_plus_qr_check}, row).output;
                row += mul_instance.rows_amount;
                y_eq_zero = generate_assignments(mul_instance, assignment, {y_eq_zero, x_squared}, row).output;
                row += mul_instance.rows_amount;

                var last_check = generate_assignments(add_instance, assignment, {in_qr, in_qnr}, row).output;
                row += add_instance.rows_amount;
                last_check = generate_assignments(add_instance, assignment, {last_check, y_eq_zero}, row).output;
                row += add_instance.rows_amount;

                assert(row == start_row_index + component.rows_amount);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType>
            void generate_copy_constraints(
                const plonk_sqrt<BlueprintFieldType> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_sqrt<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_sqrt<BlueprintFieldType>::var;

                var zero(0, start_row_index + 1, false, var::column_type::constant);
                var last_check(component.W(2), start_row_index + component.rows_amount - 1,
                               false, var::column_type::witness);
                bp.add_copy_constraint({zero, last_check});
            }

            template<typename BlueprintFieldType>
            void generate_assignments_constants(
                const plonk_sqrt<BlueprintFieldType> &component,\
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>>
                    &assignment,
                const typename plonk_sqrt<BlueprintFieldType>::input_type
                    &instance_input,
                const std::uint32_t start_row_index) {

                std::size_t row = start_row_index;
                assignment.constant(component.C(0), row) = (BlueprintFieldType::value_type::modulus - 1) / 2;
                row++;
                assignment.constant(component.C(0), row) = 0;
                row++;
                assignment.constant(component.C(0), row) = 1;
                row++;
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_ALGEBRA_FIELDS_SQRT_HPP
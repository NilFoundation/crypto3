//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_EDDSA_SUBTRACTION_COMPONENT_9_WIRES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_EDDSA_SUBTRACTION_COMPONENT_9_WIRES_HPP

#include <nil/crypto3/algebra/fields/curve25519/base_field.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/component_stretcher.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/range.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            // Input:
            // Output:
            /*
            1 non_native range for q
            2 q
            3 non-native range for r
            4
            5 a0 a1 a2 a3 b0 b1 b2 b3 q0
            6 q1 q2 q3 r0 r1 r2 r3 v0 v1
            7 v00 v01 v02 v03 v10 v11 v12 v13

            */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class subtraction;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class subtraction<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              typename crypto3::algebra::fields::curve25519_base_field,
                              basic_non_native_policy<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

                using operating_field_type = crypto3::algebra::fields::curve25519_base_field;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                constexpr static std::size_t rows_amount_internal(std::size_t witness_amount,
                                                                  std::size_t lookup_column_amount) {
                    return 2 + range_type::get_rows_amount(witness_amount, lookup_column_amount);
                }
            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using range_type = range<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                     ArithmetizationParams>,
                                         typename crypto3::algebra::fields::curve25519_base_field,
                                         non_native_policy_type>;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return subtraction::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(range_type::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(9)),
                        false
                    ).merge_with(range_type::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return rows_amount_internal(witness_amount, lookup_column_amount);
                }

                constexpr static const std::size_t T = 257;

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);
                constexpr static const std::size_t gates_amount = 1;

                struct input_type {
                    typename non_native_policy_type::template field<operating_field_type>::non_native_var_type A;
                    typename non_native_policy_type::template field<operating_field_type>::non_native_var_type B;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {A[0], A[1], A[2], A[3], B[0], B[1], B[2], B[3]};
                    }
                };

                struct result_type {
                    typename non_native_policy_type::template field<operating_field_type>::non_native_var_type output;

                    result_type(const subtraction &component, std::uint32_t start_row_index) {
                        output = {var(component.W(0), start_row_index + 2, false),
                                  var(component.W(1), start_row_index + 2, false),
                                  var(component.W(2), start_row_index + 2, false),
                                  var(component.W(3), start_row_index + 2, false)};
                    }

                    std::vector<var> all_vars() const {
                        return {output[0], output[1], output[2], output[3]};
                    }
                };

                template<typename ContainerType>
                explicit subtraction(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                subtraction(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                subtraction(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_ed25519_subtraction =
                subtraction<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            typename crypto3::algebra::fields::curve25519_base_field,
                            basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using ed25519_field_type = crypto3::algebra::fields::curve25519_base_field;

                using var = typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::var;

                std::size_t row = start_row_index;
                typename ed25519_field_type::integral_type base = 1;
                typename BlueprintFieldType::integral_type pasta_base = 1;
                typename ed25519_field_type::extended_integral_type extended_base = 1;
                std::array<typename BlueprintFieldType::value_type, 4> a = {
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A[0]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A[1]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A[2]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.A[3]).data)};
                typename ed25519_field_type::value_type eddsa_a =
                    typename ed25519_field_type::integral_type(a[0].data) +
                    typename ed25519_field_type::integral_type(a[1].data) * (base << 66) +
                    typename ed25519_field_type::integral_type(a[2].data) * (base << 132) +
                    typename ed25519_field_type::integral_type(a[3].data) * (base << 198);

                std::array<typename BlueprintFieldType::value_type, 4> b = {
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.B[0]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.B[1]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.B[2]).data),
                    typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.B[3]).data)};
                typename ed25519_field_type::extended_integral_type eddsa_p = ed25519_field_type::modulus;
                typename ed25519_field_type::value_type eddsa_b =
                    (typename ed25519_field_type::integral_type(b[0].data) +
                     typename ed25519_field_type::integral_type(b[1].data) * (base << 66) +
                     typename ed25519_field_type::integral_type(b[2].data) * (base << 132) +
                     typename ed25519_field_type::integral_type(b[3].data) * (base << 198));

                typename ed25519_field_type::value_type eddsa_r = eddsa_a - eddsa_b;
                typename ed25519_field_type::integral_type integral_eddsa_r =
                    typename ed25519_field_type::integral_type(eddsa_r.data);
                typename ed25519_field_type::extended_integral_type integral_eddsa_q =
                    (typename ed25519_field_type::extended_integral_type(eddsa_a.data) + eddsa_p -
                     typename ed25519_field_type::extended_integral_type(eddsa_b.data) -
                     typename ed25519_field_type::extended_integral_type(eddsa_r.data)) /
                    eddsa_p;
                typename ed25519_field_type::extended_integral_type pow = extended_base << 257;
                typename ed25519_field_type::extended_integral_type minus_eddsa_p = pow - eddsa_p;

                std::array<typename BlueprintFieldType::value_type, 4> r;
                std::array<typename BlueprintFieldType::value_type, 4> q;
                std::array<typename BlueprintFieldType::value_type, 4> p;
                typename BlueprintFieldType::integral_type mask = (pasta_base << 66) - 1;
                r[0] = (integral_eddsa_r) & (mask);
                q[0] = (integral_eddsa_q) & (mask);
                p[0] = (minus_eddsa_p) & (mask);
                for (std::size_t i = 1; i < 4; i++) {
                    r[i] = (integral_eddsa_r >> (66 * i)) & (mask);
                }
                typename ed25519_field_type::extended_integral_type eddsa_p0 = eddsa_p & mask;
                typename BlueprintFieldType::value_type t = a[0] + eddsa_p0 - b[0] + p[0] * q[0];

                typename BlueprintFieldType::value_type u0 = t - r[0];

                typename BlueprintFieldType::integral_type u0_integral =
                    typename BlueprintFieldType::integral_type(u0.data) >> 66;
                std::array<typename BlueprintFieldType::value_type, 4> u0_chunks;

                u0_chunks[0] = u0_integral & ((1 << 22) - 1);
                u0_chunks[1] = (u0_integral >> 22) & ((1 << 22) - 1);
                u0_chunks[2] = (u0_integral >> 44) & ((1 << 22) - 1);
                u0_chunks[3] = (u0_integral >> 66) & ((1 << 2) - 1);

                assignment.witness(component.W(0), row + 1) = a[0];
                assignment.witness(component.W(1), row + 1) = b[0];
                assignment.witness(component.W(2), row + 1) = integral_eddsa_q;
                assignment.witness(component.W(3), row + 1) = a[1];
                assignment.witness(component.W(4), row + 1) = a[2];
                assignment.witness(component.W(5), row + 1) = a[3];
                assignment.witness(component.W(6), row + 1) = b[1];
                assignment.witness(component.W(7), row + 1) = b[2];
                assignment.witness(component.W(8), row + 1) = b[3];
                assignment.witness(component.W(3), row) = u0_chunks[0];
                assignment.witness(component.W(4), row) = u0_chunks[1];
                assignment.witness(component.W(5), row) = u0_chunks[2];
                assignment.witness(component.W(6), row) = u0_chunks[3];
                assignment.witness(component.W(7), row) = typename BlueprintFieldType::value_type(u0_integral);
                assignment.witness(component.W(0), row + 2) = r[0];
                assignment.witness(component.W(1), row + 2) = r[1];
                assignment.witness(component.W(2), row + 2) = r[2];
                assignment.witness(component.W(3), row + 2) = r[3];

                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using range_type = typename plonk_ed25519_subtraction<BlueprintFieldType,
                                                                      ArithmetizationParams>::range_type;

                typename range_type::input_type range_input_r = {
                    var(0, row + 2, false), var(1, row + 2, false), var(2, row + 2, false), var(3, row + 2, false)};

                range_type range_component_instance({component.W(0), component.W(1), component.W(2), component.W(3),
                                                     component.W(4), component.W(5), component.W(6), component.W(7),
                                                     component.W(8)},
                                                    {}, {});
                generate_assignments(range_component_instance, assignment, range_input_r, row + 2);

                return typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using ed25519_field_type = crypto3::algebra::fields::curve25519_base_field;
                using var = typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::var;

                typename BlueprintFieldType::integral_type base = 1;
                typename ed25519_field_type::extended_integral_type extended_base = 1;
                typename ed25519_field_type::extended_integral_type eddsa_p = ed25519_field_type::modulus;
                typename BlueprintFieldType::value_type pasta_eddsa_p = eddsa_p;
                typename ed25519_field_type::extended_integral_type pow = extended_base << 257;
                typename ed25519_field_type::extended_integral_type minus_eddsa_p = pow - eddsa_p;
                std::array<typename BlueprintFieldType::value_type, 4> p;
                typename BlueprintFieldType::integral_type mask = (base << 66) - 1;
                typename ed25519_field_type::extended_integral_type eddsa_p0 = eddsa_p & mask;
                p[0] = minus_eddsa_p & mask;

                auto t = var(component.W(0), 0) + p[0] * var(component.W(2), 0);
                auto constraint_1 =
                    var(component.W(7), -1) * (base << 66) -
                    (t + eddsa_p0 - var(component.W(1), 0) - var(component.W(0), +1));
                auto constraint_2 = var(component.W(2), 0) * (var(component.W(2), 0) - 1);
                auto constraint_3 =
                    var(component.W(7), -1) -
                    (var(component.W(3), -1) + var(component.W(4), -1) * (1 << 22) +
                     var(component.W(5), -1) * (base << 44) +
                     var(component.W(6), -1) * (base << 66));

                auto constraint_4 =
                    (var(component.W(0), 0) + var(component.W(3), 0) * (base << 66) +
                     var(component.W(4), 0) * (base << 132) + var(component.W(5), 0) * (base << 198)) +
                    pasta_eddsa_p -
                    (var(component.W(1), 0) + var(component.W(6), 0) * (base << 66) +
                     var(component.W(7), 0) * (base << 132) + var(component.W(8), 0) * (base << 198)) -
                    pasta_eddsa_p * var(component.W(2), 0) -
                    (var(component.W(0), +1) + var(component.W(1), +1) * (base << 66) +
                     var(component.W(2), +1) * (base << 132) + var(component.W(3), +1) * (base << 198));

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::var;

                std::size_t row = start_row_index;

                bp.add_copy_constraint({var(component.W(0), row + 1, false), instance_input.A[0]});
                bp.add_copy_constraint({var(component.W(1), row + 1, false), instance_input.B[0]});
                bp.add_copy_constraint({var(component.W(3), row + 1, false), instance_input.A[1]});
                bp.add_copy_constraint({var(component.W(4), row + 1, false), instance_input.A[2]});
                bp.add_copy_constraint({var(component.W(5), row + 1, false), instance_input.A[3]});
                bp.add_copy_constraint({var(component.W(6), row + 1, false), instance_input.B[1]});
                bp.add_copy_constraint({var(component.W(7), row + 1, false), instance_input.B[2]});
                bp.add_copy_constraint({var(component.W(8), row + 1, false), instance_input.B[3]});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                std::size_t j = start_row_index;
                assignment.enable_selector(selector_index, j + 1);

                generate_copy_constraints(component, bp, assignment, instance_input, j);

                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using var = typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::var;
                using range_type = typename plonk_ed25519_subtraction<BlueprintFieldType,
                                                                      ArithmetizationParams>::range_type;

                typename range_type::input_type non_range_input_r = {
                    var(component.W(0), j + 2, false), var(component.W(1), j + 2, false),
                    var(component.W(2), j + 2, false), var(component.W(3), j + 2, false)};

                range_type range_component_instance({component.W(0), component.W(1), component.W(2), component.W(3),
                                                     component.W(4), component.W(5), component.W(6), component.W(7),
                                                     component.W(8)},
                                                    {}, {});

                generate_circuit(range_component_instance, bp, assignment, non_range_input_r, j + 2);

                return typename plonk_ed25519_subtraction<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_EDDSA_SUM_MULTIPLICATION_COMPONENT_9_WIRES_HPP

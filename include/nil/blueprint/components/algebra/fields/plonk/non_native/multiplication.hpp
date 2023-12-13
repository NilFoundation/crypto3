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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_EDDSA_MULTIPLICATION_COMPONENT_9_WIRES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_EDDSA_MULTIPLICATION_COMPONENT_9_WIRES_HPP

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
            class multiplication;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class multiplication<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                 typename crypto3::algebra::fields::curve25519_base_field,
                                 basic_non_native_policy<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

                using operating_field_type = crypto3::algebra::fields::curve25519_base_field;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                constexpr static std::size_t rows_amount_internal(std::size_t witness_amount,
                                                                  std::size_t lookup_column_amount) {
                    return 3 + 2 * range_type::get_rows_amount(witness_amount, lookup_column_amount);
                }
            public:
                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using range_type = range<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                                     ArithmetizationParams>,
                                         typename crypto3::algebra::fields::curve25519_base_field,
                                         non_native_policy_type>;
                using manifest_type = nil::blueprint::plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return multiplication::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type()).merge_with(
                            range_type::get_gate_manifest(witness_amount, lookup_column_amount));
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

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), 0);
                static constexpr const std::size_t gates_amount = 1;

                struct input_type {
                    typename non_native_policy_type::template field<operating_field_type>::non_native_var_type A;
                    typename non_native_policy_type::template field<operating_field_type>::non_native_var_type B;

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {A[0], A[1], A[2], A[3], B[0], B[1], B[2], B[3]};
                    }
                };

                struct result_type {
                    typename non_native_policy_type::template field<operating_field_type>::non_native_var_type output;

                    result_type(const multiplication &component, std::uint32_t start_row_index) {
                        output = {var(component.W(3), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(4), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(5), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(6), start_row_index + component.rows_amount - 2, false)};
                    }

                    std::vector<var> all_vars() const {
                        return {output[0], output[1], output[2], output[3]};
                    }
                };

                template<typename ContainerType>
                explicit multiplication(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                multiplication(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                multiplication(std::initializer_list<typename component_type::witness_container_type::value_type>
                                   witnesses,
                               std::initializer_list<typename component_type::constant_container_type::value_type>
                                   constants,
                               std::initializer_list<typename component_type::public_input_container_type::value_type>
                                   public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_ed25519_multiplication =
                multiplication<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                               typename crypto3::algebra::fields::curve25519_base_field,
                               basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::uint32_t start_row_index) {

                using ed25519_field_type = crypto3::algebra::fields::curve25519_base_field;

                using var = typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::var;
                using component_type = plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>;
                using range_type = typename component_type::range_type;

                using native_value_type = typename BlueprintFieldType::value_type;
                using native_integral_type = typename BlueprintFieldType::integral_type;
                using foreign_value_type = typename ed25519_field_type::value_type;
                using foreign_integral_type = typename ed25519_field_type::integral_type;
                using foreign_extended_integral_type = typename ed25519_field_type::extended_integral_type;


                std::size_t row = start_row_index;
                foreign_integral_type base = 1;
                native_integral_type pasta_base = 1;
                foreign_extended_integral_type extended_base = 1;
                std::array<native_value_type, 4> a = {
                    native_integral_type(var_value(assignment, instance_input.A[0]).data),
                    native_integral_type(var_value(assignment, instance_input.A[1]).data),
                    native_integral_type(var_value(assignment, instance_input.A[2]).data),
                    native_integral_type(var_value(assignment, instance_input.A[3]).data)};
                foreign_value_type eddsa_a =
                    foreign_integral_type(a[0].data) +
                    foreign_integral_type(a[1].data) * (base << 66) +
                    foreign_integral_type(a[2].data) * (base << 132) +
                    foreign_integral_type(a[3].data) * (base << 198);
                std::array<native_value_type, 4> b = {
                    native_integral_type(var_value(assignment, instance_input.B[0]).data),
                    native_integral_type(var_value(assignment, instance_input.B[1]).data),
                    native_integral_type(var_value(assignment, instance_input.B[2]).data),
                    native_integral_type(var_value(assignment, instance_input.B[3]).data)};
                foreign_value_type eddsa_b =
                    foreign_integral_type(b[0].data) +
                    foreign_integral_type(b[1].data) * (base << 66) +
                    foreign_integral_type(b[2].data) * (base << 132) +
                    foreign_integral_type(b[3].data) * (base << 198);
                foreign_value_type eddsa_r = eddsa_a * eddsa_b;
                foreign_integral_type integral_eddsa_r =
                    foreign_integral_type(eddsa_r.data);
                foreign_extended_integral_type eddsa_p = ed25519_field_type::modulus;
                foreign_extended_integral_type integral_eddsa_q =
                    (foreign_extended_integral_type(eddsa_a.data) *
                         foreign_extended_integral_type(eddsa_b.data) -
                     foreign_extended_integral_type(eddsa_r.data)) /
                    eddsa_p;
                foreign_extended_integral_type pow = extended_base << 257;
                foreign_extended_integral_type minus_eddsa_p = pow - eddsa_p;

                std::array<native_value_type, 4> r;
                std::array<native_value_type, 4> q;
                std::array<native_value_type, 4> p;
                native_integral_type mask = (pasta_base << 66) - 1;
                r[0] = (integral_eddsa_r) & (mask);
                q[0] = (integral_eddsa_q) & (mask);
                p[0] = (minus_eddsa_p) & (mask);
                p[1] = (minus_eddsa_p >> 66) & (mask);
                p[2] = (minus_eddsa_p >> 132) & (mask);
                p[3] = (minus_eddsa_p >> 198) & (mask);
                for (std::size_t i = 1; i < 4; i++) {
                    r[i] = (integral_eddsa_r >> (66 * i)) & (mask);
                    q[i] = (integral_eddsa_q >> (66 * i)) & (mask);
                }
                std::array<native_value_type, 4> t;
                t[0] = a[0] * b[0] + p[0] * q[0];
                t[1] = a[1] * b[0] + a[0] * b[1] + p[0] * q[1] + p[1] * q[0];
                t[2] = a[2] * b[0] + a[0] * b[2] + a[1] * b[1] + p[2] * q[0] + q[2] * p[0] + p[1] * q[1];
                t[3] = a[3] * b[0] + b[3] * a[0] + a[1] * b[2] + b[1] * a[2] + p[3] * q[0] + q[3] * p[0] + p[1] * q[2] +
                       q[1] * p[2];

                native_value_type u0 =
                    t[0] - r[0] + t[1] * (pasta_base << 66) - r[1] * (pasta_base << 66);

                native_integral_type u0_integral =
                    native_integral_type(u0.data) >> 132;
                std::array<native_value_type, 4> u0_chunks;

                u0_chunks[0] = u0_integral & ((1 << 22) - 1);
                u0_chunks[1] = (u0_integral >> 22) & ((1 << 22) - 1);
                u0_chunks[2] = (u0_integral >> 44) & ((1 << 22) - 1);
                u0_chunks[3] = (u0_integral >> 66) & ((1 << 4) - 1);

                native_value_type u1 = t[2] - r[2] + t[3] * (pasta_base << 66) -
                                                             r[3] * (pasta_base << 66) +
                                                             native_value_type(u0_integral);

                native_integral_type u1_integral =
                    native_integral_type(u1.data) >> 125;
                std::array<native_value_type, 4> u1_chunks;
                u1_chunks[0] = u1_integral & ((1 << 22) - 1);
                u1_chunks[1] = (u1_integral >> 22) & ((1 << 22) - 1);
                u1_chunks[2] = (u1_integral >> 44) & ((1 << 22) - 1);
                u1_chunks[3] = (u1_integral >> 66) & ((1 << 8) - 1);

                assignment.witness(component.W(0), row + 4) = a[0];
                assignment.witness(component.W(1), row + 4) = a[1];
                assignment.witness(component.W(2), row + 4) = a[2];
                assignment.witness(component.W(3), row + 4) = a[3];
                assignment.witness(component.W(4), row + 4) = b[0];
                assignment.witness(component.W(5), row + 4) = b[1];
                assignment.witness(component.W(6), row + 4) = b[2];
                assignment.witness(component.W(7), row + 4) = b[3];
                assignment.witness(component.W(8), row + 4) = q[0];
                assignment.witness(component.W(0), row + 5) = q[1];
                assignment.witness(component.W(1), row + 5) = q[2];
                assignment.witness(component.W(2), row + 5) = q[3];
                assignment.witness(component.W(3), row + 5) = r[0];
                assignment.witness(component.W(4), row + 5) = r[1];
                assignment.witness(component.W(5), row + 5) = r[2];
                assignment.witness(component.W(6), row + 5) = r[3];
                assignment.witness(component.W(7), row + 5) = native_value_type(u0_integral);
                assignment.witness(component.W(8), row + 5) = native_value_type(u1_integral);
                assignment.witness(component.W(0), row + 6) = u0_chunks[0];
                assignment.witness(component.W(1), row + 6) = u0_chunks[1];
                assignment.witness(component.W(2), row + 6) = u0_chunks[2];
                assignment.witness(component.W(3), row + 6) = u0_chunks[3];
                assignment.witness(component.W(4), row + 6) = u1_chunks[0];
                assignment.witness(component.W(5), row + 6) = u1_chunks[1];
                assignment.witness(component.W(6), row + 6) = u1_chunks[2];
                assignment.witness(component.W(7), row + 6) = u1_chunks[3];

                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                range_type range_component_instance({component.W(0), component.W(1), component.W(2), component.W(3),
                                                     component.W(4), component.W(5), component.W(6), component.W(7),
                                                     component.W(8)},
                                                    {}, {});

                typename range_type::input_type non_range_input_q = {
                    var(component.W(8), row + 4, false), var(component.W(0), row + 5, false),
                    var(component.W(1), row + 5, false), var(component.W(2), row + 5, false)};

                generate_assignments(range_component_instance, assignment, non_range_input_q, row);

                typename range_type::input_type non_range_input_r = {
                    var(component.W(3), row + 5, false), var(component.W(4), row + 5, false),
                    var(component.W(5), row + 5, false), var(component.W(6), row + 5, false)};

                generate_assignments(range_component_instance, assignment, non_range_input_r, row + 2);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using ed25519_field_type = crypto3::algebra::fields::curve25519_base_field;
                using var = typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::var;

                using native_value_type = typename BlueprintFieldType::value_type;
                using native_integral_type = typename BlueprintFieldType::integral_type;
                using foreign_value_type = typename ed25519_field_type::value_type;
                using foreign_integral_type = typename ed25519_field_type::integral_type;
                using foreign_extended_integral_type = typename ed25519_field_type::extended_integral_type;

                native_integral_type base = 1;
                foreign_extended_integral_type extended_base = 1;
                foreign_extended_integral_type eddsa_p = ed25519_field_type::modulus;
                native_value_type pasta_eddsa_p = eddsa_p;
                foreign_extended_integral_type pow = extended_base << 257;
                foreign_extended_integral_type minus_eddsa_p = pow - eddsa_p;
                std::array<native_value_type, 4> p;
                native_integral_type mask = (base << 66) - 1;
                p[0] = minus_eddsa_p & mask;
                p[1] = (minus_eddsa_p >> 66) & (mask);
                p[2] = (minus_eddsa_p >> 132) & (mask);
                p[3] = (minus_eddsa_p >> 198) & (mask);

                std::array<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>, 5> t;
                t[0] = var(component.W(0), -1) * var(component.W(4), -1) + p[0] * var(component.W(8), -1);
                t[1] = var(component.W(1), -1) * var(component.W(4), -1) +
                       var(component.W(0), -1) * var(component.W(5), -1) + p[0] * var(component.W(0), 0) +
                       p[1] * var(component.W(8), -1);
                t[2] = var(component.W(2), -1) * var(component.W(4), -1) +
                       var(component.W(0), -1) * var(component.W(6), -1) +
                       var(component.W(1), -1) * var(component.W(5), -1) + p[2] * var(component.W(8), -1) +
                       var(component.W(1), 0) * p[0] + p[1] * var(component.W(0), 0);
                t[3] = var(component.W(3), -1) * var(component.W(4), -1) +
                       var(component.W(7), -1) * var(component.W(0), -1) +
                       var(component.W(1), -1) * var(component.W(6), -1) +
                       var(component.W(5), -1) * var(component.W(2), -1) + p[3] * var(component.W(8), -1) +
                       var(component.W(2), 0) * p[0] + p[1] * var(component.W(1), 0) + var(component.W(0), 0) * p[2];
                auto constraint_1 =
                    var(component.W(7), 0) * (base << 132) -
                    (t[0] - var(component.W(3), 0) + t[1] * (base << 66) - var(component.W(4), 0) * (base << 66));
                auto constraint_2 = var(component.W(8), 0) * (base << 125) -
                                                      (t[2] - var(component.W(5), 0) + t[3] * (base << 66) -
                                                       var(component.W(6), 0) * (base << 66) + var(component.W(7), 0));
                auto constraint_3 = var(component.W(7), 0) -
                                                      (var(component.W(0), +1) + var(component.W(1), +1) * (1 << 22) +
                                                       var(component.W(2), +1) * (base << 44) +
                                                       var(component.W(3), +1) * (base << 66));
                auto constraint_4 = var(component.W(8), 0) -
                                                      (var(component.W(4), +1) + var(component.W(5), +1) * (1 << 22) +
                                                       var(component.W(6), +1) * (base << 44) +
                                                       var(component.W(7), +1) * (base << 66));
                auto constraint_5 =
                    (var(component.W(0), -1) + var(component.W(1), -1) * (base << 66) +
                     var(component.W(2), -1) * (base << 132) + var(component.W(3), -1) * (base << 198)) *
                        (var(component.W(4), -1) + var(component.W(5), -1) * (base << 66) +
                         var(component.W(6), -1) * (base << 132) + var(component.W(7), -1) * (base << 198)) -
                    ((var(component.W(8), -1) + var(component.W(0), 0) * (base << 66) +
                      var(component.W(1), 0) * (base << 132) + var(component.W(2), 0) * (base << 198)) *
                         pasta_eddsa_p +
                     (var(component.W(3), 0) + var(component.W(4), 0) * (base << 66) +
                      var(component.W(5), 0) * (base << 132) + var(component.W(6), 0) * (base << 198)));

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::var;

                std::size_t row = start_row_index;

                bp.add_copy_constraint({var(component.W(0), row + 4, false), instance_input.A[0]});
                bp.add_copy_constraint({var(component.W(1), row + 4, false), instance_input.A[1]});
                bp.add_copy_constraint({var(component.W(2), row + 4, false), instance_input.A[2]});
                bp.add_copy_constraint({var(component.W(3), row + 4, false), instance_input.A[3]});
                bp.add_copy_constraint({var(component.W(4), row + 4, false), instance_input.B[0]});
                bp.add_copy_constraint({var(component.W(5), row + 4, false), instance_input.B[1]});
                bp.add_copy_constraint({var(component.W(6), row + 4, false), instance_input.B[2]});
                bp.add_copy_constraint({var(component.W(7), row + 4, false), instance_input.B[3]});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                using component_type = plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>;
                using range_type = typename component_type::range_type;

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                std::size_t j = start_row_index;
                assignment.enable_selector(selector_index, j + 5);

                generate_copy_constraints(component, bp, assignment, instance_input, j);

                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using var = typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>::var;

                range_type range_component_instance({component.W(0), component.W(1), component.W(2), component.W(3),
                                                     component.W(4), component.W(5), component.W(6), component.W(7),
                                                     component.W(8)},
                                                    {}, {});

                typename range_type::input_type non_range_input_q = {
                    var(component.W(8), j + 4, false), var(component.W(0), j + 5, false),
                    var(component.W(1), j + 5, false), var(component.W(2), j + 5, false)};

                generate_circuit(range_component_instance, bp, assignment, non_range_input_q, j);

                typename range_type::input_type non_range_input_r = {
                    var(component.W(3), j + 5, false), var(component.W(4), j + 5, false),
                    var(component.W(5), j + 5, false), var(component.W(6), j + 5, false)};

                generate_circuit(range_component_instance, bp, assignment, non_range_input_r, j + 2);

                return typename component_type::result_type(component, start_row_index);
            }

            template<typename ComponentType>
            class input_type_converter;

            template<typename ComponentType>
            class result_type_converter;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class input_type_converter<plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>> {

                using component_type = plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>;
                using input_type = typename component_type::input_type;
                using var = typename nil::crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            public:
                static input_type convert(
                    const input_type &input,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &assignment,
                    nil::blueprint::assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                                                                           ArithmetizationParams>>
                        &tmp_assignment) {

                    input_type new_input;
                    for (std::size_t i = 0; i < input.A.size(); i++) {
                        tmp_assignment.public_input(0, i) = var_value(assignment, input.A[i]);
                        new_input.A[i] = var(0, i, false, var::column_type::public_input);
                    }
                    for (std::size_t i = 0; i < input.B.size(); i++) {
                        std::size_t new_idx = input.A.size() + i;
                        tmp_assignment.public_input(0, new_idx) = var_value(assignment, input.B[i]);
                        new_input.B[i] = var(0, new_idx, false, var::column_type::public_input);
                    }

                    return new_input;
                }

                static var deconvert_var(const input_type &input,
                                         var variable) {
                    BOOST_ASSERT(variable.type == var::column_type::public_input);
                    if (variable.rotation < input.A.size()) {
                        return input.A[variable.rotation];
                    } else {
                        return input.B[variable.rotation - input.A.size()];
                    }
                }
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class result_type_converter<plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>> {

                using component_type = plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams>;
                using input_type = typename component_type::input_type;
                using result_type = typename component_type::result_type;
                using stretcher_type = component_stretcher<BlueprintFieldType, ArithmetizationParams, component_type>;
            public:
                static result_type convert(const stretcher_type &component, const result_type old_result,
                                           const input_type &instance_input, std::size_t start_row_index) {
                    result_type new_result(component.component, start_row_index);

                    for (std::size_t i = 0; i < new_result.output.size(); i++) {
                        new_result.output[i] = component.move_var(
                            old_result.output[i],
                            start_row_index + component.line_mapping[old_result.output[i].rotation],
                            instance_input);
                    }

                    return new_result;
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_EDDSA_MULTIPLICATION_COMPONENT_9_WIRES_HPP

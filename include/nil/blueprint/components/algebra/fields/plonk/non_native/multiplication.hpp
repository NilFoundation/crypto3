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
            template<typename ArithmetizationType, typename FieldType, std::uint32_t WitnessesAmount,
                     typename NonNativePolicyType>
            class multiplication;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            class multiplication<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                 typename crypto3::algebra::fields::curve25519_base_field, 9,
                                 basic_non_native_policy<BlueprintFieldType>>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 9, 0, 0> {

                constexpr static const std::uint32_t WitnessesAmount = 9;

                using component_type =
                    plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0>;
                using operating_field_type = typename crypto3::algebra::fields::curve25519_base_field;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

            public:
                using var = typename component_type::var;

                constexpr static const std::size_t T = 257;

                constexpr static const std::size_t rows_amount =
                    3 +
                    2 * range<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              typename crypto3::algebra::fields::curve25519_base_field, 9,
                              non_native_policy_type>::rows_amount;

                const std::size_t gates_amount = 1;

                struct input_type {
                    typename non_native_policy_type::template field<operating_field_type>::value_type A;
                    typename non_native_policy_type::template field<operating_field_type>::value_type B;
                };

                struct result_type {
                    typename non_native_policy_type::template field<operating_field_type>::value_type output;

                    result_type(const multiplication &component, std::uint32_t start_row_index) {
                        output = {var(component.W(3), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(4), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(5), start_row_index + component.rows_amount - 2, false),
                                  var(component.W(6), start_row_index + component.rows_amount - 2, false)};
                    }
                };

                template<typename ContainerType>
                multiplication(ContainerType witness) : component_type(witness, {}, {}) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                multiplication(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input) {};

                multiplication(std::initializer_list<typename component_type::witness_container_type::value_type>
                                   witnesses,
                               std::initializer_list<typename component_type::constant_container_type::value_type>
                                   constants,
                               std::initializer_list<typename component_type::public_input_container_type::value_type>
                                   public_inputs) :
                    component_type(witnesses, constants, public_inputs) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, std::int32_t WitnessesAmount>
            using plonk_ed25519_multiplication =
                multiplication<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                               typename crypto3::algebra::fields::curve25519_base_field, WitnessesAmount,
                               basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::result_type
                generate_assignments(
                    const plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams,
                                                                9>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                using ed25519_field_type = typename crypto3::algebra::fields::curve25519_base_field;

                using var = typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::var;

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
                typename ed25519_field_type::value_type eddsa_b =
                    typename ed25519_field_type::integral_type(b[0].data) +
                    typename ed25519_field_type::integral_type(b[1].data) * (base << 66) +
                    typename ed25519_field_type::integral_type(b[2].data) * (base << 132) +
                    typename ed25519_field_type::integral_type(b[3].data) * (base << 198);
                typename ed25519_field_type::value_type eddsa_r = eddsa_a * eddsa_b;
                typename ed25519_field_type::integral_type integral_eddsa_r =
                    typename ed25519_field_type::integral_type(eddsa_r.data);
                typename ed25519_field_type::extended_integral_type eddsa_p = ed25519_field_type::modulus;
                typename ed25519_field_type::extended_integral_type integral_eddsa_q =
                    (typename ed25519_field_type::extended_integral_type(eddsa_a.data) *
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
                p[1] = (minus_eddsa_p >> 66) & (mask);
                p[2] = (minus_eddsa_p >> 132) & (mask);
                p[3] = (minus_eddsa_p >> 198) & (mask);
                for (std::size_t i = 1; i < 4; i++) {
                    r[i] = (integral_eddsa_r >> (66 * i)) & (mask);
                    q[i] = (integral_eddsa_q >> (66 * i)) & (mask);
                }
                std::array<typename BlueprintFieldType::value_type, 4> t;
                t[0] = a[0] * b[0] + p[0] * q[0];
                t[1] = a[1] * b[0] + a[0] * b[1] + p[0] * q[1] + p[1] * q[0];
                t[2] = a[2] * b[0] + a[0] * b[2] + a[1] * b[1] + p[2] * q[0] + q[2] * p[0] + p[1] * q[1];
                t[3] = a[3] * b[0] + b[3] * a[0] + a[1] * b[2] + b[1] * a[2] + p[3] * q[0] + q[3] * p[0] + p[1] * q[2] +
                       q[1] * p[2];

                typename BlueprintFieldType::value_type u0 =
                    t[0] - r[0] + t[1] * (pasta_base << 66) - r[1] * (pasta_base << 66);

                typename BlueprintFieldType::integral_type u0_integral =
                    typename BlueprintFieldType::integral_type(u0.data) >> 132;
                std::array<typename BlueprintFieldType::value_type, 4> u0_chunks;

                u0_chunks[0] = u0_integral & ((1 << 22) - 1);
                u0_chunks[1] = (u0_integral >> 22) & ((1 << 22) - 1);
                u0_chunks[2] = (u0_integral >> 44) & ((1 << 22) - 1);
                u0_chunks[3] = (u0_integral >> 66) & ((1 << 4) - 1);

                typename BlueprintFieldType::value_type u1 = t[2] - r[2] + t[3] * (pasta_base << 66) -
                                                             r[3] * (pasta_base << 66) +
                                                             typename BlueprintFieldType::value_type(u0_integral);

                typename BlueprintFieldType::integral_type u1_integral =
                    typename BlueprintFieldType::integral_type(u1.data) >> 125;
                std::array<typename BlueprintFieldType::value_type, 4> u1_chunks;
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
                assignment.witness(component.W(7), row + 5) = typename BlueprintFieldType::value_type(u0_integral);
                assignment.witness(component.W(8), row + 5) = typename BlueprintFieldType::value_type(u1_integral);
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

                range<ArithmetizationType, typename crypto3::algebra::fields::curve25519_base_field, 9,
                      basic_non_native_policy<BlueprintFieldType>>
                    range_component_instance({component.W(0), component.W(1), component.W(2), component.W(3),
                                              component.W(4), component.W(5), component.W(6), component.W(7),
                                              component.W(8)},
                                             {}, {});

                typename range<ArithmetizationType, typename crypto3::algebra::fields::curve25519_base_field, 9,
                               basic_non_native_policy<BlueprintFieldType>>::input_type non_range_input_q = {
                    var(component.W(8), row + 4, false), var(component.W(0), row + 5, false),
                    var(component.W(1), row + 5, false), var(component.W(2), row + 5, false)};

                generate_assignments(range_component_instance, assignment, non_range_input_q, row);

                typename range<ArithmetizationType, typename crypto3::algebra::fields::curve25519_base_field, 9,
                               basic_non_native_policy<BlueprintFieldType>>::input_type non_range_input_r = {
                    var(component.W(3), row + 5, false), var(component.W(4), row + 5, false),
                    var(component.W(5), row + 5, false), var(component.W(6), row + 5, false)};

                generate_assignments(range_component_instance, assignment, non_range_input_r, row + 2);

                return typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_gates(
                const plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                    &instance_input,
                const std::size_t first_selector_index) {

                using ed25519_field_type = typename crypto3::algebra::fields::curve25519_base_field;
                using var = typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::var;

                typename BlueprintFieldType::integral_type base = 1;
                typename ed25519_field_type::extended_integral_type extended_base = 1;
                typename ed25519_field_type::extended_integral_type eddsa_p = ed25519_field_type::modulus;
                typename BlueprintFieldType::value_type pasta_eddsa_p = eddsa_p;
                typename ed25519_field_type::extended_integral_type pow = extended_base << 257;
                typename ed25519_field_type::extended_integral_type minus_eddsa_p = pow - eddsa_p;
                std::array<typename BlueprintFieldType::value_type, 4> p;
                typename BlueprintFieldType::integral_type mask = (base << 66) - 1;
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
                auto constraint_1 = bp.add_constraint(
                    var(component.W(7), 0) * (base << 132) -
                    (t[0] - var(component.W(3), 0) + t[1] * (base << 66) - var(component.W(4), 0) * (base << 66)));
                auto constraint_2 = bp.add_constraint(var(component.W(8), 0) * (base << 125) -
                                                      (t[2] - var(component.W(5), 0) + t[3] * (base << 66) -
                                                       var(component.W(6), 0) * (base << 66) + var(component.W(7), 0)));
                auto constraint_3 = bp.add_constraint(var(component.W(7), 0) -
                                                      (var(component.W(0), +1) + var(component.W(1), +1) * (1 << 22) +
                                                       var(component.W(2), +1) * (base << 44) +
                                                       var(component.W(3), +1) * (base << 66)));
                auto constraint_4 = bp.add_constraint(var(component.W(8), 0) -
                                                      (var(component.W(4), +1) + var(component.W(5), +1) * (1 << 22) +
                                                       var(component.W(6), +1) * (base << 44) +
                                                       var(component.W(7), +1) * (base << 66)));
                auto constraint_5 = bp.add_constraint(
                    (var(component.W(0), -1) + var(component.W(1), -1) * (base << 66) +
                     var(component.W(2), -1) * (base << 132) + var(component.W(3), -1) * (base << 198)) *
                        (var(component.W(4), -1) + var(component.W(5), -1) * (base << 66) +
                         var(component.W(6), -1) * (base << 132) + var(component.W(7), -1) * (base << 198)) -
                    ((var(component.W(8), -1) + var(component.W(0), 0) * (base << 66) +
                      var(component.W(1), 0) * (base << 132) + var(component.W(2), 0) * (base << 198)) *
                         pasta_eddsa_p +
                     (var(component.W(3), 0) + var(component.W(4), 0) * (base << 66) +
                      var(component.W(5), 0) * (base << 132) + var(component.W(6), 0) * (base << 198))));

                bp.add_gate(first_selector_index,
                            {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5

                            });
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::var;

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
            typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::result_type
                generate_circuit(
                    const plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams,
                                                                9>::input_type &instance_input,
                    const std::size_t start_row_index) {

                auto selector_iterator = assignment.find_selector(component);
                std::size_t first_selector_index;
                if (selector_iterator == assignment.selectors_end()) {
                    first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                    generate_gates(component, bp, assignment, instance_input, first_selector_index);
                } else {
                    first_selector_index = selector_iterator->second;
                }
                std::size_t j = start_row_index;
                assignment.enable_selector(first_selector_index, j + 5);

                generate_copy_constraints(component, bp, assignment, instance_input, j);

                using ArithmetizationType =
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                using var = typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::var;

                range<ArithmetizationType, typename crypto3::algebra::fields::curve25519_base_field, 9,
                      basic_non_native_policy<BlueprintFieldType>>
                    range_component_instance({component.W(0), component.W(1), component.W(2), component.W(3),
                                              component.W(4), component.W(5), component.W(6), component.W(7),
                                              component.W(8)},
                                             {}, {});

                typename range<ArithmetizationType, typename crypto3::algebra::fields::curve25519_base_field, 9,
                               basic_non_native_policy<BlueprintFieldType>>::input_type non_range_input_q = {
                    var(component.W(8), j + 4), var(component.W(0), j + 5), var(component.W(1), j + 5),
                    var(component.W(2), j + 5)};

                generate_circuit(range_component_instance, bp, assignment, non_range_input_q, j);

                typename range<ArithmetizationType, typename crypto3::algebra::fields::curve25519_base_field, 9,
                               basic_non_native_policy<BlueprintFieldType>>::input_type non_range_input_r = {
                    var(component.W(3), j + 5), var(component.W(4), j + 5), var(component.W(5), j + 5),
                    var(component.W(6), j + 5)};

                generate_circuit(range_component_instance, bp, assignment, non_range_input_r, j + 2);

                return typename plonk_ed25519_multiplication<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_NON_NATIVE_FIELDS_EDDSA_MULTIPLICATION_COMPONENT_9_WIRES_HPP

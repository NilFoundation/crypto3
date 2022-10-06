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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_NON_NATIVE_FIELDS_EDDSA_MULTIPLICATION_COMPONENT_9_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_NON_NATIVE_FIELDS_EDDSA_MULTIPLICATION_COMPONENT_9_WIRES_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/non_native_range.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         typename Ed25519Type,
                         std::size_t... WireIndexes>
                class non_native_field_element_multiplication;

                /*
                1 non_native range for q
                2 q
                3 non-native range for r
                4
                5 a0 a1 a2 a3 b0 b1 b2 b3 q0
                6 q1 q2 q3 r0 r1 r2 r3 v0 v1
                7 v00 v01 v02 v03 v10 v11 v12 v13

                */

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         typename Ed25519Type,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8>
                class non_native_field_element_multiplication<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    Ed25519Type,
                    W0,
                    W1,
                    W2,
                    W3,
                    W4,
                    W5,
                    W6,
                    W7,
                    W8> {
                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using non_native_range_component =
                        zk::components::non_native_range<ArithmetizationType, CurveType, 0, 1, 2, 3, 4, 5, 6, 7, 8>;

                    constexpr static const std::size_t selector_seed = 0xff81;

                    constexpr static const std::size_t T = 257;

                public:
                    constexpr static const std::size_t rows_amount = 3 + 2 * non_native_range_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        std::array<var, 4> A;    // 66,66,66,66 bits
                        std::array<var, 4> B;    // 66,66,66,66 bits
                    };

                    struct result_type {
                        std::array<var, 4> output;

                        result_type(const std::size_t &component_start_row) {
                            output = {var(W3, component_start_row + rows_amount - 2, false),
                                      var(W4, component_start_row + rows_amount - 2, false),
                                      var(W5, component_start_row + rows_amount - 2, false),
                                      var(W6, component_start_row + rows_amount - 2, false)};
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;
                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }
                        std::size_t j = start_row_index;
                        assignment.enable_selector(first_selector_index, j + 5);

                        generate_copy_constraints(bp, assignment, params, j);

                        typename non_native_range_component::params_type non_range_params_q = {
                            var(W8, j + 4), var(W0, j + 5), var(W1, j + 5), var(W2, j + 5)};
                        non_native_range_component::generate_circuit(bp, assignment, non_range_params_q, j);
                        typename non_native_range_component::params_type non_range_params_r = {
                            var(W3, j + 5), var(W4, j + 5), var(W5, j + 5), var(W6, j + 5)};
                        non_native_range_component::generate_circuit(bp, assignment, non_range_params_r, j + 2);

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        typename Ed25519Type::base_field_type::integral_type base = 1;
                        typename CurveType::base_field_type::integral_type pasta_base = 1;
                        typename Ed25519Type::base_field_type::extended_integral_type extended_base = 1;
                        std::array<typename CurveType::base_field_type::value_type, 4> a = {
                            typename CurveType::base_field_type::integral_type(assignment.var_value(params.A[0]).data),
                            typename CurveType::base_field_type::integral_type(assignment.var_value(params.A[1]).data),
                            typename CurveType::base_field_type::integral_type(assignment.var_value(params.A[2]).data),
                            typename CurveType::base_field_type::integral_type(assignment.var_value(params.A[3]).data)};
                        typename Ed25519Type::base_field_type::value_type eddsa_a =
                            typename Ed25519Type::base_field_type::integral_type(a[0].data) +
                            typename Ed25519Type::base_field_type::integral_type(a[1].data) * (base << 66) +
                            typename Ed25519Type::base_field_type::integral_type(a[2].data) * (base << 132) +
                            typename Ed25519Type::base_field_type::integral_type(a[3].data) * (base << 198);
                        std::array<typename CurveType::base_field_type::value_type, 4> b = {
                            typename CurveType::base_field_type::integral_type(assignment.var_value(params.B[0]).data),
                            typename CurveType::base_field_type::integral_type(assignment.var_value(params.B[1]).data),
                            typename CurveType::base_field_type::integral_type(assignment.var_value(params.B[2]).data),
                            typename CurveType::base_field_type::integral_type(assignment.var_value(params.B[3]).data)};
                        typename Ed25519Type::base_field_type::value_type eddsa_b =
                            typename Ed25519Type::base_field_type::integral_type(b[0].data) +
                            typename Ed25519Type::base_field_type::integral_type(b[1].data) * (base << 66) +
                            typename Ed25519Type::base_field_type::integral_type(b[2].data) * (base << 132) +
                            typename Ed25519Type::base_field_type::integral_type(b[3].data) * (base << 198);
                        typename Ed25519Type::base_field_type::value_type eddsa_r = eddsa_a * eddsa_b;
                        typename Ed25519Type::base_field_type::integral_type integral_eddsa_r =
                            typename Ed25519Type::base_field_type::integral_type(eddsa_r.data);
                        typename Ed25519Type::base_field_type::extended_integral_type eddsa_p =
                            Ed25519Type::base_field_type::modulus;
                        typename Ed25519Type::base_field_type::extended_integral_type integral_eddsa_q =
                            (typename Ed25519Type::base_field_type::extended_integral_type(eddsa_a.data) *
                                 typename Ed25519Type::base_field_type::extended_integral_type(eddsa_b.data) -
                             typename Ed25519Type::base_field_type::extended_integral_type(eddsa_r.data)) /
                            eddsa_p;
                        typename Ed25519Type::base_field_type::extended_integral_type pow = extended_base << 257;
                        typename Ed25519Type::base_field_type::extended_integral_type minus_eddsa_p = pow - eddsa_p;

                        std::array<typename CurveType::base_field_type::value_type, 4> r;
                        std::array<typename CurveType::base_field_type::value_type, 4> q;
                        std::array<typename CurveType::base_field_type::value_type, 4> p;
                        typename CurveType::base_field_type::integral_type mask = (pasta_base << 66) - 1;
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
                        std::array<typename CurveType::base_field_type::value_type, 4> t;
                        t[0] = a[0] * b[0] + p[0] * q[0];
                        t[1] = a[1] * b[0] + a[0] * b[1] + p[0] * q[1] + p[1] * q[0];
                        t[2] = a[2] * b[0] + a[0] * b[2] + a[1] * b[1] + p[2] * q[0] + q[2] * p[0] + p[1] * q[1];
                        t[3] = a[3] * b[0] + b[3] * a[0] + a[1] * b[2] + b[1] * a[2] + p[3] * q[0] + q[3] * p[0] +
                               p[1] * q[2] + q[1] * p[2];

                        typename CurveType::base_field_type::value_type u0 =
                            t[0] - r[0] + t[1] * (pasta_base << 66) - r[1] * (pasta_base << 66);

                        typename CurveType::base_field_type::integral_type u0_integral =
                            typename CurveType::base_field_type::integral_type(u0.data) >> 132;
                        std::array<typename CurveType::base_field_type::value_type, 4> u0_chunks;

                        u0_chunks[0] = u0_integral & ((1 << 22) - 1);
                        u0_chunks[1] = (u0_integral >> 22) & ((1 << 22) - 1);
                        u0_chunks[2] = (u0_integral >> 44) & ((1 << 22) - 1);
                        u0_chunks[3] = (u0_integral >> 66) & ((1 << 4) - 1);

                        typename CurveType::base_field_type::value_type u1 =
                            t[2] - r[2] + t[3] * (pasta_base << 66) - r[3] * (pasta_base << 66) +
                            typename CurveType::base_field_type::value_type(u0_integral);

                        typename CurveType::base_field_type::integral_type u1_integral =
                            typename CurveType::base_field_type::integral_type(u1.data) >> 125;
                        std::array<typename CurveType::base_field_type::value_type, 4> u1_chunks;
                        u1_chunks[0] = u1_integral & ((1 << 22) - 1);
                        u1_chunks[1] = (u1_integral >> 22) & ((1 << 22) - 1);
                        u1_chunks[2] = (u1_integral >> 44) & ((1 << 22) - 1);
                        u1_chunks[3] = (u1_integral >> 66) & ((1 << 8) - 1);

                        assignment.witness(W0)[row + 4] = a[0];
                        assignment.witness(W1)[row + 4] = a[1];
                        assignment.witness(W2)[row + 4] = a[2];
                        assignment.witness(W3)[row + 4] = a[3];
                        assignment.witness(W4)[row + 4] = b[0];
                        assignment.witness(W5)[row + 4] = b[1];
                        assignment.witness(W6)[row + 4] = b[2];
                        assignment.witness(W7)[row + 4] = b[3];
                        assignment.witness(W8)[row + 4] = q[0];
                        assignment.witness(W0)[row + 5] = q[1];
                        assignment.witness(W1)[row + 5] = q[2];
                        assignment.witness(W2)[row + 5] = q[3];
                        assignment.witness(W3)[row + 5] = r[0];
                        assignment.witness(W4)[row + 5] = r[1];
                        assignment.witness(W5)[row + 5] = r[2];
                        assignment.witness(W6)[row + 5] = r[3];
                        assignment.witness(W7)[row + 5] = typename CurveType::base_field_type::value_type(u0_integral);
                        assignment.witness(W8)[row + 5] = typename CurveType::base_field_type::value_type(u1_integral);
                        assignment.witness(W0)[row + 6] = u0_chunks[0];
                        assignment.witness(W1)[row + 6] = u0_chunks[1];
                        assignment.witness(W2)[row + 6] = u0_chunks[2];
                        assignment.witness(W3)[row + 6] = u0_chunks[3];
                        assignment.witness(W4)[row + 6] = u1_chunks[0];
                        assignment.witness(W5)[row + 6] = u1_chunks[1];
                        assignment.witness(W6)[row + 6] = u1_chunks[2];
                        assignment.witness(W7)[row + 6] = u1_chunks[3];

                        typename non_native_range_component::params_type range_params_q = {
                            var(8, row + 4, false), var(0, row + 5, false), var(1, row + 5, false),
                            var(2, row + 5, false)};
                        non_native_range_component::generate_assignments(assignment, range_params_q, row);

                        typename non_native_range_component::params_type range_params_r = {
                            var(3, row + 5, false), var(4, row + 5, false), var(5, row + 5, false),
                            var(6, row + 5, false)};
                        non_native_range_component::generate_assignments(assignment, range_params_r, row + 2);

                        return result_type(start_row_index);
                    }

                private:
                    static void
                        generate_gates(blueprint<ArithmetizationType> &bp,
                                       blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                       const params_type &params,
                                       const std::size_t first_selector_index) {
                        typename CurveType::base_field_type::integral_type base = 1;
                        typename Ed25519Type::base_field_type::extended_integral_type extended_base = 1;
                        typename Ed25519Type::base_field_type::extended_integral_type eddsa_p =
                            Ed25519Type::base_field_type::modulus;
                        typename CurveType::base_field_type::value_type pasta_eddsa_p = eddsa_p;
                        typename Ed25519Type::base_field_type::extended_integral_type pow = extended_base << 257;
                        typename Ed25519Type::base_field_type::extended_integral_type minus_eddsa_p = pow - eddsa_p;
                        std::array<typename CurveType::base_field_type::value_type, 4> p;
                        typename CurveType::base_field_type::integral_type mask = (base << 66) - 1;
                        p[0] = minus_eddsa_p & mask;
                        p[1] = (minus_eddsa_p >> 66) & (mask);
                        p[2] = (minus_eddsa_p >> 132) & (mask);
                        p[3] = (minus_eddsa_p >> 198) & (mask);

                        std::array<snark::plonk_constraint<BlueprintFieldType>, 5> t;
                        t[0] = var(W0, -1) * var(W4, -1) + p[0] * var(W8, -1);
                        t[1] = var(W1, -1) * var(W4, -1) + var(W0, -1) * var(W5, -1) + p[0] * var(W0, 0) +
                               p[1] * var(W8, -1);
                        t[2] = var(W2, -1) * var(W4, -1) + var(W0, -1) * var(W6, -1) + var(W1, -1) * var(W5, -1) +
                               p[2] * var(W8, -1) + var(W1, 0) * p[0] + p[1] * var(W0, 0);
                        t[3] = var(W3, -1) * var(W4, -1) + var(W7, -1) * var(W0, -1) + var(W1, -1) * var(W6, -1) +
                               var(W5, -1) * var(W2, -1) + p[3] * var(W8, -1) + var(W2, 0) * p[0] + p[1] * var(W1, 0) +
                               var(W0, 0) * p[2];
                        auto constraint_1 =
                            bp.add_constraint(var(W7, 0) * (base << 132) -
                                              (t[0] - var(W3, 0) + t[1] * (base << 66) - var(W4, 0) * (base << 66)));
                        auto constraint_2 =
                            bp.add_constraint(var(W8, 0) * (base << 125) - (t[2] - var(W5, 0) + t[3] * (base << 66) -
                                                                            var(W6, 0) * (base << 66) + var(W7, 0)));
                        auto constraint_3 =
                            bp.add_constraint(var(W7, 0) - (var(W0, +1) + var(W1, +1) * (1 << 22) +
                                                            var(W2, +1) * (base << 44) + var(W3, +1) * (base << 66)));
                        auto constraint_4 =
                            bp.add_constraint(var(W8, 0) - (var(W4, +1) + var(W5, +1) * (1 << 22) +
                                                            var(W6, +1) * (base << 44) + var(W7, +1) * (base << 66)));
                        auto constraint_5 =
                            bp.add_constraint((var(W0, -1) + var(W1, -1) * (base << 66) + var(W2, -1) * (base << 132) +
                                               var(W3, -1) * (base << 198)) *
                                                  (var(W4, -1) + var(W5, -1) * (base << 66) +
                                                   var(W6, -1) * (base << 132) + var(W7, -1) * (base << 198)) -
                                              ((var(W8, -1) + var(W0, 0) * (base << 66) + var(W1, 0) * (base << 132) +
                                                var(W2, 0) * (base << 198)) *
                                                   pasta_eddsa_p +
                                               (var(W3, 0) + var(W4, 0) * (base << 66) + var(W5, 0) * (base << 132) +
                                                var(W6, 0) * (base << 198))));

                        bp.add_gate(first_selector_index,
                                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5

                                    });
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const params_type &params,
                        std::size_t component_start_row) {

                        std::size_t row = component_start_row;

                        bp.add_copy_constraint({var(W0, row + 4, false), params.A[0]});
                        bp.add_copy_constraint({var(W1, row + 4, false), params.A[1]});
                        bp.add_copy_constraint({var(W2, row + 4, false), params.A[2]});
                        bp.add_copy_constraint({var(W3, row + 4, false), params.A[3]});
                        bp.add_copy_constraint({var(W4, row + 4, false), params.B[0]});
                        bp.add_copy_constraint({var(W5, row + 4, false), params.B[1]});
                        bp.add_copy_constraint({var(W6, row + 4, false), params.B[2]});
                        bp.add_copy_constraint({var(W7, row + 4, false), params.B[3]});
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_NON_NATIVE_FIELDS_EDDSA_MULTIPLICATION_COMPONENT_9_WIRES_HPP

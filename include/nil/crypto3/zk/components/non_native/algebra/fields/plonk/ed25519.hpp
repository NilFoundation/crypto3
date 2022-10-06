//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for auxiliary components for the EDDSA25519 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_EDDSA25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_EDDSA25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/variable_base_multiplication_edwards25519.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/fixed_base_multiplication_edwards25519.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/complete_addition_edwards25519.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/reduction.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/non_native_range.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/scalar_non_native_range.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/ec_point_edwards25519.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/addition.hpp>
#include <nil/crypto3/zk/components/hashes/sha256/plonk/sha512.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         typename Ed25519Type,
                         std::size_t... WireIndexes>
                class eddsa25519;

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
                class eddsa25519<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                    using check_ec_point_component =
                        ec_point<ArithmetizationType, CurveType, Ed25519Type, W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using variable_base_mult_component = variable_base_multiplication<ArithmetizationType,
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
                                                                                      W8>;
                    using fixed_base_mult_component = fixed_base_multiplication<ArithmetizationType,
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
                                                                                W8>;
                    using addition_component = complete_addition<ArithmetizationType,
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
                                                                 W8>;

                    using reduction_component =
                        reduction<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using non_native_range_component =
                        non_native_range<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using scalar_non_native_range_component = scalar_non_native_range<ArithmetizationType,
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
                                                                                      W8>;
                    using non_addition_component = non_native_field_element_addition<ArithmetizationType,
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
                                                                                     W8>;
                    using sha512_component = sha512<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    constexpr static const std::size_t selector_seed = 0xfcc2;

                public:
                    constexpr static const std::size_t rows_amount =
                        /*262144;*/ scalar_non_native_range_component::rows_amount +
                        variable_base_mult_component::rows_amount + fixed_base_mult_component::rows_amount +
                        addition_component::rows_amount + reduction_component::rows_amount +
                        2 * check_ec_point_component::rows_amount + sha512_component::rows_amount;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        struct var_ec_point {
                            std::array<var, 4> x;
                            std::array<var, 4> y;
                        };
                        struct signature {
                            var_ec_point R;
                            var s;
                        };
                        signature e;
                        var_ec_point public_key;
                        std::array<var, 4> M;
                    };

                    // TODO: check if points R and public_key lie on the curve

                    struct result_type {
                        result_type(std::size_t component_start_row) {
                        }
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        // generate_lookup_table(assignment, params, component_start_row);
                        /*std::size_t n = (1 << 18);
                        for(std::size_t i = 0; i < n; i++) {
                            assignment.constant(1)[i] = i;
                        }*/
                        var s = params.e.s;
                        auto R = params.e.R;
                        auto pk = params.public_key;
                        std::array<var, 4> M = params.M;

                        /* here we check if s lies in range */
                        scalar_non_native_range_component::generate_assignments(assignment, {s}, row);
                        row += scalar_non_native_range_component::rows_amount;
                        check_ec_point_component::generate_assignments(assignment, {{R.x, R.y}}, row);
                        row += check_ec_point_component::rows_amount;
                        check_ec_point_component::generate_assignments(assignment, {{pk.x, pk.y}}, row);
                        row += check_ec_point_component::rows_amount;

                        /* here we get k = SHA(R||A||M) */
                        auto k_vec = sha512_component::generate_assignments(
                                         assignment,
                                         {{{R.x[0], R.x[1], R.x[2], R.x[3]}, {R.y[0], R.y[1], R.y[2], R.y[3]}},
                                          {{pk.x[0], pk.x[1], pk.x[2], pk.x[3]}, {pk.y[0], pk.y[1], pk.y[2], pk.y[3]}},
                                          M},
                                         row)
                                         .output_state;
                        row += sha512_component::rows_amount;
                        var k = reduction_component::generate_assignments(assignment, {k_vec}, row).output;
                        row += reduction_component::rows_amount;
                        /* here we check sB == R + kA */

                        auto S = fixed_base_mult_component::generate_assignments(assignment, {s}, row).output;
                        row += fixed_base_mult_component::rows_amount;
                        auto A = variable_base_mult_component::generate_assignments(assignment, {{pk.x, pk.y}, k}, row)
                                     .output;
                        row += variable_base_mult_component::rows_amount;
                        typename addition_component::params_type add_params = {{A.x, A.y}, {R.x, R.y}};
                        auto res = addition_component::generate_assignments(assignment, add_params, row).output;
                        row += addition_component::rows_amount;
                        return result_type(component_start_row);
                    }

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        var s = params.e.s;
                        auto R = params.e.R;
                        auto pk = params.public_key;
                        std::array<var, 4> M = params.M;

                        /* here we check if s lies in range */
                        scalar_non_native_range_component::generate_circuit(bp, assignment, {s}, row);
                        row += scalar_non_native_range_component::rows_amount;
                        check_ec_point_component::generate_circuit(bp, assignment, {{R.x, R.y}}, row);
                        row += check_ec_point_component::rows_amount;
                        check_ec_point_component::generate_circuit(bp, assignment, {{pk.x, pk.y}}, row);
                        row += check_ec_point_component::rows_amount;

                        /* here we get k = SHA(R||A||M) */
                        auto k_vec = sha512_component::generate_circuit(
                                         bp,
                                         assignment,
                                         {{{R.x[0], R.x[1], R.x[2], R.x[3]}, {R.y[0], R.y[1], R.y[2], R.y[3]}},
                                          {{pk.x[0], pk.x[1], pk.x[2], pk.x[3]}, {pk.y[0], pk.y[1], pk.y[2], pk.y[3]}},
                                          M},
                                         row)
                                         .output_state;
                        row += sha512_component::rows_amount;
                        var k = reduction_component::generate_circuit(bp, assignment, {k_vec}, row).output;
                        row += reduction_component::rows_amount;
                        /* here we check sB == R + kA */
                        auto S = fixed_base_mult_component::generate_circuit(bp, assignment, {s}, row).output;
                        row += fixed_base_mult_component::rows_amount;
                        auto A = variable_base_mult_component::generate_circuit(bp, assignment, {{pk.x, pk.y}, k}, row)
                                     .output;
                        row += variable_base_mult_component::rows_amount;
                        typename addition_component::params_type add_params = {{A.x, A.y}, {R.x, R.y}};
                        auto res = addition_component::generate_circuit(bp, assignment, add_params, row).output;
                        row += addition_component::rows_amount;
                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                private:
                    static void
                        generate_gates(blueprint<ArithmetizationType> &bp,
                                       blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                       const params_type &params,
                                       const std::size_t first_selector_index) {
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const params_type &params,
                        std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        row += scalar_non_native_range_component::rows_amount +
                               2 * check_ec_point_component::rows_amount + reduction_component::rows_amount +
                               sha512_component::rows_amount + fixed_base_mult_component::rows_amount;
                        auto S =
                            (typename fixed_base_mult_component::result_type(row - 1 - addition_component::rows_amount))
                                .output;
                        row += variable_base_mult_component::rows_amount;
                        auto res = (typename addition_component::result_type(row)).output;
                        bp.add_copy_constraint({{S.x[0]}, {res.x[0]}});
                        bp.add_copy_constraint({{S.x[1]}, {res.x[1]}});
                        bp.add_copy_constraint({{S.x[2]}, {res.x[2]}});
                        bp.add_copy_constraint({{S.x[3]}, {res.x[3]}});
                        bp.add_copy_constraint({{S.y[0]}, {res.y[0]}});
                        bp.add_copy_constraint({{S.y[1]}, {res.y[1]}});
                        bp.add_copy_constraint({{S.y[2]}, {res.y[2]}});
                        bp.add_copy_constraint({{S.y[3]}, {res.y[3]}});
                    }

                    static void generate_lookup_table(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                      const params_type &params,
                                                      std::size_t component_start_row) {

                        std::size_t row = component_start_row;
                        std::size_t n = (1 << 16);
                        for (std::size_t i = 0; i < 2; i++) {
                            assignment.constant(1)[i] = 0;
                        }
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
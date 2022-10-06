//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the MERKLE_TREE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_PER_BIT_EDWARD25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_PER_BIT_EDWARD25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/doubling_edwards25519.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/complete_addition_edwards25519.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/bool_scalar_multiplication.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         typename Ed25519Type,
                         std::size_t... WireIndexes>
                class variable_base_multiplication_per_bit;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType, typename Ed25519Type,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8>
                class variable_base_multiplication_per_bit<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType, Ed25519Type, W0, W1, W2, W3, W4, W5, W6, W7, W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using doubling_component =
                        doubling<ArithmetizationType, CurveType, Ed25519Type, W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using complete_addition_component = complete_addition<ArithmetizationType,
                                                                          CurveType, Ed25519Type,
                                                                          W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using bool_scalar_multiplication_component = bool_scalar_multiplication<ArithmetizationType,
                                                                                            CurveType, Ed25519Type,
                                                                                            W0, W1, W2, W3, W4, W5, W6,
                                                                                            W7, W8>;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    constexpr static const std::size_t selector_seed = 0xff82;

                public:
                    constexpr static const std::size_t rows_amount = doubling_component::rows_amount +
                                                                     complete_addition_component::rows_amount +
                                                                     bool_scalar_multiplication_component::rows_amount;

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        struct var_ec_point {
                            std::array<var, 4> x;
                            std::array<var, 4> y;
                        };

                        var_ec_point T;
                        var_ec_point R;
                        var k;
                    };

                    struct result_type {
                        struct var_ec_point {
                            std::array<var, 4> x;
                            std::array<var, 4> y;
                        };
                        var_ec_point output;
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        std::array<var, 4> T_x = params.T.x;
                        std::array<var, 4> T_y = params.T.y;
                        std::array<var, 4> R_x = params.R.x;
                        std::array<var, 4> R_y = params.R.y;

                        auto bool_mul_res = bool_scalar_multiplication_component::generate_assignments(
                            assignment,
                            typename bool_scalar_multiplication_component::params_type({{T_x, T_y}, params.k}),
                            row);
                        row += bool_scalar_multiplication_component::rows_amount;

                        auto doubling_res = doubling_component::generate_assignments(
                            assignment, typename doubling_component::params_type({R_x, R_y}), row);
                        row += doubling_component::rows_amount;

                        auto add_res = complete_addition_component::generate_assignments(
                            assignment,
                            typename complete_addition_component::params_type(
                                {{doubling_res.output.x, doubling_res.output.y},
                                 {bool_mul_res.output.x, bool_mul_res.output.y}}),
                            row);
                        row += complete_addition_component::rows_amount;

                        return {add_res.output.x, add_res.output.y};
                    }

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        std::array<var, 4> T_x = params.T.x;
                        std::array<var, 4> T_y = params.T.y;
                        std::array<var, 4> R_x = params.R.x;
                        std::array<var, 4> R_y = params.R.y;

                        auto bool_mul_res = bool_scalar_multiplication_component::generate_circuit(
                            bp,
                            assignment,
                            typename bool_scalar_multiplication_component::params_type({{T_x, T_y}, params.k}),
                            row);
                        row += bool_scalar_multiplication_component::rows_amount;

                        auto doubling_res = doubling_component::generate_circuit(
                            bp, assignment, typename doubling_component::params_type({R_x, R_y}), row);
                        row += doubling_component::rows_amount;

                        auto add_res = complete_addition_component::generate_circuit(
                            bp,
                            assignment,
                            typename complete_addition_component::params_type(
                                {{doubling_res.output.x, doubling_res.output.y},
                                 {bool_mul_res.output.x, bool_mul_res.output.y}}),
                            row);
                        row += complete_addition_component::rows_amount;

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        return {add_res.output.x, add_res.output.y};
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
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
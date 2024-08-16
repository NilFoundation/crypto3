//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/crypto3/zk/chips/plonk/bit_check.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace chips {

                template<typename ArithmetizationType, typename CurveType>
                class fixed_base_scalar_mul_phi1;

                template<typename BlueprintFieldType, typename CurveType>
                class fixed_base_scalar_mul_phi1<
                    snark::plonk_constraint_system<BlueprintFieldType>, CurveType> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                public:
                    constexpr static const std::size_t selector_seed = 0xff07;
                    constexpr static const std::size_t rows_amount = 0;

                    static snark::plonk_constraint<BlueprintFieldType>
                        generate(blueprint<ArithmetizationType> &bp, const var &x_1, const var &x_2, const var &x_3,
                                 const var &x_4, std::array<typename CurveType::base_field_type::value_type, 8> u) {

                        return bp.add_constraint(
                            x_3 * (-u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2 - u[0] + u[2] * x_1 * x_2 - u[2] * x_2 +
                                   u[4] * x_1 * x_2 - u[4] * x_2 - u[6] * x_1 * x_2 + u[1] * x_2 * x_1 - u[1] * x_1 -
                                   u[1] * x_2 + u[1] - u[3] * x_1 * x_2 + u[3] * x_2 - u[5] * x_1 * x_2 + u[5] * x_2 +
                                   u[7] * x_1 * x_2) -
                            (x_4 - u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2 - u[0] + u[2] * x_1 * x_2 - u[2] * x_2 +
                             u[4] * x_1 * x_2 - u[4] * x_2 - u[6] * x_1 * x_2));
                    }
                };

                template<typename ArithmetizationType, typename CurveType>
                class fixed_base_scalar_mul_phi2;

                template<typename BlueprintFieldType, typename CurveType>
                class fixed_base_scalar_mul_phi2<
                    snark::plonk_constraint_system<BlueprintFieldType>, CurveType> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                public:
                    constexpr static const std::size_t rows_amount = 0;

                    static snark::plonk_constraint<BlueprintFieldType>
                        generate(blueprint<ArithmetizationType> &bp, const var &x_1, const var &x_2, const var &x_3,
                                 const var &x_4, std::array<typename CurveType::base_field_type::value_type, 8> v) {

                        return bp.add_constraint(
                            x_3 * (-v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2 - v[0] + v[2] * x_1 * x_2 - v[2] * x_2 +
                                   v[4] * x_1 * x_2 - v[4] * x_2 - v[6] * x_1 * x_2 + v[1] * x_2 * x_1 - v[1] * x_1 -
                                   v[1] * x_2 + v[1] - v[3] * x_1 * x_2 + v[3] * x_2 - v[5] * x_1 * x_2 + v[5] * x_2 +
                                   v[7] * x_1 * x_2) -
                            (x_4 - v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2 - v[0] + v[2] * x_1 * x_2 - v[2] * x_2 +
                             v[4] * x_1 * x_2 - v[4] * x_2 - v[6] * x_1 * x_2));
                    }
                };

            }    // namespace chips

            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class element_g1_fixed_base_scalar_mul;

                template<typename BlueprintFieldType, typename CurveType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class element_g1_fixed_base_scalar_mul<
                    snark::plonk_constraint_system<BlueprintFieldType>, CurveType, W0, W1, W2,
                    W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {
                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using phi1_chip = chips::fixed_base_scalar_mul_phi1<ArithmetizationType, CurveType>;

                    using phi2_chip = chips::fixed_base_scalar_mul_phi2<ArithmetizationType, CurveType>;

                    using bit_check_chip = chips::bit_check<ArithmetizationType>;

                public:
                    constexpr static const std::size_t rows_amount = 43;

                    struct public_params_type {
                        typename CurveType::template g1_type<>::value_type B;
                    };

                    struct input_type {
                        var X;
                        var Y;
                    };

                    struct private_params_type {
                        typename CurveType::scalar_field_type::value_type a;
                        typename CurveType::scalar_field_type::value_type s;
                        typename CurveType::template g1_type<>::value_type P;
                    };

                    struct output_type {
                        var result;
                    };

                    static std::size_t allocate_rows(blueprint<ArithmetizationType> &bp) {
                        return bp.allocate_rows(rows_amount);
                    }

                private:
                    static typename CurveType::template g1_type<>::value_type
                        get_omega(typename CurveType::template g1_type<>::value_type B, std::size_t s, std::size_t i) {

                        std::size_t coef = i * std::pow(2, 3 * s);

                        return coef * B;
                    }

                    static output_type
                        generate_gates(blueprint<ArithmetizationType> &bp,
                                       blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                       const public_params_type &init_params,
                                       std::size_t component_start_row) {

                        std::size_t j = component_start_row;

                        auto bit_check_0 = bit_check_chip::generate(bp, var(W0, 0));
                        auto bit_check_1 = bit_check_chip::generate(bp, var(W1, 0));
                        auto bit_check_2 = bit_check_chip::generate(bp, var(W2, 0));
                        auto bit_check_3 = bit_check_chip::generate(bp, var(W3, 0));
                        auto bit_check_4 = bit_check_chip::generate(bp, var(W4, 0));
                        auto bit_check_5 = bit_check_chip::generate(bp, var(W5, 0));

                        std::array<typename CurveType::base_field_type::value_type, 8> u;
                        std::array<typename CurveType::base_field_type::value_type, 8> v;

                        // For j + 0:
                        {
                            std::size_t selector_index_j_0 = public_assignment.add_selector(j);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega =
                                    get_omega(init_params.B, 0, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            auto constraint_1 =
                                phi1_chip::generate(bp, var(W0, 0), var(W1, 0), var(W2, 0), var(W6, 0), u);
                            auto constraint_2 =
                                phi2_chip::generate(bp, var(W0, 0), var(W1, 0), var(W2, 0), var(W8, 0), v);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega =
                                    get_omega(init_params.B, 1, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }
                            auto constraint_3 =
                                phi1_chip::generate(bp, var(W3, 0), var(W4, 0), var(W5, 0), var(W7, 0), u);
                            auto constraint_4 =
                                phi2_chip::generate(bp, var(W3, 0), var(W4, 0), var(W5, 0), var(W9, 0), v);

                            auto acc_constraint =
                                bp.add_constraint(var(W14, 0) - (var(W0, 0) + var(W1, 0) * 2 + var(W2, 0) * 4 +
                                                                 var(W3, 0) * 8 + var(W4, 0) * 16 + var(W5, 0) * 32));

                            auto constraint_6 = bp.add_constraint(var(W10, 0) - var(W6, 0));
                            auto constraint_7 = bp.add_constraint(var(W11, 0) - var(W8, 0));

                            // auto incomplete_addition_constraint_1;
                            // auto incomplete_addition_constraint_2;
                            // TODO: add constraints for incomplete addition

                            bp.add_gate(selector_index_j_0,
                                        {bit_check_0, bit_check_1, bit_check_2, bit_check_3, bit_check_4, bit_check_5,
                                         constraint_1, constraint_2, constraint_3, constraint_4, acc_constraint,
                                         constraint_6, constraint_7});
                        }

                        // For j + z, z = 1..41:
                        for (std::size_t z = 1; z <= 41; z++) {

                            std::size_t selector_index_j_z = public_assignment.add_selector(j + z);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega =
                                    get_omega(init_params.B, z * 2, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            auto constraint_1 =
                                phi1_chip::generate(bp, var(W0, 0), var(W1, 0), var(W2, 0), var(W6, 0), u);
                            auto constraint_2 =
                                phi2_chip::generate(bp, var(W0, 0), var(W1, 0), var(W2, 0), var(W8, 0), v);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega =
                                    get_omega(init_params.B, z * 2 + 1, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }
                            auto constraint_3 =
                                phi1_chip::generate(bp, var(W3, 0), var(W4, 0), var(W5, 0), var(W7, 0), u);
                            auto constraint_4 =
                                phi2_chip::generate(bp, var(W3, 0), var(W4, 0), var(W5, 0), var(W9, 0), v);

                            auto acc_constraint = bp.add_constraint(
                                var(W14, 0) - (var(W0, 0) + var(W1, 0) * 2 + var(W2, 0) * 4 + var(W3, 0) * 8 +
                                               var(W4, 0) * 16 + var(W5, 0) * 32 + var(W14, -1) * 64));

                            // auto incomplete_addition_constraint_1;
                            // auto incomplete_addition_constraint_2;
                            // TODO: add constraints for incomplete addition

                            bp.add_gate(selector_index_j_z,
                                        {
                                            bit_check_0, bit_check_1, bit_check_2, bit_check_3, bit_check_4,
                                            bit_check_5, constraint_1, constraint_2, constraint_3, constraint_4,
                                            acc_constraint,
                                            // incomplete_addition_constraint_1,
                                            // incomplete_addition_constraint_2
                                        });
                        }

                        // For j + 42:
                        {

                            std::size_t selector_index_j_42 = public_assignment.add_selector(j + 42);

                            for (std::size_t i = 0; i <= 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega =
                                    get_omega(init_params.B, 84, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            auto constraint_1 =
                                phi1_chip::generate(bp, var(W0, 0), var(W1, 0), var(W2, 0), var(W6, 0), u);
                            auto constraint_2 =
                                phi2_chip::generate(bp, var(W0, 0), var(W1, 0), var(W2, 0), var(W8, 0), v);

                            auto acc_constraint = bp.add_constraint(
                                var(W14, 0) - (var(W0, 0) + var(W1, 0) * 2 + var(W2, 0) * 4 + var(W14, -1) * 8));

                            // auto complete_addition_constraint_1;
                            // auto complete_addition_constraint_2;
                            // TODO: add constraints for complete addition

                            bp.add_gate(
                                selector_index_j_42,
                                {
                                    bit_check_0, bit_check_1, bit_check_2, constraint_1, constraint_2, acc_constraint,
                                    // complete_addition_constraint_1,
                                    // complete_addition_constraint_2
                                });
                        }
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const input_type &input,
                        std::size_t component_start_row) {

                        const std::size_t j = component_start_row;

                        bp.add_copy_constraint({input.X, var(W10, j, false)});

                        bp.add_copy_constraint({input.Y, var(W11, j, false)});
                    }

                public:
                    static output_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                         const public_params_type &init_params,
                                         const input_type &input,
                                         std::size_t component_start_row) {

                        generate_copy_constraints(bp, public_assignment, init_params, input, component_start_row);

                        return generate_gates(bp, public_assignment, init_params, component_start_row);
                    }

                    static void generate_assignments(
                        blueprint_private_assignment_table<ArithmetizationType> &private_assignment,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const public_params_type &init_params,
                        const private_params_type &params,
                        std::size_t component_start_row) {
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

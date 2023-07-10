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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_9_WIRES_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_9_WIRES_HPP

#include <nil/crypto3/math/detail/field_utils.hpp>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class element_g1_fixed_base_scalar_mul;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8>
                class element_g1_fixed_base_scalar_mul<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType, W0, W1, W2,
                    W3, W4, W5, W6, W7, W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                public:
                    constexpr static const std::size_t rows_amount = 85;

                    struct init_params_type {
                        typename CurveType::template g1_type<>::value_type B;
                    };

                    struct assignment_params_type {
                        typename CurveType::scalar_field_type::value_type a;
                        typename CurveType::scalar_field_type::value_type s;
                        typename CurveType::template g1_type<>::value_type P;
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

                    static snark::plonk_constraint<BlueprintFieldType>
                        generate_phi1_constraint(blueprint<ArithmetizationType> &bp, var x_1, var x_2, var x_3, var x_4,
                                                 std::array<typename CurveType::base_field_type::value_type, 8> u) {

                        return bp.add_constraint(
                            x_3 * (-u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2 - u[0] + u[2] * x_1 * x_2 - u[2] * x_2 +
                                   u[4] * x_1 * x_2 - u[4] * x_2 - u[6] * x_1 * x_2 + u[1] * x_2 * x_1 - u[1] * x_1 -
                                   u[1] * x_2 + u[1] - u[3] * x_1 * x_2 + u[3] * x_2 - u[5] * x_1 * x_2 + u[5] * x_2 +
                                   u[7] * x_1 * x_2) -
                            (x_4 - u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2 - u[0] + u[2] * x_1 * x_2 - u[2] * x_2 +
                             u[4] * x_1 * x_2 - u[4] * x_2 - u[6] * x_1 * x_2));
                    }

                    static snark::plonk_constraint<BlueprintFieldType>
                        generate_phi2_constraint(blueprint<ArithmetizationType> &bp, var x_1, var x_2, var x_3, var x_4,
                                                 std::array<typename CurveType::base_field_type::value_type, 8> v) {

                        return bp.add_constraint(
                            x_3 * (-v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2 - v[0] + v[2] * x_1 * x_2 - v[2] * x_2 +
                                   v[4] * x_1 * x_2 - v[4] * x_2 - v[6] * x_1 * x_2 + v[1] * x_2 * x_1 - v[1] * x_1 -
                                   v[1] * x_2 + v[1] - v[3] * x_1 * x_2 + v[3] * x_2 - v[5] * x_1 * x_2 + v[5] * x_2 +
                                   v[7] * x_1 * x_2) -
                            (x_4 - v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2 - v[0] + v[2] * x_1 * x_2 - v[2] * x_2 +
                             v[4] * x_1 * x_2 - v[4] * x_2 - v[6] * x_1 * x_2));
                    }

                    static snark::plonk_constraint<BlueprintFieldType>
                        generate_phi3_gate(blueprint<ArithmetizationType> &bp, var x_1, var x_2, var x_3, var x_4,
                                           var x_5, var x_6) {
                        return bp.add_constraint(
                            x_1 * (1 + CurveType::template g1_type<>::params_type::b * x_3 * x_4 * x_5 * x_6) -
                            (x_3 * x_6 + x_4 * x_5));
                    }

                    static snark::plonk_constraint<BlueprintFieldType>
                        generate_phi4_gate(blueprint<ArithmetizationType> &bp, var x_1, var x_2, var x_3, var x_4,
                                           var x_5, var x_6) {
                        return bp.add_constraint(
                            x_2 * (1 - CurveType::template g1_type<>::params_type::b * x_3 * x_4 * x_5 * x_6) -
                            (x_3 * x_5 + x_4 * x_6));
                    }

                public:
                    static void
                        generate_gates(blueprint<ArithmetizationType> &bp,
                                       blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                       const init_params_type &init_params,
                                       std::size_t component_start_row) {

                        std::size_t j = component_start_row;

                        bp.add_bit_check({j, j + 2}, var(W1, 0));
                        bp.add_bit_check({j, j + 2}, var(W2, 0));
                        bp.add_bit_check({j, j + 1, j + 3}, var(W3, 0));
                        bp.add_bit_check({j + 2, j + 3}, var(W4, 0));

                        // j=0
                        bp.add_gate(j, var(W0, 0) - (var(W1, 0) * 4 + var(W2, 0) * 2 + var(W3, 0)));

                        generate_phi3_constraint(bp, j, var(W1, +1), var(W2, +1), var(W4, 0), var(W0, +1), var(W4, +1),
                                                 var(W3, +2));
                        generate_phi4_constraint(bp, j, var(W1, +1), var(W2, +1), var(W4, 0), var(W0, +1), var(W4, +1),
                                                 var(W3, +2));

                        // j+z, z=0 mod 5, z!=0
                        for (std::size_t z = 5; z <= 84; z += 5) {

                            std::size_t selector_index = public_assignment.add_selector(j + z);

                            bp.add_gate(selector_index,
                                        var(W0, 0) - (var(W1, 0) * 4 + var(W2, 0) * 2 + var(W3, 0) + var(W0, -1) * 8));

                            std::array<typename CurveType::base_field_type::value_type, 8> u;
                            std::array<typename CurveType::base_field_type::value_type, 8> v;

                            for (std::size_t i = 0; i < 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega = get_omega(3 * z / 5, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            generate_phi1_constraint(bp, selector_index, var(W1, 0), var(W2, 0), var(W3, 0), var(W4, 0),
                                                     u);
                            generate_phi2_constraint(bp, selector_index, var(W1, 0), var(W2, 0), var(W3, 0),
                                                     var(W4, +1), v);
                            generate_phi3_constraint(bp, selector_index, var(W1, +1), var(W2, +1), var(W1, -1),
                                                     var(W2, -1), var(W4, +1), var(W3, +2));
                            generate_phi4_constraint(bp, selector_index, var(W1, +1), var(W2, +1), var(W1, -1),
                                                     var(W2, -1), var(W4, +1), var(W3, +2));
                        }

                        // j+z, z=2 mod 5
                        for (std::size_t z = 2; z <= 84; z += 5) {

                            std::size_t selector_index = public_assignment.add_selector(j + z);

                            bp.add_gate(selector_index,
                                        var(W0, 0) - (var(W1, 0) * 4 + var(W2, 0) * 2 + var(W3, -1) + var(W0, -2) * 8));

                            std::array<typename CurveType::base_field_type::value_type, 8> u;
                            std::array<typename CurveType::base_field_type::value_type, 8> v;
                            for (std::size_t i = 0; i < 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega =
                                    get_omega(3 * (z - 2) / 5, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            generate_phi1_constraint(bp, selector_index, var(W1, 0), var(W2, 0), var(W3, -1),
                                                     var(W4, -1), u);
                            generate_phi2_constraint(bp, selector_index, var(W1, 0), var(W2, 0), var(W3, -1),
                                                     var(W4, 0), v);
                            generate_phi3_constraint(bp, selector_index, var(W1, +1), var(W2, +1), var(W1, -1),
                                                     var(W2, -1), var(W0, +1), var(W3, +2));
                            generate_phi4_constraint(bp, selector_index, var(W1, +1), var(W2, +1), var(W1, -1),
                                                     var(W2, -1), var(W0, +1), var(W3, +2));
                        }

                        // j+z, z=3 mod 5
                        for (std::size_t z = 3; z <= 84; z += 5) {

                            std::array<typename CurveType::base_field_type::value_type, 8> u;
                            std::array<typename CurveType::base_field_type::value_type, 8> v;
                            for (std::size_t i = 0; i < 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega =
                                    get_omega(3 * (z - 3) / 5, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            std::size_t selector_index = public_assignment.add_selector(j + z);
                            generate_phi1_constraint(bp, selector_index, var(W4, -1), var(W3, 0), var(W4, 0),
                                                     var(W0, 0), u);
                            generate_phi2_constraint(bp, selector_index, var(W4, -1), var(W3, 0), var(W4, 0),
                                                     var(W0, +1), v);
                        }

                        // j+z, z=4 mod 5
                        for (std::size_t z = 4; z <= 84; z += 5) {

                            bp.add_gate(public_assignment.add_selector(j + z - 1),
                                        var(W0, +1) -
                                            (var(W4, -1) * 4 + var(W3, -2) * 2 + var(W4, -2) + var(W0, -1) * 8));

                            std::size_t selector_index = public_assignment.add_selector(j + z);
                            generate_phi3_constraint(bp, selector_index, var(W1, -2), var(W2, 0), var(W1, -1),
                                                     var(W2, -1), var(W4, +1), var(W0, +2));
                            generate_phi4_constraint(bp, selector_index, var(W1, -2), var(W2, 0), var(W1, -1),
                                                     var(W2, -1), var(W4, +1), var(W0, +2));
                        }
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        std::size_t component_start_row) {
                    }

                    static void generate_assignments(
                        blueprint_private_assignment_table<ArithmetizationType> &private_assignment,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const assignment_params_type &params,
                        std::size_t component_start_row) {

                        std::array<bool, CurveType::scalar_field_type::modulus_bits> b =
                            nil::marshalling::pack<nil::marshalling::option::big_endian>(params.s);

                        private_assignment.witness(W1)[j] = b[0];
                        private_assignment.witness(W2)[j] = b[1];
                        private_assignment.witness(W3)[j] = b[2];

                        private_assignment.witness(W1)[j + 1] = params.P.X;
                        private_assignment.witness(W2)[j + 1] = params.P.Y;
                        private_assignment.witness(W3)[j + 1] = b[3];

                        private_assignment.witness(W1)[j + 2] = b[4];
                        private_assignment.witness(W2)[j + 2] = b[5];
                        private_assignment.witness(W4)[j + 2] = b[6];

                        private_assignment.witness(W3)[j + 3] = b[7];
                        private_assignment.witness(W4)[j + 3] = b[8];
                    }
                };

            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_9_WIRES_HPP

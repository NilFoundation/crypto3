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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_9_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_9_WIRES_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class element_g1_variable_base_scalar_mul;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8>
                class element_g1_variable_base_scalar_mul<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    CurveType,
                    W0, W1, W2, W3, W4,
                    W5, W6, W7, W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType> arithmetization_type;
                    
                    constexpr static const std::size_t selector_seed = 0xff05;

                    template<typename ComponentType, typename ArithmetizationType>
                    friend void generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const typename ComponentType::params_type params,
                        const std::size_t start_row_index);
                public:
                    
                    constexpr static const std::size_t rows_amount = 213;

                    struct init_params_type {
                    };

                    struct assignment_params_type {
                        typename CurveType::template g1_type<>::value_type P;
                        typename CurveType::scalar_field_type::value_type b;
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(rows_amount);
                    }

                private:
                    static snark::plonk_constraint<BlueprintFieldType>
                        generate_phi1_constraint(blueprint<ArithmetizationType> &bp,
                                            var b, var x_1, var y_1,
                                            var x_2, var y_2, var x_3) {

                        return bp.add_constraint(row_index,
                                          x_3 * ((y_1 ^ 2 - x_1 ^ 2) * (2 - y_1 ^ 2 + x_1 ^ 2) +
                                                 2 * CurveType::d * x_1 * y_1 * (y_1 ^ 2 + x_1 ^ 2) * x_2 * y_2 * b) -
                                              (2 * x_1 * y_1 * (2 - y_1 ^ 2 + x_1 ^ 2) * (y_2 * b + (1 - b)) +
                                               (y_1 ^ 2 + x_1 ^ 2) * (y_1 ^ 2 - x_1 ^ 2) * x_2 * b));
                    }

                    static snark::plonk_constraint<BlueprintFieldType>
                        generate_phi2_constraint(blueprint<ArithmetizationType> &bp,
                                            var b, var x_1, var y_1,
                                            var x_2, var y_2, var y_3) {

                        return bp.add_constraint(row_index,
                                          y_3 * ((y_1 ^ 2 - x_1 ^ 2) * (2 - y_1 ^ 2 + x_1 ^ 2) -
                                                 2 * CurveType::d * x_1 * y_1 * (y_1 ^ 2 + x_1 ^ 2) * x_2 * y_2 * b) -
                                              (2 * x_1 * y_1 * (2 - y_1 ^ 2 + x_1 ^ 2) * x_2 * b +
                                               (y_1 ^ 2 + x_1 ^ 2) * (y_1 ^ 2 - x_1 ^ 2) * (y_2 * b + (1 - b))));
                    }

                public:
                    
                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const std::size_t &component_start_row) {

                        const std::size_t &j = component_start_row;

                        bp.add_bit_check(j, w[1][cur]);
                        bp.add_bit_check(j + 211, w[4][cur]);
                        bp.add_bit_check(j + 211, w[3][cur]);

                        // j=0
                        bp.add_gate(j, w[0][cur] - (w[1][cur] * 2 + w[4][cur]));
                        generate_phi1_constraint(j + 1, w[1][m1], w[1][p1], w[2][p1], w[1][p1], w[2][p1], w[2][m1]);
                        generate_phi2_constraint(j + 1, w[1][m1], w[1][p1], w[2][p1], w[1][p1], w[2][p1], w[3][m1]);

                        // j+z, z=0 mod 5, z!=0
                        for (std::size_t z = 5; z <= 84; z += 5) {

                            bp.add_gate(j + z, w[0][cur] - (w[1][cur] * 2 + w[4][cur] + w[0][m1]));

                            generate_phi1_constraint(j + z, w[4][cur], w[2][m1], w[3][m1], w[1][p2], w[2][p2], w[2][cur]);
                            generate_phi2_constraint(j + z, w[4][cur], w[2][m1], w[3][m1], w[1][p2], w[2][p2], w[3][cur]);
                        }

                        // j+z, z=1 mod 5
                        for (std::size_t z = 1; z <= 84; z += 5) {

                            bp.add_gate(j + z, w[0][cur] - (w[0][m1] + w[4][cur]));

                            generate_phi1_constraint(j + z, w[4][m1], w[2][m1], w[3][m1], w[1][p1], w[2][p1], w[1][cur]);
                            generate_phi2_constraint(j + z, w[4][m1], w[2][m1], w[3][m1], w[1][p1], w[2][p1], w[2][cur]);
                            generate_phi1_constraint(j + z, w[4][cur], w[1][cur], w[2][cur], w[1][p1], w[2][p1], w[3][cur]);
                        }

                        // j+z, z=2 mod 5
                        for (std::size_t z = 2; z <= 84; z += 5) {

                            bp.add_gate(j + z, w[0][cur] - (w[0][m1] + w[4][cur]));

                            generate_phi2_constraint(j + z, w[4][m1], w[1][m1], w[2][m1], w[1][cur], w[2][cur], w[3][cur]);
                        }

                        // j+z, z=3 mod 5
                        for (std::size_t z = 2; z <= 84; z += 5) {

                            bp.add_gate(j + z, w[0][cur] - (w[0][m1] + w[4][cur]));

                            generate_phi1_constraint(j + z, w[4][m1], w[3][m2], w[3][m1], w[1][m1], w[2][m1], w[1][cur]);
                            generate_phi2_constraint(j + z, w[4][m1], w[3][m2], w[3][m1], w[1][m1], w[2][m1], w[2][cur]);
                            generate_phi1_constraint(j + z, w[4][cur], w[1][cur], w[2][cur], w[1][m1], w[2][m1], w[3][cur]);
                        }

                        // j+z, z=4 mod 5
                        for (std::size_t z = 4; z <= 84; z += 5) {

                            bp.add_gate(j + z, w[0][cur] - (w[0][m1] + w[4][cur]));

                            generate_phi1_constraint(j + z, w[4][m1], w[1][m1], w[2][m1], w[1][m2], w[2][m2], w[1][cur]);
                            generate_phi2_constraint(j + z, w[4][cur], w[3][m1], w[1][cur], w[1][m2], w[2][m2], w[2][cur]);
                            generate_phi1_constraint(j + z, w[4][cur], w[3][m1], w[1][cur], w[1][m2], w[2][m2], w[3][cur]);
                        }
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const std::size_t &component_start_row) {

                    }

                    static void generate_assignments(
                        blueprint_private_assignment_table<ArithmetizationType>
                            &private_assignment,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const assignment_params_type &params,
                        const std::size_t &component_start_row) {
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_9_WIRES_HPP

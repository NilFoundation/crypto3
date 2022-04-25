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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_5_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_5_WIRES_HPP

#include <nil/crypto3/algebra/matrix/matrix.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class poseidon;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4>
                class poseidon<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    CurveType,
                    W0, W1, W2, W3, W4> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    constexpr static const algebra::matrix<typename CurveType::scalar_field_type::value_type, 3, 3> M;
                    constexpr static const algebra::vector<typename CurveType::scalar_field_type::value_type, 3> RC;

                public:
                    constexpr static const std::size_t rows_amount = ;

                    struct init_params_type {
                        typename CurveType::template g1_type<>::value_type B;
                    };

                    struct assignment_params_type {
                        typename CurveType::scalar_field_type::value_type a;
                        typename CurveType::scalar_field_type::value_type s;
                        typename CurveType::template g1_type<>::value_type P;
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(rows_amount);
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const init_params_type &init_params,
                        const std::size_t &component_start_row) {

                        const std::size_t &j = component_start_row;

                        for (std::size_t z = 0; z < 4; z++) {
                            this->bp.add_gate(j + z,
                                              w[4][cur] - (w[1][cur] ^ 5 * M[0][0] + w[2][cur] ^
                                                           5 * M[0][1] + w[3][cur] ^ 5 * M[0][2] + RC[0]));
                            this->bp.add_gate(j + z,
                                              w[0][cur] - (w[1][cur] ^ 5 * M[1][0] + w[2][cur] ^
                                                           5 * M[1][1] + w[3][cur] ^ 5 * M[1][2] + RC[1]));
                            this->bp.add_gate(j + z,
                                              w[1][p1] - (w[1][cur] ^ 5 * M[2][0] + w[2][cur] ^
                                                          5 * M[2][1] + w[3][cur] ^ 5 * M[2][2] + RC[2]));
                        }

                        for (std::size_t z = 4; z < 57; z++) {
                            this->bp.add_gate(j + 3,
                                              w[1][p1] - (w[3][cur] * M[0][0] + w[4][cur] * M[0][1] + w[0][cur] ^
                                                          5 * M[0][2] + RC[0]));
                            this->bp.add_gate(j + 3,
                                              w[2][p1] - (w[3][cur] * M[1][0] + w[4][cur] * M[1][1] + w[0][cur] ^
                                                          5 * M[1][2] + RC[1]));
                            this->bp.add_gate(j + 3,
                                              w[3][p1] - (w[3][cur] * M[2][0] + w[4][cur] * M[2][1] + w[0][cur] ^
                                                          5 * M[2][2] + RC[2]));
                        }

                        this->bp.add_gate(j + 36,
                                          w[2][p1] - (w[4][cur] ^ 5 * M[0][0] + w[0][cur] ^ 5 * M[0][1] + w[1][p1] ^
                                                      5 * M[0][2] + RC[0]));
                        this->bp.add_gate(j + 36,
                                          w[3][p1] - (w[4][cur] ^ 5 * M[1][0] + w[0][cur] ^ 5 * M[1][1] + w[1][p1] ^
                                                      5 * M[1][2] + RC[1]));
                        this->bp.add_gate(j + 36,
                                          w[4][p1] - (w[4][cur] ^ 5 * M[2][0] + w[0][cur] ^ 5 * M[2][1] + w[1][p1] ^
                                                      5 * M[2][2] + RC[2]));
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

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_5_WIRES_HPP

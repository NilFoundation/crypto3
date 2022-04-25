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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_9_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_9_WIRES_HPP

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
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8>
                class poseidon<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    CurveType,
                    W0, W1, W2, W3, W4,
                    W5, W6, W7, W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    const algebra::matrix<
                        typename CurveType::scalar_field_type::value_type, 3, 3> M;
                    const algebra::vector<
                        typename CurveType::scalar_field_type::value_type, 3> RC;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                public:

                    constexpr static const std::size_t rows_amount = 22;

                    struct init_params_type { };

                    struct assignment_params_type {
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

                        // For $j + 0$:
                        std::size_t selector_index_j_0 = public_assignment.add_selector(j + 0);

                        auto constraint_j_0_0 = bp.add_constraint(var(W4, 0) -
                            (var(W1, 0) ^ 5 * M[0][0] + var(W2, 0) ^ 5 * M[0][1] + var(W3, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        auto constraint_j_0_1 = bp.add_constraint(var(W5, 0) -
                            (var(W1, 0) ^ 5 * M[1][0] + var(W2, 0) ^ 5 * M[1][1] + var(W3, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        auto constraint_j_0_2 = bp.add_constraint(var(W6, 0) -
                            (var(W1, 0) ^ 5 * M[2][0] + var(W2, 0) ^ 5 * M[2][1] + var(W3, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        auto constraint_j_0_3 = bp.add_constraint(var(W7, 0) -
                            (var(W3, 0) ^ 5 * M[0][0] + var(W4, 0) ^ 5 * M[0][1] + var(W5, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        auto constraint_j_0_4 = bp.add_constraint(var(W8, 0) -
                            (var(W3, 0) ^ 5 * M[1][0] + var(W4, 0) ^ 5 * M[1][1] + var(W5, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        auto constraint_j_0_5 = bp.add_constraint(var(W9, 0) -
                            (var(W3, 0) ^ 5 * M[2][0] + var(W4, 0) ^ 5 * M[2][1] + var(W5, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        bp.add_gate(selector_index_j_0,
                                              {constraint_j_0_0, constraint_j_0_1, constraint_j_0_2,
                                               constraint_j_0_3, constraint_j_0_4, constraint_j_0_5});

                        // For $j + 1$:
                        std::size_t selector_index_j_1 = public_assignment.add_selector(j + 1);

                        auto constraint_j_1_0 = bp.add_constraint(var(W1, 0) -
                            (var(W3, 0) ^ 5 * M[0][0] + var(W8, 0) ^ 5 * M[0][1] + var(W9, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        auto constraint_j_1_1 = bp.add_constraint(var(W2, 0) -
                            (var(W3, 0) ^ 5 * M[1][0] + var(W8, 0) ^ 5 * M[1][1] + var(W9, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        auto constraint_j_1_2 = bp.add_constraint(var(W3, 0) -
                            (var(W3, 0) ^ 5 * M[2][0] + var(W8, 0) ^ 5 * M[2][1] + var(W9, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        auto constraint_j_1_3 = bp.add_constraint(var(W4, 0) -
                            (var(W1, 0) ^ 5 * M[0][0] + var(W2, 0) ^ 5 * M[0][1] + var(W3, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        auto constraint_j_1_4 = bp.add_constraint(var(W5, 0) -
                            (var(W1, 0) ^ 5 * M[1][0] + var(W2, 0) ^ 5 * M[1][1] + var(W3, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        auto constraint_j_1_5 = bp.add_constraint(var(W6, 0) -
                            (var(W1, 0) ^ 5 * M[2][0] + var(W2, 0) ^ 5 * M[2][1] + var(W3, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        auto constraint_j_1_6 = bp.add_constraint(var(W7, 0) -
                            (var(W4, 0) * M[0][0] + var(W5, 0) * M[0][1] + var(W6, 0) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_1_7 = bp.add_constraint(var(W8, 0) -
                            (var(W4, 0) * M[1][0] + var(W5, 0) * M[1][1] + var(W6, 0) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_1_8 = bp.add_constraint(var(W9, 0) -
                            (var(W4, 0) * M[2][0] + var(W5, 0) * M[2][1] + var(W6, 0) ^ 5 * M[2][2] + RC[2]));

                        bp.add_gate(selector_index_j_1,
                                              {constraint_j_1_0, constraint_j_1_1, constraint_j_1_2,
                                               constraint_j_1_3, constraint_j_1_4, constraint_j_1_5,
                                               constraint_j_1_6, constraint_j_1_7, constraint_j_1_8});

                        // For $j + k$, $k \in \{2, 19\}$:
                        std::size_t selector_index_j_2 = public_assignment.add_selector(j + 2, j + 19);
                        
                        auto constraint_j_2_0 = bp.add_constraint(var(W1, 0) -
                                            (var(W7, -1) * M[0][0] + var(W8, -1) * M[0][1] +
                                                var(W9, -1) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_2_1 = bp.add_constraint(var(W2, 0) -
                                            (var(W7, -1) * M[1][0] + var(W8, -1) * M[1][1] +
                                                var(W9, -1) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_2_2 = bp.add_constraint(var(W3, 0) -
                                            (var(W7, -1) * M[2][0] + var(W8, -1) * M[2][1] +
                                                var(W9, -1) ^ 5 * M[2][2] + RC[2]));

                        auto constraint_j_2_3 = bp.add_constraint(var(W4, 0) -
                                            (var(W1, 0) * M[0][0] + var(W2, 0) * M[0][1] +
                                                var(W3, 0) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_2_4 = bp.add_constraint(var(W5, 0) -
                                            (var(W1, 0) * M[1][0] + var(W2, 0) * M[1][1] +
                                                var(W3, 0) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_2_5 = bp.add_constraint(var(W6, 0) -
                                            (var(W1, 0) * M[2][0] + var(W2, 0) * M[2][1] +
                                                var(W3, 0) ^ 5 * M[2][2] + RC[2]));

                        auto constraint_j_2_6 = bp.add_constraint(var(W7, 0) -
                                            (var(W4, 0) * M[0][0] + var(W5, 0) * M[0][1] +
                                                var(W6, 0) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_2_7 = bp.add_constraint(var(W8, 0) -
                                            (var(W4, 0) * M[1][0] + var(W5, 0) * M[1][1] +
                                                var(W6, 0) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_2_8 = bp.add_constraint(var(W9, 0) -
                                            (var(W4, 0) * M[2][0] + var(W5, 0) * M[2][1] +
                                                var(W6, 0) ^ 5 * M[2][2] + RC[2]));

                        bp.add_gate(selector_index_j_2,
                                              {constraint_j_2_0, constraint_j_2_1, constraint_j_2_2,
                                               constraint_j_2_3, constraint_j_2_4, constraint_j_2_5,
                                               constraint_j_2_6, constraint_j_2_7, constraint_j_2_8});

                        // For $j + 20$:
                        std::size_t selector_index_j_20 = public_assignment.add_selector(j + 20);

                        auto constraint_j_20_0 = bp.add_constraint(var(W1, 0) -
                                        (var(W7, -1) * M[0][0] + var(W8, -1) * M[0][1] +
                                            var(W9, -1) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_20_1 = bp.add_constraint(var(W2, 0) -
                                        (var(W7, -1) * M[1][0] + var(W8, -1) * M[1][1] +
                                            var(W9, -1) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_20_2 = bp.add_constraint(var(W3, 0) -
                                        (var(W7, -1) * M[2][0] + var(W8, -1) * M[2][1] +
                                            var(W9, -1) ^ 5 * M[2][2] + RC[2]));

                        auto constraint_j_20_3 = bp.add_constraint(var(W4, 0) -
                                        (var(W1, 0) * M[0][0] + var(W2, 0) * M[0][1] +
                                            var(W3, 0) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_20_4 = bp.add_constraint(var(W5, 0) -
                                        (var(W1, 0) * M[1][0] + var(W2, 0) * M[1][1] +
                                            var(W3, 0) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_20_5 = bp.add_constraint(var(W6, 0) -
                                        (var(W1, 0) * M[2][0] + var(W2, 0) * M[2][1] +
                                            var(W3, 0) ^ 5 * M[2][2] + RC[2]));

                        auto constraint_j_20_6 = bp.add_constraint(var(W7, 0) -
                                        (var(W3, 0) ^ 5 * M[0][0] +
                                         var(W4, 0) ^ 5 * M[0][1] +
                                         var(W5, 0) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_20_7 = bp.add_constraint(var(W8, 0) -
                                        (var(W3, 0) ^ 5 * M[1][0] +
                                         var(W4, 0) ^ 5 * M[1][1] +
                                         var(W5, 0) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_20_8 = bp.add_constraint(var(W9, 0) -
                                        (var(W3, 0) ^ 5 * M[2][0] +
                                         var(W4, 0) ^ 5 * M[2][1] +
                                         var(W5, 0) ^ 5 * M[2][2] + RC[2]));

                        bp.add_gate(selector_index_j_20,
                                              {constraint_j_20_0, constraint_j_20_1, constraint_j_20_2,
                                               constraint_j_20_3, constraint_j_20_4, constraint_j_20_5,
                                               constraint_j_20_6, constraint_j_20_7, constraint_j_20_8});

                        // For $j + 21$:
                        std::size_t selector_index_j_21 = public_assignment.add_selector(j + 21);

                        auto constraint_j_21_0 = bp.add_constraint(var(W1, 0) -
                                        (var(W3, -1) ^ 5 * M[0][0] +
                                         var(W8, -1) ^ 5 * M[0][1] +
                                         var(W9, -1) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_21_1 = bp.add_constraint(var(W2, 0) -
                                        (var(W3, -1) ^ 5 * M[1][0] +
                                         var(W8, -1) ^ 5 * M[1][1] +
                                         var(W9, -1) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_21_2 = bp.add_constraint(var(W3, 0) -
                                        (var(W3, -1) ^ 5 * M[2][0] +
                                         var(W8, -1) ^ 5 * M[2][1] +
                                         var(W9, -1) ^ 5 * M[2][2] + RC[2]));

                        auto constraint_j_21_3 = bp.add_constraint(var(W4, 0) -
                                        (var(W1, 0) ^ 5 * M[0][0] +
                                         var(W2, 0) ^ 5 * M[0][1] +
                                         var(W3, 0) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_21_4 = bp.add_constraint(var(W5, 0) -
                                        (var(W1, 0) ^ 5 * M[1][0] +
                                         var(W2, 0) ^ 5 * M[1][1] +
                                         var(W3, 0) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_21_5 = bp.add_constraint(var(W6, 0) -
                                        (var(W1, 0) ^ 5 * M[2][0] +
                                         var(W2, 0) ^ 5 * M[2][1] +
                                         var(W3, 0) ^ 5 * M[2][2] + RC[2]));

                        auto constraint_j_21_6 = bp.add_constraint(var(W7, 0) -
                                        (var(W3, 0) ^ 5 * M[0][0] +
                                         var(W4, 0) ^ 5 * M[0][1] +
                                         var(W5, 0) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_21_7 = bp.add_constraint(var(W8, 0) -
                                        (var(W3, 0) ^ 5 * M[1][0] +
                                         var(W4, 0) ^ 5 * M[1][1] +
                                         var(W5, 0) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_21_8 = bp.add_constraint(var(W9, 0) -
                                        (var(W3, 0) ^ 5 * M[2][0] +
                                         var(W4, 0) ^ 5 * M[2][1] +
                                         var(W5, 0) ^ 5 * M[2][2] + RC[2]));

                        bp.add_gate(selector_index_j_21,
                                              {constraint_j_21_0, constraint_j_21_1, constraint_j_21_2,
                                               constraint_j_21_3, constraint_j_21_4, constraint_j_21_5,
                                               constraint_j_21_6, constraint_j_21_7, constraint_j_21_8});
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

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
                         std::size_t W0 = 0,
                         std::size_t W1 = 1,
                         std::size_t W2 = 2,
                         std::size_t W3 = 3,
                         std::size_t W4 = 4,
                         std::size_t W5 = 5,
                         std::size_t W6 = 6,
                         std::size_t W7 = 7,
                         std::size_t W8 = 8>
                class poseidon;

                template<typename BlueprintFieldType,
                         typename CurveType,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9>
                class poseidon<snark::plonk_constraint_system<BlueprintFieldType>,
                                     CurveType,
                                     W0,
                                     W1,
                                     W2,
                                     W3,
                                     W4,
                                     W5,
                                     W6,
                                     W7,
                                     W8>
                    : public component<snark::plonk_constraint_system<BlueprintFieldType>> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;
                    typedef blueprint<ArithmetizationType> blueprint_type;

                    const algebra::matrix<
                        typename CurveType::scalar_field_type::value_type, 3, 3> M;
                    const algebra::vector<
                        typename CurveType::scalar_field_type::value_type, 3> RC;

                    std::size_t j;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t required_rows_amount = 22;

                public:

                    struct init_params {
                    };

                    struct assignment_params {
                    };

                    poseidon(blueprint<arithmetization_type> &bp,
                             const init_params &params) :
                        component<arithmetization_type>(bp) {

                        j = this->bp.allocate_rows(required_rows_amount);
                    }

                    static std::size_t allocate_rows(blueprint<arithmetization_type> &in_bp) {
                        return in_bp.allocate_rows(required_rows_amount);
                    }

                    template<std::size_t SelectorColumns, std::size_t PublicInputColumns, std::size_t ConstantColumns>
                    void generate_gates(blueprint_public_assignment_table<arithmetization_type,
                                                                          SelectorColumns,
                                                                          PublicInputColumns,
                                                                          ConstantColumns> &public_assignment,
                                        std::size_t circuit_start_row = 0) {

                        std::size_t selector_index_j_0 = public_assignment.add_selector(j + 0);
                        // For $j + 0$:
                        auto constraint_j_0_0 = this->bp.add_constraint(var(W4, 0) -
                            (var(W1, 0) ^ 5 * M[0][0] + var(W2, 0) ^ 5 * M[0][1] + var(W3, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        auto constraint_j_0_1 = this->bp.add_constraint(var(W5, 0) -
                            (var(W1, 0) ^ 5 * M[1][0] + var(W2, 0) ^ 5 * M[1][1] + var(W3, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        auto constraint_j_0_2 = this->bp.add_constraint(var(W6, 0) -
                            (var(W1, 0) ^ 5 * M[2][0] + var(W2, 0) ^ 5 * M[2][1] + var(W3, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        auto constraint_j_0_3 = this->bp.add_constraint(var(W7, 0) -
                            (var(W3, 0) ^ 5 * M[0][0] + var(W4, 0) ^ 5 * M[0][1] + var(W5, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        auto constraint_j_0_4 = this->bp.add_constraint(var(W8, 0) -
                            (var(W3, 0) ^ 5 * M[1][0] + var(W4, 0) ^ 5 * M[1][1] + var(W5, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        auto constraint_j_0_5 = this->bp.add_constraint(var(W9, 0) -
                            (var(W3, 0) ^ 5 * M[2][0] + var(W4, 0) ^ 5 * M[2][1] + var(W5, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        this->bp.add_gate(selector_index_j_0,
                                              {constraint_j_0_0, constraint_j_0_1, constraint_j_0_2,
                                               constraint_j_0_3, constraint_j_0_4, constraint_j_0_5});

                        std::size_t selector_index_j_1 = public_assignment.add_selector(j + 1);

                        // For $j + 1$:
                        auto constraint_j_1_0 = this->bp.add_constraint(var(W1, 0) -
                            (var(W3, 0) ^ 5 * M[0][0] + var(W8, 0) ^ 5 * M[0][1] + var(W9, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        auto constraint_j_1_1 = this->bp.add_constraint(var(W2, 0) -
                            (var(W3, 0) ^ 5 * M[1][0] + var(W8, 0) ^ 5 * M[1][1] + var(W9, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        auto constraint_j_1_2 = this->bp.add_constraint(var(W3, 0) -
                            (var(W3, 0) ^ 5 * M[2][0] + var(W8, 0) ^ 5 * M[2][1] + var(W9, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        auto constraint_j_1_3 = this->bp.add_constraint(var(W4, 0) -
                            (var(W1, 0) ^ 5 * M[0][0] + var(W2, 0) ^ 5 * M[0][1] + var(W3, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        auto constraint_j_1_4 = this->bp.add_constraint(var(W5, 0) -
                            (var(W1, 0) ^ 5 * M[1][0] + var(W2, 0) ^ 5 * M[1][1] + var(W3, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        auto constraint_j_1_5 = this->bp.add_constraint(var(W6, 0) -
                            (var(W1, 0) ^ 5 * M[2][0] + var(W2, 0) ^ 5 * M[2][1] + var(W3, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        auto constraint_j_1_6 = this->bp.add_constraint(var(W7, 0) -
                            (var(W4, 0) * M[0][0] + var(W5, 0) * M[0][1] + var(W6, 0) ^ 5 * M[0][2] + RC[0]));
                        auto constraint_j_1_7 = this->bp.add_constraint(var(W8, 0) -
                            (var(W4, 0) * M[1][0] + var(W5, 0) * M[1][1] + var(W6, 0) ^ 5 * M[1][2] + RC[1]));
                        auto constraint_j_1_8 = this->bp.add_constraint(var(W9, 0) -
                            (var(W4, 0) * M[2][0] + var(W5, 0) * M[2][1] + var(W6, 0) ^ 5 * M[2][2] + RC[2]));

                        this->bp.add_gate(selector_index_j_1,
                                              {constraint_j_1_0, constraint_j_1_1, constraint_j_1_2,
                                               constraint_j_1_3, constraint_j_1_4, constraint_j_1_5});

                        // For $j + k$, $k \in \{2, 19\}$:
                        for (std::size_t z = 2; z <= 19; z++) {
                            this->bp.add_gate(j + z,
                                        var(W1, 0) -
                                            (var(W7, -1) * M[0][0] + var(W8, -1) * M[0][1] + var(W9, -1) ^ 5 * M[0][2] + RC[0]));
                            this->bp.add_gate(j + z,
                                        var(W2, 0) -
                                            (var(W7, -1) * M[1][0] + var(W8, -1) * M[1][1] + var(W9, -1) ^ 5 * M[1][2] + RC[1]));
                            this->bp.add_gate(j + z,
                                        var(W3, 0) -
                                            (var(W7, -1) * M[2][0] + var(W8, -1) * M[2][1] + var(W9, -1) ^ 5 * M[2][2] + RC[2]));

                            this->bp.add_gate(j + z,
                                        var(W4, 0) - (var(W1, 0) * M[0][0] + var(W2, 0) * M[0][1] + var(W3, 0) ^
                                                     5 * M[0][2] + RC[0]));
                            this->bp.add_gate(j + z,
                                        var(W5, 0) - (var(W1, 0) * M[1][0] + var(W2, 0) * M[1][1] + var(W3, 0) ^
                                                     5 * M[1][2] + RC[1]));
                            this->bp.add_gate(j + z,
                                        var(W6, 0) - (var(W1, 0) * M[2][0] + var(W2, 0) * M[2][1] + var(W3, 0) ^
                                                     5 * M[2][2] + RC[2]));

                            this->bp.add_gate(j + z,
                                        var(W7, 0) - (var(W4, 0) * M[0][0] + var(W5, 0) * M[0][1] + var(W6, 0) ^
                                                     5 * M[0][2] + RC[0]));
                            this->bp.add_gate(j + z,
                                        var(W8, 0) - (var(W4, 0) * M[1][0] + var(W5, 0) * M[1][1] + var(W6, 0) ^
                                                     5 * M[1][2] + RC[1]));
                            this->bp.add_gate(j + z,
                                        var(W9, 0) - (var(W4, 0) * M[2][0] + var(W5, 0) * M[2][1] + var(W6, 0) ^
                                                     5 * M[2][2] + RC[2]));
                        }

                        // For $j + 20$:
                        this->bp.add_gate(j + 20,
                                    var(W1, 0) -
                                        (var(W7, -1) * M[0][0] + var(W8, -1) * M[0][1] + var(W9, -1) ^ 5 * M[0][2] + RC[0]));
                        this->bp.add_gate(j + 20,
                                    var(W2, 0) -
                                        (var(W7, -1) * M[1][0] + var(W8, -1) * M[1][1] + var(W9, -1) ^ 5 * M[1][2] + RC[1]));
                        this->bp.add_gate(j + 20,
                                    var(W3, 0) -
                                        (var(W7, -1) * M[2][0] + var(W8, -1) * M[2][1] + var(W9, -1) ^ 5 * M[2][2] + RC[2]));

                        this->bp.add_gate(j + 20,
                                    var(W4, 0) -
                                        (var(W1, 0) * M[0][0] + var(W2, 0) * M[0][1] + var(W3, 0) ^ 5 * M[0][2] + RC[0]));
                        this->bp.add_gate(j + 20,
                                    var(W5, 0) -
                                        (var(W1, 0) * M[1][0] + var(W2, 0) * M[1][1] + var(W3, 0) ^ 5 * M[1][2] + RC[1]));
                        this->bp.add_gate(j + 20,
                                    var(W6, 0) -
                                        (var(W1, 0) * M[2][0] + var(W2, 0) * M[2][1] + var(W3, 0) ^ 5 * M[2][2] + RC[2]));

                        this->bp.add_gate(j + 20,
                                    var(W7, 0) - (var(W3, 0) ^ 5 * M[0][0] + var(W4, 0) ^ 5 * M[0][1] + var(W5, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        this->bp.add_gate(j + 20,
                                    var(W8, 0) - (var(W3, 0) ^ 5 * M[1][0] + var(W4, 0) ^ 5 * M[1][1] + var(W5, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        this->bp.add_gate(j + 20,
                                    var(W9, 0) - (var(W3, 0) ^ 5 * M[2][0] + var(W4, 0) ^ 5 * M[2][1] + var(W5, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        // For $j + 21$:
                        this->bp.add_gate(j + 21,
                                    var(W1, 0) - (var(W3, -1) ^ 5 * M[0][0] + var(W8, -1) ^ 5 * M[0][1] + var(W9, -1) ^
                                                 5 * M[0][2] + RC[0]));
                        this->bp.add_gate(j + 21,
                                    var(W2, 0) - (var(W3, -1) ^ 5 * M[1][0] + var(W8, -1) ^ 5 * M[1][1] + var(W9, -1) ^
                                                 5 * M[1][2] + RC[1]));
                        this->bp.add_gate(j + 21,
                                    var(W3, 0) - (var(W3, -1) ^ 5 * M[2][0] + var(W8, -1) ^ 5 * M[2][1] + var(W9, -1) ^
                                                 5 * M[2][2] + RC[2]));

                        this->bp.add_gate(j + 21,
                                    var(W4, 0) - (var(W1, 0) ^ 5 * M[0][0] + var(W2, 0) ^ 5 * M[0][1] + var(W3, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        this->bp.add_gate(j + 21,
                                    var(W5, 0) - (var(W1, 0) ^ 5 * M[1][0] + var(W2, 0) ^ 5 * M[1][1] + var(W3, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        this->bp.add_gate(j + 21,
                                    var(W6, 0) - (var(W1, 0) ^ 5 * M[2][0] + var(W2, 0) ^ 5 * M[2][1] + var(W3, 0) ^
                                                 5 * M[2][2] + RC[2]));

                        this->bp.add_gate(j + 21,
                                    var(W7, 0) - (var(W3, 0) ^ 5 * M[0][0] + var(W4, 0) ^ 5 * M[0][1] + var(W5, 0) ^
                                                 5 * M[0][2] + RC[0]));
                        this->bp.add_gate(j + 21,
                                    var(W8, 0) - (var(W3, 0) ^ 5 * M[1][0] + var(W4, 0) ^ 5 * M[1][1] + var(W5, 0) ^
                                                 5 * M[1][2] + RC[1]));
                        this->bp.add_gate(j + 21,
                                    var(W9, 0) - (var(W3, 0) ^ 5 * M[2][0] + var(W4, 0) ^ 5 * M[2][1] + var(W5, 0) ^
                                                 5 * M[2][2] + RC[2]));
                    }

                    template<std::size_t SelectorColumns, std::size_t PublicInputColumns, std::size_t ConstantColumns>
                    void
                        generate_copy_constraints(blueprint_public_assignment_table<arithmetization_type,
                                                                                    SelectorColumns,
                                                                                    PublicInputColumns,
                                                                                    ConstantColumns> &public_assignment,
                                                  std::size_t circuit_start_row = 0) {
                    }

                    template<std::size_t WitnessColumns,
                             std::size_t SelectorColumns,
                             std::size_t PublicInputColumns,
                             std::size_t ConstantColumns>
                    void generate_assignments(
                        blueprint_private_assignment_table<arithmetization_type, WitnessColumns> &private_assignment,
                        blueprint_public_assignment_table<arithmetization_type,
                                                          SelectorColumns,
                                                          PublicInputColumns,
                                                          ConstantColumns> &public_assignment,
                        const assignment_params &params,
                        std::size_t circuit_start_row = 0) {

                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_5_WIRES_HPP

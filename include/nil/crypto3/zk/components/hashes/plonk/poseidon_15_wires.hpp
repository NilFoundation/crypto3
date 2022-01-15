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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_15_WIRES_HPP

#include <nil/crypto3/algebra/matrix/matrix.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>
#include <nil/crypto3/zk/components/detail/plonk/n_wires.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TArithmetization,
                         typename CurveType,
                         std::size_t W0 = 0,
                         std::size_t W1 = 1,
                         std::size_t W2 = 2,
                         std::size_t W3 = 3,
                         std::size_t W4 = 4,
                         std::size_t W5 = 5,
                         std::size_t W6 = 6,
                         std::size_t W7 = 7,
                         std::size_t W8 = 8,
                         std::size_t W9 = 9,
                         std::size_t W10 = 10,
                         std::size_t W11 = 11,
                         std::size_t W12 = 12,
                         std::size_t W13 = 13,
                         std::size_t W14 = 14>
                class poseidon_plonk;

                template<typename TBlueprintField,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class poseidon_plonk<snark::plonk_constraint_system<TBlueprintField, 15>,
                                     CurveType,
                                     W0,
                                     W1,
                                     W2,
                                     W3,
                                     W4,
                                     W5,
                                     W6,
                                     W7,
                                     W8,
                                     W9,
                                     W10,
                                     W11,
                                     W12,
                                     W13,
                                     W14> : public component<snark::plonk_constraint_system<TBlueprintField, 15>> {
                    typedef snark::plonk_constraint_system<TBlueprintField, 15> arithmetization_type;

                    typedef blueprint<arithmetization_type> blueprint_type;

                    constexpr static const algebra::matrix<typename CurveType::scalar_field_type::value_type, 3, 3> M;
                    constexpr static const algebra::vector<typename CurveType::scalar_field_type::value_type, 3> RC;

                    std::size_t j;

                public:
                    poseidon_plonk(blueprint_type &bp) : component<arithmetization_type>(bp) {

                        j = bp.allocate_rows(12);
                    }

                    void generate_gates() {

                        constexpr static const typename blueprint_type::value_type T_0_0(
                            W0, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_0_1(
                            W1, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_0_2(
                            W2, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_4_0(
                            W3, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_4_1(
                            W4, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_4_2(
                            W5, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_1_0(
                            W6, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_1_1(
                            W7, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_1_2(
                            W8, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_2_0(
                            W9, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_2_1(
                            W10, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_2_2(
                            W11, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_3_0(
                            W12, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_3_1(
                            W13, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type T_3_2(
                            W14, blueprint_type::value_type::rotation_type::current);

                        constexpr static const typename blueprint_type::value_type T_0_0_next(
                            W0, blueprint_type::value_type::rotation_type::next);
                        constexpr static const typename blueprint_type::value_type T_0_1_next(
                            W1, blueprint_type::value_type::rotation_type::next);
                        constexpr static const typename blueprint_type::value_type T_0_2_next(
                            W2, blueprint_type::value_type::rotation_type::next);

                        // TODO: The gates are similar for each z, it can be optimized using selectors
                        for (std::size_t z = 0; z <= 11; z++) {

                            this->bp.add_gate(
                                j + z,
                                T_1_0 - (T_0_0 ^ 5 * M[0][0] + T_0_1 ^ 5 * M[0][1] + T_0_2 ^ 5 * M[0][2] + RC[0]));
                            this->bp.add_gate(
                                j + z,
                                T_1_1 - (T_0_0 ^ 5 * M[1][0] + T_0_1 ^ 5 * M[1][1] + T_0_2 ^ 5 * M[1][2] + RC[1]));
                            this->bp.add_gate(
                                j + z,
                                T_1_2 - (T_0_0 ^ 5 * M[2][0] + T_0_1 ^ 5 * M[2][1] + T_0_2 ^ 5 * M[2][2] + RC[2]));

                            this->bp.add_gate(
                                j + z,
                                T_2_0 - (T_1_0 ^ 5 * M[0][0] + T_1_1 ^ 5 * M[0][1] + T_1_2 ^ 5 * M[0][2] + RC[0]));
                            this->bp.add_gate(
                                j + z,
                                T_2_1 - (T_1_0 ^ 5 * M[1][0] + T_1_1 ^ 5 * M[1][1] + T_1_2 ^ 5 * M[1][2] + RC[1]));
                            this->bp.add_gate(
                                j + z,
                                T_2_2 - (T_1_0 ^ 5 * M[2][0] + T_1_1 ^ 5 * M[2][1] + T_1_2 ^ 5 * M[2][2] + RC[2]));

                            this->bp.add_gate(
                                j + z,
                                T_3_0 - (T_2_0 ^ 5 * M[0][0] + T_2_1 ^ 5 * M[0][1] + T_2_2 ^ 5 * M[0][2] + RC[0]));
                            this->bp.add_gate(
                                j + z,
                                T_3_1 - (T_2_0 ^ 5 * M[1][0] + T_2_1 ^ 5 * M[1][1] + T_2_2 ^ 5 * M[1][2] + RC[1]));
                            this->bp.add_gate(
                                j + z,
                                T_3_2 - (T_2_0 ^ 5 * M[2][0] + T_2_1 ^ 5 * M[2][1] + T_2_2 ^ 5 * M[2][2] + RC[2]));

                            this->bp.add_gate(
                                j + z,
                                T_4_0 - (T_3_0 ^ 5 * M[0][0] + T_3_1 ^ 5 * M[0][1] + T_3_2 ^ 5 * M[0][2] + RC[0]));
                            this->bp.add_gate(
                                j + z,
                                T_4_1 - (T_3_0 ^ 5 * M[1][0] + T_3_1 ^ 5 * M[1][1] + T_3_2 ^ 5 * M[1][2] + RC[1]));
                            this->bp.add_gate(
                                j + z,
                                T_4_2 - (T_3_0 ^ 5 * M[2][0] + T_3_1 ^ 5 * M[2][1] + T_3_2 ^ 5 * M[2][2] + RC[2]));

                            this->bp.add_gate(
                                j + z,
                                T_0_0_next - (T_4_0 ^ 5 * M[0][0] + T_4_1 ^ 5 * M[0][1] + T_4_2 ^ 5 * M[0][2] + RC[0]));
                            this->bp.add_gate(
                                j + z,
                                T_0_1_next - (T_4_0 ^ 5 * M[1][0] + T_4_1 ^ 5 * M[1][1] + T_4_2 ^ 5 * M[1][2] + RC[1]));
                            this->bp.add_gate(
                                j + z,
                                T_0_2_next - (T_4_0 ^ 5 * M[2][0] + T_4_1 ^ 5 * M[2][1] + T_4_2 ^ 5 * M[2][2] + RC[2]));
                        }
                    }

                    void generate_assignments() {
                        // TODO: Get state values from the actual Poseidon hash
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_15_WIRES_HPP

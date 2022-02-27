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
#include <nil/crypto3/zk/components/detail/plonk/n_wires.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TArithmetization,
                         typename CurveType,
                         std::size_t W0 = 4,
                         std::size_t W1 = 0,
                         std::size_t W2 = 1,
                         std::size_t W3 = 2,
                         std::size_t W4 = 3>
                class poseidon_plonk;

                template<typename BlueprintFieldType,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4>
                class poseidon_plonk<snark::plonk_constraint_system<BlueprintFieldType, 5>, CurveType, W0, W1, W2, W3, W4>
                    : public detail::
                          n_wires_helper<snark::plonk_constraint_system<BlueprintFieldType, 5>, W0, W1, W2, W3, W4> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, 5> TArithmetization;
                    typedef blueprint<TArithmetization> blueprint_type;

                    constexpr static const algebra::matrix<typename CurveType::scalar_field_type::value_type, 3, 3> M;
                    constexpr static const algebra::vector<typename CurveType::scalar_field_type::value_type, 3> RC;

                    std::size_t j;

                    using n_wires_helper =
                        detail::n_wires_helper<snark::plonk_constraint_system<BlueprintFieldType, 5>, W0, W1, W2, W3, W4>;

                    using n_wires_helper::w;
                    enum indices { m2 = 0, m1, cur, p1, p2 };

                public:
                    poseidon_plonk(blueprint_type &bp) :
                        detail::n_wires_helper<TArithmetization, W0, W1, W2, W3, W4>(bp) {

                        j = bp.allocate_rows();
                    }

                    void generate_gates() {

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

                    void generate_assignments() {
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_5_WIRES_HPP

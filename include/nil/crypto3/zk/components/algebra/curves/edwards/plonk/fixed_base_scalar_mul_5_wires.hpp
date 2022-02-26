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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_5_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_5_WIRES_HPP

#include <nil/crypto3/math/detail/field_utils.hpp>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/detail/plonk/n_wires.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TArithmetization,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class element_g1_fixed_base_scalar_mul;

                template<typename TBlueprintField,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4>
                class element_g1_fixed_base_scalar_mul<snark::plonk_constraint_system<TBlueprintField, 5>,
                                                       CurveType,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4>
                    : public detail::
                          n_wires_helper<snark::plonk_constraint_system<TBlueprintField, 5>, W0, W1, W2, W3, W4> {

                    typedef snark::plonk_constraint_system<TBlueprintField, 5> TArithmetization;
                    typedef blueprint<TArithmetization> blueprint_type;

                    std::size_t j;
                    typename CurveType::template g1_type<>::value_type B;

                    using n_wires_helper =
                        detail::n_wires_helper<snark::plonk_constraint_system<TBlueprintField, 5>, W0, W1, W2, W3, W4>;

                    using n_wires_helper::w;
                    enum indices { m2 = 0, m1, cur, p1, p2 };

                public:
                    element_g1_fixed_base_scalar_mul(blueprint_type &bp,
                                                     typename CurveType::template g1_type<>::value_type B) :
                        n_wires_helper(bp),
                        B(B) {

                        j = this->bp.allocate_rows(85);
                    }

                private:
                    typename CurveType::template g1_type<>::value_type get_omega(std::size_t s, std::size_t i) {

                        std::size_t coef = i * math::detail::power_of_two(3 * s);

                        return coef * B;
                    }

                    void generate_phi1_gate(std::size_t row_index,
                                            typename blueprint_type::value_type x_1,
                                            typename blueprint_type::value_type x_2,
                                            typename blueprint_type::value_type x_3,
                                            typename blueprint_type::value_type x_4,
                                            std::array<typename CurveType::base_field_type::value_type, 8>
                                                u) {

                        this->bp.add_gate(row_index,
                                          x_3 * (-u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2 - u[0] + u[2] * x_1 * x_2 -
                                                 u[2] * x_2 + u[4] * x_1 * x_2 - u[4] * x_2 - u[6] * x_1 * x_2 +
                                                 u[1] * x_2 * x_1 - u[1] * x_1 - u[1] * x_2 + u[1] - u[3] * x_1 * x_2 +
                                                 u[3] * x_2 - u[5] * x_1 * x_2 + u[5] * x_2 + u[7] * x_1 * x_2) -
                                              (x_4 - u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2 - u[0] +
                                               u[2] * x_1 * x_2 - u[2] * x_2 + u[4] * x_1 * x_2 - u[4] * x_2 -
                                               u[6] * x_1 * x_2));
                    }

                    void generate_phi2_gate(std::size_t row_index,
                                            typename blueprint_type::value_type x_1,
                                            typename blueprint_type::value_type x_2,
                                            typename blueprint_type::value_type x_3,
                                            typename blueprint_type::value_type x_4,
                                            std::array<typename CurveType::base_field_type::value_type, 8>
                                                v) {

                        this->bp.add_gate(row_index,
                                          x_3 * (-v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2 - v[0] + v[2] * x_1 * x_2 -
                                                 v[2] * x_2 + v[4] * x_1 * x_2 - v[4] * x_2 - v[6] * x_1 * x_2 +
                                                 v[1] * x_2 * x_1 - v[1] * x_1 - v[1] * x_2 + v[1] - v[3] * x_1 * x_2 +
                                                 v[3] * x_2 - v[5] * x_1 * x_2 + v[5] * x_2 + v[7] * x_1 * x_2) -
                                              (x_4 - v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2 - v[0] +
                                               v[2] * x_1 * x_2 - v[2] * x_2 + v[4] * x_1 * x_2 - v[4] * x_2 -
                                               v[6] * x_1 * x_2));
                    }

                    void generate_phi3_gate(std::size_t row_index,
                                            typename blueprint_type::value_type x_1,
                                            typename blueprint_type::value_type x_2,
                                            typename blueprint_type::value_type x_3,
                                            typename blueprint_type::value_type x_4,
                                            typename blueprint_type::value_type x_5,
                                            typename blueprint_type::value_type x_6) {
                        this->bp.add_gate(
                            row_index,
                            x_1 * (1 + CurveType::template g1_type<>::params_type::b * x_3 * x_4 * x_5 * x_6) -
                                (x_3 * x_6 + x_4 * x_5));
                    }

                    void generate_phi4_gate(std::size_t row_index,
                                            typename blueprint_type::value_type x_1,
                                            typename blueprint_type::value_type x_2,
                                            typename blueprint_type::value_type x_3,
                                            typename blueprint_type::value_type x_4,
                                            typename blueprint_type::value_type x_5,
                                            typename blueprint_type::value_type x_6) {
                        this->bp.add_gate(
                            row_index,
                            x_2 * (1 - CurveType::template g1_type<>::params_type::b * x_3 * x_4 * x_5 * x_6) -
                                (x_3 * x_5 + x_4 * x_6));
                    }

                public:
                    void generate_gates() {

                        this->bp.add_gate({j, j + 2}, w[1][cur] * (w[1][cur] - 1));
                        this->bp.add_gate({j, j + 2}, w[2][cur] * (w[2][cur] - 1));
                        this->bp.add_gate({j, j + 1, j + 3}, w[3][cur] * (w[3][cur] - 1));
                        this->bp.add_gate({j + 2, j + 3}, w[4][cur] * (w[4][cur] - 1));

                        // j=0
                        this->bp.add_gate(j, w[0][cur] - (w[1][cur] * 4 + w[2][cur] * 2 + w[3][cur]));

                        generate_phi3_gate(j, w[1][p1], w[2][p1], w[4][cur], w[0][p1], w[4][p1], w[3][p2]);
                        generate_phi4_gate(j, w[1][p1], w[2][p1], w[4][cur], w[0][p1], w[4][p1], w[3][p2]);

                        // j+z, z=0 mod 5, z!=0
                        for (std::size_t z = 5; z <= 84; z += 5) {

                            this->bp.add_gate(j + z,
                                              w[0][cur] - (w[1][cur] * 4 + w[2][cur] * 2 + w[3][cur] + w[0][m1] * 8));

                            std::array<typename CurveType::base_field_type::value_type, 8> u;
                            std::array<typename CurveType::base_field_type::value_type, 8> v;

                            for (std::size_t i = 0; i < 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega = get_omega(3 * z / 5, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            generate_phi1_gate(j + z, w[1][cur], w[2][cur], w[3][cur], w[4][cur], u);
                            generate_phi2_gate(j + z, w[1][cur], w[2][cur], w[3][cur], w[4][p1], v);
                            generate_phi3_gate(j + z, w[1][p1], w[2][p1], w[1][m1], w[2][m1], w[4][p1], w[3][p2]);
                            generate_phi4_gate(j + z, w[1][p1], w[2][p1], w[1][m1], w[2][m1], w[4][p1], w[3][p2]);
                        }

                        // j+z, z=2 mod 5
                        for (std::size_t z = 2; z <= 84; z += 5) {

                            this->bp.add_gate(j + z,
                                              w[0][cur] - (w[1][cur] * 4 + w[2][cur] * 2 + w[3][m1] + w[0][m2] * 8));

                            std::array<typename CurveType::base_field_type::value_type, 8> u;
                            std::array<typename CurveType::base_field_type::value_type, 8> v;
                            for (std::size_t i = 0; i < 7; i++) {
                                typename CurveType::template g1_type<>::value_type omega =
                                    get_omega(3 * (z - 2) / 5, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            generate_phi1_gate(j + z, w[1][cur], w[2][cur], w[3][m1], w[4][m1], u);
                            generate_phi2_gate(j + z, w[1][cur], w[2][cur], w[3][m1], w[4][cur], v);
                            generate_phi3_gate(j + z, w[1][p1], w[2][p1], w[1][m1], w[2][m1], w[0][p1], w[3][p2]);
                            generate_phi4_gate(j + z, w[1][p1], w[2][p1], w[1][m1], w[2][m1], w[0][p1], w[3][p2]);
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

                            generate_phi1_gate(j + z, w[4][m1], w[3][cur], w[4][cur], w[0][cur], u);
                            generate_phi2_gate(j + z, w[4][m1], w[3][cur], w[4][cur], w[0][p1], v);
                        }

                        // j+z, z=4 mod 5
                        for (std::size_t z = 4; z <= 84; z += 5) {

                            this->bp.add_gate(j + z - 1,
                                              w[0][p1] - (w[4][m1] * 4 + w[3][m2] * 2 + w[4][m2] + w[0][m1] * 8));

                            generate_phi3_gate(j + z, w[1][m2], w[2][cur], w[1][m1], w[2][m1], w[4][p1], w[0][p2]);
                            generate_phi4_gate(j + z, w[1][m2], w[2][cur], w[1][m1], w[2][m1], w[4][p1], w[0][p2]);
                        }
                    }

                    void generate_assignments(const typename CurveType::scalar_field_type::value_type &a,
                                              const typename CurveType::template g1_type<>::value_type &P) {

                        std::array<bool, 9> b{};
                        // = marshalling::unpack(a);

                        this->bp.assignment(W1, j) = b[0];
                        this->bp.assignment(W2, j) = b[1];
                        this->bp.assignment(W3, j) = b[2];

                        this->bp.assignment(W1, j + 1) = P.X;
                        this->bp.assignment(W2, j + 1) = P.Y;
                        this->bp.assignment(W3, j + 1) = b[3];

                        this->bp.assignment(W1, j + 2) = b[4];
                        this->bp.assignment(W2, j + 2) = b[5];
                        this->bp.assignment(W4, j + 2) = b[6];

                        this->bp.assignment(W3, j + 3) = b[7];
                        this->bp.assignment(W4, j + 3) = b[8];
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_5_WIRES_HPP

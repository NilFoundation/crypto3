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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class element_g1_fixed_base_scalar_mul;

                template<typename BlueprintFieldType,
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
                class element_g1_fixed_base_scalar_mul<
                    snark::plonk_constraint_system<BlueprintFieldType>,
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
                    W14> : 
                    public detail::n_wires_helper<snark::plonk_constraint_system<BlueprintFieldType>,
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
                                                    W14> {
                    typedef snark::plonk_constraint_system<BlueprintFieldType> arithmetization_type;

                    typedef blueprint<arithmetization_type> blueprint_type;

                    std::size_t j;

                    constexpr static const std::size_t endo = 3;

                    typename CurveType::template g1_type<>::value_type B;

                    using n_wires_helper =
                        detail::n_wires_helper<snark::plonk_constraint_system<BlueprintFieldType>, 
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using n_wires_helper::w;
                    enum indices { m2 = 0, m1, cur, p1, p2 };

                public:

                    struct init_params {
                        typename CurveType::template g1_type<>::value_type B;
                    };

                    struct assignment_params {
                        typename CurveType::scalar_field_type::value_type a;
                        typename CurveType::scalar_field_type::value_type s;
                        typename CurveType::template g1_type<>::value_type P;
                    };

                    element_g1_fixed_base_scalar_mul(blueprint_type &bp,
                        const init_params &params) :
                        n_wires_helper(bp),
                        B(params.B) {

                        j = this->bp.allocate_rows(43);
                    }

                private:

                    typename CurveType::template g1_type<>::value_type get_omega(std::size_t s, std::size_t i) {

                        std::size_t coef = i * math::detail::power_of_two(3 * s);

                        return coef * B;
                    }

                    void generate_phi1_gate(std::size_t selector_index,
                                            typename blueprint_type::value_type x_1,
                                            typename blueprint_type::value_type x_2,
                                            typename blueprint_type::value_type x_3,
                                            typename blueprint_type::value_type x_4,
                                            std::array<typename CurveType::base_field_type::value_type, 8>
                                                u) {

                        this->bp.add_gate(selector_index,
                            x_3 * (-u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2
                            - u[0] + u[2] * x_1 * x_2 - u[2]* x_2 + u[4] * x_1 * x_2
                            - u[4]* x_2 -u[6] * x_1 * x_2 + u[1] * x_2 * x_1
                            - u[1] * x_1 - u[1] * x_2 + u[1]  - u[3] * x_1 * x_2 + u[3]* x_2
                            - u[5] * x_1 * x_2 + u[5]* x_2 + u[7] * x_1 * x_2) -
                            (x_4 - u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2
                            - u[0] + u[2] * x_1 * x_2 - u[2]* x_2 + u[4] * x_1 * x_2
                            - u[4]* x_2 -u[6] * x_1 * x_2));
                    }

                    void generate_phi2_gate(std::size_t selector_index,
                                            typename blueprint_type::value_type x_1,
                                            typename blueprint_type::value_type x_2,
                                            typename blueprint_type::value_type x_3,
                                            typename blueprint_type::value_type x_4,
                                            std::array<typename CurveType::base_field_type::value_type, 8>
                                                v) {
                        this->bp.add_gate(selector_index,
                            x_3 * (-v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2
                            - v[0] + v[2] * x_1 * x_2 -v[2] * x_2 + v[4] * x_1 * x_2
                            - v[4] * x_2 - v[6] * x_1 * x_2 + v[1] * x_2 * x_1
                            - v[1] * x_1 - v[1] * x_2 + v[1]  - v[3] * x_1 * x_2
                            + v[3] * x_2 - v[5] * x_1 * x_2 + v[5] * x_2
                            + v[7] * x_1 * x_2) - (x_4 - v[0] * x_2 * x_1
                            + v[0] * x_1 + v[0] * x_2 - v[0] + v[2] * x_1 * x_2
                            - v[2] * x_2 + v[4] * x_1 * x_2 - v[4] * x_2 - v[6] * x_1 * x_2));
                    }
                public:

                    void generate_gates() {

                        // For j + 0:
                        std::size_t selector_index_j_0 = public_assignment.add_selector(j);

                        for (std::size_t i = 0; i <= 5; i++){
                            this->bp.add_gate(selector_index_j_0, w[i][cur] * (w[i][cur] - 1));
                        }

                        std::array<typename CurveType::base_field_type::value_type, 8> u;
                        std::array<typename CurveType::base_field_type::value_type, 8> v;

                        for (std::size_t i = 0; i < 7; i++) {
                            typename CurveType::template g1_type<>::value_type omega = get_omega(0, i);
                            u[i] = omega.X;
                            v[i] = omega.Y;
                        }

                        generate_phi1_gate(selector_index_j_0, w[0][cur], w[1][cur], w[2][cur], w[6][cur], u);
                        generate_phi1_gate(selector_index_j_0, w[0][cur], w[1][cur], w[2][cur], w[8][cur], v);

                        for (std::size_t i = 0; i < 7; i++) {
                            typename CurveType::template g1_type<>::value_type omega = get_omega(1, i);
                            u[i] = omega.X;
                            v[i] = omega.Y;
                        }
                        generate_phi1_gate(selector_index_j_0, w[3][cur], w[4][cur], w[5][cur], w[7][cur], u);
                        generate_phi1_gate(selector_index_j_0, w[3][cur], w[4][cur], w[5][cur], w[9][cur], v);

                        this->bp.add_gate(selector_index, w[14][cur] - (w[0][cur] + w[1][cur] * 2 + 
                            w[2][cur] * 4 + w[3][cur] * 8 + w[4][cur] * 16 + w[5][cur] * 32));

                        this->bp.add_gate(selector_index, w[10][cur] - w[6][cur]);

                        //TODO: add_gate for incomplete addition

                    }

                    void generate_assignments() {


                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_FIXED_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

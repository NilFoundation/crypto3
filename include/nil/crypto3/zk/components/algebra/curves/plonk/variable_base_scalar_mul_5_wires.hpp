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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_5_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_5_WIRES_HPP

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/component.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename TBlueprintField,
                         typename CurveType,
                         std::size_t W0 = 4,
                         std::size_t W1 = 0,
                         std::size_t W2 = 1,
                         std::size_t W3 = 2,
                         std::size_t W4 = 3>
                class element_g1_variable_base_scalar_mul_plonk : public component<TBlueprintField> {
                    typedef snark::plonk_constraint_system<TBlueprintField, 5> arithmetization_type;

                    typedef blueprint<arithmetization_type> blueprint_type;

                    std::size_t j;

                public:
                    element_g1_variable_base_scalar_mul_plonk(blueprint_type &bp) : component<TBlueprintField>(bp) {

                        j = bp.allocate_rows(213);
                    }

                private:
                    void generate_phi1_gate(std::size_t row_index,
                                            typename blueprint_type::value_type b,
                                            typename blueprint_type::value_type x_1,
                                            typename blueprint_type::value_type y_1,
                                            typename blueprint_type::value_type x_2,
                                            typename blueprint_type::value_type y_2,
                                            typename blueprint_type::value_type x_3) {

                        this->bp.add_gate(row_index,
                                          x_3 * ((y_1 ^ 2 - x_1 ^ 2) * (2 - y_1 ^ 2 + x_1 ^ 2) +
                                                 2 * CurveType::d * x_1 * y_1 * (y_1 ^ 2 + x_1 ^ 2) * x_2 * y_2 * b) -
                                              (2 * x_1 * y_1 * (2 - y_1 ^ 2 + x_1 ^ 2) * (y_2 * b + (1 - b)) +
                                               (y_1 ^ 2 + x_1 ^ 2) * (y_1 ^ 2 - x_1 ^ 2) * x_2 * b));
                    }

                    void generate_phi2_gate(std::size_t row_index,
                                            typename blueprint_type::value_type b,
                                            typename blueprint_type::value_type x_1,
                                            typename blueprint_type::value_type y_1,
                                            typename blueprint_type::value_type x_2,
                                            typename blueprint_type::value_type y_2,
                                            typename blueprint_type::value_type y_3) {

                        this->bp.add_gate(row_index,
                                          y_3 * ((y_1 ^ 2 - x_1 ^ 2) * (2 - y_1 ^ 2 + x_1 ^ 2) -
                                                 2 * CurveType::d * x_1 * y_1 * (y_1 ^ 2 + x_1 ^ 2) * x_2 * y_2 * b) -
                                              (2 * x_1 * y_1 * (2 - y_1 ^ 2 + x_1 ^ 2) * x_2 * b +
                                               (y_1 ^ 2 + x_1 ^ 2) * (y_1 ^ 2 - x_1 ^ 2) * (y_2 * b + (1 - b))));
                    }

                public:
                    void generate_gates() {

                        constexpr static const typename blueprint_type::value_type w_o_jp2(
                            W0, blueprint_type::value_type::rotation_type::pre_previous);
                        constexpr static const typename blueprint_type::value_type w_1_jp2(
                            W1, blueprint_type::value_type::rotation_type::pre_previous);
                        constexpr static const typename blueprint_type::value_type w_2_jp2(
                            W2, blueprint_type::value_type::rotation_type::pre_previous);
                        constexpr static const typename blueprint_type::value_type w_3_jp2(
                            W3, blueprint_type::value_type::rotation_type::pre_previous);
                        constexpr static const typename blueprint_type::value_type w_4_jp2(
                            W4, blueprint_type::value_type::rotation_type::pre_previous);

                        constexpr static const typename blueprint_type::value_type w_o_jm1(
                            W0, blueprint_type::value_type::rotation_type::previous);
                        constexpr static const typename blueprint_type::value_type w_1_jm1(
                            W1, blueprint_type::value_type::rotation_type::previous);
                        constexpr static const typename blueprint_type::value_type w_2_jm1(
                            W2, blueprint_type::value_type::rotation_type::previous);
                        constexpr static const typename blueprint_type::value_type w_3_jm1(
                            W3, blueprint_type::value_type::rotation_type::previous);
                        constexpr static const typename blueprint_type::value_type w_4_jm1(
                            W4, blueprint_type::value_type::rotation_type::previous);

                        constexpr static const typename blueprint_type::value_type w_o_j(
                            W0, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type w_1_j(
                            W1, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type w_2_j(
                            W2, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type w_3_j(
                            W3, blueprint_type::value_type::rotation_type::current);
                        constexpr static const typename blueprint_type::value_type w_4_j(
                            W4, blueprint_type::value_type::rotation_type::current);

                        constexpr static const typename blueprint_type::value_type w_o_jp1(
                            W0, blueprint_type::value_type::rotation_type::next);
                        constexpr static const typename blueprint_type::value_type w_1_jp1(
                            W1, blueprint_type::value_type::rotation_type::next);
                        constexpr static const typename blueprint_type::value_type w_2_jp1(
                            W2, blueprint_type::value_type::rotation_type::next);
                        constexpr static const typename blueprint_type::value_type w_3_jp1(
                            W3, blueprint_type::value_type::rotation_type::next);
                        constexpr static const typename blueprint_type::value_type w_4_jp1(
                            W4, blueprint_type::value_type::rotation_type::next);

                        constexpr static const typename blueprint_type::value_type w_o_jm2(
                            W0, blueprint_type::value_type::rotation_type::after_next);
                        constexpr static const typename blueprint_type::value_type w_1_jm2(
                            W1, blueprint_type::value_type::rotation_type::after_next);
                        constexpr static const typename blueprint_type::value_type w_2_jm2(
                            W2, blueprint_type::value_type::rotation_type::after_next);
                        constexpr static const typename blueprint_type::value_type w_3_jm2(
                            W3, blueprint_type::value_type::rotation_type::after_next);
                        constexpr static const typename blueprint_type::value_type w_4_jm2(
                            W4, blueprint_type::value_type::rotation_type::after_next);

                        this->bp.add_gate(j, w_1_j * (w_1_j - 1));
                        this->bp.add_gate({j + w_1_j + 211}, w_4_j * (w_4_j - 1));
                        this->bp.add_gate(j + 211, w_3_j * (w_3_j - 1));

                        // j=0
                        this->bp.add_gate(j, w_o_j - (w_1_j * 2 + w_4_j));
                        generate_phi1_gate(j + 1, w_1_jm1, w_1_jp1, w_2_jp1, w_1_jp1, w_2_jp1, w_2_jm1);
                        generate_phi2_gate(j + 1, w_1_jm1, w_1_jp1, w_2_jp1, w_1_jp1, w_2_jp1, w_3_jm1);

                        // j+z, z=0 mod 5, z!=0
                        for (std::size_t z = 5; z <= 84; z += 5) {

                            this->bp.add_gate(j + z, w_o_j - (w_1_j * 2 + w_4_j + w_o_jm1));

                            generate_phi1_gate(j + z, w_4_j, w_2_jm1, w_3_jm1, w_1_jp2, w_2_jp2, w_2_j);
                            generate_phi2_gate(j + z, w_4_j, w_2_jm1, w_3_jm1, w_1_jp2, w_2_jp2, w_3_j);
                        }

                        // j+z, z=1 mod 5
                        for (std::size_t z = 1; z <= 84; z += 5) {

                            this->bp.add_gate(j + z, w_o_j - (w_o_jm1 + w_4_j));

                            generate_phi1_gate(j + z, w_4_jm1, w_2_jm1, w_3_jm1, w_1_jp1, w_2_jp1, w_1_j);
                            generate_phi2_gate(j + z, w_4_jm1, w_2_jm1, w_3_jm1, w_1_jp1, w_2_jp1, w_2_j);
                            generate_phi1_gate(j + z, w_4_j, w_1_j, w_2_j, w_1_jp1, w_2_jp1, w_3_j);
                        }

                        // j+z, z=2 mod 5
                        for (std::size_t z = 2; z <= 84; z += 5) {

                            this->bp.add_gate(j + z, w_o_j - (w_o_jm1 + w_4_j));

                            generate_phi2_gate(j + z, w_4_jm1, w_1_jm1, w_2_jm1, w_1_j, w_2_j, w_3_j);
                        }

                        // j+z, z=3 mod 5
                        for (std::size_t z = 2; z <= 84; z += 5) {

                            this->bp.add_gate(j + z, w_o_j - (w_o_jm1 + w_4_j));

                            generate_phi1_gate(j + z, w_4_jm1, w_3_jm2, w_3_jm1, w_1_jm1, w_2_jm1, w_1_j);
                            generate_phi2_gate(j + z, w_4_jm1, w_3_jm2, w_3_jm1, w_1_jm1, w_2_jm1, w_2_j);
                            generate_phi1_gate(j + z, w_4_j, w_1_j, w_2_j, w_1_jm1, w_2_jm1, w_3_j);
                        }

                        // j+z, z=4 mod 5
                        for (std::size_t z = 4; z <= 84; z += 5) {

                            this->bp.add_gate(j + z, w_o_j - (w_o_jm1 + w_4_j));

                            generate_phi1_gate(j + z, w_4_jm1, w_1_jm1, w_2_jm1, w_1_jm2, w_2_jm2, w_1_j);
                            generate_phi2_gate(j + z, w_4_j, w_3_jm1, w_1_j, w_1_jm2, w_2_jm2, w_2_j);
                            generate_phi1_gate(j + z, w_4_j, w_3_jm1, w_1_j, w_1_jm2, w_2_jm2, w_3_j);
                        }
                    }

                    void generate_assignments(typename CurveType::scalar_field_type::value_type &a,
                                              typename CurveType::template g1_type<>::value_type &P) {
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_5_WIRES_HPP

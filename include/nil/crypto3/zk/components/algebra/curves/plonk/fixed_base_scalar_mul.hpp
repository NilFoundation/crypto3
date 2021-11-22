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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_SCALAR_MUL_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_SCALAR_MUL_COMPONENT_HPP

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/algebra/curves/plonk/doubling.hpp>
#include <nil/crypto3/zk/components/algebra/curves/plonk/addition.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TBlueprintField, typename CurveType, 
                    std::size_t W0 = 4, std::size_t W1 = 0, std::size_t W2 = 1, std::size_t W3 = 2, 
                    std::size_t W4 = 3, CurveType::g1_type<>::value_type B>
                class element_g1_scalar_mul_plonk : public component<TBlueprintField> {
                    typedef snark::plonk_constraint_system<TBlueprintField> arithmetization_type;

                    typedef blueprint<arithmetization_type, TBlueprintField> blueprint_type;

                    typename blueprint_type::row_index_type j;
                public:

                    element_g1_scalar_mul_plonk(blueprint_type &bp) :
                        component<FieldType>(bp){

                        j = bp.allocate_row(85);
                    }
                private:
                    typename CurveType::g1_type<>::value_type omega(
                        std::size_t s, std::size_t i){

                        return (i * 8**s)*B;
                    }

                    void generate_phi1_gate(
                        typename blueprint_type::row_index_type row_index,
                        typename blueprint_type::variable_type x_1,
                        typename blueprint_type::variable_type x_2,
                        typename blueprint_type::variable_type x_3,
                        typename blueprint_type::variable_type x_4,
                        std::array<typename CurveType::base_field_type, 7> u) {

                        bp.add_gate(row_index, 
                            x_3 * (-u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2
                            - u[0] + u[2] * x_1 * x_2 - u[2]* x_2 + u[4] * x_1 * x_2
                            - u[4]* x_2 -u[6] * x_1 * x_2 + u[1] * x_2 * x_1
                            - u[1] * x_1 - u[1] * x_2 + u[1]  - u[3] * x_1 * x_2 + u[3]* x_2
                            - u[5] * x_1 * x_2 + u[5]* x_2 + u[7] * x_1 * x_2) -
                            (x_4 - u[0] * x_2 * x_1 + u[0] * x_1 + u[0] * x_2
                            - u[0] + u[2] * x_1 * x_2 - u[2]* x_2 + u[4] * x_1 * x_2
                            - u[4]* x_2 -u[6] * x_1 * x_2));
                    }

                    void generate_phi2_gate(
                        typename blueprint_type::row_index_type row_index,
                        typename blueprint_type::variable_type x_1,
                        typename blueprint_type::variable_type x_2,
                        typename blueprint_type::variable_type x_3,
                        typename blueprint_type::variable_type x_4,
                        std::array<typename CurveType::base_field_type, 7> v) {

                        bp.add_gate(row_index, 
                            x_3 * (-v[0] * x_2 * x_1 + v[0] * x_1 + v[0] * x_2
                            - v[0] + v[2] * x_1 * x_2 -v[2] * x_2 + v[4] * x_1 * x_2
                            - v[4] * x_2 - v[6] * x_1 * x_2 + v[1] * x_2 * x_1
                            - v[1] * x_1 - v[1] * x_2 + v[1]  - v[3] * x_1 * x_2
                            + v[3] * x_2 - v[5] * x_1 * x_2 + v[5] * x_2
                            + v[7] * x_1 * x_2) - (x_4 - v[0] * x_2 * x_1
                            + v[0] * x_1 + v[0] * x_2 - v[0] + v[2] * x_1 * x_2
                            - v[2] * x_2 + v[4] * x_1 * x_2 - v[4] * x_2 - v[6] * x_1 * x_2));
                    }

                    void generate_phi3_gate(
                        typename blueprint_type::row_index_type row_index,
                        typename blueprint_type::variable_type x_1,
                        typename blueprint_type::variable_type x_2,
                        typename blueprint_type::variable_type x_3,
                        typename blueprint_type::variable_type x_4,
                        typename blueprint_type::variable_type x_5,
                        typename blueprint_type::variable_type x_6) {
                        bp.add_gate(row_index, x_1 * (1 + CurveType::d * x_3*x_4*x_5*x_6) - (x_3*x_6 + x_4*x_5));
                    }

                    void generate_phi4_gate(
                        typename blueprint_type::row_index_type row_index,
                        typename blueprint_type::variable_type x_1,
                        typename blueprint_type::variable_type x_2,
                        typename blueprint_type::variable_type x_3,
                        typename blueprint_type::variable_type x_4,
                        typename blueprint_type::variable_type x_5,
                        typename blueprint_type::variable_type x_6) {
                        bp.add_gate(row_index, x_2 * (1 - CurveType::d * x_3*x_4*x_5*x_6) - (x_3*x_5 + x_4*x_6));
                    }
                public:
                    void generate_gates() {

                        constexpr static const typename blueprint_type::variable_type w_o_jp2(W0, 
                            blueprint_type::variable_type::rotation_type::pre_previous);
                        constexpr static const typename blueprint_type::variable_type w_1_jp2(W1, 
                            blueprint_type::variable_type::rotation_type::pre_previous);
                        constexpr static const typename blueprint_type::variable_type w_2_jp2(W2, 
                            blueprint_type::variable_type::rotation_type::pre_previous);
                        constexpr static const typename blueprint_type::variable_type w_3_jp2(W3, 
                            blueprint_type::variable_type::rotation_type::pre_previous);
                        constexpr static const typename blueprint_type::variable_type w_4_jp2(W4, 
                            blueprint_type::variable_type::rotation_type::pre_previous);

                        constexpr static const typename blueprint_type::variable_type w_o_jm1(W0, 
                            blueprint_type::variable_type::rotation_type::previous);
                        constexpr static const typename blueprint_type::variable_type w_1_jm1(W1, 
                            blueprint_type::variable_type::rotation_type::previous);
                        constexpr static const typename blueprint_type::variable_type w_2_jm1(W2, 
                            blueprint_type::variable_type::rotation_type::previous);
                        constexpr static const typename blueprint_type::variable_type w_3_jm1(W3, 
                            blueprint_type::variable_type::rotation_type::previous);
                        constexpr static const typename blueprint_type::variable_type w_4_jm1(W4, 
                            blueprint_type::variable_type::rotation_type::previous);

                        constexpr static const typename blueprint_type::variable_type w_o_j(W0, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type w_1_j(W1, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type w_2_j(W2, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type w_3_j(W3, 
                            blueprint_type::variable_type::rotation_type::current);
                        constexpr static const typename blueprint_type::variable_type w_4_j(W4, 
                            blueprint_type::variable_type::rotation_type::current);

                        constexpr static const typename blueprint_type::variable_type w_o_jp1(W0, 
                            blueprint_type::variable_type::rotation_type::next);
                        constexpr static const typename blueprint_type::variable_type w_1_jp1(W1, 
                            blueprint_type::variable_type::rotation_type::next);
                        constexpr static const typename blueprint_type::variable_type w_2_jp1(W2, 
                            blueprint_type::variable_type::rotation_type::next);
                        constexpr static const typename blueprint_type::variable_type w_3_jp1(W3, 
                            blueprint_type::variable_type::rotation_type::next);
                        constexpr static const typename blueprint_type::variable_type w_4_jp1(W4, 
                            blueprint_type::variable_type::rotation_type::next);

                        constexpr static const typename blueprint_type::variable_type w_o_jp2(W0, 
                            blueprint_type::variable_type::rotation_type::after_next);
                        constexpr static const typename blueprint_type::variable_type w_1_jp2(W1, 
                            blueprint_type::variable_type::rotation_type::after_next);
                        constexpr static const typename blueprint_type::variable_type w_2_jp2(W2, 
                            blueprint_type::variable_type::rotation_type::after_next);
                        constexpr static const typename blueprint_type::variable_type w_3_jp2(W3, 
                            blueprint_type::variable_type::rotation_type::after_next);
                        constexpr static const typename blueprint_type::variable_type w_4_jp2(W4, 
                            blueprint_type::variable_type::rotation_type::after_next);

                        // j=0
                        bp.add_gate(j, w_o_j - (w_1_j*4 + w_2_j*2 + w_3_j));

                        generate_phi3_gate(j, w_1_jp1, w_2_jp1, w_4_j, w_o_jp1, w_4_jp1, w_3_jp2);
                        generate_phi4_gate(j, w_1_jp1, w_2_jp1, w_4_j, w_o_jp1, w_4_jp1, w_3_jp2);

                        // j+z, z=0 mod 5, z!=0
                        for (typename blueprint_type::row_index_type z = 5, z <= 84; z+=5){

                            bp.add_gate(j + z, w_o_j - (w_1_j*4 + w_2_j*2 + w_3_j + w_o_jm1 * 8));

                            std::array<typename CurveType::base_field_type::value_type, 7> u;
                            std::array<typename CurveType::base_field_type::value_type, 7> v;
                            for (std::size_t i=0; i<7; i++){
                                typename CurveType::g1_type<>::value_type omega = omega(3*z/5, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            generate_phi1_gate(j+z, w_1_j, w_2_j, w_3_j, w_4_j, u);
                            generate_phi2_gate(j+z, w_1_j, w_2_j, w_3_j, w_4_jp1, v);
                            generate_phi3_gate(j+z, w_1_jp1, w_2_jp1, w_1_jm1, w_2_jm1, w_4_jp1, w_3_jp2);
                            generate_phi4_gate(j+z, w_1_jp1, w_2_jp1, w_1_jm1, w_2_jm1, w_4_jp1, w_3_jp2);
                        }

                        // j+z, z=2 mod 5
                        for (typename blueprint_type::row_index_type z = 2, z <= 84; z+=5){

                            bp.add_gate(j + z, w_o_j - (w_1_j*4 + w_2_j*2 + w_3_jm1 + w_o_jm2 * 8));

                            std::array<typename CurveType::base_field_type::value_type, 7> u;
                            std::array<typename CurveType::base_field_type::value_type, 7> v;
                            for (std::size_t i=0; i<7; i++){
                                typename CurveType::g1_type<>::value_type omega = omega(3*(z-2)/5, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            generate_phi1_gate(j+z, w_1_j, w_2_j, w_3_jm1, w_4_jm1, u);
                            generate_phi2_gate(j+z, w_1_j, w_2_j, w_3_jm1, w_4_j, v);
                            generate_phi3_gate(j+z, w_1_jp1, w_2_jp1, w_1_jm1, w_2_jm1, w_o_jp1, w_3_jp2);
                            generate_phi4_gate(j+z, w_1_jp1, w_2_jp1, w_1_jm1, w_2_jm1, w_o_jp1, w_3_jp2);
                        }

                        // j+z, z=3 mod 5
                        for (typename blueprint_type::row_index_type z = 3, z <= 84; z+=5){

                            std::array<typename CurveType::base_field_type::value_type, 7> u;
                            std::array<typename CurveType::base_field_type::value_type, 7> v;
                            for (std::size_t i=0; i<7; i++){
                                typename CurveType::g1_type<>::value_type omega = omega(3*(z-3)/5, i);
                                u[i] = omega.X;
                                v[i] = omega.Y;
                            }

                            generate_phi1_gate(j+z, w_4_jm1, w_3_j, w_4_j, w_o_j, u);
                            generate_phi2_gate(j+z, w_4_jm1, w_3_j, w_4_j, w_o_jp1, v);
                        }

                        // j+z, z=4 mod 5
                        for (typename blueprint_type::row_index_type z = 4, z <= 84; z+=5){

                            bp.add_gate(j + z - 1, w_o_jp1 - (w_4_jm1*4 + w_3_jm2*2 + w_4_jm2 + w_o_jm1 * 8));

                            generate_phi3_gate(j+z, w_1_jm2, w_2_j, w_1_jm1, w_2_jm1, w_4_jp1, w_o_jp2);
                            generate_phi4_gate(j+z, w_1_jm2, w_2_j, w_1_jm1, w_2_jm1, w_4_jp1, w_o_jp2);
                        }
                    }

                    void generate_assignments(typename CurveType::scalar_field_type::value_type &a, 
                                              typename CurveType::g1_type<>::value_type &P) {

                        std::array<bool, 9> b = marshalling::unpack(a);

                        bp.val(W1, j) = b[0];
                        bp.val(W2, j) = b[1];
                        bp.val(W3, j) = b[2];

                        bp.val(W1, j+1) = P.X;
                        bp.val(W2, j+1) = P.Y;
                        bp.val(W3, j+1) = b[3];

                        bp.val(W1, j+2) = b[4];
                        bp.val(W2, j+2) = b[5];
                        bp.val(W4, j+2) = b[6];

                        bp.val(W3, j+3) = b[7];
                        bp.val(W4, j+3) = b[8];
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_SCALAR_MUL_COMPONENT_HPP

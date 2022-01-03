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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_5_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_5_WIRES_HPP

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TBlueprintField, typename CurveType, 
                    std::size_t W0 = 4, std::size_t W1 = 0, std::size_t W2 = 1, std::size_t W3 = 2, 
                    std::size_t W4 = 3>
                class poseidon_plonk : public component<TBlueprintField> {

                    typedef snark::plonk_constraint_system<TBlueprintField> arithmetization_type;

                    constexpr algebra::matrix<typename CurveType::scalar_field_type::value_type, 3, 3> M;
                    constexpr algebra::vector<typename CurveType::scalar_field_type::value_type, 3> RC;

                    typedef blueprint<arithmetization_type, TBlueprintField> blueprint_type;

                    std::size_t j;
                public:

                    poseidon_plonk(blueprint_type &bp) :
                        component<FieldType>(bp) {

                        j = bp.allocate_row();

                    }

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

                        for (std::size_t z=0; z < 4; z++){
                            bp.add_gate(j + z, w_4_j - (w_1_j^5 * M[0][0] + w_2_j^5 * M[0][1] + w_3_j^5 * M[0][2] + RC[0]));
                            bp.add_gate(j + z, w_o_j - (w_1_j^5 * M[1][0] + w_2_j^5 * M[1][1] + w_3_j^5 * M[1][2] + RC[1]));
                            bp.add_gate(j + z, w_1_jp1 - (w_1_j^5 * M[2][0] + w_2_j^5 * M[2][1] + w_3_j^5 * M[2][2] + RC[2]));
                        }

                        for (std::size_t z=4; z < 57; z++){
                            bp.add_gate(j + 3, w_1_jp1 - (w_3_j * M[0][0] + w_4_j * M[0][1] + w_o_j^5 * M[0][2] + RC[0]));
                            bp.add_gate(j + 3, w_2_jp1 - (w_3_j * M[1][0] + w_4_j * M[1][1] + w_o_j^5 * M[1][2] + RC[1]));
                            bp.add_gate(j + 3, w_3_jp1 - (w_3_j * M[2][0] + w_4_j * M[2][1] + w_o_j^5 * M[2][2] + RC[2]));
                        }

                        bp.add_gate(j + 36, w_2_jp1 - (w_4_j^5 * M[0][0] + w_o_j^5 * M[0][1] + w_1_jp1^5 * M[0][2] + RC[0]));
                        bp.add_gate(j + 36, w_3_jp1 - (w_4_j^5 * M[1][0] + w_o_j^5 * M[1][1] + w_1_jp1^5 * M[1][2] + RC[1]));
                        bp.add_gate(j + 36, w_4_jp1 - (w_4_j^5 * M[2][0] + w_o_j^5 * M[2][1] + w_1_jp1^5 * M[2][2] + RC[2]));
                    }

                    void generate_assignments() {
                        
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_POSEIDON_5_WIRES_HPP

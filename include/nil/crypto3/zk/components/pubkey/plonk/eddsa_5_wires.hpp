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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_EDDSA_5_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_EDDSA_5_WIRES_HPP

#include <nil/crypto3/zk/components/blueprint.hpp>
#include <nil/crypto3/zk/components/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename TBlueprintField, typename CurveType, 
                    std::size_t W0 = 4, std::size_t W1 = 0, std::size_t W2 = 1, std::size_t W3 = 2, 
                    std::size_t W4 = 3>
                class eddsa_verifier_plonk : public component<TBlueprintField> {

                    typedef snark::plonk_constraint_system<TBlueprintField> arithmetization_type;

                    constexpr algebra::matrix<typename CurveType::scalar_field_type::value_type, 3, 3> M;
                    constexpr algebra::vector<typename CurveType::scalar_field_type::value_type, 3> RC;

                    typedef blueprint<arithmetization_type, TBlueprintField> blueprint_type;

                    typename blueprint_type::row_index_type j;

                    range_plonk<TBlueprintField> range_proof;
                    sha512_plonk<TBlueprintField> sha512;
                    element_g1_fixed_base_scalar_mul_plonk<TBlueprintField> fixed_scalar_mul;
                    element_g1_variable_base_scalar_mul_plonk<TBlueprintField> variable_base_mul;
                public:

                    eddsa_verifier_plonk(blueprint_type &bp) :
                        component<BlueprintFieldType>(bp), range_proof(bp), sha512(bp), 
                        fixed_scalar_mul(bp), variable_base_mul(bp) {

                        j = bp.allocate_rows(6);
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

                        range_proof.generate_gates();
                        sha512_plonk.generate_gates();
                        fixed_scalar_mul.generate_gates();

                        bp.add_gate(j, x_t*(1 + CurveType::d*x_s * (-x_r)*y_s*y_r) - (x_s*y_r - x_r*y_s));
                        bp.add_gate(j, y_t*(1 + CurveType::d*x_s * (-x_r)*y_s*y_r) - (x_s*(-x_r) + y_r*y_s));
                        bp.add_gate(j, -x_r^2 +y_r^2 - (1 - CurveType::d*x_r^2*y_r^2));

                        variable_base_mul.generate_gates();
                    }

                    void generate_assignments(
                        pubkey::eddsa<FieldType>::digest_type signature,
                        pubkey::eddsa<FieldType>::message_type M,
                        pubkey::eddsa<FieldType>::public_key_type A,
                        pubkey::eddsa<FieldType>::generator_type B) {
                        
                        range_proof.generate_assignments(signature.s, 2**252, 2**252+27742317777372353535851937790883648493);
                        sha512_plonk.generate_assignments(data, R, A ,M);

                        fixed_scalar_mul.generate_assignments(s, B, s*B);
                        variable_scalar_mul.generate_assignments();
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_EDDSA_5_WIRES_HPP

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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_DOUBLING_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_DOUBLING_COMPONENT_HPP

#include <nil/crypto3/zk/components/blueprint.hpp>

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
                         std::size_t W6 = 6>
                class element_g1_doubling_plonk;

                template<typename TBlueprintField,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W6>
                class element_g1_doubling_plonk<snark::plonk_constraint_system<TBlueprintField, 5>,
                                                       CurveType,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W6>
                    : public component<TBlueprintField> {

                    typedef snark::plonk_constraint_system<TBlueprintField, 5> arithmetization_type;
                    typedef blueprint<arithmetization_type> blueprint_type;

                    std::size_t i;
                public:

                    element_g1_doubling_plonk(blueprint_type &bp) :
                        component<FieldType>(bp) {
                        i = bp.allocate_row();
                    }

                    void generate_r1cs_constraints() {
                        typename blueprint_type::variable_type x_1(W0, 
                            blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type y_1(W1, 
                            blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type x_2(W2, 
                            blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type y_2(W3, 
                            blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type r(W6, 
                            blueprint_type::variable_type::rotation_type::current);

                        bp.add_gate(i, 4*y_1^2 * (x_2 + 2*x_1) - 9 * x_1^4);
                        bp.add_gate(i, 2*y_1 * (y_2 + y_1) - 3*x_1^2 * (x_1 - x_2));
                        bp.add_gate(i, y_1*r_1 - 1);
                    }

                    void generate_r1cs_witness(typename CurveType::value_type &P1) {
                        generate_r1cs_witness(P1, P1.doubled());
                    }

                    void generate_r1cs_witness(typename CurveType::value_type &P1, 
                                               typename CurveType::value_type &P2) {
                        bp.val(W0, i) = P1.X;
                        bp.val(W1, i) = P1.Y;
                        bp.val(W2, i) = P2.X;
                        bp.val(W3, i) = P2.Y;
                        bp.val(W6, i) = ?;
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_DOUBLING_COMPONENT_HPP

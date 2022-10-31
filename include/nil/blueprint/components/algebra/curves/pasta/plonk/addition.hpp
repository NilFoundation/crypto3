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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ADDITION_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ADDITION_COMPONENT_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class element_g1_addition;

                template<typename BlueprintFieldType,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6>
                class element_g1_addition<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>,
                                          CurveType,
                                          W0,
                                          W1,
                                          W2,
                                          W3,
                                          W4,
                                          W5,
                                          W6> : public component<BlueprintFieldType> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType> arithmetization_type;
                    typedef blueprint<arithmetization_type> blueprint_type;

                    std::size_t i;

                public:
                    element_g1_addition(blueprint_type &bp) : component<FieldType>(bp) {
                        i = bp.allocate_row();
                    }

                    void generate_gates() {
                        typename blueprint_type::variable_type x_1(
                            W0, blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type y_1(
                            W1, blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type x_2(
                            W2, blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type y_2(
                            W3, blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type x_3(
                            W4, blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type y_3(
                            W5, blueprint_type::variable_type::rotation_type::current);
                        typename blueprint_type::variable_type r(W6,
                                                                 blueprint_type::variable_type::rotation_type::current);

                        bp.add_gate(i, (x_2 - x_1) * (y_1 + y_3) - (y_1 - y_2) * (x_1 - x_3));
                        bp.add_gate(i, (x_1 + x_2 + x_3) * (x_1 - x_3) ^ 2 - (y_1 + y_3) ^ 2);
                        bp.add_gate(i, (x_2 - x_1) * r - 1);
                    }

                    void generate_assignments(typename CurveType::value_type &P1, typename CurveType::value_type &P2) {
                        generate_assignments(P1, P2, P1 + P2);
                    }

                    void generate_assignments(typename CurveType::value_type &P1,
                                               typename CurveType::value_type &P2,
                                               typename CurveType::value_type &P3) {
                        bp.val(W0, i) = P1.X;
                        bp.val(W1, i) = P1.Y;
                        bp.val(W2, i) = P2.X;
                        bp.val(W3, i) = P2.Y;
                        bp.val(W4, i) = P3.X;
                        bp.val(W5, i) = P3.Y;
                        bp.val(W6, i) = ? ;
                    }
                };

            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ADDITION_COMPONENT_HPP

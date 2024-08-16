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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_TRIPLING_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_TRIPLING_COMPONENT_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/doubling.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/addition.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, std::size_t... WireIndexes>
                class element_g1_tripling;

                template<typename BlueprintFieldType, typename CurveType, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7>
                class element_g1_tripling<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>, CurveType, W0, W1, W2, W3,
                                          W4, W5, W6, W7> : public component<BlueprintFieldType> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType> arithmetization_type;
                    typedef blueprint<arithmetization_type> blueprint_type;

                    element_g1_doubling_plonk<arithmetization_type, CurveType, W0, W1, W2, W3, W6> doubling_component;
                    element_g1_addition_plonk<arithmetization_type, CurveType, W0, W1, W2, W3, W4, W5, W7>
                        addition_component;

                public:
                    element_g1_tripling(blueprint_type &bp) :
                        component<FieldType>(bp), doubling_component(bp), addition_component(bp) {
                    }

                    void generate_gates() {
                        doubling_component.generate_gates();
                        addition_component.generate_gates();
                    }

                    void generate_assignments(typename CurveType::value_type &P1) {
                        generate_assignments(P1, P1.doubled() + P1);
                    }

                    void generate_assignments(typename CurveType::value_type &P1, typename CurveType::value_type &P2) {
                        doubling_component.generate_assignments(P1, P1.doubled());
                        addition_component.generate_assignments(P1.doubled(), P1, P2);
                    }
                };

            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_TRIPLING_COMPONENT_HPP

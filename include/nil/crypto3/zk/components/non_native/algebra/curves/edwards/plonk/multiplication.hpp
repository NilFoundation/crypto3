//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_NON_NATIVE_CURVES_ED25519_MULTIPLICATION_COMPONENT_9_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_NON_NATIVE_CURVES_ED25519_MULTIPLICATION_COMPONENT_9_WIRES_HPP

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
                class non_native_curve_element_multiplication;

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
                         std::size_t W8>
                class non_native_curve_element_multiplication<snark::plonk_constraint_system<BlueprintFieldType>,
                                                       CurveType,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4,
                                                       W5,
                                                       W6,
                                                       W7,
                                                       W8>
                    : public component<snark::plonk_constraint_system<BlueprintFieldType>> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;
                    typedef blueprint<ArithmetizationType> blueprint_type;

                    std::size_t j;

                    enum indices { m2 = 0, m1, cur, p1, p2 };

                    using var = snark::plonk_variable<BlueprintFieldType>;

                public:

                    struct init_params {
                    };

                    struct assignment_params {
                        typename CurveType::scalar_field_type::value_type A;
                        typename CurveType::scalar_field_type::value_type B;
                    };

                    non_native_curve_element_multiplication(blueprint<ArithmetizationType> &bp,
                                                     const init_params &params) :
                        component<ArithmetizationType>(bp){

                        j = this->bp.allocate_rows();
                    }

                    void generate_gates(blueprint_public_assignment_table<ArithmetizationType> &public_assignment) {

                        std::size_t selector_index = public_assignment.add_selector({j + 0, j + 2, j + 4, j + 6});

                        snark::plonk_constraint<BlueprintFieldType> s = 
                            (var(W1, 0) + var(W2, 0) + var(W3, 0) +
                             var(W4, 0) + var(W5, 0) + var(W6, 0) +
                             var(W7, 0) + var(W2, +1) + var(W3, +1) +
                             var(W4, +1) + var(W5, +1) + var(W6, +1)
                             - 12 * (2^20 - 1));

                        this->bp.add_gate(selector_index, s * (var(W8, 0) * s - 1));
                        this->bp.add_gate(selector_index, var(W8, 0) * s + (1 - var(W8, 0) * s) * var(W8, +1) - 1);
                        this->bp.add_gate(selector_index, var(W0, 0) - (var(W7, +1) + var(W6, +1) * 2^15 + var(W5, +1) * 2^35 + var(W4, +1) * 2^55));
                        this->bp.add_gate(selector_index, var(W0, +1) - (var(W3, +1) + var(W2, +1) * 2^20 + var(W7, 0) * 2^40));
                        this->bp.add_gate(selector_index, var(W1, +1) - (var(W6, 0) + var(W5, 0) * 2^20 + var(W4, 0) * 2^40));

                        selector_index = public_assignment.add_selector(j + 7);
                        this->bp.add_gate(selector_index, var(W3, +1) - var(W1, 0));
                        this->bp.add_gate(selector_index, var(W5, +1) - var(W0, 0));
                    }

                    void generate_copy_constraints(){

                        this->bp.add_copy_constraint({var(W0, j + 8, true), var(W0, j + 4, true)});
                        this->bp.add_copy_constraint({var(W1, j + 8, true), var(W0, j + 5, true)});
                        this->bp.add_copy_constraint({var(W2, j + 8, true), var(W1, j + 5, true)});
                        this->bp.add_copy_constraint({var(W6, j + 8, true), var(W0, j + 6, true)});
                        this->bp.add_copy_constraint({var(W7, j + 8, true), var(W1, j + 4, true)});
                        this->bp.add_copy_constraint({var(W6, j + 8, true), var(W0, j + 6, true)});
                        this->bp.add_copy_constraint({var(W7, j + 8, true), var(W1, j + 4, true)});
                        this->bp.add_copy_constraint({var(W8, j + 8, true), var(W2, j + 4, true)});
                        this->bp.add_copy_constraint({var(W0, j + 9, true), var(W0, j + 3, true)});
                        this->bp.add_copy_constraint({var(W1, j + 9, true), var(W1, j + 3, true)});
                        this->bp.add_copy_constraint({var(W2, j + 9, true), var(W3, j + 4, true)});
                        this->bp.add_copy_constraint({var(W3, j + 9, true), var(W1, j + 2, true)});
                        this->bp.add_copy_constraint({var(W4, j + 9, true), var(W2, j + 2, true)});
                        this->bp.add_copy_constraint({var(W5, j + 9, true), var(W3, j + 2, true)});
                        this->bp.add_copy_constraint({var(W7, j + 9, true), var(W0, j + 11, true)});
                        this->bp.add_copy_constraint({var(W8, j + 9, true), var(W4, j + 11, true)});
                        this->bp.add_copy_constraint({var(W0, j + 10, true), var(W0, j + 0, true)});
                        this->bp.add_copy_constraint({var(W1, j + 10, true), var(W0, j + 1, true)});
                        this->bp.add_copy_constraint({var(W2, j + 10, true), var(W1, j + 1, true)});
                        this->bp.add_copy_constraint({var(W3, j + 10, true), var(W0, j + 2, true)});
                        this->bp.add_copy_constraint({var(W4, j + 10, true), var(W1, j + 0, true)});
                        this->bp.add_copy_constraint({var(W5, j + 10, true), var(W2, j + 0, true)});
                        this->bp.add_copy_constraint({var(W6, j + 10, true), var(W3, j + 0, true)});
                    }

                    void generate_assignments(blueprint_private_assignment_table<ArithmetizationType> &private_assignment,
                                              const assignment_params &params) {
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_NON_NATIVE_CURVES_ED25519_MULTIPLICATION_COMPONENT_9_WIRES_HPP

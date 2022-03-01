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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

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
                class curve_element_variable_base_scalar_mul;

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
                class curve_element_variable_base_scalar_mul<
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
                    W14> : public component<snark::plonk_constraint_system<BlueprintFieldType>> {
                    typedef snark::plonk_constraint_system<BlueprintFieldType> arithmetization_type;

                    typedef blueprint<arithmetization_type> blueprint_type;

                    std::size_t j;
                    typename CurveType::template g1_type<>::value_type B;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t required_rows_amount = 102;

                public:

                    struct init_params {
                        typename CurveType::template g1_type<>::value_type B;
                    };

                    struct assignment_params {
                    };

                    curve_element_variable_base_scalar_mul(blueprint_type &bp,
                        const init_params &params) :
                        component<arithmetization_type>(bp),
                        B(params.B) {

                        j = this->bp.allocate_rows(required_rows_amount);
                    }

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &in_bp){
                        return in_bp.allocate_rows(required_rows_amount);
                    }

                    void generate_gates(blueprint_public_assignment_table<ArithmetizationType> &public_assignment, 
                        std::size_t circuit_start_row = 0) {

                        std::size_t vbsm_selector_index = public_assignment.add_selector(j, j + required_rows_amount - 1, 2);

                        auto bit_check_1 = this->bp.add_constraint(var(W2, +1) * (var(W2, 0) - 1) );
                        auto bit_check_2 = this->bp.add_constraint(var(W3, +1) * (var(W3, 0) - 1) );
                        auto bit_check_3 = this->bp.add_constraint(var(W4, +1) * (var(W4, 0) - 1) );
                        auto bit_check_4 = this->bp.add_constraint(var(W5, +1) * (var(W5, 0) - 1) );
                        auto bit_check_5 = this->bp.add_constraint(var(W6, +1) * (var(W6, 0) - 1) );

                        auto constraint_1 = this->bp.add_constraint((var(W2, 0) - var(W0, 0)) * var(W7, +1) -
                            (var(W3, 0) - (2 * var(W2, +1) - 1) * var(W1, 0)));
                        auto constraint_2 = this->bp.add_constraint((var(W7, 0) - var(W0, 0)) * var(W8, +1) -
                            (var(W8, 0) - (2 * var(W3, +1) - 1) * var(W1, 0)));
                        auto constraint_3 = this->bp.add_constraint((var(W10, 0) - var(W0, 0)) * var(W9, +1) -
                            (var(W11, 0) - (2 * var(W4, +1) - 1) * var(W1, 0)));
                        auto constraint_4 = this->bp.add_constraint((var(W12, 0) - var(W0, 0)) * var(W10, +1) -
                            (var(W13, 0) - (2 * var(W5, +1) - 1) * var(W1, 0)));
                        auto constraint_5 = this->bp.add_constraint((var(W0, +1) - var(W0, 0)) * var(W11, +1) -
                            (var(W1, +1) - (2 * var(W6, +1) - 1) * var(W1, 0)));

                        auto constraint_6 = this->bp.add_constraint((2 * var(W3, 0) -
                            var(W7, 1) * (2  * var(W2, 0) - var(W7, 1)^2 + var(W0, 0)))^2 -
                            ((2  * var(W2, 0) - var(W7, 1)^2 + var(W0, 0))^2  * (var(W7, 0) -
                            var(W0, 0) + var(W7, 1)^2)));
                        auto constraint_7 = this->bp.add_constraint((2 * var(W8, 0) -
                            var(W8, 1) * (2  * var(W7, 0) - var(W8, 1)^2 + var(W0, 0)))^2 -
                            ((2  * var(W7, 0) - var(W8, 1)^2 + var(W0, 0))^2  * (var(W9, 0) -
                            var(W0, 0) + var(W8, 1)^2)));
                        auto constraint_8 = this->bp.add_constraint((2 * var(W10, 0) -
                            var(W9, 1) * (2  * var(W9, 0) - var(W9, 1)^2 + var(W0, 0)))^2 -
                            ((2  * var(W9, 0) - var(W9, 1)^2 + var(W0, 0))^2  * (var(W11, 0) -
                            var(W0, 0) + var(W9, 1)^2)));
                        auto constraint_9 = this->bp.add_constraint((2 * var(W12, 0) - 
                            var(W10, +1)  * (2  * var(W11, 0) - var(W10, +1)^2 + var(W0, 0)))^2 -
                            ((2  * var(W11, 0) - var(W10, +1)^2 + var(W0, 0))^2  * 
                            (var(W13, 0) - var(W0, 0) + var(W10, +1)^2)));
                        auto constraint_10 = this->bp.add_constraint((2 * var(W14, 0) -
                            var(W11, +1)  * (2  * var(W13, 0) - var(W11, +1)^2 + var(W0, 0)))^2 -
                            (2  * var(W13, 0) - var(W11, +1)^2 + var(W0, 0))^2  * 
                            (var(W0, 1) - var(W0, 0) + var(W11, +1)^2));

                        auto constraint_11 = this->bp.add_constraint((var(W8, 0) + var(W3, 0)) *
                            (2 * var(W2, 0) - var(W7, +1)^2 + var(W0, 0)) -
                            ((var(W2, 0) - var(W7, 0)) * (2* var(W3, 0) - var(W7, +1) *
                            (2 * var(W2, 0) - var(W7, +1)^2 + var(W0, 0)))));
                        auto constraint_12 = this->bp.add_constraint((var(W10, 0) + var(W8, 0)) *
                            (2 * var(W7, 0) - var(W8, +1)^2 + var(W0, 0)) -
                            ((var(W7, 0) - var(W9, 0)) * (2* var(W8, 0) - var(W8, +1) *
                            (2 * var(W7, 0) - var(W8, +1)^2 + var(W0, 0)))));
                        auto constraint_13 = this->bp.add_constraint((var(W12, 0) + var(W10, 0)) *
                            (2 * var(W9, 0) - var(W9, +1)^2 + var(W0, 0)) -
                            ((var(W9, 0) - var(W11, 0)) * (2* var(W10, 0) - var(W9, +1) * 
                            (2 * var(W9, 0) - var(W9, +1)^2 + var(W0, 0)))));
                        auto constraint_14 = this->bp.add_constraint((var(W14, 0) + var(W10, 0)) *
                            (2 * var(W11, 0) - var(W10, +1)^2 + var(W0, 0)) -
                            ((var(W11, 0) - var(W13, 0)) * (2* var(W12, 0) - var(W10, +1) * 
                            (2 * var(W11, 0) - var(W10, +1)^2 + var(W0, 0)))));
                        auto constraint_15 = this->bp.add_constraint((var(W1, +1) + var(W14, 0)) *
                            (2 * var(W13, 0) - var(W11, +1)^2 + var(W0, 0)) -
                            ((var(W13, 0) - var(W0, +1)) * (2* var(W14, 0) - var(W11, +1) * 
                            (2 * var(W13, 0) - var(W11, +1)^2 + var(W0, 0)))));
                        
                        auto constraint_16 = this->bp.add_constraint(var(W5, 0) - (32 * (var(W4, 0)) + 
                            16 * var(W2, +1) + 8 * var(W3, +1) + 4 * var(W4, +1) + 
                            2 * var(W5, +1) + var(W6, +1)));
                        this->bp.add_gate(vbsm_selector_index, 
                            {bit_check_1, bit_check_2, bit_check_3, bit_check_4, bit_check_5,
                            constraint_1, constraint_2, constraint_3, constraint_4, constraint_5,
                            constraint_6, constraint_7, constraint_8, constraint_9, constraint_10,
                            constraint_11, constraint_12, constraint_13, constraint_14, constraint_15,
                            constraint_16});
                    }

                    void generate_copy_constraints(blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        std::size_t circuit_start_row = 0){

                        std::size_t public_input_column_index = 0;
                        this->bp.add_copy_constraint({{W6, j, false}, {0, j, false, var::column_type::public_input}});
                    }

                    template <std::size_t WitnessColumns>
                    void generate_assignments(blueprint_private_assignment_table<ArithmetizationType, WitnessColumns> &private_assignment,
                                              blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                              const assignment_params &params,
                                              std::size_t circuit_start_row = 0) {

                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_CURVE_ELEMENT_VARIABLE_BASE_SCALAR_MUL_COMPONENT_15_WIRES_HPP

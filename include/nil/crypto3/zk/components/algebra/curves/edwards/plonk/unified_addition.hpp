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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_UNIFIED_ADDITION_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_UNIFIED_ADDITION_COMPONENT_15_WIRES_HPP

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
                class curve_element_unified_addition;

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
                         std::size_t W10>
                class curve_element_unified_addition<
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
                    W10> : public component<snark::plonk_constraint_system<BlueprintFieldType>> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType> ArithmetizationType;
                    typedef blueprint<ArithmetizationType> blueprint_type;

                    std::size_t j;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                public:

                    constexpr static const std::size_t required_rows_amount = 1;

                    struct init_params {
                    };

                    struct assignment_params {
                        typename CurveType::template g1_type<>::value_type P;
                        typename CurveType::template g1_type<>::value_type Q;
                    };

                    curve_element_unified_addition(blueprint_type &bp, 
                        const init_params &params) :
                        component<ArithmetizationType>(bp) {

                        j = this->bp.allocate_rows();
                    }

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &in_bp){
                        return in_bp.allocate_rows(required_rows_amount);
                    }

                    template <std::size_t SelectorColumns, std::size_t PublicInputColumns,
                        std::size_t ConstantColumns>
                    void generate_gates(blueprint_public_assignment_table<ArithmetizationType,
                            SelectorColumns, PublicInputColumns, ConstantColumns> &public_assignment, 
                        std::size_t circuit_start_row = 0) {

                        public_assignment.allocate_rows(j + required_rows_amount);

                        std::size_t selector_index = public_assignment.add_selector(j);

                        auto constraint_1 = this->bp.add_constraint(
                            var(W7, 0) * (var(W2, 0) - var(W0, 0)));
                        auto constraint_2 = this->bp.add_constraint(
                            (var(W2, 0) - var(W0, 0)) * var(W10, 0) - 
                            (1 - var(W7, 0)));
                        auto constraint_3 = this->bp.add_constraint(
                            var(W7, 0) * (2*var(W8, 0) * var(W1, 0) - 
                            3*(var(W0, 0) * var(W0, 0))) + (1 - var(W7, 0)) * 
                            ((var(W2, 0) - var(W0, 0)) * var(W8, 0) - 
                            (var(W3, 0) - var(W1, 0))));
                        auto constraint_4 = this->bp.add_constraint(
                            (var(W8, 0) * var(W8, 0)) - (var(W0, 0) + var(W2, 0) + var(W4, 0)));
                        auto constraint_5 = this->bp.add_constraint(
                            var(W5, 0) - (var(W8, 0) * (var(W0, 0) - 
                            var(W4, 0)) - var(W1, 0)));
                        auto constraint_6 = this->bp.add_constraint(
                            (var(W3, 0) - var(W1, 0)) * (var(W7, 0) - var(W6, 0)));
                        auto constraint_7 = this->bp.add_constraint(
                            (var(W3, 0) - var(W1, 0)) * var(W9, 0) - var(W6, 0));

                        this->bp.add_gate(selector_index, 
                            { constraint_1, constraint_2, constraint_3,
                            constraint_4, constraint_5, constraint_6,
                            constraint_7
                        });
                    }

                    template <std::size_t SelectorColumns, std::size_t PublicInputColumns,
                        std::size_t ConstantColumns>
                    void generate_copy_constraints(
                            blueprint_public_assignment_table<ArithmetizationType, SelectorColumns,
                                PublicInputColumns, ConstantColumns> &public_assignment,
                        std::size_t circuit_start_row = 0){

                        public_assignment.allocate_rows(j + required_rows_amount);

                        std::size_t public_input_column_index = 0;
                        this->bp.add_copy_constraint({{W6, j, false}, 
                            {public_input_column_index, 0, false, var::column_type::public_input}});
                    }

                    template <std::size_t WitnessColumns, std::size_t SelectorColumns,
                        std::size_t PublicInputColumns, std::size_t ConstantColumns>
                    void generate_assignments(
                            blueprint_private_assignment_table<ArithmetizationType, WitnessColumns> &private_assignment,
                            blueprint_public_assignment_table<ArithmetizationType, SelectorColumns,
                                PublicInputColumns, ConstantColumns> &public_assignment,
                                              const assignment_params &params,
                                              std::size_t circuit_start_row = 0) {
                        
                        private_assignment.allocate_rows(j + required_rows_amount);
                        public_assignment.allocate_rows(j + required_rows_amount);

                        public_assignment.public_input(0)[0] = ArithmetizationType::field_type::value_type::zero();

                        const typename CurveType::template g1_type<>::value_type R = params.P + params.Q;
                        const typename CurveType::template g1_type<>::value_type &P = params.P;
                        const typename CurveType::template g1_type<>::value_type &Q = params.Q;

                        auto P_affine = P.to_affine();
                        auto Q_affine = Q.to_affine();
                        auto R_affine = R.to_affine();

                        private_assignment.witness(W0)[j] = P_affine.X;
                        private_assignment.witness(W1)[j] = P_affine.Y;
                        private_assignment.witness(W2)[j] = Q_affine.X;
                        private_assignment.witness(W3)[j] = Q_affine.Y;
                        private_assignment.witness(W4)[j] = R_affine.X;
                        private_assignment.witness(W5)[j] = R_affine.Y;

                        // TODO: check, if this one correct:
                        private_assignment.witness(W6)[j] = R.is_zero();

                        if (P.X != Q.X){
                            private_assignment.witness(W7)[j] = 0;
                            private_assignment.witness(W8)[j] = (P_affine.Y - Q_affine.Y)/(P_affine.X - Q_affine.X);

                            private_assignment.witness(W9)[j] = 0;

                            private_assignment.witness(W10)[j] = (Q_affine.X - P_affine.X).inversed();
                        } else {
                            private_assignment.witness(W7)[j] = 1;

                            if (P.Y != Q.Y) { 
                                private_assignment.witness(W9)[j] = (Q_affine.Y - P_affine.Y).inversed();
                            } else { // doubling
                                if (P.Y != 0) {
                                    private_assignment.witness(W8)[j] = (3 * (P_affine.X * P_affine.X))/(2 * P_affine.Y);
                                } else {
                                    private_assignment.witness(W8)[j] = 0;
                                }
                                
                                private_assignment.witness(W9)[j] = 0;
                            }

                            private_assignment.witness(W10)[j] = 0;
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_UNIFIED_ADDITION_COMPONENT_15_WIRES_HPP

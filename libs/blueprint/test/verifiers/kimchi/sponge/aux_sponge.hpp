//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_AUXILIARY_SPONGE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_AUXILIARY_SPONGE_HPP

#include <iostream>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/sponge.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<size_t num_squeezes,
                         typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class aux;

                template<typename BlueprintFieldType,
                         size_t num_squeezes,

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
                class aux<
                    num_squeezes,
                    snark::plonk_constraint_system<BlueprintFieldType>,
                    CurveType,
                    W0, W1, W2, W3,
                    W4, W5, W6, W7,
                    W8, W9, W10, W11,
                    W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using sponge_type =
                        zk::components::kimchi_sponge<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6,
                                                                            W7, W8, W9, W10, W11, W12, W13, W14>;
                    sponge_type sponge;

                public:
                    constexpr static const std::size_t selector_seed = 0x0fd2;
                    constexpr static const std::size_t rows_amount = 200;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::vector<var> input;
                        var zero;
                    };

                    struct result_type {
                        var squeezed = var(0, 0, false);
                        result_type(var &input) : squeezed(input) {}
                        result_type(const params_type &params, const std::size_t &start_row_index) {
                            squeezed = var(W6, start_row_index + rows_amount - 1, false, var::column_type::witness);
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index){

                        std::size_t row = start_row_index;
                        sponge_type sponge;
                        sponge.init_circuit(bp, assignment, params.zero, row);
                        row += sponge_type::init_rows;
                        for (std::size_t i = 0; i < params.input.size(); ++i) {
                            sponge.absorb_circuit(bp, assignment, params.input[i], row);
                            row += sponge_type::absorb_rows;
                        }
                        var sq;
                        for (size_t i = 0; i < num_squeezes; ++i) {
                            sq = sponge.squeeze_circuit(bp, assignment, row);
                            row += sponge_type::squeeze_rows;
                        }
                        return {sq};
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType>
                                &assignment,
                            const params_type &params,
                            const std::size_t start_row_index){
                        std::size_t row = start_row_index;

                        sponge_type sponge;
                        sponge.init_assignment(assignment, params.zero, row);
                        row += sponge_type::init_rows;
                        for (std::size_t i = 0; i < params.input.size(); ++i) {
                            sponge.absorb_assignment(assignment, params.input[i], row);
                            row += sponge_type::absorb_rows;
                        }
                        var sq;
                        for (size_t i = 0; i < num_squeezes; ++i) {
                            sq = sponge.squeeze_assignment(assignment, row);
                            row += sponge_type::squeeze_rows;
                        }
                        return {sq};
                    }

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t first_selector_index) {}

                    static void generate_copy_constraints(
                            blueprint<ArithmetizationType> &bp,
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            const std::size_t start_row_index) {}
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ENDO_SCALAR_COMPONENT_15_WIRES_HPP

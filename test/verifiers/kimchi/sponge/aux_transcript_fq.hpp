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
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<size_t num_absorb,
                         size_t num_challenges,
                         size_t num_challenges_fq,
                         bool digest,
                         typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class aux_fq;

                template<typename BlueprintFieldType,
                         size_t num_absorb,
                         size_t num_challenges,
                         size_t num_challenges_fq,
                         bool digest,
                         typename ArithmetizationParams,
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
                class aux_fq<
                    num_absorb,
                    num_challenges,
                    num_challenges_fq,
                    digest,
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    W0, W1, W2, W3,
                    W4, W5, W6, W7,
                    W8, W9, W10, W11,
                    W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;
                    using transcript_type =
                        zk::components::kimchi_transcript_fq<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5, W6, 
                                                                            W7, W8, W9, W10, W11, W12, W13, W14>;

                public:
                    constexpr static const std::size_t selector_seed = 0x0fd8;
                    constexpr static const std::size_t rows_amount = transcript_type::init_rows + num_absorb * transcript_type::absorb_group_rows + 
                                                                    num_challenges * transcript_type::challenge_rows + 
                                                                    num_challenges_fq * transcript_type::challenge_fq_rows +
                                                                    static_cast<int>(digest) * transcript_type::digest_rows;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::vector<var> input_fr;
                        std::vector<std::array<var, 2>> input_g;
                    };

                    struct result_type {
                        var squeezed = var(0, 0, false);
                        result_type(var &input) : squeezed(input) {}
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index){

                        generate_assignments_constants(bp, assignment, params, start_row_index);
                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        var zero(0, start_row_index, false, var::column_type::constant);

                        std::size_t row = start_row_index;

                        transcript_type transcript;
                        transcript.init_circuit(bp, assignment, zero, row);
                        row += transcript_type::init_rows;
                        for (std::size_t i = 0; i < params.input_fr.size(); ++i) {
                            transcript.absorb_fr_circuit(bp, assignment, {params.input_fr[i]}, row);
                            row += transcript_type::absorb_fr_rows;
                        }
                        for (std::size_t i = 0; i < params.input_g.size(); ++i) {
                            transcript.absorb_g_circuit(bp, assignment, {params.input_g[i][0], params.input_g[i][1]}, row);
                            row += transcript_type::absorb_group_rows;
                        }
                        var sq;
                        for (size_t i = 0; i < num_challenges; ++i) {
                            sq = transcript.challenge_circuit(bp, assignment, row);
                            row += transcript_type::challenge_rows;
                        }
                        for (size_t i = 0; i < num_challenges_fq; ++i) {
                            sq = transcript.challenge_fq_circuit(bp, assignment, row);
                            row += transcript_type::challenge_fq_rows;
                        }
                        if (digest) {
                            sq = transcript.digest_circuit(bp, assignment, row);
                            row += transcript_type::digest_rows;
                        }
                        return {sq};
                    }

                    static result_type generate_assignments(
                            blueprint_assignment_table<ArithmetizationType>
                                &assignment,
                            const params_type &params,
                            const std::size_t start_row_index){

                        std::size_t row = start_row_index;

                        var zero = var(0, start_row_index, false, var::column_type::constant);

                        transcript_type transcript;
                        transcript.init_assignment(assignment, zero, row);
                        row += transcript_type::init_rows;
                        for (std::size_t i = 0; i < params.input_fr.size(); ++i) {
                            transcript.absorb_fr_assignment(assignment, {params.input_fr[i]}, row);
                            row += transcript_type::absorb_fr_rows;
                        }
                        for (std::size_t i = 0; i < params.input_g.size(); ++i) {
                            transcript.absorb_g_assignment(assignment, {params.input_g[i][0], params.input_g[i][1]}, row);
                            row += transcript_type::absorb_group_rows;
                        }
                        var sq;
                        for (size_t i = 0; i < num_challenges; ++i) {
                            sq = transcript.challenge_assignment(assignment, row);
                            row += transcript_type::challenge_rows;
                        }
                        for (size_t i = 0; i < num_challenges_fq; ++i) {
                            sq = transcript.challenge_fq_assignment(assignment, row);
                            row += transcript_type::challenge_fq_rows;
                        }
                        if (digest) {
                            sq = transcript.digest_assignment(assignment, row);
                            row += transcript_type::digest_rows;
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

                    static void generate_assignments_constants(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row] = 0;
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ENDO_SCALAR_COMPONENT_15_WIRES_HPP

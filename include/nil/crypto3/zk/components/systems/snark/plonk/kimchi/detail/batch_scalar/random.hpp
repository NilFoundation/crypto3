//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_SCALAR_RANDOM_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_SCALAR_RANDOM_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // pseudo-random element generation
                // it's used for randomization here:
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/poly-commitment/src/commitment.rs#L656
                // Input: -
                // Output: x \in F_r
                template<typename ArithmetizationType,
                         typename KimchiParamsType,
                         std::size_t BatchSize,
                         std::size_t... WireIndexes>
                class random;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename KimchiParamsType,
                         std::size_t BatchSize, std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3,
                         std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8,
                         std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13,
                         std::size_t W14>
                class random<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             KimchiParamsType, BatchSize, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10,
                             W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using transcript_type = kimchi_transcript_fr<ArithmetizationType,
                                                                 typename KimchiParamsType::curve_type,
                                                                 KimchiParamsType,
                                                                 W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12,
                                                                 W13, W14>;

                    using batch_proof =
                        batch_evaluation_proof_scalar<BlueprintFieldType,
                                                      ArithmetizationType,
                                                      KimchiParamsType,
                                                      typename KimchiParamsType::commitment_params_type>;

                    constexpr static const std::size_t selector_seed = 0x0f29;

                public:
                    constexpr static const std::size_t rows_amount =
                        transcript_type::init_rows +
                        BatchSize * (transcript_type::state_size * transcript_type::absorb_rows +
                                     3 * transcript_type::absorb_rows) +
                        transcript_type::challenge_rows;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<batch_proof, BatchSize> batches;
                    };

                    struct result_type {
                        var output;
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var zero(0, start_row_index, false, var::column_type::constant);

                        transcript_type transcript;
                        transcript.init_circuit(bp, assignment, zero, row);
                        row += transcript_type::init_rows;

                        for (auto batched_proof : params.batches) {
                            // the most part of the data that influences the results is accumulated in the transcript
                            auto state = batched_proof.transcript.state();
                            for (std::size_t i = 0; i < state.size(); i++) {
                                transcript.absorb_circuit(bp, assignment, state[i], row);
                                row += transcript_type::absorb_rows;
                            }

                            transcript.absorb_circuit(bp, assignment, batched_proof.cip, row);
                            row += transcript_type::absorb_rows;

                            transcript.absorb_circuit(bp, assignment, batched_proof.opening.z1, row);
                            row += transcript_type::absorb_rows;
                            transcript.absorb_circuit(bp, assignment, batched_proof.opening.z2, row);
                            row += transcript_type::absorb_rows;
                        }

                        var output = transcript.challenge_circuit(bp, assignment, row);
                        row += transcript_type::challenge_rows;

                        assert(row == start_row_index + rows_amount);

                        generate_assignments_constants(assignment, params, start_row_index);

                        result_type res = {output};
                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var zero(0, start_row_index, false, var::column_type::constant);

                        transcript_type transcript;
                        transcript.init_assignment(assignment, zero, row);
                        row += transcript_type::init_rows;

                        for (auto batched_proof : params.batches) {
                            // the most part of the data that influences the results is accumulated in the transcript
                            auto state = batched_proof.transcript.state();
                            for (std::size_t i = 0; i < state.size(); i++) {
                                transcript.absorb_assignment(assignment, state[i], row);
                                row += transcript_type::absorb_rows;
                            }

                            transcript.absorb_assignment(assignment, batched_proof.cip, row);
                            row += transcript_type::absorb_rows;

                            transcript.absorb_assignment(assignment, batched_proof.opening.z1, row);
                            row += transcript_type::absorb_rows;
                            transcript.absorb_assignment(assignment, batched_proof.opening.z2, row);
                            row += transcript_type::absorb_rows;
                        }

                        var output = transcript.challenge_assignment(assignment, row);
                        row += transcript_type::challenge_rows;

                        assert(row == start_row_index + rows_amount);

                        result_type res = {output};
                        return res;
                    }

                private:
                    static void generate_assignments_constants(
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = 0;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_SCALAR_RANDOM_HPP
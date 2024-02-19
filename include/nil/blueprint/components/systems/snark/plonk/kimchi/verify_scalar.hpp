//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_VERIFY_SCALAR_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_VERIFY_SCALAR_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/prepare_batch_scalar.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/batch_verify_scalar_field.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/binding.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/map_fr.hpp>
#include <nil/blueprint/components/systems/snark/plonk/kimchi/detail/batch_scalar/prepare_scalars.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // scalar field part of batch_verify
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L911
                // Input: list of mina-proofs (scalar field part),
                //      precalculated fq_data and fr_data (the data that used both by scalar and base verifiers)
                //      verifier index (public data)
                // Output: -
                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType,
                         typename KimchiCommitmentParamsType, std::size_t BatchSize, std::size_t... WireIndexes>
                class verify_scalar;

                template<typename CurveType, typename KimchiParamsType,
                         typename KimchiCommitmentParamsType, std::size_t BatchSize, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                         std::size_t W13, std::size_t W14>
                class verify_scalar<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type>,
                    CurveType, KimchiParamsType, KimchiCommitmentParamsType, BatchSize, W0, W1, W2, W3, W4, W5, W6, W7,
                    W8, W9, W10, W11, W12, W13, W14> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using batch_verify_component =
                        zk::components::batch_verify_scalar_field<ArithmetizationType, CurveType, KimchiParamsType,
                                                                  KimchiCommitmentParamsType, BatchSize, W0, W1, W2, W3,
                                                                  W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                    using prepare_batch_component =
                        zk::components::prepare_batch_scalar<ArithmetizationType, CurveType, KimchiParamsType,
                                                             KimchiCommitmentParamsType, W0, W1, W2, W3, W4, W5, W6, W7,
                                                             W8, W9, W10, W11, W12, W13, W14>;
                    using map_fr_component =
                        zk::components::map_fr<ArithmetizationType, CurveType, KimchiParamsType,
                                               KimchiCommitmentParamsType, BatchSize, W0, W1, W2, W3, W4, W5, W6, W7,
                                               W8, W9, W10, W11, W12, W13, W14>;

                    using proof_binding =
                        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;

                    using batch_proof = batch_evaluation_proof_scalar<BlueprintFieldType, ArithmetizationType,
                                                                      KimchiParamsType, KimchiCommitmentParamsType>;

                    using prepare_scalars_component =
                        zk::components::prepare_scalars<ArithmetizationType, CurveType, 1, W0, W1, W2, W3, W4, W5, W6,
                                                        W7, W8, W9, W10, W11, W12, W13, W14>;

                    using verifier_index_type = kimchi_verifier_index_scalar<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0f2A;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        for (std::size_t i = 0; i < BatchSize; i++) {
                            row += prepare_batch_component::rows_amount;

                            row += prepare_scalars_component::rows_amount;
                        }

                        row += batch_verify_component::rows_amount;

                        row += map_fr_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        typename proof_binding::template fr_data<var, BatchSize> fr_data;
                        typename proof_binding::template fq_data<var> fq_data;

                        verifier_index_type &verifier_index;
                        std::array<kimchi_proof_scalar<BlueprintFieldType, KimchiParamsType,
                                                       KimchiCommitmentParamsType::eval_rounds>,
                                   BatchSize> &proof;
                        std::array<typename proof_binding::fq_sponge_output, BatchSize> &fq_output;
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

                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        typename proof_binding::template fr_data<var, BatchSize> fr_data_recalculated;

                        std::array<batch_proof, BatchSize> batches;
                        for (std::size_t i = 0; i < BatchSize; i++) {
                            auto prepare_output = prepare_batch_component::generate_circuit(
                                bp, assignment, {params.verifier_index, params.proof[i], params.fq_output[i]}, row);
                            batches[i] = prepare_output.prepared_proof;
                            fr_data_recalculated.f_comm_scalars[i] = prepare_output.f_comm_scalars;
                            fr_data_recalculated.zeta_to_srs_len[i] = prepare_output.zeta_to_srs_len;
                            row += prepare_batch_component::rows_amount;

                            var cip_shifted = prepare_scalars_component::generate_circuit(
                                                  bp, assignment, {{prepare_output.prepared_proof.cip}}, row)
                                                  .output[0];
                            fr_data_recalculated.cip_shifted[i] = cip_shifted;
                            row += prepare_scalars_component::rows_amount;
                        }

                        auto res = batch_verify_component::generate_circuit(bp, assignment, {batches}, row);
                        row += batch_verify_component::rows_amount;

                        map_fr_component::generate_circuit(bp, assignment, {params.fr_data, fr_data_recalculated}, row);
                        row += map_fr_component::rows_amount;

                        return result_type();
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        typename proof_binding::template fr_data<var, BatchSize> fr_data_recalculated;

                        std::array<batch_proof, BatchSize> batches;
                        for (std::size_t i = 0; i < BatchSize; i++) {
                            auto prepare_output = prepare_batch_component::generate_assignments(
                                assignment, {params.verifier_index, params.proof[i], params.fq_output[i]}, row);
                            batches[i] = prepare_output.prepared_proof;
                            fr_data_recalculated.f_comm_scalars[i] = prepare_output.f_comm_scalars;
                            fr_data_recalculated.zeta_to_srs_len[i] = prepare_output.zeta_to_srs_len;
                            row += prepare_batch_component::rows_amount;

                            var cip_shifted = prepare_scalars_component::generate_assignments(
                                                  assignment, {{prepare_output.prepared_proof.cip}}, row)
                                                  .output[0];
                            fr_data_recalculated.cip_shifted[i] = cip_shifted;
                            row += prepare_scalars_component::rows_amount;
                        }

                        auto res = batch_verify_component::generate_assignments(assignment, {batches}, row);
                        row += batch_verify_component::rows_amount;

                        map_fr_component::generate_assignments(assignment, {params.fr_data, fr_data_recalculated}, row);
                        row += map_fr_component::rows_amount;

                        return result_type();
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t component_start_row = 0) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row = 0) {
                    }

                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_VERIFY_SCALAR_HPP
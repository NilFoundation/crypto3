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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_GENERIC_SCALARS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_GENERIC_SCALARS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // generic constraint scalars
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/circuits/polynomials/generic.rs#L242
                // Input:
                // Output: generic-gate-related scalar x for linearization
                template<typename ArithmetizationType, typename KimchiParamsType, std::size_t... WireIndexes>
                class generic_scalars;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename KimchiParamsType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class generic_scalars<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                      KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13,
                                      W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0f26;

                    constexpr static const std::size_t generic_registers = 3;

                public:
                    constexpr static const std::size_t rows_amount = 12 * mul_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    constexpr static const std::size_t output_size = 10;

                    struct params_type {
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>,
                                   KimchiParamsType::eval_points_amount>
                            evals;
                        std::array<var, KimchiParamsType::alpha_powers_n> alphas;
                        std::size_t start_idx;
                    };

                    struct result_type {
                        std::array<var, output_size> output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index;

                            constexpr std::size_t parts = 2;

                            for (std::size_t i = 0; i < parts; i++) {
                                var alpha_generic = typename mul_component::result_type(row).output;
                                row += mul_component::rows_amount;

                                // addition part
                                // alpha_generic * w_zeta[register_offset + j]
                                for (std::size_t j = 0; j < 3; j++) {
                                    output[5 * i + j] = typename mul_component::result_type(row).output;
                                    row += mul_component::rows_amount;
                                }

                                // multiplication
                                var tmp = typename mul_component::result_type(row).output;
                                row += mul_component::rows_amount;
                                output[5 * i + 3] = typename mul_component::result_type(row).output;
                                row += mul_component::rows_amount;

                                // constant
                                output[5 * i + 4] = alpha_generic;
                            }
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        std::array<var, output_size> output;

                        constexpr std::size_t parts = 2;

                        std::array<var, parts> alpha_pows = {
                            params.alphas[params.start_idx],
                            params.alphas[params.start_idx + 1],
                        };
                        std::array<std::size_t, parts> offsets = {0, generic_registers};

                        for (std::size_t i = 0; i < parts; i++) {
                            var alpha_generic =
                                zk::components::generate_circuit<mul_component>(
                                    bp, assignment, {alpha_pows[i], params.evals[0].generic_selector}, row)
                                    .output;
                            row += mul_component::rows_amount;

                            // addition part
                            // alpha_generic * w_zeta[register_offset + j]
                            for (std::size_t j = 0; j < 3; j++) {
                                output[5 * i + j] =
                                    zk::components::generate_circuit<mul_component>(
                                        bp, assignment, {alpha_generic, params.evals[0].w[offsets[i] + j]}, row)
                                        .output;
                                row += mul_component::rows_amount;
                            }

                            // multiplication
                            var tmp = zk::components::generate_circuit<mul_component>(
                                          bp, assignment,
                                          {params.evals[0].w[offsets[i]], params.evals[0].w[offsets[i] + 1]}, row)
                                          .output;
                            row += mul_component::rows_amount;
                            output[5 * i + 3] = zk::components::generate_circuit<mul_component>(
                                                    bp, assignment, {alpha_generic, tmp}, row)
                                                    .output;
                            row += mul_component::rows_amount;

                            // constant
                            output[5 * i + 4] = alpha_generic;
                        }

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        std::array<var, output_size> output;

                        constexpr std::size_t parts = 2;

                        std::array<var, parts> alpha_pows = {
                            params.alphas[params.start_idx],
                            params.alphas[params.start_idx + 1],
                        };
                        std::array<std::size_t, parts> offsets = {0, generic_registers};

                        for (std::size_t i = 0; i < parts; i++) {
                            var alpha_generic = mul_component::generate_assignments(
                                                    assignment, {alpha_pows[i], params.evals[0].generic_selector}, row)
                                                    .output;
                            row += mul_component::rows_amount;

                            // addition part
                            // alpha_generic * w_zeta[register_offset + j]
                            for (std::size_t j = 0; j < 3; j++) {
                                output[5 * i + j] =
                                    mul_component::generate_assignments(
                                        assignment, {alpha_generic, params.evals[0].w[offsets[i] + j]}, row)
                                        .output;
                                row += mul_component::rows_amount;
                            }

                            // multiplication
                            var tmp =
                                mul_component::generate_assignments(
                                    assignment, {params.evals[0].w[offsets[i]], params.evals[0].w[offsets[i] + 1]}, row)
                                    .output;
                            row += mul_component::rows_amount;
                            output[5 * i + 3] =
                                mul_component::generate_assignments(assignment, {alpha_generic, tmp}, row).output;
                            row += mul_component::rows_amount;

                            // constant
                            output[5 * i + 4] = alpha_generic;
                        }

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                    }

                    static void generate_assignments_constants(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_GENERIC_SCALARS_HPP
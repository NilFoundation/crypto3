//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Ekaterina Chukavina <kate@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ORACLES_CIP_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ORACLES_CIP_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/combined_inner_product.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // combined inner product from oracles data
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L386-L441
                // Input:
                // Output:
                template<typename ArithmetizationType, typename KimchiParamsType, std::size_t... WireIndexes>
                class oracles_cip;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename KimchiParamsType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class oracles_cip<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                  KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static std::size_t poseidon_selector_size() {
                        if (KimchiParamsType::circuit_params::poseidon_gate == true) {
                            return 1;
                        }
                        return 0;
                    }
                    constexpr static std::size_t generic_selector_size() {
                        if (KimchiParamsType::circuit_params::ec_arithmetic_gates == true) {
                            return 1;
                        }
                        return 0;
                    }
                    constexpr static std::size_t p_eval_size() {
                        if (KimchiParamsType::public_input_size > 0) {
                            return 1;
                        }
                        return 0;
                    }
                    constexpr static const std::size_t cip_size =
                        KimchiParamsType::prev_challenges_size + p_eval_size()    // p_eval
                        + 1                                                       // ft_eval
                        + 1                                                       // z
                        + generic_selector_size()                                 // generic_selector
                        + poseidon_selector_size()                                // poseidon_selector
                        + KimchiParamsType::witness_columns + KimchiParamsType::permut_size - 1;

                    constexpr static const std::size_t eval_points_amount = 2;

                    using cip_component =
                        zk::components::combined_inner_product<ArithmetizationType, cip_size, W0, W1, W2, W3, W4, W5,
                                                               W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t selector_seed = 0xf2e;

                public:
                    constexpr static const std::size_t rows_amount = cip_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var v;
                        var u;

                        var ft_eval0;
                        var ft_eval1;
                        std::array<
                            std::array<std::array<var, KimchiParamsType::commitment_params_type::split_poly_eval_size>,
                                       eval_points_amount>,
                            KimchiParamsType::prev_challenges_size>
                            polys;
                        std::array<var, eval_points_amount> p_eval;
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, eval_points_amount>
                            evals;
                    };

                    struct result_type {
                        var output;
                        result_type() {
                        }
                        result_type(std::size_t start_row_index) {
                        }

                        result_type(const params_type &params, std::size_t start_row_index) {
                            output = params.ft_eval0;
                        }
                    };

                private:
                    static std::array<std::array<var, cip_size>, eval_points_amount>
                        prepare_cip_input(const params_type &params) {
                        std::array<std::array<var, cip_size>, eval_points_amount> es;
                        //  std::cout<<KimchiParamsType::public_input_size<<std::endl;
                        // in the original code, cip transpose the evaluations of the same polynomial according to the
                        // evaluation point we do it right here to use cip_component for general use-case from
                        // [[f_full(zeta), f_diff(zeta)], [f_full(zeta_omega), f_diff(zeta_omega)]] to [[f_full(zeta),
                        // f_full(zeta_omega)], [f_diff(zeta), f_diff(zeta_omega)]]
                        std::size_t es_idx = 0;
                        if (KimchiParamsType::prev_challenges_size > 0) {
                            for (std::size_t i = 0; i < KimchiParamsType::prev_challenges_size; ++i) {
                                for (std::size_t j = 0;
                                     j < KimchiParamsType::commitment_params_type::split_poly_eval_size;
                                     ++j) {
                                    for (std::size_t k = 0; k < eval_points_amount; ++k) {
                                        es[k][i] = params.polys[i][k][j];
                                    }
                                }
                            }
                            es_idx += KimchiParamsType::prev_challenges_size;
                        }
                        if (KimchiParamsType::public_input_size > 0) {
                            for (std::size_t i = 0; i < eval_points_amount; ++i) {
                                es[i][es_idx] = params.p_eval[i];
                            }
                            es_idx++;
                        }

                        es[0][es_idx] = params.ft_eval0;
                        es[1][es_idx] = params.ft_eval1;
                        es_idx++;

                        for (std::size_t i = 0; i < eval_points_amount; ++i) {
                            es[i][es_idx] = params.evals[i].z;
                        }
                        es_idx++;
                        if (KimchiParamsType::circuit_params::ec_arithmetic_gates == true) {
                            for (std::size_t i = 0; i < eval_points_amount; ++i) {
                                es[i][es_idx] = params.evals[i].generic_selector;
                            }
                            es_idx++;
                        }

                        if (KimchiParamsType::circuit_params::poseidon_gate == true) {
                            for (std::size_t i = 0; i < eval_points_amount; ++i) {
                                es[i][es_idx] = params.evals[i].poseidon_selector;
                            }

                            es_idx++;
                        }
                        for (std::size_t i = 0; i < eval_points_amount; ++i) {
                            //                            std::size_t es_idx_tmp = es_idx;
                            for (std::size_t j = 0, es_idx_tmp = es_idx; j < KimchiParamsType::witness_columns;
                                 ++j, ++es_idx_tmp) {
                                es[i][es_idx_tmp] = params.evals[i].w[j];
                            }
                        }
                        es_idx += KimchiParamsType::witness_columns;
                        for (std::size_t i = 0; i < eval_points_amount; ++i) {
                            for (std::size_t j = 0, es_idx_tmp = es_idx; j < KimchiParamsType::permut_size - 1;
                                 ++j, ++es_idx_tmp) {
                                es[i][es_idx_tmp] = params.evals[i].s[j];
                            }
                            // es_idx++;
                        }
                        es_idx += KimchiParamsType::permut_size - 1;

                        assert(es_idx <= cip_size);

                        return es;
                    }

                public:
                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        auto es = prepare_cip_input(params);

                        var res =
                            cip_component::generate_circuit(bp, assignment, {es[0], es[1], params.v, params.u}, row)
                                .output;
                        row += cip_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        result_type result;
                        result.output = res;
                        return result;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        auto es = prepare_cip_input(params);

                        var res =
                            cip_component::generate_assignments(assignment, {es[0], es[1], params.v, params.u}, row)
                                .output;
                        row += cip_component::rows_amount;

                        assert(row == start_row_index + rows_amount);
                        result_type result;
                        result.output = res;
                        return result;
                    }

                private:
                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ORACLES_CIP_HPP
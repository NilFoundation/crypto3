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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_EVALS_OF_SPLIT_EVALS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_EVALS_OF_SPLIT_EVALS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/zkpm_evaluate.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/index_terms_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/perm_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/generic_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/evaluation_proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/element_powers.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/pickles/scalar_details/plonk_map_fields.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/a76a550bc2724f53be8ebaf681c3b35686a7f080/src/lib/pickles/plonk_checks/plonk_checks.ml#L380
                template<typename ArithmetizationType, typename KimchiParamsType, std::size_t... WireIndexes>
                class derive_plonk;

                template<typename BlueprintFieldType, typename KimchiParamsType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class derive_plonk<snark::plonk_constraint_system<BlueprintFieldType>,
                                          KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13,
                                          W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using zkpm_evaluate_component = zkpm_evaluate<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6, W7,
                                                                  W8, W9, W10, W11, W12, W13, W14>;

                    using perm_scalars_component = perm_scalars<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3,
                                                                W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using generic_scalars_component =
                        generic_scalars<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9,
                                        W10, W11, W12, W13, W14>;

                    using index_terms_scalars_component =
                        index_terms_scalars<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8,
                                            W9, W10, W11, W12, W13, W14>;

                    using alpha_powers_component = zk::components::element_powers<ArithmetizationType, KimchiParamsType::alpha_powers_n, W0, W1, W2, W3,
                                                                          W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using plonk_map_fields_component =
                        plobk_map_fields<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8,
                                            W9, W10, W11, W12, W13, W14>;

                    using verifier_index_type = kimchi_verifier_index_scalar<BlueprintFieldType>;
                    using index_terms_list = typename KimchiParamsType::circuit_params::index_terms_list;

                    constexpr static const std::size_t lookup_rows() {
                        std::size_t rows = 0;
                        if (KimchiParamsType::circuit_params::lookup_columns > 0) {

                            if (KimchiParamsType::circuit_params::lookup_runtime) {
                            }
                        }

                        return rows;
                    }

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;
                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        verifier_index_type verifier_index;
                        var zeta;
                        var alpha;
                        var beta;
                        var gamma;
                        var joint_combiner;
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>,
                            KimchiParamsType::eval_points_amount> combined_evals;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t component_start_row) {
                            std::size_t row = component_start_row;


                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constant(assignment, params, start_row_index);

                        std::size_t row = start_row_index;

                        var one(0, start_row_index, false, var::column_type::public_input);

                        std::array<var, KimchiParamsType::alpha_powers_n> alpha_powers =
                            alpha_powers_component::generate_circuit(bp, assignment, {params.alpha, one}, row).output;
                        row += alpha_powers_component::rows_amount;

                        var zkp = zkpm_evaluate_component::generate_circuit(bp, assignment,
                                                                                {params.verifier_index.omega,
                                                                                 params.verifier_index.domain_size,
                                                                                 params.zeta},
                                                                                row)
                                      .output;
                        row += zkpm_evaluate_component::rows_amount;


                        auto index_scalars =
                            index_terms_scalars_component::generate_circuit(bp,
                                assignment,
                                {params.zeta, params.alpha, params.beta,
                                 params.gamma, params.joint_combiner, params.combined_evals,
                                 params.verifier_index.omega, params.verifier_index.domain_size},
                                row)
                                .output;
                        row += index_terms_scalars_component::rows_amount;

                        std::pair<std::size_t, std::size_t> alpha_idxs =
                            index_terms_list::alpha_map(argument_type::Permutation);
                        var perm_scalar =
                            perm_scalars_component::generate_circuit(bp,
                                assignment,
                                {params.combined_evals, alpha_powers, alpha_idxs.first,
                                 params.fq_output.beta, params.fq_output.gamma, zkp},
                                row)
                                .output;
                        row += perm_scalars_component::rows_amount;

                        alpha_idxs = index_terms_list::alpha_map(argument_type::Generic);
                        std::array<var, generic_scalars_component::output_size> generic_scalars =
                            generic_scalars_component::generate_circuit(bp,
                                assignment,
                                {params.combined_evals, oracles_output.alpha_powers, alpha_idxs.first}, row)
                                .output;
                        row += generic_scalars_component::rows_amount;

                        var output = plonk_map_fields_component::generate_circuit(bp,
                            assignment,
                            {params.alpha, params.beta, params.gamma, params.joint_combiner,
                             index_scalars, perm_scalar, generic_scalars},
                            row).output;
                        row += plonk_map_fields_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var one(0, start_row_index, false, var::column_type::public_input);

                        std::array<var, KimchiParamsType::alpha_powers_n> alpha_powers =
                            alpha_powers_component::generate_circuit(bp, assignment, {params.alpha, one}, row).output;
                        row += alpha_powers_component::rows_amount;

                        var zkp = zkpm_evaluate_component::generate_assignments(assignment,
                                                                                {params.verifier_index.omega,
                                                                                 params.verifier_index.domain_size,
                                                                                 params.zeta},
                                                                                row)
                                      .output;
                        row += zkpm_evaluate_component::rows_amount;


                        auto index_scalars =
                            index_terms_scalars_component::generate_assignments(
                                assignment,
                                {params.zeta, params.alpha, params.beta,
                                 params.gamma, params.joint_combiner, params.combined_evals,
                                 params.verifier_index.omega, params.verifier_index.domain_size},
                                row)
                                .output;
                        row += index_terms_scalars_component::rows_amount;

                        std::pair<std::size_t, std::size_t> alpha_idxs =
                            index_terms_list::alpha_map(argument_type::Permutation);
                        var perm_scalar =
                            perm_scalars_component::generate_assignments(
                                assignment,
                                {params.combined_evals, alpha_powers, alpha_idxs.first,
                                 params.fq_output.beta, params.fq_output.gamma, zkp},
                                row)
                                .output;
                        row += perm_scalars_component::rows_amount;

                        alpha_idxs = index_terms_list::alpha_map(argument_type::Generic);
                        std::array<var, generic_scalars_component::output_size> generic_scalars =
                            generic_scalars_component::generate_assignments(
                                assignment,
                                {params.combined_evals, oracles_output.alpha_powers, alpha_idxs.first}, row)
                                .output;
                        row += generic_scalars_component::rows_amount;

                        var output = plonk_map_fields_component::generate_assignments(
                            assignment,
                            {params.alpha, params.beta, params.gamma, params.joint_combiner,
                             index_scalars, perm_scalar, generic_scalars},
                            row).output;
                        row += plonk_map_fields_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                    private:

                    static void generate_assignments_constant(
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row] = 1;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_EVALS_OF_SPLIT_EVALS_HPP
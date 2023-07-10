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

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/evaluation_proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/oracles_scalar/combine_proof_evals.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/a76a550bc2724f53be8ebaf681c3b35686a7f080/src/lib/pickles/plonk_checks/plonk_checks.ml#L83
                template<typename ArithmetizationType, typename KimchiParamsType, std::size_t SplitSize, std::size_t... WireIndexes>
                class evals_of_split_evals;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename KimchiParamsType,
                         std::size_t SplitSize,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class evals_of_split_evals<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                          KimchiParamsType, SplitSize, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13,
                                          W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;
                    using exponentiation_component =
                        zk::components::exponentiation<ArithmetizationType, 255, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9,
                                                       W10, W11, W12, W13, W14>;
                    using combined_proof_evals_component =
                        zk::components::combine_proof_evals<ArithmetizationType, KimchiParamsType, W0, W1, W2, W3, W4,
                                                            W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

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
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, SplitSize> split_evals;
                        std::array<var, KimchiParamsType::eval_points_amount> points;
                    };

                    struct result_type {
                        kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType> output;

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

                        var exponent(0, start_row_index, false, var::column_type::public_input);

                        for (std::size_t i = 0; i < KimchiParamsType::eval_points_amount; i++) {
                            var point_exp =
                                exponentiation_component::generate_circuit(bp, assignment, {params.points[i], exponent}, row).output;
                            row += exponentiation_component::rows_amount;

                            kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType> evals_acc;
                            
                            // init
                            for (std::size_t j = 0; j < evals_acc.w.size(); j++) {
                                evals_acc.w[j] = params.split_evals[SplitSize - 1].w[j];
                            }
                            evals_acc.z = params.split_evals[SplitSize - 1].z;
                            for (std::size_t j = 0; j < evals_acc.s.size(); j++) {
                                evals_acc.s[j] = params.split_evals[SplitSize - 1].s[j];
                            }
                            for (std::size_t j = 0; j < evals_acc.lookup.sorted.size(); j++) {
                                evals_acc.lookup.sorted[j] = params.split_evals[SplitSize - 1].lookup.sorted[j];
                            }
                            evals_acc.lookup.aggreg = params.split_evals[SplitSize - 1].lookup.aggreg;
                            evals_acc.lookup.table = params.split_evals[SplitSize - 1].lookup.table;
                            evals_acc.lookup.runtime = params.split_evals[SplitSize - 1].lookup.runtime;
                            evals_acc.generic_selector = params.split_evals[SplitSize - 1].generic_selector;
                            evals_acc.poseidon_selector = params.split_evals[SplitSize - 1].poseidon_selector;

                            // accumulation
                            for (std::size_t j = SplitSize - 2; j >= 0; j--) {
                                evals_acc =
                                    combined_proof_evals_component::generate_circuit(bp, 
                                        assignment, {evals_acc, point_exp},
                                        row)
                                        .output;
                                row += combined_proof_evals_component::rows_amount;

                                for (std::size_t k = 0; k < evals_acc.w.size(); k++) {
                                    evals_acc.w[k] = zk::components::generate_circuit<add_component>(bp, assignment, {evals_acc.w[k], params.split_evals[j].w[k]}, row).output;
                                    row += add_component::rows_amount;
                                }

                                evals_acc.z = zk::components::generate_circuit<add_component>(bp, assignment, {evals_acc.z, params.split_evals[j].z}, row).output;
                                row += add_component::rows_amount;

                                for (std::size_t k = 0; k < evals_acc.s.size(); k++) {
                                    evals_acc.s[k] = zk::components::generate_circuit<add_component>(bp, assignment, {evals_acc.s[k], params.split_evals[j].s[k]}, row).output;
                                    row += add_component::rows_amount;
                                }

                                if (KimchiParamsType::circuit_params::lookup_columns > 0) {
                                    for (std::size_t k = 0; k < evals_acc.lookup.sorted.size(); k++) {
                                        evals_acc.lookup.sorted[k] = zk::components::generate_circuit<add_component>(bp, assignment, {evals_acc.lookup.sorted[k], params.split_evals[j].lookup.sorted[k]}, row).output;
                                        row += add_component::rows_amount;
                                    }
                                    
                                    evals_acc.lookup.aggreg = zk::components::generate_circuit<add_component>(bp, assignment, {evals_acc.lookup.aggreg, params.split_evals[j].lookup.aggreg}, row).output;
                                    row += add_component::rows_amount;

                                    evals_acc.lookup.table = zk::components::generate_circuit<add_component>(bp, assignment, {evals_acc.lookup.table, params.split_evals[j].lookup.table}, row).output;
                                    row += add_component::rows_amount;

                                    if (KimchiParamsType::circuit_params::lookup_runtime) {
                                        evals_acc.lookup.runtime = zk::components::generate_circuit<add_component>(bp, assignment, {evals_acc.lookup.runtime, params.split_evals[j].lookup.runtime}, row).output;
                                        row += add_component::rows_amount;
                                    }
                                }

                                evals_acc.generic_selector = zk::components::generate_circuit<add_component>(bp, assignment, {evals_acc.generic_selector, params.split_evals[j].generic_selector}, row).output;
                                row += add_component::rows_amount;

                                evals_acc.poseidon_selector = zk::components::generate_circuit<add_component>(bp, assignment, {evals_acc.poseidon_selector, params.split_evals[j].poseidon_selector}, row).output;
                                row += add_component::rows_amount;
                            }
                        }

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var exponent(0, start_row_index, false, var::column_type::public_input);

                        for (std::size_t i = 0; i < KimchiParamsType::eval_points_amount; i++) {
                            var point_exp =
                                exponentiation_component::generate_assignments(assignment, {params.points[i], exponent}, row).output;
                            row += exponentiation_component::rows_amount;

                            kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType> evals_acc;
                            
                            // init
                            for (std::size_t j = 0; j < evals_acc.w.size(); j++) {
                                evals_acc.w[j] = params.split_evals[SplitSize - 1].w[j];
                            }
                            evals_acc.z = params.split_evals[SplitSize - 1].z;
                            for (std::size_t j = 0; j < evals_acc.s.size(); j++) {
                                evals_acc.s[j] = params.split_evals[SplitSize - 1].s[j];
                            }
                            for (std::size_t j = 0; j < evals_acc.lookup.sorted.size(); j++) {
                                evals_acc.lookup.sorted[j] = params.split_evals[SplitSize - 1].lookup.sorted[j];
                            }
                            evals_acc.lookup.aggreg = params.split_evals[SplitSize - 1].lookup.aggreg;
                            evals_acc.lookup.table = params.split_evals[SplitSize - 1].lookup.table;
                            evals_acc.lookup.runtime = params.split_evals[SplitSize - 1].lookup.runtime;
                            evals_acc.generic_selector = params.split_evals[SplitSize - 1].generic_selector;
                            evals_acc.poseidon_selector = params.split_evals[SplitSize - 1].poseidon_selector;

                            // accumulation
                            for (std::size_t j = SplitSize - 2; j >= 0; j--) {
                                evals_acc =
                                    combined_proof_evals_component::generate_assignments(
                                        assignment, {evals_acc, point_exp},
                                        row)
                                        .output;
                                row += combined_proof_evals_component::rows_amount;

                                for (std::size_t k = 0; k < evals_acc.w.size(); k++) {
                                    evals_acc.w[k] = add_component::generate_assignments(assignment, {evals_acc.w[k], params.split_evals[j].w[k]}, row).output;
                                    row += add_component::rows_amount;
                                }

                                evals_acc.z = add_component::generate_assignments(assignment, {evals_acc.z, params.split_evals[j].z}, row).output;
                                row += add_component::rows_amount;

                                for (std::size_t k = 0; k < evals_acc.s.size(); k++) {
                                    evals_acc.s[k] = add_component::generate_assignments(assignment, {evals_acc.s[k], params.split_evals[j].s[k]}, row).output;
                                    row += add_component::rows_amount;
                                }

                                if (KimchiParamsType::circuit_params::lookup_columns > 0) {
                                    for (std::size_t k = 0; k < evals_acc.lookup.sorted.size(); k++) {
                                        evals_acc.lookup.sorted[k] = add_component::generate_assignments(assignment, {evals_acc.lookup.sorted[k], params.split_evals[j].lookup.sorted[k]}, row).output;
                                        row += add_component::rows_amount;
                                    }
                                    
                                    evals_acc.lookup.aggreg = add_component::generate_assignments(assignment, {evals_acc.lookup.aggreg, params.split_evals[j].lookup.aggreg}, row).output;
                                    row += add_component::rows_amount;

                                    evals_acc.lookup.table = add_component::generate_assignments(assignment, {evals_acc.lookup.table, params.split_evals[j].lookup.table}, row).output;
                                    row += add_component::rows_amount;

                                    if (KimchiParamsType::circuit_params::lookup_runtime) {
                                        evals_acc.lookup.runtime = add_component::generate_assignments(assignment, {evals_acc.lookup.runtime, params.split_evals[j].lookup.runtime}, row).output;
                                        row += add_component::rows_amount;
                                    }
                                }

                                evals_acc.generic_selector = add_component::generate_assignments(assignment, {evals_acc.generic_selector, params.split_evals[j].generic_selector}, row).output;
                                row += add_component::rows_amount;

                                evals_acc.poseidon_selector = add_component::generate_assignments(assignment, {evals_acc.poseidon_selector, params.split_evals[j].poseidon_selector}, row).output;
                                row += add_component::rows_amount;
                            }
                        }

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                    private:

                    static void generate_assignments_constant(
                            blueprint_public_assignment_table<ArithmetizationType> &assignment,
                            const params_type &params,
                            std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row] = 1 << KimchiParamsType::commitment_params_type::eval_rounds;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_SCALAR_DETAILS_EVALS_OF_SPLIT_EVALS_HPP
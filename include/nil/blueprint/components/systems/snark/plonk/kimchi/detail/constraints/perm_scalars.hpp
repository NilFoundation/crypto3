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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_PERM_SCALAR_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_PERM_SCALAR_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>

#include <nil/blueprint/components/systems/snark/plonk/kimchi/types/evaluation_proof.hpp>

#include <nil/blueprint/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                // permutation argument scalars
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/circuits/polynomials/permutation.rs#L325
                // Input:
                // Output: permutation-related scalar x for linearization
                template<typename ArithmetizationType, typename KimchiParamsType, std::size_t... WireIndexes>
                class perm_scalars;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename KimchiParamsType,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11,
                         std::size_t W12, std::size_t W13, std::size_t W14>
                class perm_scalars<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                   KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<typename BlueprintFieldType::value_type>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using mul_const_component = zk::components::mul_by_constant<ArithmetizationType, W0, W1>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0f2E;

                    constexpr static const std::size_t scalar_rows = KimchiParamsType::permut_size - 1;

                public:
                    constexpr static const std::size_t rows_amount =
                        3 * mul_component::rows_amount +
                        scalar_rows * (2 * mul_component::rows_amount + 2 * add_component::rows_amount) +
                        mul_const_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>,
                                   KimchiParamsType::eval_points_amount>
                            evals;
                        std::array<var, KimchiParamsType::alpha_powers_n> alphas;
                        std::size_t start_idx;

                        var beta;
                        var gamma;
                        var zkp_zeta;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            output = {var(W1, start_row_index + rows_amount - 1, false)};
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        std::array<var, KimchiParamsType::witness_columns> w;
                        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                            w[i] = params.evals[0].w[i];
                        }
                        std::array<var, KimchiParamsType::permut_size - 1> s;
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                            s[i] = params.evals[0].s[i];
                        }
                        var z = params.evals[1].z;
                        std::size_t size = KimchiParamsType::permut_size - 1;

                        zk::components::generate_circuit<mul_component>(bp, assignment, {z, params.beta}, row);
                        auto res = typename mul_component::result_type({z, params.beta}, row);
                        row += mul_component::rows_amount;
                        zk::components::generate_circuit<mul_component>(
                            bp, assignment, {res.output, params.alphas[params.start_idx]}, row);
                        res = typename mul_component::result_type({res.output, params.alphas[params.start_idx]}, row);
                        row += mul_component::rows_amount;
                        zk::components::generate_circuit<mul_component>(
                            bp, assignment, {res.output, params.zkp_zeta}, row);
                        res = typename mul_component::result_type({res.output, params.zkp_zeta}, row);
                        row += mul_component::rows_amount;

                        for (std::size_t i = 0; i < size; i++) {
                            zk::components::generate_circuit<mul_component>(bp, assignment, {s[i], params.beta}, row);
                            auto tmp = typename mul_component::result_type({s[i], params.beta}, row);
                            row += mul_component::rows_amount;
                            zk::components::generate_circuit<add_component>(
                                bp, assignment, {tmp.output, params.gamma}, row);
                            auto add_tmp = typename add_component::result_type({tmp.output, params.gamma}, row);
                            row += add_component::rows_amount;
                            zk::components::generate_circuit<add_component>(
                                bp, assignment, {add_tmp.output, w[i]}, row);
                            add_tmp = typename add_component::result_type({add_tmp.output, w[i]}, row);
                            row += add_component::rows_amount;
                            zk::components::generate_circuit<mul_component>(
                                bp, assignment, {add_tmp.output, res.output}, row);
                            res = typename mul_component::result_type({add_tmp.output, res.output}, row);
                            row += mul_component::rows_amount;
                        }
                        zk::components::generate_circuit<mul_const_component>(bp, assignment, {res.output, -1}, row);
                        auto const_res = typename mul_const_component::result_type({res.output, -1}, row);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        std::array<var, KimchiParamsType::witness_columns> w;
                        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                            w[i] = params.evals[0].w[i];
                        }
                        std::array<var, KimchiParamsType::permut_size - 1> s;
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                            s[i] = params.evals[0].s[i];
                        }
                        var z = params.evals[1].z;
                        std::size_t size = KimchiParamsType::permut_size - 1;

                        auto res = mul_component::generate_assignments(assignment, {z, params.beta}, row);
                        row += mul_component::rows_amount;
                        res = mul_component::generate_assignments(
                            assignment, {res.output, params.alphas[params.start_idx]}, row);
                        row += mul_component::rows_amount;
                        res = mul_component::generate_assignments(assignment, {res.output, params.zkp_zeta}, row);
                        row += mul_component::rows_amount;

                        for (std::size_t i = 0; i < size; i++) {
                            auto tmp = mul_component::generate_assignments(assignment, {s[i], params.beta}, row);
                            row += mul_component::rows_amount;
                            auto add_tmp =
                                add_component::generate_assignments(assignment, {tmp.output, params.gamma}, row);
                            row += add_component::rows_amount;
                            add_tmp = add_component::generate_assignments(assignment, {add_tmp.output, w[i]}, row);
                            row += add_component::rows_amount;
                            res = mul_component::generate_assignments(assignment, {add_tmp.output, res.output}, row);
                            row += add_component::rows_amount;
                        }
                        auto const_res = mul_const_component::generate_assignments(assignment, {res.output, -1}, row);
                        return result_type(start_row_index);
                    }
                };
            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PLONK_KIMCHI_DETAIL_PERM_SCALAR_HPP
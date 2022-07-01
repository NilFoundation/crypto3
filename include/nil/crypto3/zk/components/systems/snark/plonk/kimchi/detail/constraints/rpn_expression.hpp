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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_RPN_EXPRESSION_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_RPN_EXPRESSION_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/endo_scalar.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // Evaluate an RPN expression
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/circuits/expr.rs#L467
                // Input: RPN expression E, variables values V
                // Output: E(V) \in F_r
                template<typename ArithmetizationType, typename KimchiParamsType,
                    std::size_t... WireIndexes>
                class rpn_expression;

                template<typename BlueprintFieldType, 
                         typename ArithmetizationParams,
                         typename KimchiParamsType,
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
                class rpn_expression<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    KimchiParamsType,
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
                    W10,
                    W11,
                    W12,
                    W13,
                    W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using add_component = zk::components::addition<ArithmetizationType, W0, W1, W2>;

                    using endo_scalar_component =
                        zk::components::endo_scalar<ArithmetizationType, typename KimchiParamsType::curve_type,
                            KimchiParamsType::scalar_challenge_size,
                            W0, W1, W2, W3, W4, W5, W6, W7, W8,
                            W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t selector_seed = 0x0f27;

                    constexpr static const std::size_t mds_size = 3;

                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 0;

                    enum token_type {
                        alpha,
                        beta,
                        gamma,
                        joint_combiner,
                        endo_coefficient,
                        mds,
                        literal,
                        cell,
                        dup,
                        pow,
                        add,
                        mul,
                        sub,
                        vanishes_on_last_4_rows,
                        unnormalized_lagrange_basis,
                        store,
                        load
                    };

                    struct params_type {
                        struct token_value_type {
                            token_type type;
                            typename BlueprintFieldType::value_type value;
                            typename BlueprintFieldType::value_type value_second;
                        };

                        std::vector<token_value_type> tokens;

                        var alpha;
                        var beta;
                        var gamma;
                        var joint_combiner;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index;
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        generate_assignments_constants(assignment, params, start_row_index);

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::vector<var> stack;
                        std::vector<var> cache;

                        var endo_factor(0, row, false, var::column_type::constant);

                        for (typename params_type::token_value_type t : params.tokens) {
                            switch (t.type) {
                                case token_type::alpha:
                                    stack.emplace_back(params.alpha);
                                    break;
                                case token_type::beta:
                                    stack.emplace_back(params.beta);
                                    break;
                                case token_type::gamma:
                                    stack.emplace_back(params.gamma);
                                    break;
                                case token_type::joint_combiner:
                                    stack.emplace_back(params.joint_combiner);
                                    break;
                                case token_type::endo_coefficient:
                                    stack.emplace_back(endo_factor);
                                    break;
                                case token_type::mds:
                                    break;
                                case token_type::literal:
                                    break;
                                case token_type::cell:
                                    break;
                                case token_type::dup:
                                    break;
                                case token_type::pow:
                                    break;
                                case token_type::add:
                                    break;
                                case token_type::mul:
                                    break;
                                case token_type::sub:
                                    break;
                                case token_type::vanishes_on_last_4_rows:
                                    break;
                                case token_type::unnormalized_lagrange_basis:
                                    break;
                                case token_type::store:
                                    break;
                            }
                        }

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                    }

                    static void generate_assignments_constants(
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = endo_scalar_component::endo_factor;
                        row++;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_RPN_EXPRESSION_HPP
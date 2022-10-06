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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_B_POLY_COEFFICIENTS_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_B_POLY_COEFFICIENTS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // Coefficients of univariate polynomial
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/poly-commitment/src/commitment.rs#L251
                // Input: challenges
                // Output: f = [c0, c1, ...], where f = (1 + challenges[-1] * X)(1 + challenges[-2] * X^2)(1 +
                // challenges[-3] * X^4)...
                template<typename ArithmetizationType, std::size_t EvalRounds, std::size_t... WireIndexes>
                class b_poly_coefficients;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t EvalRounds,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class b_poly_coefficients<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                          EvalRounds, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0f21;

                public:
                    constexpr static const std::size_t polynomial_len = 1 << EvalRounds;

                    constexpr static const std::size_t rows_amount = mul_component::rows_amount * polynomial_len;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::array<var, EvalRounds> &challenges;
                        var one;
                    };

                    struct result_type {
                        std::array<var, polynomial_len> output;
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::array<var, polynomial_len> output;
                        output[0] = params.one;
                        std::size_t k = 0;
                        std::size_t pow = 1;

                        for (std::size_t i = 1; i < polynomial_len; i++) {
                            std::size_t shift = i == pow ? 1 : 0;
                            k += shift;
                            pow <<= shift;
                            output[i] = zk::components::generate_circuit<mul_component>(
                                            bp, assignment,
                                            {output[i - (pow >> 1)], params.challenges[EvalRounds - 1 - (k - 1)]}, row)
                                            .output;
                            row += mul_component::rows_amount;
                        }

                        result_type res;
                        res.output = output;
                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        std::array<var, polynomial_len> output;
                        output[0] = params.one;
                        std::size_t k = 0;
                        std::size_t pow = 1;

                        for (std::size_t i = 1; i < polynomial_len; i++) {
                            std::size_t shift = i == pow ? 1 : 0;
                            k += shift;
                            pow <<= shift;
                            output[i] = mul_component::generate_assignments(
                                            assignment,
                                            {output[i - (pow >> 1)], params.challenges[EvalRounds - 1 - (k - 1)]},
                                            row)
                                            .output;
                            row += mul_component::rows_amount;
                        }

                        result_type res;
                        res.output = output;
                        return res;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_B_POLY_COEFFICIENTS_HPP
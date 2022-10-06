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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ZK_W3_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ZK_W3_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>

#include <nil/crypto3/zk/components/algebra/fields/plonk/exponentiation.hpp>
#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // Returns the end of the circuit, which is used for introducing zero-knowledge in the permutation
                // polynomial
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/circuits/polynomials/permutation.rs#L85
                // Input: verifier_index
                // Output: g**(domain_size - zk_rows)
                template<typename ArithmetizationType, std::size_t... WireIndexes>
                class zk_w3;

                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                         std::size_t W13, std::size_t W14>
                class zk_w3<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, W0, W1, W2, W3,
                            W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static std::size_t exp_size = 64;
                    using exp_component =
                        zk::components::exponentiation<ArithmetizationType, exp_size, W0, W1, W2, W3, W4, W5, W6, W7,
                                                       W8, W9, W10, W11, W12, W13, W14>;

                    using verifier_index_type = kimchi_verifier_index_scalar<BlueprintFieldType>;

                    constexpr static const std::size_t zk_rows = 3;

                    constexpr static const std::size_t selector_seed = 0xf21;

                public:
                    constexpr static const std::size_t rows_amount = exp_component::rows_amount + 1;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        verifier_index_type verifier_index;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            std::size_t row = start_row_index;
                            output = typename exp_component::result_type(start_row_index + 1).output;
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        // domain.group_gen.pow(&[domain.size - (ZK_ROWS)])
                        var exponent(0, start_row_index, false, var::column_type::constant);
                        row++;    // exponent component also uses constant column
                        var res = exp_component::generate_circuit(bp, assignment,
                                                                  {params.verifier_index.omega, exponent}, row)
                                      .output;
                        row += exp_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        generate_assignments_constants(assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        // domain.group_gen.pow(&[domain.size - (ZK_ROWS)])
                        var exponent(0, start_row_index, false, var::column_type::constant);
                        row++;    // exponent component also uses constant column
                        var res = exp_component::generate_assignments(assignment,
                                                                      {params.verifier_index.omega, exponent}, row)
                                      .output;
                        row += exp_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_assignments_constants(
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = params.verifier_index.domain_size - zk_rows;
                        row++;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ZK_W3_HPP
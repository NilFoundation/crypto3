//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_SIMPLE_EXAMPLE_HPP
#define CRYPTO3_SIMPLE_EXAMPLE_HPP

#include "relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp"

#include <nil/crypto3/algebra/random_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename FieldType>
                r1cs_example<FieldType> gen_r1cs_example_from_blueprint(const std::size_t num_constraints,
                                                                        const std::size_t num_inputs);

                /* NOTE: all examples here actually generate one constraint less to account for soundness constraint in
                 * QAP */

                template<typename FieldType>
                r1cs_example<FieldType> gen_r1cs_example_from_blueprint(const std::size_t num_constraints) {
                    const std::size_t new_num_constraints = num_constraints - 1;

                    /* construct dummy example: inner products of two vectors */
                    blueprint<FieldType> bp;
                    blueprint_variable_vector<FieldType> A;
                    blueprint_variable_vector<FieldType> B;
                    blueprint_variable<FieldType> res;

                    // the variables on the blueprint are (ONE (constant 1 term), res, A[0], ..., A[num_constraints-1],
                    // B[0], ..., B[num_constraints-1])
                    res.allocate(bp);
                    A.allocate(bp, new_num_constraints);
                    B.allocate(bp, new_num_constraints);

                    inner_product<FieldType> compute_inner_product(bp, A, B, res, "compute_inner_product");
                    compute_inner_product.generate_r1cs_constraints();

                    /* fill in random example */
                    for (std::size_t i = 0; i < new_num_constraints; ++i) {
                        bp.val(A[i]) = algebra::random_element<FieldType>();
                        bp.val(B[i]) = algebra::random_element<FieldType>();
                    }

                    compute_inner_product.generate_r1cs_witness();
                    return r1cs_example<FieldType>(
                        bp.get_constraint_system(), bp.primary_input(), bp.auxiliary_input());
                }

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SIMPLE_EXAMPLE_HPP

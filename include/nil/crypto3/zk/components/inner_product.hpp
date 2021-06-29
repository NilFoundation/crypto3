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

#ifndef CRYPTO3_ZK_BLUEPRINT_INNER_PRODUCT_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_INNER_PRODUCT_COMPONENT_HPP

#include <cassert>
#include <memory>

#include <nil/crypto3/zk/components/component.hpp>

#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                /*
                  the components below are Fp specific:
                  I * X = R
                  (1-R) * X = 0

                  if X = 0 then R = 0
                  if X != 0 then R = 1 and I = X^{-1}
                */
                template<typename FieldType>
                class inner_product : public component<FieldType> {
                private:
                    /* S_i = \sum_{k=0}^{i+1} A[i] * B[i] */
                    blueprint_variable_vector<FieldType> S;

                public:
                    const blueprint_linear_combination_vector<FieldType> A;
                    const blueprint_linear_combination_vector<FieldType> B;
                    const blueprint_variable<FieldType> result;

                    inner_product(blueprint<FieldType> &bp,
                                  const blueprint_linear_combination_vector<FieldType> &A,
                                  const blueprint_linear_combination_vector<FieldType> &B,
                                  const blueprint_variable<FieldType> &result) :
                        component<FieldType>(bp),
                        A(A), B(B), result(result) {
                        assert(A.size() >= 1);
                        assert(A.size() == B.size());

                        S.allocate(bp, A.size() - 1);
                    }

                    void generate_r1cs_constraints() {
                        /*
                          S_i = \sum_{k=0}^{i+1} A[i] * B[i]
                          S[0] = A[0] * B[0]
                          S[i+1] - S[i] = A[i] * B[i]
                        */
                        for (std::size_t i = 0; i < A.size(); ++i) {
                            this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                A[i], B[i],
                                (i == A.size() - 1 ? result : S[i]) +
                                    (i == 0 ? 0 * blueprint_variable<FieldType>(0) : -S[i - 1])));
                        }
                    }

                    void generate_r1cs_witness() {
                        typename FieldType::value_type total = FieldType::value_type::zero();
                        for (std::size_t i = 0; i < A.size(); ++i) {
                            A[i].evaluate(this->bp);
                            B[i].evaluate(this->bp);

                            total += this->bp.lc_val(A[i]) * this->bp.lc_val(B[i]);
                            this->bp.val(i == A.size() - 1 ? result : S[i]) = total;
                        }
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_INNER_PRODUCT_COMPONENT_HPP

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

#ifndef CRYPTO3_ZK_BLUEPRINT_COMPARISON_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_COMPARISON_COMPONENT_HPP

#include <cassert>
#include <memory>

#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/components/disjunction.hpp>

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
                class comparison : public component<FieldType> {
                private:
                    blueprint_variable_vector<FieldType> alpha;
                    blueprint_variable<FieldType> alpha_packed;
                    std::shared_ptr<packing_component<FieldType>> pack_alpha;

                    std::shared_ptr<disjunction<FieldType>> all_zeros_test;
                    blueprint_variable<FieldType> not_all_zeros;

                public:
                    const std::size_t n;
                    const blueprint_linear_combination<FieldType> A;
                    const blueprint_linear_combination<FieldType> B;
                    const blueprint_variable<FieldType> less;
                    const blueprint_variable<FieldType> less_or_eq;

                    comparison(blueprint<FieldType> &bp,
                               std::size_t n,
                               const blueprint_linear_combination<FieldType> &A,
                               const blueprint_linear_combination<FieldType> &B,
                               const blueprint_variable<FieldType> &less,
                               const blueprint_variable<FieldType> &less_or_eq) :
                        component<FieldType>(bp),
                        n(n), A(A), B(B), less(less), less_or_eq(less_or_eq) {
                        alpha.allocate(bp, n);
                        alpha.emplace_back(less_or_eq);    // alpha[n] is less_or_eq

                        alpha_packed.allocate(bp);
                        not_all_zeros.allocate(bp);

                        pack_alpha.reset(new packing_component<FieldType>(bp, alpha, alpha_packed));

                        all_zeros_test.reset(new disjunction<FieldType>(
                            bp, blueprint_variable_vector<FieldType>(alpha.begin(), alpha.begin() + n), not_all_zeros));
                    };

                    void generate_r1cs_constraints() {
                        /*
                          packed(alpha) = 2^n + B - A

                          not_all_zeros = \bigvee_{i=0}^{n-1} alpha_i

                          if B - A > 0, then 2^n + B - A > 2^n,
                              so alpha_n = 1 and not_all_zeros = 1
                          if B - A = 0, then 2^n + B - A = 2^n,
                              so alpha_n = 1 and not_all_zeros = 0
                          if B - A < 0, then 2^n + B - A \in {0, 1, \ldots, 2^n-1},
                              so alpha_n = 0

                          therefore alpha_n = less_or_eq and alpha_n * not_all_zeros = less
                         */

                        /* not_all_zeros to be Boolean, alpha_i are Boolean by packing component */
                        generate_boolean_r1cs_constraint<FieldType>(this->bp, not_all_zeros);

                        /* constraints for packed(alpha) = 2^n + B - A */
                        pack_alpha->generate_r1cs_constraints(true);
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                            1, (typename FieldType::value_type(0x02).pow(n)) + B - A, alpha_packed));

                        /* compute result */
                        all_zeros_test->generate_r1cs_constraints();
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<FieldType>(less_or_eq, not_all_zeros, less));
                    }

                    void generate_r1cs_witness() {
                        A.evaluate(this->bp);
                        B.evaluate(this->bp);

                        /* unpack 2^n + B - A into alpha_packed */
                        this->bp.val(alpha_packed) =
                            (typename FieldType::value_type(0x02).pow(n)) + this->bp.lc_val(B) - this->bp.lc_val(A);
                        pack_alpha->generate_r1cs_witness_from_packed();

                        /* compute result */
                        all_zeros_test->generate_r1cs_witness();
                        this->bp.val(less) = this->bp.val(less_or_eq) * this->bp.val(not_all_zeros);
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_COMPARISON_COMPONENT_HPP

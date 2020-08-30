//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef SIMPLE_EXAMPLE_HPP_
#define SIMPLE_EXAMPLE_HPP_

#include "relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp"

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                r1cs_example<FieldType> gen_r1cs_example_from_protoboard(const std::size_t num_constraints,
                                                                      const std::size_t num_inputs);

                /* NOTE: all examples here actually generate one constraint less to account for soundness constraint in
                 * QAP */

                template<typename FieldType>
                r1cs_example<FieldType> gen_r1cs_example_from_protoboard(const std::size_t num_constraints) {
                    const std::size_t new_num_constraints = num_constraints - 1;

                    /* construct dummy example: inner products of two vectors */
                    protoboard<FieldType> pb;
                    pb_variable_array<FieldType> A;
                    pb_variable_array<FieldType> B;
                    pb_variable<FieldType> res;

                    // the variables on the protoboard are (ONE (constant 1 term), res, A[0], ..., A[num_constraints-1],
                    // B[0], ..., B[num_constraints-1])
                    res.allocate(pb);
                    A.allocate(pb, new_num_constraints);
                    B.allocate(pb, new_num_constraints);

                    inner_product_gadget<FieldType> compute_inner_product(pb, A, B, res, "compute_inner_product");
                    compute_inner_product.generate_r1cs_constraints();

                    /* fill in random example */
                    for (std::size_t i = 0; i < new_num_constraints; ++i) {
                        pb.val(A[i]) = random_element<FieldType>();
                        pb.val(B[i]) = random_element<FieldType>();
                    }

                    compute_inner_product.generate_r1cs_witness();
                    return r1cs_example<FieldType>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
                }

            }
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // SIMPLE_EXAMPLE_HPP_

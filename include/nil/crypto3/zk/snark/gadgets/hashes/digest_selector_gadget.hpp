//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_DIGEST_SELECTOR_GADGET_HPP_
#define CRYPTO3_ZK_DIGEST_SELECTOR_GADGET_HPP_

#include <vector>

#include <nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/hashes/hash_io.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class digest_selector_gadget : public gadget<FieldType> {
                public:
                    std::size_t digest_size;
                    digest_variable<FieldType> input;
                    pb_linear_combination<FieldType> is_right;
                    digest_variable<FieldType> left;
                    digest_variable<FieldType> right;

                    digest_selector_gadget(protoboard<FieldType> &pb,
                                           const std::size_t digest_size,
                                           const digest_variable<FieldType> &input,
                                           const pb_linear_combination<FieldType> &is_right,
                                           const digest_variable<FieldType> &left,
                                           const digest_variable<FieldType> &right);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                template<typename FieldType>
                digest_selector_gadget<FieldType>::digest_selector_gadget(
                    protoboard<FieldType> &pb,
                    const std::size_t digest_size,
                    const digest_variable<FieldType> &input,
                    const pb_linear_combination<FieldType> &is_right,
                    const digest_variable<FieldType> &left,
                    const digest_variable<FieldType> &right) :
                    gadget<FieldType>(pb),
                    digest_size(digest_size), input(input), is_right(is_right), left(left), right(right) {
                }

                template<typename FieldType>
                void digest_selector_gadget<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < digest_size; ++i) {
                        /*
                          input = is_right * right + (1-is_right) * left
                          input - left = is_right(right - left)
                        */
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            is_right, right.bits[i] - left.bits[i], input.bits[i] - left.bits[i]));
                    }
                }

                template<typename FieldType>
                void digest_selector_gadget<FieldType>::generate_r1cs_witness() {
                    is_right.evaluate(this->pb);

                    assert(this->pb.lc_val(is_right) == FieldType::one() ||
                           this->pb.lc_val(is_right) == FieldType::zero());
                    if (this->pb.lc_val(is_right) == FieldType::one()) {
                        for (std::size_t i = 0; i < digest_size; ++i) {
                            this->pb.val(right.bits[i]) = this->pb.val(input.bits[i]);
                        }
                    } else {
                        for (std::size_t i = 0; i < digest_size; ++i) {
                            this->pb.val(left.bits[i]) = this->pb.val(input.bits[i]);
                        }
                    }
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // DIGEST_SELECTOR_GADGET_HPP_

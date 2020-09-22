//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_DIGEST_SELECTOR_COMPONENT_HPP
#define CRYPTO3_ZK_DIGEST_SELECTOR_COMPONENT_HPP

#include <vector>

#include <nil/crypto3/zk/snark/components/basic_components.hpp>
#include <nil/crypto3/zk/snark/components/hashes/hash_io.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class digest_selector_component : public component<FieldType> {
                public:
                    std::size_t digest_size;
                    digest_variable<FieldType> input;
                    blueprint_linear_combination<FieldType> is_right;
                    digest_variable<FieldType> left;
                    digest_variable<FieldType> right;

                    digest_selector_component(blueprint<FieldType> &pb,
                                           const std::size_t digest_size,
                                           const digest_variable<FieldType> &input,
                                           const blueprint_linear_combination<FieldType> &is_right,
                                           const digest_variable<FieldType> &left,
                                           const digest_variable<FieldType> &right) :
                        component<FieldType>(pb),
                        digest_size(digest_size), input(input), is_right(is_right), left(left), right(right) {
                    }

                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < digest_size; ++i) {
                            /*
                              input = is_right * right + (1-is_right) * left
                              input - left = is_right(right - left)
                            */
                            this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                                is_right, right.bits[i] - left.bits[i], input.bits[i] - left.bits[i]));
                        }
                    }
                    void generate_r1cs_witness() {
                        is_right.evaluate(this->pb);

                        assert(this->pb.lc_val(is_right) == FieldType::value_type::zero() ||
                               this->pb.lc_val(is_right) == FieldType::value_type::zero());
                        if (this->pb.lc_val(is_right) == FieldType::value_type::zero()) {
                            for (std::size_t i = 0; i < digest_size; ++i) {
                                this->pb.val(right.bits[i]) = this->pb.val(input.bits[i]);
                            }
                        } else {
                            for (std::size_t i = 0; i < digest_size; ++i) {
                                this->pb.val(left.bits[i]) = this->pb.val(input.bits[i]);
                            }
                        }
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_DIGEST_SELECTOR_COMPONENT_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_DIGEST_SELECTOR_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_DIGEST_SELECTOR_COMPONENT_HPP

#include <vector>

#include <nil/crypto3/zk/components/hashes/hash_io.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename FieldType>
                class digest_selector_component : public component<FieldType> {
                public:
                    std::size_t digest_size;
                    digest_variable<FieldType> input;
                    detail::blueprint_linear_combination<FieldType> is_right;
                    digest_variable<FieldType> left;
                    digest_variable<FieldType> right;

                    digest_selector_component(blueprint<FieldType> &bp,
                                              const std::size_t digest_size,
                                              const digest_variable<FieldType> &input,
                                              const detail::blueprint_linear_combination<FieldType> &is_right,
                                              const digest_variable<FieldType> &left,
                                              const digest_variable<FieldType> &right) :
                        component<FieldType>(bp),
                        digest_size(digest_size), input(input), is_right(is_right), left(left), right(right) {
                    }

                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < digest_size; ++i) {
                            /*
                              input = is_right * right + (1-is_right) * left
                              input - left = is_right(right - left)
                            */
                            this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                is_right, right.bits[i] - left.bits[i], input.bits[i] - left.bits[i]));
                        }
                    }
                    void generate_r1cs_witness() {
                        is_right.evaluate(this->bp);

                        assert(this->bp.lc_val(is_right) == FieldType::value_type::one() ||
                               this->bp.lc_val(is_right) == FieldType::value_type::zero());
                        if (this->bp.lc_val(is_right) == FieldType::value_type::one()) {
                            for (std::size_t i = 0; i < digest_size; ++i) {
                                this->bp.val(right.bits[i]) = this->bp.val(input.bits[i]);
                            }
                        } else {
                            for (std::size_t i = 0; i < digest_size; ++i) {
                                this->bp.val(left.bits[i]) = this->bp.val(input.bits[i]);
                            }
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_DIGEST_SELECTOR_COMPONENT_HPP

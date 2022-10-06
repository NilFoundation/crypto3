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

#ifndef CRYPTO3_ZK_BLUEPRINT_HASH_IO_HPP
#define CRYPTO3_ZK_BLUEPRINT_HASH_IO_HPP

#include <cstddef>
#include <vector>

#include <nil/crypto3/zk/components/packing.hpp>
#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/blueprint/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename FieldType>
                class digest_variable : public component<FieldType> {
                public:
                    std::size_t digest_size;
                    detail::blueprint_variable_vector<FieldType> bits;

                    digest_variable(blueprint<FieldType> &bp, std::size_t digest_size) :
                        component<FieldType>(bp), digest_size(digest_size) {

                        bits.allocate(bp, digest_size);
                    }

                    digest_variable(blueprint<FieldType> &bp,
                                    std::size_t digest_size,
                                    const detail::blueprint_variable_vector<FieldType> &partial_bits,
                                    const detail::blueprint_variable<FieldType> &padding) :
                        component<FieldType>(bp),
                        digest_size(digest_size) {

                        assert(bits.size() <= digest_size);
                        bits = partial_bits;
                        while (bits.size() != digest_size) {
                            bits.emplace_back(padding);
                        }
                    }

                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < digest_size; ++i) {
                            generate_boolean_r1cs_constraint<FieldType>(this->bp, bits[i]);
                        }
                    }

                    void generate_r1cs_witness(const std::vector<bool> &contents) {
                        bits.fill_with_bits(this->bp, contents);
                    }

                    std::vector<bool> get_digest() const {
                        return bits.bits(this->bp);
                    }
                };

                template<typename FieldType>
                class block_variable : public component<FieldType> {
                public:
                    std::size_t block_size;
                    detail::blueprint_variable_vector<FieldType> bits;

                    block_variable(blueprint<FieldType> &bp, std::size_t block_size) :
                        component<FieldType>(bp), block_size(block_size) {
                        bits.allocate(bp, block_size);
                    }

                    block_variable(blueprint<FieldType> &bp,
                                   const std::vector<detail::blueprint_variable_vector<FieldType>> &parts) :
                        component<FieldType>(bp) {

                        for (auto &part : parts) {
                            bits.insert(bits.end(), part.begin(), part.end());
                        }
                        block_size = bits.size();
                    }

                    block_variable(blueprint<FieldType> &bp,
                                   const digest_variable<FieldType> &left,
                                   const digest_variable<FieldType> &right) :
                        component<FieldType>(bp) {

                        assert(left.bits.size() == right.bits.size());
                        block_size = 2 * left.bits.size();
                        bits.insert(bits.end(), left.bits.begin(), left.bits.end());
                        bits.insert(bits.end(), right.bits.begin(), right.bits.end());
                    }

                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < block_size; ++i) {
                            generate_boolean_r1cs_constraint<FieldType>(this->bp, bits[i]);
                        }
                    }

                    template<typename InputRange>
                    void generate_r1cs_witness(const InputRange &contents) {
                        bits.fill_with_bits(this->bp, contents);
                    }

                    std::vector<bool> get_block() const {
                        return bits.bits(this->bp);
                    }
                };

                template<typename FieldType>
                class merkle_damagard_padding : public component<FieldType> {
                public:
                    detail::blueprint_variable_vector<FieldType> bits;
                    detail::blueprint_variable<FieldType> one;
                    detail::blueprint_variable<FieldType> zero;

                    merkle_damagard_padding(blueprint<FieldType> &bp,
                                            size_t message_length,
                                            size_t message_length_bits_size,
                                            size_t block_bits) :
                        component<FieldType>(bp) {
                        assert(message_length_bits_size <= block_bits);
                        one.allocate(bp);
                        zero.allocate(bp);
                        std::size_t message_remainder = message_length % block_bits;
                        size_t padding_length = 2 * block_bits - message_remainder - message_length_bits_size;
                        padding_length = padding_length % block_bits;

                        bits.resize(padding_length + message_length_bits_size);
                        if (padding_length > 0) {
                            bits[0] = one;
                            for (size_t i = 1; i < padding_length; ++i) {
                                bits[i] = zero;
                            }
                        }

                        unsigned long long message_length_iter = message_length;
                        for (int i = message_length_bits_size - 1; i >= 0; --i) {
                            bits[padding_length + i] = (message_length_iter & 1 ? one : zero);
                            message_length_iter = message_length_iter >> 1;
                        }
                        assert(message_length_iter == 0);
                    }

                    void generate_r1cs_constraints() {
                        generate_r1cs_equals_const_constraint<FieldType>(this->bp, one, FieldType::value_type::one());
                        generate_r1cs_equals_const_constraint<FieldType>(this->bp, zero, FieldType::value_type::zero());
                    }

                    void generate_r1cs_witness() {
                        this->bp.val(one) = 1;
                        this->bp.val(zero) = 0;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_BLUEPRINT_HASH_IO_HPP

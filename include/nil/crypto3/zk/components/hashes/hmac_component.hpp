//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_HMAC_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_HMAC_COMPONENT_HPP

#include <nil/crypto3/zk/components/hashes/hash_io.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename FieldType, typename Hash1, typename Hash2 = Hash1>
                class hmac_component : component<FieldType> {
                    static_assert(std::is_same<typename Hash1::hash_value_type, std::vector<bool>>::value);

                public:
                    blueprint_variable_vector<FieldType> padded_key;
                    blueprint_variable_vector<FieldType> key_xor_ipad;
                    blueprint_variable_vector<FieldType> key_xor_opad;
                    std::shared_ptr<Hash1> hash1;
                    std::shared_ptr<digest_variable<FieldType>> hash1_result;
                    std::shared_ptr<Hash2> hash2;
                    blueprint_variable<FieldType> zero;

                public:
                    hmac_component(blueprint<FieldType> &bp,
                                   const block_variable<FieldType> &key,
                                   const block_variable<FieldType> &message,
                                   const typename Hash2::hash_variable_type &output) :
                        component<FieldType>(bp) {
                        assert(Hash1::get_block_len() == Hash2::get_block_len());
                        assert(Hash1::get_block_len() == 0 || key.block_size <= Hash1::get_block_len());

                        std::size_t padded_key_size =
                            (Hash1::get_block_len() != 0 ? Hash1::get_block_len() : key.block_size);
                        zero.allocate(bp);
                        blueprint_variable_vector<FieldType> padding(padded_key_size - key.block_size, zero);
                        padded_key.reserve(padded_key_size);
                        padded_key.insert(padded_key.end(), key.bits.begin(), key.bits.end());
                        padded_key.insert(padded_key.end(), padding.begin(), padding.end());

                        key_xor_ipad.allocate(bp, padded_key_size);
                        key_xor_opad.allocate(bp, padded_key_size);

                        block_variable<FieldType> iblock(bp, {key_xor_ipad, message.bits});
                        hash1_result.reset(new digest_variable<FieldType>(bp, Hash1::get_digest_len()));
                        hash1.reset(new Hash1(bp, iblock.block_size, iblock, *hash1_result));

                        block_variable<FieldType> oblock(bp, {key_xor_opad, hash1_result->bits});
                        hash2.reset(new Hash2(bp, oblock.block_size, oblock, output));
                    }

                    void generate_r1cs_constraints() {
                        generate_r1cs_equals_const_constraint<FieldType>(this->bp, zero, FieldType::value_type::zero());
                        generate_xor_constraints(0x36, padded_key, key_xor_ipad);
                        generate_xor_constraints(0x5c, padded_key, key_xor_opad);
                        hash1->generate_r1cs_constraints();
                        hash2->generate_r1cs_constraints();
                    }

                    void generate_r1cs_witness() {
                        this->bp.val(zero) = FieldType::value_type::zero();
                        generate_xor_witness(0x36, padded_key, key_xor_ipad);
                        generate_xor_witness(0x5c, padded_key, key_xor_opad);
                        hash1->generate_r1cs_witness();
                        hash2->generate_r1cs_witness();
                    }

                    static typename Hash2::hash_value_type get_hmac(const std::vector<bool> &key,
                                                                    const std::vector<bool> &message) {
                        assert(Hash1::get_block_len() == Hash2::get_block_len());
                        assert(Hash1::get_block_len() == 0 || key.size() <= Hash1::get_block_len());

                        std::size_t padded_key_size =
                            (Hash1::get_block_len() != 0 ? Hash1::get_block_len() : key.size());

                        std::vector<bool> padded_key;
                        padded_key.reserve(padded_key_size);
                        padded_key.insert(padded_key.end(), key.begin(), key.end());
                        padded_key.insert(padded_key.end(), padded_key_size - key.size(), false);

                        std::vector<bool> ipad_bits = unpack_byte(0x36);
                        std::vector<bool> opad_bits = unpack_byte(0x5c);
                        std::vector<bool> key_xor_ipad(padded_key_size);
                        std::vector<bool> key_xor_opad(padded_key_size);

                        for (std::size_t i = 0; i < padded_key_size; ++i) {
                            key_xor_ipad[i] = padded_key[i] != ipad_bits[i % 8];
                            key_xor_opad[i] = padded_key[i] != opad_bits[i % 8];
                        }

                        std::vector<bool> hash1_input;
                        hash1_input.reserve(padded_key_size + message.size());
                        hash1_input.insert(hash1_input.end(), key_xor_ipad.begin(), key_xor_ipad.end());
                        hash1_input.insert(hash1_input.end(), message.begin(), message.end());
                        std::vector<bool> hash1_output = Hash1::get_hash(hash1_input);

                        std::vector<bool> hash2_input;
                        hash2_input.reserve(padded_key_size + hash1_output.size());
                        hash2_input.insert(hash2_input.end(), key_xor_opad.begin(), key_xor_opad.end());
                        hash2_input.insert(hash2_input.end(), hash1_output.begin(), hash1_output.end());
                        return Hash2::get_hash(hash2_input);
                    }

                private:
                    void generate_xor_constraints(std::uint8_t xor_pad,
                                                  const blueprint_variable_vector<FieldType> &input,
                                                  const blueprint_variable_vector<FieldType> &output) {
                        assert(input.size() == output.size());
                        std::vector<bool> xor_pad_bits = unpack_byte(xor_pad);
                        for (std::size_t i = 0; i < input.size(); ++i) {
                            // x xor 0 = x
                            // x xor 1 = !x
                            if (!xor_pad_bits[i % 8]) {
                                this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(1, input[i], output[i]));
                            } else {
                                this->bp.add_r1cs_constraint(
                                    snark::r1cs_constraint<FieldType>(1, 1 - input[i], output[i]));
                            }
                        }
                    }

                    void generate_xor_witness(std::uint8_t xor_pad,
                                              const blueprint_variable_vector<FieldType> &input,
                                              const blueprint_variable_vector<FieldType> &output) {
                        assert(input.size() == output.size());
                        std::vector<bool> xor_pad_bits = unpack_byte(xor_pad);
                        for (std::size_t i = 0; i < input.size(); ++i) {
                            // x xor 0 = x
                            // x xor 1 = !x
                            if (!xor_pad_bits[i % 8]) {
                                this->bp.val(output[i]) = this->bp.val(input[i]);
                            } else {
                                this->bp.val(output[i]) = (this->bp.val(input[i]) == 0 ? 1 : 0);
                            }
                        }
                    }

                    static std::vector<bool> unpack_byte(std::uint8_t byte) {
                        std::vector<bool> bits(8);
                        for (std::size_t i = 0; i < 8; ++i) {
                            bits[7 - i] = byte & (1 << i);
                        }
                        return bits;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_HMAC_COMPONENT_HPP

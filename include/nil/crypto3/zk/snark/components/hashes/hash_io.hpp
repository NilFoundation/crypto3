//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_HASH_IO_HPP
#define CRYPTO3_ZK_HASH_IO_HPP

#include <cstddef>
#include <vector>

#include <nil/crypto3/zk/snark/components/basic_components.hpp>

#include <nil/crypto3/zk/snark/blueprint.hpp>
#include <nil/crypto3/zk/snark/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class digest_variable : public component<FieldType> {
                public:
                    std::size_t digest_size;
                    blueprint_variable_vector<FieldType> bits;

                    digest_variable(blueprint<FieldType> &bp, std::size_t digest_size) :
                        component<FieldType>(bp), digest_size(digest_size) {

                        bits.allocate(bp, digest_size);
                    }

                    digest_variable(blueprint<FieldType> &bp,
                                    std::size_t digest_size,
                                    const blueprint_variable_vector<FieldType> &partial_bits,
                                    const blueprint_variable<FieldType> &padding) :
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
                        return bits.get_bits(this->bp);
                    }
                };

                template<typename FieldType>
                class block_variable : public component<FieldType> {
                public:
                    std::size_t block_size;
                    blueprint_variable_vector<FieldType> bits;

                    block_variable(blueprint<FieldType> &bp, std::size_t block_size) :
                        component<FieldType>(bp), block_size(block_size) {
                        bits.allocate(bp, block_size);
                    }

                    block_variable(blueprint<FieldType> &bp,
                                   const std::vector<blueprint_variable_vector<FieldType>> &parts) :
                        component<FieldType>(bp) {

                        for (auto &part : parts) {
                            bits.insert(bits.end(), part.begin(), part.end());
                        }
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

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(const std::vector<bool> &contents) {
                        bits.fill_with_bits(this->bp, contents);
                    }

                    std::vector<bool> get_block() const {
                        return bits.get_bits(this->bp);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ZK_HASH_IO_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_HASH_IO_HPP_
#define CRYPTO3_ZK_HASH_IO_HPP_

#include <cstddef>
#include <vector>

#include <nil/crypto3/zk/snark/components/basic_components.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class digest_variable : public component<FieldType> {
                public:
                    std::size_t digest_size;
                    pb_variable_array<FieldType> bits;

                    digest_variable<FieldType>(blueprint<FieldType> &pb, std::size_t digest_size);

                    digest_variable<FieldType>(blueprint<FieldType> &pb,
                                               std::size_t digest_size,
                                               const pb_variable_array<FieldType> &partial_bits,
                                               const variable<FieldType> &padding);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(const std::vector<bool> &contents);
                    std::vector<bool> get_digest() const;
                };

                template<typename FieldType>
                class block_variable : public component<FieldType> {
                public:
                    std::size_t block_size;
                    pb_variable_array<FieldType> bits;

                    block_variable(blueprint<FieldType> &pb, std::size_t block_size);

                    block_variable(blueprint<FieldType> &pb, const std::vector<pb_variable_array<FieldType>> &parts);

                    block_variable(blueprint<FieldType> &pb,
                                   const digest_variable<FieldType> &left,
                                   const digest_variable<FieldType> &right);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(const std::vector<bool> &contents);
                    std::vector<bool> get_block() const;
                };

                template<typename FieldType>
                digest_variable<FieldType>::digest_variable(blueprint<FieldType> &pb, std::size_t digest_size) :
                    component<FieldType>(pb), digest_size(digest_size) {
                    bits.allocate(pb, digest_size);
                }

                template<typename FieldType>
                digest_variable<FieldType>::digest_variable(blueprint<FieldType> &pb,
                                                            std::size_t digest_size,
                                                            const pb_variable_array<FieldType> &partial_bits,
                                                            const variable<FieldType> &padding) :
                    component<FieldType>(pb),
                    digest_size(digest_size) {
                    assert(bits.size() <= digest_size);
                    bits = partial_bits;
                    while (bits.size() != digest_size) {
                        bits.emplace_back(padding);
                    }
                }

                template<typename FieldType>
                void digest_variable<FieldType>::generate_r1cs_constraints() {
                    for (std::size_t i = 0; i < digest_size; ++i) {
                        generate_boolean_r1cs_constraint<FieldType>(this->pb, bits[i]);
                    }
                }

                template<typename FieldType>
                void digest_variable<FieldType>::generate_r1cs_witness(const std::vector<bool> &contents) {
                    bits.fill_with_bits(this->pb, contents);
                }

                template<typename FieldType>
                std::vector<bool> digest_variable<FieldType>::get_digest() const {
                    return bits.get_bits(this->pb);
                }

                template<typename FieldType>
                block_variable<FieldType>::block_variable(blueprint<FieldType> &pb, std::size_t block_size) :
                    component<FieldType>(pb), block_size(block_size) {
                    bits.allocate(pb, block_size);
                }

                template<typename FieldType>
                block_variable<FieldType>::block_variable(blueprint<FieldType> &pb,
                                                          const std::vector<pb_variable_array<FieldType>> &parts) :
                    component<FieldType>(pb) {
                    for (auto &part : parts) {
                        bits.insert(bits.end(), part.begin(), part.end());
                    }
                }

                template<typename FieldType>
                block_variable<FieldType>::block_variable(blueprint<FieldType> &pb,
                                                          const digest_variable<FieldType> &left,
                                                          const digest_variable<FieldType> &right) :
                    component<FieldType>(pb) {
                    assert(left.bits.size() == right.bits.size());
                    block_size = 2 * left.bits.size();
                    bits.insert(bits.end(), left.bits.begin(), left.bits.end());
                    bits.insert(bits.end(), right.bits.begin(), right.bits.end());
                }

                template<typename FieldType>
                void block_variable<FieldType>::generate_r1cs_witness(const std::vector<bool> &contents) {
                    bits.fill_with_bits(this->pb, contents);
                }

                template<typename FieldType>
                std::vector<bool> block_variable<FieldType>::get_block() const {
                    return bits.get_bits(this->pb);
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // HASH_IO_HPP_

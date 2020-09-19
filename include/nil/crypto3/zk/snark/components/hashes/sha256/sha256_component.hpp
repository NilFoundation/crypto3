//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for top-level SHA256 gadgets.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_SHA256_GADGET_HPP
#define CRYPTO3_ZK_SHA256_GADGET_HPP

#include <nil/crypto3/zk/snark/merkle_tree.hpp>
#include <nil/crypto3/zk/snark/components/basic_components.hpp>
#include <nil/crypto3/zk/snark/components/hashes/hash_io.hpp>
#include <nil/crypto3/zk/snark/components/hashes/sha256/sha256_construction.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Gadget for the SHA256 compression function.
                 */
                template<typename FieldType>
                class sha256_compression_function_component : public component<FieldType> {
                public:
                    std::vector<pb_linear_combination_array<FieldType>> round_a;
                    std::vector<pb_linear_combination_array<FieldType>> round_b;
                    std::vector<pb_linear_combination_array<FieldType>> round_c;
                    std::vector<pb_linear_combination_array<FieldType>> round_d;
                    std::vector<pb_linear_combination_array<FieldType>> round_e;
                    std::vector<pb_linear_combination_array<FieldType>> round_f;
                    std::vector<pb_linear_combination_array<FieldType>> round_g;
                    std::vector<pb_linear_combination_array<FieldType>> round_h;

                    pb_variable_array<FieldType> packed_W;
                    std::shared_ptr<sha256_message_schedule_component<FieldType>> message_schedule;
                    std::vector<sha256_round_function_component<FieldType>> round_functions;

                    pb_variable_array<FieldType> unreduced_output;
                    pb_variable_array<FieldType> reduced_output;
                    std::vector<lastbits_component<FieldType>> reduce_output;

                public:
                    pb_linear_combination_array<FieldType> prev_output;
                    pb_variable_array<FieldType> new_block;
                    digest_variable<FieldType> output;

                    sha256_compression_function_component(blueprint<FieldType> &pb,
                                                       const pb_linear_combination_array<FieldType> &prev_output,
                                                       const pb_variable_array<FieldType> &new_block,
                                                       const digest_variable<FieldType> &output);
                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();
                };

                /**
                 * Gadget for the SHA256 compression function, viewed as a 2-to-1 hash
                 * function, and using the same initialization vector as in SHA256
                 * specification. Thus, any collision for
                 * sha256_two_to_one_hash_component trivially extends to a collision for
                 * full SHA256 (by appending the same padding).
                 */
                template<typename FieldType>
                class sha256_two_to_one_hash_component : public component<FieldType> {
                public:
                    typedef std::vector<bool> hash_value_type;
                    typedef merkle_authentication_path merkle_authentication_path_type;

                    std::shared_ptr<sha256_compression_function_component<FieldType>> f;

                    sha256_two_to_one_hash_component(blueprint<FieldType> &pb,
                                                  const digest_variable<FieldType> &left,
                                                  const digest_variable<FieldType> &right,
                                                  const digest_variable<FieldType> &output);
                    sha256_two_to_one_hash_component(blueprint<FieldType> &pb,
                                                  size_t block_length,
                                                  const block_variable<FieldType> &input_block,
                                                  const digest_variable<FieldType> &output);

                    void generate_r1cs_constraints(bool ensure_output_bitness = true);    // TODO: ignored for now
                    void generate_r1cs_witness();

                    static std::size_t get_block_len();
                    static std::size_t get_digest_len();
                    static std::vector<bool> get_hash(const std::vector<bool> &input);

                    static std::size_t
                        expected_constraints(bool ensure_output_bitness = true);    // TODO: ignored for now
                };

                template<typename FieldType>
                sha256_compression_function_component<FieldType>::sha256_compression_function_component(
                    blueprint<FieldType> &pb,
                    const pb_linear_combination_array<FieldType> &prev_output,
                    const pb_variable_array<FieldType> &new_block,
                    const digest_variable<FieldType> &output) :
                    component<FieldType>(pb),
                    prev_output(prev_output), new_block(new_block), output(output) {
                    /* message schedule and inputs for it */
                    packed_W.allocate(pb, block::detail::shacal2_policy<256>::rounds);
                    message_schedule.reset(new sha256_message_schedule_component<FieldType>(pb, new_block, packed_W));

                    /* initalize */
                    round_a.push_back(pb_linear_combination_array<FieldType>(
                        prev_output.rbegin() + 7 * hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 8 * hashes::sha2<256>::word_bits));
                    round_b.push_back(pb_linear_combination_array<FieldType>(
                        prev_output.rbegin() + 6 * hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 7 * hashes::sha2<256>::word_bits));
                    round_c.push_back(pb_linear_combination_array<FieldType>(
                        prev_output.rbegin() + 5 * hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 6 * hashes::sha2<256>::word_bits));
                    round_d.push_back(pb_linear_combination_array<FieldType>(
                        prev_output.rbegin() + 4 * hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 5 * hashes::sha2<256>::word_bits));
                    round_e.push_back(pb_linear_combination_array<FieldType>(
                        prev_output.rbegin() + 3 * hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 4 * hashes::sha2<256>::word_bits));
                    round_f.push_back(pb_linear_combination_array<FieldType>(
                        prev_output.rbegin() + 2 * hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 3 * hashes::sha2<256>::word_bits));
                    round_g.push_back(pb_linear_combination_array<FieldType>(
                        prev_output.rbegin() + 1 * hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 2 * hashes::sha2<256>::word_bits));
                    round_h.push_back(pb_linear_combination_array<FieldType>(
                        prev_output.rbegin() + 0 * hashes::sha2<256>::word_bits,
                        prev_output.rbegin() + 1 * hashes::sha2<256>::word_bits));

                    /* do the rounds */
                    for (std::size_t i = 0; i < block::detail::shacal2_policy<256>::rounds; ++i) {
                        round_h.push_back(round_g[i]);
                        round_g.push_back(round_f[i]);
                        round_f.push_back(round_e[i]);
                        round_d.push_back(round_c[i]);
                        round_c.push_back(round_b[i]);
                        round_b.push_back(round_a[i]);

                        pb_variable_array<FieldType> new_round_a_variables;
                        new_round_a_variables.allocate(pb, hashes::sha2<256>::word_bits);
                        round_a.emplace_back(new_round_a_variables);

                        pb_variable_array<FieldType> new_round_e_variables;
                        new_round_e_variables.allocate(pb, hashes::sha2<256>::word_bits);
                        round_e.emplace_back(new_round_e_variables);

                        round_functions.push_back(sha256_round_function_component<FieldType>(
                            pb, round_a[i], round_b[i], round_c[i], round_d[i], round_e[i], round_f[i], round_g[i],
                            round_h[i], packed_W[i], block::detail::shacal2_policy<256>::constants[i], round_a[i + 1],
                            round_e[i + 1]));
                    }

                    /* finalize */
                    unreduced_output.allocate(pb, 8);
                    reduced_output.allocate(pb, 8);
                    for (std::size_t i = 0; i < 8; ++i) {
                        reduce_output.push_back(lastbits_component<FieldType>(
                            pb,
                            unreduced_output[i],
                            hashes::sha2<256>::word_bits + 1,
                            reduced_output[i],
                            pb_variable_array<FieldType>(output.bits.rbegin() + (7 - i) * hashes::sha2<256>::word_bits,
                                                         output.bits.rbegin() +
                                                             (8 - i) * hashes::sha2<256>::word_bits)));
                    }
                }

                template<typename FieldType>
                void sha256_compression_function_component<FieldType>::generate_r1cs_constraints() {
                    message_schedule->generate_r1cs_constraints();
                    for (std::size_t i = 0; i < block::detail::shacal2_policy<256>::rounds; ++i) {
                        round_functions[i].generate_r1cs_constraints();
                    }

                    for (std::size_t i = 0; i < 4; ++i) {
                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            1,
                            round_functions[3 - i].packed_d + round_functions[63 - i].packed_new_a,
                            unreduced_output[i]));

                        this->pb.add_r1cs_constraint(r1cs_constraint<FieldType>(
                            1,
                            round_functions[3 - i].packed_h + round_functions[63 - i].packed_new_e,
                            unreduced_output[4 + i]));
                    }

                    for (std::size_t i = 0; i < 8; ++i) {
                        reduce_output[i].generate_r1cs_constraints();
                    }
                }

                template<typename FieldType>
                void sha256_compression_function_component<FieldType>::generate_r1cs_witness() {
                    message_schedule->generate_r1cs_witness();

                    for (std::size_t i = 0; i < block::detail::shacal2_policy<256>::rounds; ++i) {
                        round_functions[i].generate_r1cs_witness();
                    }

                    for (std::size_t i = 0; i < 4; ++i) {
                        this->pb.val(unreduced_output[i]) = this->pb.val(round_functions[3 - i].packed_d) +
                                                            this->pb.val(round_functions[63 - i].packed_new_a);
                        this->pb.val(unreduced_output[4 + i]) = this->pb.val(round_functions[3 - i].packed_h) +
                                                                this->pb.val(round_functions[63 - i].packed_new_e);
                    }

                    for (std::size_t i = 0; i < 8; ++i) {
                        reduce_output[i].generate_r1cs_witness();
                    }
                }

                template<typename FieldType>
                sha256_two_to_one_hash_component<FieldType>::sha256_two_to_one_hash_component(
                    blueprint<FieldType> &pb,
                    const digest_variable<FieldType> &left,
                    const digest_variable<FieldType> &right,
                    const digest_variable<FieldType> &output) :
                    component<FieldType>(pb) {
                    /* concatenate block = left || right */
                    pb_variable_array<FieldType> block;
                    block.insert(block.end(), left.bits.begin(), left.bits.end());
                    block.insert(block.end(), right.bits.begin(), right.bits.end());

                    /* compute the hash itself */
                    f.reset(new sha256_compression_function_component<FieldType>(pb, SHA256_default_IV<FieldType>(pb),
                                                                                 block, output));
                }

                template<typename FieldType>
                sha256_two_to_one_hash_component<FieldType>::sha256_two_to_one_hash_component(
                    blueprint<FieldType> &pb,
                    size_t block_length,
                    const block_variable<FieldType> &input_block,
                    const digest_variable<FieldType> &output) :
                    component<FieldType>(pb) {
                    assert(block_length == hashes::sha2<256>::block_bits);
                    assert(input_block.bits.size() == block_length);
                    f.reset(new sha256_compression_function_component<FieldType>(pb, SHA256_default_IV<FieldType>(pb),
                                                                                 input_block.bits, output));
                }

                template<typename FieldType>
                void sha256_two_to_one_hash_component<FieldType>::generate_r1cs_constraints(
                    BOOST_ATTRIBUTE_UNUSED bool ensure_output_bitness) {
                    f->generate_r1cs_constraints();
                }

                template<typename FieldType>
                void sha256_two_to_one_hash_component<FieldType>::generate_r1cs_witness() {
                    f->generate_r1cs_witness();
                }

                template<typename FieldType>
                std::size_t sha256_two_to_one_hash_component<FieldType>::get_block_len() {
                    return hashes::sha2<256>::block_bits;
                }

                template<typename FieldType>
                std::size_t sha256_two_to_one_hash_component<FieldType>::get_digest_len() {
                    return hashes::sha2<256>::digest_bits;
                }

                template<typename FieldType>
                std::vector<bool>
                    sha256_two_to_one_hash_component<FieldType>::get_hash(const std::vector<bool> &input) {
                    blueprint<FieldType> pb;

                    block_variable<FieldType> input_variable(pb, hashes::sha2<256>::block_bits);
                    digest_variable<FieldType> output_variable(pb, hashes::sha2<256>::digest_bits);
                    sha256_two_to_one_hash_component<FieldType> f(pb, hashes::sha2<256>::block_bits, input_variable,
                                                                  output_variable);

                    input_variable.generate_r1cs_witness(input);
                    f.generate_r1cs_witness();

                    return output_variable.get_digest();
                }

                template<typename FieldType>
                std::size_t sha256_two_to_one_hash_component<FieldType>::expected_constraints(
                    BOOST_ATTRIBUTE_UNUSED bool ensure_output_bitness) {
                    return 27280; /* hardcoded for now */
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SHA256_GADGET_HPP

//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the Merkle tree check read gadget.
//
// The gadget checks the following: given a root R, address A, value V, and
// authentication path P, check that P is a valid authentication path for the
// value V as the A-th leaf in a Merkle tree with root R.
//---------------------------------------------------------------------------//

#ifndef MERKLE_TREE_CHECK_READ_GADGET_HPP_
#define MERKLE_TREE_CHECK_READ_GADGET_HPP_

#include <nil/crypto3/zk/snark/merkle_tree.hpp>
#include <nil/crypto3/zk/snark/gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/hashes/crh_gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/hashes/digest_selector_gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/hashes/hash_io.hpp>
#include <nil/crypto3/zk/snark/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename Hash>
                class merkle_tree_check_read_gadget : public gadget<FieldType> {
                private:
                    std::vector<Hash> hashers;
                    std::vector<block_variable<FieldType>> hasher_inputs;
                    std::vector<digest_selector_gadget<FieldType>> propagators;
                    std::vector<digest_variable<FieldType>> internal_output;

                    std::shared_ptr<digest_variable<FieldType>> computed_root;
                    std::shared_ptr<bit_vector_copy_gadget<FieldType>> check_root;

                public:
                    const std::size_t digest_size;
                    const std::size_t tree_depth;
                    pb_linear_combination_array<FieldType> address_bits;
                    digest_variable<FieldType> leaf;
                    digest_variable<FieldType> root;
                    merkle_authentication_path_variable<FieldType, Hash> path;
                    pb_linear_combination<FieldType> read_successful;

                    merkle_tree_check_read_gadget(protoboard<FieldType> &pb,
                                                  const std::size_t tree_depth,
                                                  const pb_linear_combination_array<FieldType> &address_bits,
                                                  const digest_variable<FieldType> &leaf_digest,
                                                  const digest_variable<FieldType> &root_digest,
                                                  const merkle_authentication_path_variable<FieldType, Hash> &path,
                                                  const pb_linear_combination<FieldType> &read_successful);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();

                    static std::size_t root_size_in_bits();
                    /* for debugging purposes */
                    static std::size_t expected_constraints(const std::size_t tree_depth);
                };

                template<typename FieldType, typename Hash>
                void test_merkle_tree_check_read_gadget();

                template<typename FieldType, typename Hash>
                merkle_tree_check_read_gadget<FieldType, Hash>::merkle_tree_check_read_gadget(
                    protoboard<FieldType> &pb,
                    const std::size_t tree_depth,
                    const pb_linear_combination_array<FieldType> &address_bits,
                    const digest_variable<FieldType> &leaf,
                    const digest_variable<FieldType> &root,
                    const merkle_authentication_path_variable<FieldType, Hash> &path,
                    const pb_linear_combination<FieldType> &read_successful) :
                    gadget<FieldType>(pb),
                    digest_size(Hash::get_digest_len()), tree_depth(tree_depth), address_bits(address_bits),
                    leaf(leaf), root(root), path(path), read_successful(read_successful) {
                    /*
                       The tricky part here is ordering. For Merkle tree
                       authentication paths, path[0] corresponds to one layer below
                       the root (and path[tree_depth-1] corresponds to the layer
                       containing the leaf), while address_bits has the reverse order:
                       address_bits[0] is LSB, and corresponds to layer containing the
                       leaf, and address_bits[tree_depth-1] is MSB, and corresponds to
                       the subtree directly under the root.
                    */
                    assert(tree_depth > 0);
                    assert(tree_depth == address_bits.size());

                    for (std::size_t i = 0; i < tree_depth - 1; ++i) {
                        internal_output.emplace_back(digest_variable<FieldType>(pb, digest_size));
                    }

                    computed_root.reset(new digest_variable<FieldType>(pb, digest_size));

                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        block_variable<FieldType> inp(pb, path.left_digests[i], path.right_digests[i]);
                        hasher_inputs.emplace_back(inp);
                        hashers.emplace_back(
                            Hash(pb, 2 * digest_size, inp, (i == 0 ? *computed_root : internal_output[i - 1])));
                    }

                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        /*
                          The propagators take a computed hash value (or leaf in the
                          base case) and propagate it one layer up, either in the left
                          or the right slot of authentication_path_variable.
                        */
                        propagators.emplace_back(digest_selector_gadget<FieldType>(
                            pb, digest_size, i < tree_depth - 1 ? internal_output[i] : leaf,
                            address_bits[tree_depth - 1 - i], path.left_digests[i], path.right_digests[i]));
                    }

                    check_root.reset(new bit_vector_copy_gadget<FieldType>(pb, computed_root->bits, root.bits,
                                                                           read_successful, FieldType::capacity()));
                }

                template<typename FieldType, typename Hash>
                void merkle_tree_check_read_gadget<FieldType, Hash>::generate_r1cs_constraints() {
                    /* ensure correct hash computations */
                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        // Note that we check root outside and have enforced booleanity of
                        // path.left_digests/path.right_digests outside in path.generate_r1cs_constraints
                        hashers[i].generate_r1cs_constraints(false);
                    }

                    /* ensure consistency of path.left_digests/path.right_digests with internal_output */
                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        propagators[i].generate_r1cs_constraints();
                    }

                    check_root->generate_r1cs_constraints(false, false);
                }

                template<typename FieldType, typename Hash>
                void merkle_tree_check_read_gadget<FieldType, Hash>::generate_r1cs_witness() {
                    /* do the hash computations bottom-up */
                    for (int i = tree_depth - 1; i >= 0; --i) {
                        /* propagate previous input */
                        propagators[i].generate_r1cs_witness();

                        /* compute hash */
                        hashers[i].generate_r1cs_witness();
                    }

                    check_root->generate_r1cs_witness();
                }

                template<typename FieldType, typename Hash>
                std::size_t merkle_tree_check_read_gadget<FieldType, Hash>::root_size_in_bits() {
                    return Hash::get_digest_len();
                }

                template<typename FieldType, typename Hash>
                std::size_t merkle_tree_check_read_gadget<FieldType, Hash>::expected_constraints(const std::size_t tree_depth) {
                    /* NB: this includes path constraints */
                    const std::size_t hasher_constraints = tree_depth * Hash::expected_constraints(false);
                    const std::size_t propagator_constraints = tree_depth * Hash::get_digest_len();
                    const std::size_t authentication_path_constraints = 2 * tree_depth * Hash::get_digest_len();
                    const std::size_t check_root_constraints =
                        3 * (Hash::get_digest_len() + (FieldType::capacity()) - 1) / FieldType::capacity();

                    return hasher_constraints + propagator_constraints + authentication_path_constraints +
                           check_root_constraints;
                }

                template<typename FieldType, typename Hash>
                void test_merkle_tree_check_read_gadget() {
                    /* prepare test */
                    const std::size_t digest_len = Hash::get_digest_len();
                    const std::size_t tree_depth = 16;
                    std::vector<merkle_authentication_node> path(tree_depth);

                    std::vector<bool> prev_hash(digest_len);
                    std::generate(prev_hash.begin(), prev_hash.end(), [&]() { return std::rand() % 2; });
                    std::vector<bool> leaf = prev_hash;

                    std::vector<bool> address_bits;

                    std::size_t address = 0;
                    for (long level = tree_depth - 1; level >= 0; --level) {
                        const bool computed_is_right = (std::rand() % 2);
                        address |= (computed_is_right ? 1ul << (tree_depth - 1 - level) : 0);
                        address_bits.push_back(computed_is_right);
                        std::vector<bool> other(digest_len);
                        std::generate(other.begin(), other.end(), [&]() { return std::rand() % 2; });

                        std::vector<bool> block = prev_hash;
                        block.insert(computed_is_right ? block.begin() : block.end(), other.begin(), other.end());
                        std::vector<bool> h = Hash::get_hash(block);

                        path[level] = other;

                        prev_hash = h;
                    }
                    std::vector<bool> root = prev_hash;

                    /* execute test */
                    protoboard<FieldType> pb;
                    pb_variable_array<FieldType> address_bits_va;
                    address_bits_va.allocate(pb, tree_depth);
                    digest_variable<FieldType> leaf_digest(pb, digest_len);
                    digest_variable<FieldType> root_digest(pb, digest_len);
                    merkle_authentication_path_variable<FieldType, Hash> path_var(pb, tree_depth);
                    merkle_tree_check_read_gadget<FieldType, Hash> ml(pb, tree_depth, address_bits_va, leaf_digest,
                                                                       root_digest, path_var, pb_variable<FieldType>(0));

                    path_var.generate_r1cs_constraints();
                    ml.generate_r1cs_constraints();

                    address_bits_va.fill_with_bits(pb, address_bits);
                    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
                    leaf_digest.generate_r1cs_witness(leaf);
                    path_var.generate_r1cs_witness(address, path);
                    ml.generate_r1cs_witness();

                    /* make sure that read checker didn't accidentally overwrite anything */
                    address_bits_va.fill_with_bits(pb, address_bits);
                    leaf_digest.generate_r1cs_witness(leaf);
                    root_digest.generate_r1cs_witness(root);
                    assert(pb.is_satisfied());

                    const std::size_t num_constraints = pb.num_constraints();
                    const std::size_t expected_constraints =
                        merkle_tree_check_read_gadget<FieldType, Hash>::expected_constraints(tree_depth);
                    assert(num_constraints == expected_constraints);
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // MERKLE_TREE_CHECK_READ_GADGET_HPP_

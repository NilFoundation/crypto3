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
// @file Declaration of interfaces for the Merkle tree check read component.
//
// The component checks the following: given a root R, address A, value V, and
// authentication path P, check that P is a valid authentication path for the
// value V as the A-th leaf in a Merkle tree with root R.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_MERKLE_TREE_CHECK_READ_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_MERKLE_TREE_CHECK_READ_COMPONENT_HPP

#include <nil/crypto3/zk/snark/merkle_tree.hpp>
#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/hashes/crh_component.hpp>
#include <nil/crypto3/zk/components/hashes/digest_selector_component.hpp>
#include <nil/crypto3/zk/components/hashes/hash_io.hpp>
#include <nil/crypto3/zk/components/merkle_tree/merkle_authentication_path_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename FieldType, typename Hash>
                class merkle_tree_check_read_component : public component<FieldType> {
                private:
                    std::vector<Hash> hashers;
                    std::vector<block_variable<FieldType>> hasher_inputs;
                    std::vector<digest_selector_component<FieldType>> propagators;
                    std::vector<digest_variable<FieldType>> internal_output;

                    std::shared_ptr<digest_variable<FieldType>> computed_root;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> check_root;

                public:
                    const std::size_t digest_size;
                    const std::size_t tree_depth;
                    blueprint_linear_combination_vector<FieldType> address_bits;
                    digest_variable<FieldType> leaf;
                    digest_variable<FieldType> root;
                    merkle_authentication_path_variable<FieldType, Hash> path;
                    blueprint_linear_combination<FieldType> read_successful;

                    merkle_tree_check_read_component(blueprint<FieldType> &bp,
                                                     const std::size_t tree_depth,
                                                     const blueprint_linear_combination_vector<FieldType> &address_bits,
                                                     const digest_variable<FieldType> &leaf_digest,
                                                     const digest_variable<FieldType> &root_digest,
                                                     const merkle_authentication_path_variable<FieldType, Hash> &path,
                                                     const blueprint_linear_combination<FieldType> &read_successful);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();

                    static std::size_t root_size_in_bits();
                    /* for debugging purposes */
                    static std::size_t expected_constraints(const std::size_t tree_depth);
                };

                template<typename FieldType, typename Hash>
                merkle_tree_check_read_component<FieldType, Hash>::merkle_tree_check_read_component(
                    blueprint<FieldType> &bp,
                    const std::size_t tree_depth,
                    const blueprint_linear_combination_vector<FieldType> &address_bits,
                    const digest_variable<FieldType> &leaf,
                    const digest_variable<FieldType> &root,
                    const merkle_authentication_path_variable<FieldType, Hash> &path,
                    const blueprint_linear_combination<FieldType> &read_successful) :
                    component<FieldType>(bp),
                    digest_size(Hash::get_digest_len()), tree_depth(tree_depth), address_bits(address_bits), leaf(leaf),
                    root(root), path(path), read_successful(read_successful) {
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
                        internal_output.emplace_back(digest_variable<FieldType>(bp, digest_size));
                    }

                    computed_root.reset(new digest_variable<FieldType>(bp, digest_size));

                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        block_variable<FieldType> inp(bp, path.left_digests[i], path.right_digests[i]);
                        hasher_inputs.emplace_back(inp);
                        hashers.emplace_back(
                            Hash(bp, 2 * digest_size, inp, (i == 0 ? *computed_root : internal_output[i - 1])));
                    }

                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        /*
                          The propagators take a computed hash value (or leaf in the
                          base case) and propagate it one layer up, either in the left
                          or the right slot of authentication_path_variable.
                        */
                        propagators.emplace_back(digest_selector_component<FieldType>(
                            bp, digest_size, i < tree_depth - 1 ? internal_output[i] : leaf,
                            address_bits[tree_depth - 1 - i], path.left_digests[i], path.right_digests[i]));
                    }

                    check_root.reset(new bit_vector_copy_component<FieldType>(bp, computed_root->bits, root.bits,
                                                                              read_successful, FieldType::number_bits));
                }

                template<typename FieldType, typename Hash>
                void merkle_tree_check_read_component<FieldType, Hash>::generate_r1cs_constraints() {
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
                void merkle_tree_check_read_component<FieldType, Hash>::generate_r1cs_witness() {
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
                std::size_t merkle_tree_check_read_component<FieldType, Hash>::root_size_in_bits() {
                    return Hash::get_digest_len();
                }

                template<typename FieldType, typename Hash>
                std::size_t merkle_tree_check_read_component<FieldType, Hash>::expected_constraints(
                    const std::size_t tree_depth) {
                    /* NB: this includes path constraints */
                    const std::size_t hasher_constraints = tree_depth * Hash::expected_constraints(false);
                    const std::size_t propagator_constraints = tree_depth * Hash::get_digest_len();
                    const std::size_t authentication_path_constraints = 2 * tree_depth * Hash::get_digest_len();
                    const std::size_t check_root_constraints =
                        3 * (Hash::get_digest_len() + (FieldType::capacity()) - 1) / FieldType::capacity();

                    return hasher_constraints + propagator_constraints + authentication_path_constraints +
                           check_root_constraints;
                }

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_MERKLE_TREE_CHECK_READ_COMPONENT_HPP

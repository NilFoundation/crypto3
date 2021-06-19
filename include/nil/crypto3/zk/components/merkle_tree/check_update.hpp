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
// @file Declaration of interfaces for the Merkle tree check update component.
//
// The component checks the following: given two roots R1 and R2, address A, two
// values V1 and V2, and authentication path P, check that
// - P is a valid authentication path for the value V1 as the A-th leaf in a Merkle tree with root R1, and
// - P is a valid authentication path for the value V2 as the A-th leaf in a Merkle tree with root R2.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_MERKLE_TREE_CHECK_UPDATE_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_MERKLE_TREE_CHECK_UPDATE_COMPONENT_HPP

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
                class merkle_tree_check_update_components : public component<FieldType> {

                    std::vector<Hash> prev_hashers;
                    std::vector<block_variable<FieldType>> prev_hasher_inputs;
                    std::vector<digest_selector_component<FieldType>> prev_propagators;
                    std::vector<digest_variable<FieldType>> prev_internal_output;

                    std::vector<Hash> next_hashers;
                    std::vector<block_variable<FieldType>> next_hasher_inputs;
                    std::vector<digest_selector_component<FieldType>> next_propagators;
                    std::vector<digest_variable<FieldType>> next_internal_output;

                    std::shared_ptr<digest_variable<FieldType>> computed_next_root;
                    std::shared_ptr<bit_vector_copy_component<FieldType>> check_next_root;

                public:
                    const std::size_t digest_size;
                    const std::size_t tree_depth;

                    blueprint_variable_vector<FieldType> address_bits;
                    digest_variable<FieldType> prev_leaf_digest;
                    digest_variable<FieldType> prev_root_digest;
                    merkle_authentication_path_variable<FieldType, Hash> prev_path;
                    digest_variable<FieldType> next_leaf_digest;
                    digest_variable<FieldType> next_root_digest;
                    merkle_authentication_path_variable<FieldType, Hash> next_path;
                    blueprint_linear_combination<FieldType> update_successful;

                    /* Note that while it is necessary to generate R1CS constraints
                       for prev_path, it is not necessary to do so for next_path. See
                       comment in the implementation of generate_r1cs_constraints() */

                    merkle_tree_check_update_components(
                        blueprint<FieldType> &bp,
                        const std::size_t tree_depth,
                        const blueprint_variable_vector<FieldType> &address_bits,
                        const digest_variable<FieldType> &prev_leaf_digest,
                        const digest_variable<FieldType> &prev_root_digest,
                        const merkle_authentication_path_variable<FieldType, Hash> &prev_path,
                        const digest_variable<FieldType> &next_leaf_digest,
                        const digest_variable<FieldType> &next_root_digest,
                        const merkle_authentication_path_variable<FieldType, Hash> &next_path,
                        const blueprint_linear_combination<FieldType> &update_successful) :
                        component<FieldType>(bp),
                        digest_size(Hash::get_digest_len()), tree_depth(tree_depth), address_bits(address_bits),
                        prev_leaf_digest(prev_leaf_digest), prev_root_digest(prev_root_digest), prev_path(prev_path),
                        next_leaf_digest(next_leaf_digest), next_root_digest(next_root_digest), next_path(next_path),
                        update_successful(update_successful) {
                        assert(tree_depth > 0);
                        assert(tree_depth == address_bits.size());

                        for (std::size_t i = 0; i < tree_depth - 1; ++i) {
                            prev_internal_output.emplace_back(digest_variable<FieldType>(bp, digest_size));
                            next_internal_output.emplace_back(digest_variable<FieldType>(bp, digest_size));
                        }

                        computed_next_root.reset(new digest_variable<FieldType>(bp, digest_size));

                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            block_variable<FieldType> prev_inp(bp, prev_path.left_digests[i],
                                                               prev_path.right_digests[i]);
                            prev_hasher_inputs.emplace_back(prev_inp);
                            prev_hashers.emplace_back(Hash(bp, 2 * digest_size, prev_inp,
                                                           (i == 0 ? prev_root_digest : prev_internal_output[i - 1])));

                            block_variable<FieldType> next_inp(bp, next_path.left_digests[i],
                                                               next_path.right_digests[i]);
                            next_hasher_inputs.emplace_back(next_inp);
                            next_hashers.emplace_back(
                                Hash(bp, 2 * digest_size, next_inp,
                                     (i == 0 ? *computed_next_root : next_internal_output[i - 1])));
                        }

                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            prev_propagators.emplace_back(digest_selector_component<FieldType>(
                                bp, digest_size, i < tree_depth - 1 ? prev_internal_output[i] : prev_leaf_digest,
                                address_bits[tree_depth - 1 - i], prev_path.left_digests[i],
                                prev_path.right_digests[i]));
                            next_propagators.emplace_back(digest_selector_component<FieldType>(
                                bp, digest_size, i < tree_depth - 1 ? next_internal_output[i] : next_leaf_digest,
                                address_bits[tree_depth - 1 - i], next_path.left_digests[i],
                                next_path.right_digests[i]));
                        }

                        check_next_root.reset(new bit_vector_copy_component<FieldType>(
                            bp, computed_next_root->bits, next_root_digest.bits, update_successful,
                            FieldType::capacity()));
                    }

                    void generate_r1cs_constraints() {
                        /* ensure correct hash computations */
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            prev_hashers[i].generate_r1cs_constraints(
                                false);    // we check root outside and prev_left/prev_right above
                            next_hashers[i].generate_r1cs_constraints(
                                true);    // however we must check right side hashes
                        }

                        /* ensure consistency of internal_left/internal_right with internal_output */
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            prev_propagators[i].generate_r1cs_constraints();
                            next_propagators[i].generate_r1cs_constraints();
                        }

                        /* ensure that prev auxiliary input and next auxiliary input match */
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            for (std::size_t j = 0; j < digest_size; ++j) {
                                /*
                                  addr * (prev_left - next_left) + (1 - addr) * (prev_right - next_right) = 0
                                  addr * (prev_left - next_left - prev_right + next_right) = next_right - prev_right
                                */
                                this->bp.add_r1cs_constraint(snark::r1cs_constraint<FieldType>(
                                    address_bits[tree_depth - 1 - i],
                                    prev_path.left_digests[i].bits[j] - next_path.left_digests[i].bits[j] -
                                        prev_path.right_digests[i].bits[j] + next_path.right_digests[i].bits[j],
                                    next_path.right_digests[i].bits[j] - prev_path.right_digests[i].bits[j]));
                            }
                        }

                        /* Note that while it is necessary to generate R1CS constraints
                           for prev_path, it is not necessary to do so for next_path.

                           This holds, because { next_path.left_inputs[i],
                           next_path.right_inputs[i] } is a pair { hash_output,
                           auxiliary_input }. The bitness for hash_output is enforced
                           above by next_hashers[i].generate_r1cs_constraints.

                           Because auxiliary input is the same for prev_path and next_path
                           (enforced above), we have that auxiliary_input part is also
                           constrained to be boolean, because prev_path is *all*
                           constrained to be all boolean. */

                        check_next_root->generate_r1cs_constraints(false, false);
                    }

                    void generate_r1cs_witness() {
                        /* do the hash computations bottom-up */
                        for (int i = tree_depth - 1; i >= 0; --i) {
                            /* ensure consistency of prev_path and next_path */
                            if (this->bp.val(address_bits[tree_depth - 1 - i]) == FieldType::value_type::zero()) {
                                next_path.left_digests[i].generate_r1cs_witness(prev_path.left_digests[i].get_digest());
                            } else {
                                next_path.right_digests[i].generate_r1cs_witness(
                                    prev_path.right_digests[i].get_digest());
                            }

                            /* propagate previous input */
                            prev_propagators[i].generate_r1cs_witness();
                            next_propagators[i].generate_r1cs_witness();

                            /* compute hash */
                            prev_hashers[i].generate_r1cs_witness();
                            next_hashers[i].generate_r1cs_witness();
                        }

                        check_next_root->generate_r1cs_witness();
                    }

                    static std::size_t root_size_in_bits() {
                        return Hash::get_digest_len();
                    }
                    /* for debugging purposes */
                    static std::size_t expected_constraints(const std::size_t tree_depth) {
                        /* NB: this includes path constraints */
                        const std::size_t prev_hasher_constraints = tree_depth * Hash::expected_constraints(false);
                        const std::size_t next_hasher_constraints = tree_depth * Hash::expected_constraints(true);
                        const std::size_t prev_authentication_path_constraints =
                            2 * tree_depth * Hash::get_digest_len();
                        const std::size_t prev_propagator_constraints = tree_depth * Hash::get_digest_len();
                        const std::size_t next_propagator_constraints = tree_depth * Hash::get_digest_len();
                        const std::size_t check_next_root_constraints =
                            3 * (Hash::get_digest_len() + (FieldType::capacity()) - 1) / FieldType::capacity();
                        const std::size_t aux_equality_constraints = tree_depth * Hash::get_digest_len();

                        return (prev_hasher_constraints + next_hasher_constraints +
                                prev_authentication_path_constraints + prev_propagator_constraints +
                                next_propagator_constraints + check_next_root_constraints + aux_equality_constraints);
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_MERKLE_TREE_CHECK_UPDATE_COMPONENT_HPP

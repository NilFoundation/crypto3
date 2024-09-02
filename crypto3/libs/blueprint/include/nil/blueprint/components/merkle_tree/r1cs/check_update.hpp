//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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
// @file Declaration of interfaces for the Merkle tree check update component.
//
// The component checks the following: given two roots R1 and R2, address A, two
// values V1 and V2, and authentication path P, check that
// - P is a valid authentication path for the value V1 as the A-th leaf in a Merkle tree with root R1, and
// - P is a valid authentication path for the value V2 as the A-th leaf in a Merkle tree with root R2.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_TREE_CHECK_UPDATE_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_TREE_CHECK_UPDATE_COMPONENT_HPP

#include <nil/blueprint/components/component.hpp>
#include <nil/blueprint/components/hashes/digest_selector_component.hpp>
#include <nil/blueprint/components/hashes/hash_io.hpp>
#include <nil/blueprint/components/merkle_tree/prove.hpp>
#include <nil/blueprint/components/packing.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                template<typename HashComponent = pedersen<>, typename FieldType = typename HashComponent::field_type,
                         std::size_t Arity = 2>
                class merkle_proof_update : public component<FieldType> {
                    using hash_type = typename HashComponent::hash_type;

                    static_assert(std::is_same<digest_variable<FieldType>, typename HashComponent::result_type>::value);
                    // TODO: add support of the trees with arity more than 2
                    static_assert(Arity == 2);

                    std::vector<HashComponent> prev_hashers;
                    std::vector<block_variable<FieldType>> prev_hasher_inputs;
                    std::vector<digest_selector_component<FieldType>> prev_propagators;
                    std::vector<digest_variable<FieldType>> prev_internal_output;

                    std::vector<HashComponent> next_hashers;
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
                    merkle_proof<HashComponent, FieldType, Arity> prev_path;
                    digest_variable<FieldType> next_leaf_digest;
                    digest_variable<FieldType> next_root_digest;
                    merkle_proof<HashComponent, FieldType, Arity> next_path;
                    blueprint_linear_combination<FieldType> update_successful;

                    /* Note that while it is necessary to generate R1CS constraints
                       for prev_path, it is not necessary to do so for next_path. See
                       comment in the implementation of generate_gates() */

                    merkle_proof_update(blueprint<FieldType> &bp,
                                        const std::size_t tree_depth,
                                        const blueprint_variable_vector<FieldType> &address_bits,
                                        const digest_variable<FieldType> &prev_leaf_digest,
                                        const digest_variable<FieldType> &prev_root_digest,
                                        const merkle_proof<HashComponent, FieldType, Arity> &prev_path,
                                        const digest_variable<FieldType> &next_leaf_digest,
                                        const digest_variable<FieldType> &next_root_digest,
                                        const merkle_proof<HashComponent, FieldType, Arity> &next_path,
                                        const blueprint_linear_combination<FieldType> &update_successful) :
                        component<FieldType>(bp),
                        digest_size(hash_type::digest_bits), tree_depth(tree_depth), address_bits(address_bits),
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
                            // TODO: generalize for Arity > 2
                            block_variable<FieldType> prev_inp(bp, prev_path.path[i][0], prev_path.path[i][1]);
                            prev_hasher_inputs.emplace_back(prev_inp);
                            prev_hashers.emplace_back(
                                HashComponent(bp, prev_inp, (i == 0 ? prev_root_digest : prev_internal_output[i - 1])));

                            // TODO: generalize for Arity > 2
                            block_variable<FieldType> next_inp(bp, next_path.path[i][0], next_path.path[i][1]);
                            next_hasher_inputs.emplace_back(next_inp);
                            next_hashers.emplace_back(HashComponent(
                                bp, next_inp, (i == 0 ? *computed_next_root : next_internal_output[i - 1])));
                        }

                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            // TODO: generalize for Arity > 2
                            prev_propagators.emplace_back(digest_selector_component<FieldType>(
                                bp, digest_size, i < tree_depth - 1 ? prev_internal_output[i] : prev_leaf_digest,
                                address_bits[tree_depth - 1 - i], prev_path.path[i][0], prev_path.path[i][1]));
                            // TODO: generalize for Arity > 2
                            next_propagators.emplace_back(digest_selector_component<FieldType>(
                                bp, digest_size, i < tree_depth - 1 ? next_internal_output[i] : next_leaf_digest,
                                address_bits[tree_depth - 1 - i], next_path.path[i][0], next_path.path[i][1]));
                        }

                        check_next_root.reset(new bit_vector_copy_component<FieldType>(
                            bp, computed_next_root->bits, next_root_digest.bits, update_successful,
                            FieldType::value_bits - 1));
                    }

                    void generate_gates() {
                        /* ensure correct hash computations */
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            prev_hashers[i].generate_gates(
                                false);    // we check root outside and prev_left/prev_right above
                            next_hashers[i].generate_gates(
                                true);    // however we must check right side hashes
                        }

                        /* ensure consistency of internal_left/internal_right with internal_output */
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            prev_propagators[i].generate_gates();
                            next_propagators[i].generate_gates();
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
                           above by next_hashers[i].generate_gates.

                           Because auxiliary input is the same for prev_path and next_path
                           (enforced above), we have that auxiliary_input part is also
                           constrained to be boolean, because prev_path is *all*
                           constrained to be all boolean. */

                        check_next_root->generate_gates(false, false);
                    }

                    void generate_assignments() {
                        /* do the hash computations bottom-up */
                        for (int i = tree_depth - 1; i >= 0; --i) {
                            /* ensure consistency of prev_path and next_path */
                            if (this->bp.val(address_bits[tree_depth - 1 - i]) == FieldType::value_type::zero()) {
                                next_path.left_digests[i].generate_assignments(prev_path.left_digests[i].get_digest());
                            } else {
                                next_path.right_digests[i].generate_assignments(
                                    prev_path.right_digests[i].get_digest());
                            }

                            /* propagate previous input */
                            prev_propagators[i].generate_assignments();
                            next_propagators[i].generate_assignments();

                            /* compute hash */
                            prev_hashers[i].generate_assignments();
                            next_hashers[i].generate_assignments();
                        }

                        check_next_root->generate_assignments();
                    }
                };

            }    // namespace components
        }        // namespace blueprint
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_TREE_CHECK_UPDATE_COMPONENT_HPP

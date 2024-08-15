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
// @file Declaration of interfaces for the Merkle tree check read component.
//
// The component checks the following: given a root R, address A, value V, and
// authentication path P, check that P is a valid authentication path for the
// value V as the A-th leaf in a Merkle tree with root R.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_TREE_CHECK_READ_COMPONENT_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_TREE_CHECK_READ_COMPONENT_HPP

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/components/hashes/digest_selector_component.hpp>
#include <nil/blueprint/components/hashes/hash_io.hpp>
#include <nil/blueprint/components/merkle_tree/prove.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename HashComponent = pedersen<>, typename Field = typename HashComponent::field_type,
                     std::size_t Arity = 2>
            struct merkle_proof_validate : public component<Field> {
                static constexpr std::size_t arity = Arity;

                using field_type = Field;
                using hash_component = HashComponent;
                using merkle_proof_component = merkle_proof<hash_component, field_type, arity>;

                // TODO: add support of the trees with arity more than 2
                static_assert(arity == 2);
                static_assert(
                    std::is_same<digest_variable<field_type>, typename HashComponent::result_type>::value);

            private:
                std::vector<HashComponent> hashers;
                std::vector<block_variable<field_type>> hasher_inputs;
                std::vector<digest_selector_component<field_type>> propagators;
                std::vector<digest_variable<field_type>> internal_output;

                std::shared_ptr<digest_variable<field_type>> computed_root;
                std::shared_ptr<bit_vector_copy_component<field_type>> check_root;

            public:
                const std::size_t digest_size;
                const std::size_t tree_depth;
                detail::blueprint_linear_combination_vector<field_type> address_bits;
                digest_variable<field_type> leaf;
                digest_variable<field_type> root;
                merkle_proof_component path;
                detail::blueprint_linear_combination<field_type> read_successful;

                merkle_proof_validate(blueprint<field_type> &bp,
                                      const std::size_t tree_depth,
                                      const detail::blueprint_linear_combination_vector<field_type> &address_bits,
                                      const digest_variable<field_type> &leaf,
                                      const digest_variable<field_type> &root,
                                      const merkle_proof_component &path,
                                      const detail::blueprint_linear_combination<field_type> &read_successful) :
                    component<field_type>(bp),
                    digest_size(HashComponent::digest_bits), tree_depth(tree_depth), address_bits(address_bits),
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
                        internal_output.emplace_back(digest_variable<field_type>(bp, digest_size));
                    }

                    computed_root.reset(new digest_variable<field_type>(bp, digest_size));

                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        // TODO: generalize for arity > 2
                        block_variable<field_type> inp(bp, path.path[i][0], path.path[i][1]);
                        hasher_inputs.emplace_back(inp);
                        hashers.emplace_back(
                            HashComponent(bp, inp, (i == 0 ? *computed_root : internal_output[i - 1])));
                    }

                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        /*
                          The propagators take a computed hash value (or leaf in the
                          base case) and propagate it one layer up, either in the left
                          or the right slot of authentication_path_variable.
                        */
                        // TODO: generalize for arity > 2
                        propagators.emplace_back(digest_selector_component<field_type>(
                            bp, digest_size, i < tree_depth - 1 ? internal_output[i] : leaf,
                            address_bits[tree_depth - 1 - i], path.path[i][0], path.path[i][1]));
                    }

                    check_root.reset(new bit_vector_copy_component<field_type>(
                        bp, computed_root->bits, root.bits, read_successful, field_type::number_bits));
                }

                void generate_gates() {
                    /* ensure correct hash computations */
                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        // Note that we check root outside and have enforced booleanity of
                        // path.left_digests/path.right_digests outside in path.generate_gates
                        hashers[i].generate_gates(false);
                    }

                    /* ensure consistency of path.left_digests/path.right_digests with internal_output */
                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        propagators[i].generate_gates();
                    }

                    check_root->generate_gates(false, false);
                }

                void generate_assignments() {
                    /* do the hash computations bottom-up */
                    for (int i = tree_depth - 1; i >= 0; --i) {
                        /* propagate previous input */
                        propagators[i].generate_assignments();

                        /* compute hash */
                        hashers[i].generate_assignments();
                    }

                    check_root->generate_assignments();
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_TREE_CHECK_READ_COMPONENT_HPP

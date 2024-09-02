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
// @file Test program that exercises the SEppzkSNARK (first generator, then
// prover, then verifier) on a synthetic R1CS instance.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_AUTHENTICATION_PATH_VARIABLE_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_AUTHENTICATION_PATH_VARIABLE_HPP

#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/components/hashes/hash_io.hpp>
#include <nil/blueprint/components/hashes/pedersen.hpp>

namespace nil {
    namespace blueprint {
        namespace components {
            template<typename HashComponent = nil::crypto3::zk::components::pedersen<>,
                     typename FieldType = typename HashComponent::field_type, std::size_t Arity = 2>
            struct merkle_proof : public component<FieldType> {
                using merkle_tree_container =
                    nil::crypto3::containers::merkle_tree<typename HashComponent::hash_type, Arity>;
                using merkle_proof_container =
                    nil::crypto3::containers::merkle_proof<typename HashComponent::hash_type, Arity>;
                using path_type = std::vector<std::vector<digest_variable<FieldType>>>;

                std::size_t address;
                const std::size_t tree_depth;
                path_type path;

                merkle_proof(blueprint<FieldType> &bp, const std::size_t tree_depth) :
                    component<FieldType>(bp), tree_depth(tree_depth) {

                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        std::vector<digest_variable<FieldType>> layer;

                        for (std::size_t j = 0; j < Arity; ++j) {
                            layer.template emplace_back(
                                digest_variable<FieldType>(this->bp, HashComponent::digest_bits));
                        }

                        path.emplace_back(layer);
                    }
                }

                void generate_gates() {
                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        for (std::size_t j = 0; j < Arity; ++j) {
                            path[i][j].generate_gates();
                        }
                    }
                }

                void generate_assignments(const merkle_proof_container &proof, bool do_clear = false) {
                    // TODO: generalize for Arity > 2
                    assert(Arity == 2);
                    assert(proof._path.size() == tree_depth);

                    this->address = 0;
                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        for (std::size_t j = 0; j < Arity - 1; ++j) {
                            auto position = proof._path[tree_depth - 1 - i][j]._position;
                            path[i][position].generate_assignments(proof._path[tree_depth - 1 - i][j]._hash);
                            this->address |= (position ? 0 : 1ul << (tree_depth - 1 - i));
                            if (do_clear) {
                                path[i][position ? 0 : 1].generate_assignments(
                                    std::vector<bool>(HashComponent::digest_bits, false));
                            }
                        }
                    }
                }

                void generate_assignments(std::size_t address, const std::vector<std::vector<bool>> &proof) {
                    // TODO: generalize for Arity > 2
                    assert(Arity == 2);
                    assert(proof.size() == tree_depth);

                    for (std::size_t i = 0; i < tree_depth; ++i) {
                        if (address & (1ul << (tree_depth - 1 - i))) {
                            path[i][0].generate_assignments(proof[i]);
                        } else {
                            path[i][1].generate_assignments(proof[i]);
                        }
                    }

                    this->address = address;
                }

                /// For test only
                static auto root(const merkle_proof_container &proof) {
                    return proof.root();
                }
            };
        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_MERKLE_AUTHENTICATION_PATH_VARIABLE_HPP

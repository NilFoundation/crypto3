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
// @file Test program that exercises the SEppzkSNARK (first generator, then
// prover, then verifier) on a synthetic R1CS instance.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_MERKLE_AUTHENTICATION_PATH_VARIABLE_HPP
#define CRYPTO3_ZK_BLUEPRINT_MERKLE_AUTHENTICATION_PATH_VARIABLE_HPP

#include <nil/crypto3/zk/snark/merkle_tree.hpp>
#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/hashes/hash_io.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename FieldType, typename Hash>
                struct merkle_authentication_path_variable : public component<FieldType> {

                    const std::size_t tree_depth;
                    std::vector<digest_variable<FieldType>> left_digests;
                    std::vector<digest_variable<FieldType>> right_digests;

                    merkle_authentication_path_variable(blueprint<FieldType> &bp, const std::size_t tree_depth) :
                        component<FieldType>(bp), tree_depth(tree_depth) {
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            left_digests.emplace_back(digest_variable<FieldType>(bp, Hash::get_digest_len()));
                            right_digests.emplace_back(digest_variable<FieldType>(bp, Hash::get_digest_len()));
                        }
                    }

                    void generate_r1cs_constraints() {
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            left_digests[i].generate_r1cs_constraints();
                            right_digests[i].generate_r1cs_constraints();
                        }
                    }

                    void generate_r1cs_witness(const std::size_t address, const merkle_authentication_path &path) {
                        assert(path.size() == tree_depth);

                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            if (address & (1ul << (tree_depth - 1 - i))) {
                                left_digests[i].generate_r1cs_witness(path[i]);
                            } else {
                                right_digests[i].generate_r1cs_witness(path[i]);
                            }
                        }
                    }

                    merkle_authentication_path get_authentication_path(const std::size_t address) const {
                        merkle_authentication_path result;
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            if (address & (1ul << (tree_depth - 1 - i))) {
                                result.emplace_back(left_digests[i].get_digest());
                            } else {
                                result.emplace_back(right_digests[i].get_digest());
                            }
                        }

                        return result;
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_MERKLE_AUTHENTICATION_PATH_VARIABLE_HPP

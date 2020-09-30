//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Test program that exercises the SEppzkSNARK (first generator, then
// prover, then verifier) on a synthetic R1CS instance.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MERKLE_AUTHENTICATION_PATH_VARIABLE_HPP
#define CRYPTO3_ZK_MERKLE_AUTHENTICATION_PATH_VARIABLE_HPP

#include <nil/crypto3/zk/snark/merkle_tree.hpp>
#include <nil/crypto3/zk/snark/component.hpp>
#include <nil/crypto3/zk/snark/components/hashes/hash_io.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename Hash>
                struct merkle_authentication_path_variable : public component<FieldType> {

                    const std::size_t tree_depth;
                    std::vector<digest_variable<FieldType>> left_digests;
                    std::vector<digest_variable<FieldType>> right_digests;

                    merkle_authentication_path_variable(blueprint<FieldType> &pb, const std::size_t tree_depth) :
                        component<FieldType>(pb),
                        tree_depth(tree_depth) {
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            left_digests.emplace_back(digest_variable<FieldType>(pb, Hash::get_digest_len()));
                            right_digests.emplace_back(digest_variable<FieldType>(pb, Hash::get_digest_len()));
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

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MERKLE_AUTHENTICATION_PATH_VARIABLE_HPP

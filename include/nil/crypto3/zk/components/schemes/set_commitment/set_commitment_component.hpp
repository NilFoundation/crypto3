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

#ifndef CRYPTO3_ZK_BLUEPRINT_SET_COMMITMENT_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_SET_COMMITMENT_COMPONENT_HPP

#include <nil/crypto3/zk/components/component.hpp>
#include <nil/crypto3/zk/components/hashes/hash_io.hpp>
#include <nil/crypto3/zk/components/merkle_tree/merkle_tree_check_read_component.hpp>
#include <nil/crypto3/zk/snark/components/set_commitment/set_membership_proof_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace components {

                    template<typename FieldType, typename Hash>
                    using set_commitment_variable = digest_variable<FieldType>;

                    template<typename FieldType, typename Hash>
                    class set_commitment_component : public component<FieldType> {
                    private:
                        std::shared_ptr<block_variable<FieldType>> element_block;
                        std::shared_ptr<digest_variable<FieldType>> element_digest;
                        std::shared_ptr<Hash> hash_element;
                        std::shared_ptr<merkle_tree_check_read_component<FieldType, Hash>> check_membership;

                    public:
                        std::size_t tree_depth;
                        blueprint_variable_vector<FieldType> element_bits;
                        set_commitment_variable<FieldType, Hash> root_digest;
                        set_membership_proof_variable<FieldType, Hash> proof;
                        blueprint_linear_combination<FieldType> check_successful;

                        set_commitment_component(blueprint<FieldType> &bp,
                                                 const std::size_t max_entries,
                                                 const blueprint_variable_vector<FieldType> &element_bits,
                                                 const set_commitment_variable<FieldType, Hash> &root_digest,
                                                 const set_membership_proof_variable<FieldType, Hash> &proof,
                                                 const blueprint_linear_combination<FieldType> &check_successful) :
                            component<FieldType>(bp),
                            tree_depth(static_cast<std::size_t>(std::ceil(std::log2(max_entries)))),
                            element_bits(element_bits), root_digest(root_digest), proof(proof),
                            check_successful(check_successful) {
                            element_block.reset(new block_variable<FieldType>(bp, {element_bits}));

                            if (tree_depth == 0) {
                                hash_element.reset(new Hash(bp, element_bits.size(), *element_block, root_digest));
                            } else {
                                element_digest.reset(new digest_variable<FieldType>(bp, Hash::get_digest_len()));
                                hash_element.reset(new Hash(bp, element_bits.size(), *element_block, *element_digest));
                                check_membership.reset(
                                    new merkle_tree_check_read_component<FieldType, Hash>(bp,
                                                                                          tree_depth,
                                                                                          proof.address_bits,
                                                                                          *element_digest,
                                                                                          root_digest,
                                                                                          *proof.merkle_path,
                                                                                          check_successful));
                            }
                        }

                        void generate_r1cs_constraints() {
                            hash_element->generate_r1cs_constraints();

                            if (tree_depth > 0) {
                                check_membership->generate_r1cs_constraints();
                            }
                        }

                        void generate_r1cs_witness() {
                            hash_element->generate_r1cs_witness();

                            if (tree_depth > 0) {
                                check_membership->generate_r1cs_witness();
                            }
                        }

                        static std::size_t root_size_in_bits() {
                            return merkle_tree_check_read_component<FieldType, Hash>::root_size_in_bits();
                        }
                    };
                }    // namespace components
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_SET_COMMITMENT_COMPONENT_HPP

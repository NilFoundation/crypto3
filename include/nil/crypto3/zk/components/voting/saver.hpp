//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_VOTING_SAVER_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_VOTING_SAVER_COMPONENT_HPP

#include <nil/crypto3/zk/components/merkle_tree/validate.hpp>
#include <nil/crypto3/zk/components/hashes/pedersen.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<std::size_t Arity = 2,
                         typename HashComponent = pedersen<>,
                         typename MerkleTreeHashComponent = HashComponent,
                         typename Field = typename HashComponent::field_type>
                struct saver : public component<Field> {
                    using field_type = Field;
                    using hash_component = HashComponent;
                    using merkle_proof_validating_component =
                        merkle_proof_validate<MerkleTreeHashComponent, Field, Arity>;
                    using merkle_proof_component = typename merkle_proof_validating_component::merkle_proof_component;

                    digest_variable<field_type> sn_computed;
                    digest_variable<field_type> pk;
                    // TODO: clarify how to compute pk_leaf from pk
                    digest_variable<field_type> pk_leaf;
                    hash_component pk_hasher;
                    hash_component pk_leaf_hasher;
                    merkle_proof_validating_component root_validator;
                    hash_component sn_hasher;
                    bit_vector_copy_component<field_type> check_sn;

                    block_variable<field_type> m;
                    block_variable<field_type> eid;
                    digest_variable<field_type> sn;
                    block_variable<field_type> sk;

                    /**
                     * @warning If you just want to compute intermediate fields (\p rt and \p sn) it is sufficient to
                     * instantiate saver component and call \p generate_r1cs_witness, but if you want to check
                     * satisfiability of the CS you have to call \p generate_r1cs_witness for \p rt and \p sn with
                     * expected values before call \p is_satisfied for \p bp. This is due to using of the
                     * bit_vector_copy_component which is responsible for both logics: copying of the computed fields
                     * (\p rt and \p sn) and comparison of the computed and passed values. So, if you don't call \p
                     * generate_r1cs_witness for \p rt and \p sn satisfiability check will always be positive. Also be
                     * sure to
                     */
                    saver(blueprint<field_type> &bp,
                          const block_variable<field_type> &m,
                          const block_variable<field_type> &eid,
                          const digest_variable<field_type> &sn,
                          const digest_variable<field_type> &rt,
                          const blueprint_linear_combination_vector<field_type> &address_bits,
                          const merkle_proof_component &path,
                          const block_variable<field_type> &sk,
                          const blueprint_linear_combination<field_type> &read_successful) :
                        component<field_type>(bp),
                        // private fields
                        sn_computed(bp, hash_component::digest_bits), pk(bp, hash_component::digest_bits),
                        pk_leaf(bp, MerkleTreeHashComponent::digest_bits), pk_hasher(bp, sk, pk),
                        pk_leaf_hasher(bp, pk, pk_leaf),
                        root_validator(bp, path.tree_depth, address_bits, pk_leaf, rt, path, read_successful),
                        sn_hasher(bp,
                                  std::vector {
                                      eid,
                                      sk,
                                  },
                                  sn_computed),
                        check_sn(bp, sn_computed.bits, sn.bits, read_successful, field_type::number_bits),
                        // public fields
                        m(m), eid(eid), sn(sn), sk(sk) {
                    }

                    // TODO: review all necessary constrains, for example, eid
                    void generate_r1cs_constraints() {
                        pk_hasher.generate_r1cs_constraints();
                        pk_leaf_hasher.generate_r1cs_constraints();
                        root_validator.generate_r1cs_constraints();
                        sn_hasher.generate_r1cs_constraints();
                        check_sn.generate_r1cs_constraints(false, false);

                        snark::linear_combination<field_type> sum_m_i;
                        for (const auto &m_i : m.bits) {
                            // m_i == 0 or m_i == 1
                            generate_boolean_r1cs_constraint(
                                this->bp, static_cast<blueprint_linear_combination<field_type>>(m_i));
                            sum_m_i = sum_m_i + m_i;
                        }
                        // sum_m_i == 1
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<Field>(
                            Field::value_type::one(), Field::value_type::one() - sum_m_i, Field::value_type::zero()));
                    }
                    void generate_r1cs_witness() {
                        pk_hasher.generate_r1cs_witness();
                        pk_leaf_hasher.generate_r1cs_witness();
                        root_validator.generate_r1cs_witness();
                        sn_hasher.generate_r1cs_witness();
                        check_sn.generate_r1cs_witness();
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VOTING_SAVER_COMPONENT_HPP

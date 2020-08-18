//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Test program that exercises the SEppzkSNARK (first generator, then
// prover, then verifier) on a synthetic R1CS instance.
//---------------------------------------------------------------------------//

#ifndef SET_MEMBERSHIP_PROOF_VARIABLE_HPP_
#define SET_MEMBERSHIP_PROOF_VARIABLE_HPP_

#include <nil/crypto3/zk/snark/data_structures/set_commitment.hpp>
#include <nil/crypto3/zk/snark/gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/hashes/hash_io.hpp>
#include <nil/crypto3/zk/snark/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename Hash>
                class set_membership_proof_variable : public gadget<FieldType> {
                public:
                    pb_variable_array<FieldType> address_bits;
                    std::shared_ptr<merkle_authentication_path_variable<FieldType, Hash>> merkle_path;

                    const std::size_t max_entries;
                    const std::size_t tree_depth;

                    set_membership_proof_variable(protoboard<FieldType> &pb, const std::size_t max_entries);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness(const set_membership_proof &proof);

                    set_membership_proof get_membership_proof() const;

                    static r1cs_variable_assignment<FieldType>
                        as_r1cs_variable_assignment(const set_membership_proof &proof);
                };

                template<typename FieldType, typename Hash>
                set_membership_proof_variable<FieldType, Hash>::set_membership_proof_variable(
                    protoboard<FieldType> &pb,
                    const std::size_t max_entries) :
                    gadget<FieldType>(pb),
                    max_entries(max_entries), tree_depth(static_cast<std::size_t>(std::ceil(std::log2(max_entries)))) {
                    if (tree_depth > 0) {
                        address_bits.allocate(pb, tree_depth);
                        merkle_path.reset(new merkle_authentication_path_variable<FieldType, Hash>(pb, tree_depth));
                    }
                }

                template<typename FieldType, typename Hash>
                void set_membership_proof_variable<FieldType, Hash>::generate_r1cs_constraints() {
                    if (tree_depth > 0) {
                        for (std::size_t i = 0; i < tree_depth; ++i) {
                            generate_boolean_r1cs_constraint<FieldType>(this->pb, address_bits[i]);
                        }
                        merkle_path->generate_r1cs_constraints();
                    }
                }

                template<typename FieldType, typename Hash>
                void set_membership_proof_variable<FieldType, Hash>::generate_r1cs_witness(
                    const set_membership_proof &proof) {
                    if (tree_depth > 0) {
                        address_bits.fill_with_bits_of_field_element(this->pb, typename FieldType::value_type(proof.address));
                        merkle_path->generate_r1cs_witness(proof.address, proof.merkle_path);
                    }
                }

                template<typename FieldType, typename Hash>
                set_membership_proof set_membership_proof_variable<FieldType, Hash>::get_membership_proof() const {
                    set_membership_proof result;

                    if (tree_depth == 0) {
                        result.address = 0;
                    } else {
                        result.address = address_bits.get_field_element_from_bits(this->pb).as_ulong();
                        result.merkle_path = merkle_path->get_authentication_path(result.address);
                    }

                    return result;
                }

                template<typename FieldType, typename Hash>
                r1cs_variable_assignment<FieldType>
                    set_membership_proof_variable<FieldType, Hash>::as_r1cs_variable_assignment(
                        const set_membership_proof &proof) {
                    protoboard<FieldType> pb;
                    const std::size_t max_entries = (1ul << (proof.merkle_path.size()));
                    set_membership_proof_variable<FieldType, Hash> proof_variable(pb, max_entries, "proof_variable");
                    proof_variable.generate_r1cs_witness(proof);

                    return pb.full_variable_assignment();
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // SET_MEMBERSHIP_PROOF_VARIABLE_HPP

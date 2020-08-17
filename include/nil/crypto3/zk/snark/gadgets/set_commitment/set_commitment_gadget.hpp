//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef SET_COMMITMENT_GADGET_HPP_
#define SET_COMMITMENT_GADGET_HPP_

#include <nil/crypto3/zk/snark/gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/basic_gadgets.hpp>
#include <nil/crypto3/zk/snark/gadgets/hashes/hash_io.hpp>
#include <nil/crypto3/zk/snark/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <nil/crypto3/zk/snark/gadgets/set_commitment/set_membership_proof_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename HashT>
                using set_commitment_variable = digest_variable<FieldType>;

                template<typename FieldType, typename HashT>
                class set_commitment_gadget : public gadget<FieldType> {
                private:
                    std::shared_ptr<block_variable<FieldType>> element_block;
                    std::shared_ptr<digest_variable<FieldType>> element_digest;
                    std::shared_ptr<HashT> hash_element;
                    std::shared_ptr<merkle_tree_check_read_gadget<FieldType, HashT>> check_membership;

                public:
                    size_t tree_depth;
                    pb_variable_array<FieldType> element_bits;
                    set_commitment_variable<FieldType, HashT> root_digest;
                    set_membership_proof_variable<FieldType, HashT> proof;
                    pb_linear_combination<FieldType> check_successful;

                    set_commitment_gadget(protoboard<FieldType> &pb,
                                          const size_t max_entries,
                                          const pb_variable_array<FieldType> &element_bits,
                                          const set_commitment_variable<FieldType, HashT> &root_digest,
                                          const set_membership_proof_variable<FieldType, HashT> &proof,
                                          const pb_linear_combination<FieldType> &check_successful);

                    void generate_r1cs_constraints();
                    void generate_r1cs_witness();

                    static size_t root_size_in_bits();
                };

                template<typename FieldType, typename HashT>
                void test_set_commitment_gadget();

                template<typename FieldType, typename HashT>
                set_commitment_gadget<FieldType, HashT>::set_commitment_gadget(
                    protoboard<FieldType> &pb,
                    const size_t max_entries,
                    const pb_variable_array<FieldType> &element_bits,
                    const set_commitment_variable<FieldType, HashT> &root_digest,
                    const set_membership_proof_variable<FieldType, HashT> &proof,
                    const pb_linear_combination<FieldType> &check_successful) :
                    gadget<FieldType>(pb),
                    tree_depth(static_cast<std::size_t>(std::ceil(std::log2(max_entries)))), element_bits(element_bits),
                    root_digest(root_digest), proof(proof), check_successful(check_successful) {
                    element_block.reset(new block_variable<FieldType>(pb, {element_bits}));

                    if (tree_depth == 0) {
                        hash_element.reset(new HashT(pb, element_bits.size(), *element_block, root_digest));
                    } else {
                        element_digest.reset(new digest_variable<FieldType>(pb, HashT::get_digest_len()));
                        hash_element.reset(new HashT(pb, element_bits.size(), *element_block, *element_digest));
                        check_membership.reset(new merkle_tree_check_read_gadget<FieldType, HashT>(pb,
                                                                                                   tree_depth,
                                                                                                   proof.address_bits,
                                                                                                   *element_digest,
                                                                                                   root_digest,
                                                                                                   *proof.merkle_path,
                                                                                                   check_successful));
                    }
                }

                template<typename FieldType, typename HashT>
                void set_commitment_gadget<FieldType, HashT>::generate_r1cs_constraints() {
                    hash_element->generate_r1cs_constraints();

                    if (tree_depth > 0) {
                        check_membership->generate_r1cs_constraints();
                    }
                }

                template<typename FieldType, typename HashT>
                void set_commitment_gadget<FieldType, HashT>::generate_r1cs_witness() {
                    hash_element->generate_r1cs_witness();

                    if (tree_depth > 0) {
                        check_membership->generate_r1cs_witness();
                    }
                }

                template<typename FieldType, typename HashT>
                size_t set_commitment_gadget<FieldType, HashT>::root_size_in_bits() {
                    return merkle_tree_check_read_gadget<FieldType, HashT>::root_size_in_bits();
                }

                template<typename FieldType, typename HashT>
                void test_set_commitment_gadget() {
                    const size_t digest_len = HashT::get_digest_len();
                    const size_t max_set_size = 16;
                    const size_t value_size = (HashT::get_block_len() > 0 ? HashT::get_block_len() : 10);

                    set_commitment_accumulator<HashT> accumulator(max_set_size, value_size);

                    std::vector<std::vector<bool>> set_elems;
                    for (size_t i = 0; i < max_set_size; ++i) {
                        std::vector<bool> elem(value_size);
                        std::generate(elem.begin(), elem.end(), [&]() { return std::rand() % 2; });
                        set_elems.emplace_back(elem);
                        accumulator.add(elem);
                        assert(accumulator.is_in_set(elem));
                    }

                    protoboard<FieldType> pb;
                    pb_variable_array<FieldType> element_bits;
                    element_bits.allocate(pb, value_size);
                    set_commitment_variable<FieldType, HashT> root_digest(pb, digest_len);

                    pb_variable<FieldType> check_succesful;
                    check_succesful.allocate(pb);

                    set_membership_proof_variable<FieldType, HashT> proof(pb, max_set_size);

                    set_commitment_gadget<FieldType, HashT> sc(pb, max_set_size, element_bits, root_digest, proof,
                                                               check_succesful);
                    sc.generate_r1cs_constraints();

                    /* test all elements from set */
                    for (size_t i = 0; i < max_set_size; ++i) {
                        element_bits.fill_with_bits(pb, set_elems[i]);
                        pb.val(check_succesful) = FieldType::one();
                        proof.generate_r1cs_witness(accumulator.get_membership_proof(set_elems[i]));
                        sc.generate_r1cs_witness();
                        root_digest.generate_r1cs_witness(accumulator.get_commitment());
                        assert(pb.is_satisfied());
                    }
                    printf("membership tests OK\n");

                    /* test an element not in set */
                    for (size_t i = 0; i < value_size; ++i) {
                        pb.val(element_bits[i]) = FieldType(std::rand() % 2);
                    }

                    pb.val(check_succesful) = FieldType::zero(); /* do not require the check result to be successful */
                    proof.generate_r1cs_witness(
                        accumulator.get_membership_proof(set_elems[0])); /* try it with invalid proof */
                    sc.generate_r1cs_witness();
                    root_digest.generate_r1cs_witness(accumulator.get_commitment());
                    assert(pb.is_satisfied());

                    pb.val(check_succesful) = FieldType::one(); /* now require the check result to be succesful */
                    proof.generate_r1cs_witness(
                        accumulator.get_membership_proof(set_elems[0])); /* try it with invalid proof */
                    sc.generate_r1cs_witness();
                    root_digest.generate_r1cs_witness(accumulator.get_commitment());
                    assert(!pb.is_satisfied()); /* the protoboard should be unsatisfied */
                    printf("non-membership test OK\n");
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // SET_COMMITMENT_GADGET_HPP_

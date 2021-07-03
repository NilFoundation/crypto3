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
// @file Declaration of functionality that runs the R1CS multi-predicate ppzkPCD
// for a compliance predicate example.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_R1CS_MP_PPZKPCD_HPP
#define CRYPTO3_RUN_R1CS_MP_PPZKPCD_HPP

#include <cstddef>
#include <vector>

#include "tally_cp.hpp"

#include <nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_mp_ppzkpcd/r1cs_mp_ppzkpcd.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the multi-predicate ppzkPCD (generator, prover, and verifier) for the
                 * "tally compliance predicate", of a given wordsize, arity, and depth.
                 *
                 * Optionally, also test the case of compliance predicates with different types.
                 */
                template<typename PCD_ppT>
                bool run_r1cs_mp_ppzkpcd_tally_example(std::size_t wordsize,
                                                       std::size_t max_arity,
                                                       std::size_t depth,
                                                       bool test_multi_type,
                                                       bool test_same_type_optimization) {
                    typedef algebra::Fr<typename PCD_ppT::curve_A_pp> FieldType;

                    bool all_accept = true;

                    std::size_t tree_size = 0;
                    std::size_t nodes_in_layer = 1;
                    for (std::size_t layer = 0; layer <= depth; ++layer) {
                        tree_size += nodes_in_layer;
                        nodes_in_layer *= max_arity;
                    }

                    std::vector<std::size_t> tree_types(tree_size);
                    std::vector<std::size_t> tree_elems(tree_size);
                    std::vector<std::size_t> tree_arity(tree_size);

                    nodes_in_layer = 1;
                    std::size_t node_idx = 0;
                    for (std::size_t layer = 0; layer <= depth; ++layer) {
                        for (std::size_t id_in_layer = 0; id_in_layer < nodes_in_layer; ++id_in_layer, ++node_idx) {
                            if (!test_multi_type) {
                                tree_types[node_idx] = 1;
                            } else {
                                if (test_same_type_optimization) {
                                    tree_types[node_idx] = 1 + ((depth - layer) & 1);
                                } else {
                                    tree_types[node_idx] = 1 + (std::rand() % 2);
                                }
                            }

                            tree_elems[node_idx] = std::rand() % 100;
                            tree_arity[node_idx] =
                                1 + (std::rand() % max_arity); /* we will just skip below this threshold */
                            printf("tree_types[%zu] = %zu\n", node_idx, tree_types[node_idx]);
                            printf("tree_elems[%zu] = %zu\n", node_idx, tree_elems[node_idx]);
                            printf("tree_arity[%zu] = %zu\n", node_idx, tree_arity[node_idx]);
                        }
                        nodes_in_layer *= max_arity;
                    }

                    std::vector<r1cs_mp_ppzkpcd_proof<PCD_ppT>> tree_proofs(tree_size);
                    std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> tree_messages(tree_size);

                    std::set<std::size_t> tally_1_accepted_types, tally_2_accepted_types;
                    if (test_same_type_optimization) {
                        if (!test_multi_type) {
                            /* only tally 1 is going to be used */
                            tally_1_accepted_types.insert(1);
                        } else {
                            tally_1_accepted_types.insert(2);
                            tally_2_accepted_types.insert(1);
                        }
                    }

                    tally_cp_handler<FieldType> tally_1(
                        1, max_arity, wordsize, test_same_type_optimization, tally_1_accepted_types);
                    tally_cp_handler<FieldType> tally_2(
                        2, max_arity, wordsize, test_same_type_optimization, tally_2_accepted_types);
                    tally_1.generate_r1cs_constraints();
                    tally_2.generate_r1cs_constraints();
                    r1cs_pcd_compliance_predicate<FieldType> cp_1 = tally_1.get_compliance_predicate();
                    r1cs_pcd_compliance_predicate<FieldType> cp_2 = tally_2.get_compliance_predicate();

                    r1cs_mp_ppzkpcd_keypair<PCD_ppT> keypair = r1cs_mp_ppzkpcd_generator<PCD_ppT>({cp_1, cp_2});

                    r1cs_mp_ppzkpcd_processed_verification_key<PCD_ppT> pvk =
                        r1cs_mp_ppzkpcd_process_vk<PCD_ppT>(keypair.vk);

                    std::shared_ptr<r1cs_pcd_message<FieldType>> base_msg =
                        tally_1.get_base_case_message(); /* we choose the base to always be tally_1 */
                    nodes_in_layer /= max_arity;
                    for (long layer = depth; layer >= 0; --layer, nodes_in_layer /= max_arity) {
                        for (std::size_t i = 0; i < nodes_in_layer; ++i) {
                            const std::size_t cur_idx = (nodes_in_layer - 1) / (max_arity - 1) + i;

                            tally_cp_handler<FieldType> &cur_tally = (tree_types[cur_idx] == 1 ? tally_1 : tally_2);
                            r1cs_pcd_compliance_predicate<FieldType> &cur_cp = (tree_types[cur_idx] == 1 ? cp_1 : cp_2);

                            const bool base_case = (max_arity * cur_idx + max_arity >= tree_size);

                            std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> msgs(max_arity, base_msg);
                            std::vector<r1cs_mp_ppzkpcd_proof<PCD_ppT>> proofs(max_arity);

                            if (!base_case) {
                                for (std::size_t i = 0; i < max_arity; ++i) {
                                    msgs[i] = tree_messages[max_arity * cur_idx + i + 1];
                                    proofs[i] = tree_proofs[max_arity * cur_idx + i + 1];
                                }
                            }
                            msgs.resize(tree_arity[i]);
                            proofs.resize(tree_arity[i]);

                            std::shared_ptr<r1cs_pcd_local_data<FieldType>> ld;
                            ld.reset(new tally_pcd_local_data<FieldType>(tree_elems[cur_idx]));
                            cur_tally.generate_r1cs_witness(msgs, ld);

                            const r1cs_pcd_compliance_predicate_primary_input<FieldType> tally_primary_input(
                                cur_tally.get_outgoing_message());
                            const r1cs_pcd_compliance_predicate_auxiliary_input<FieldType> tally_auxiliary_input(
                                msgs, ld, cur_tally.get_witness());

                            r1cs_mp_ppzkpcd_proof<PCD_ppT> proof = r1cs_mp_ppzkpcd_prover<PCD_ppT>(
                                keypair.pk, cur_cp.name, tally_primary_input, tally_auxiliary_input, proofs);

                            tree_proofs[cur_idx] = proof;
                            tree_messages[cur_idx] = cur_tally.get_outgoing_message();

                            const r1cs_mp_ppzkpcd_primary_input<PCD_ppT> pcd_verifier_input(tree_messages[cur_idx]);
                            const bool ans =
                                r1cs_mp_ppzkpcd_verifier<PCD_ppT>(keypair.vk, pcd_verifier_input, tree_proofs[cur_idx]);

                            const bool ans2 =
                                r1cs_mp_ppzkpcd_online_verifier<PCD_ppT>(pvk, pcd_verifier_input, tree_proofs[cur_idx]);
                            BOOST_CHECK(ans == ans2);

                            all_accept = all_accept && ans;

                            printf("\n");
                            for (std::size_t i = 0; i < msgs.size(); ++i) {
                                printf("Message %zu was:\n", i);
                                msgs[i]->print();
                            }
                            printf("Summand at this node:\n%zu\n", tree_elems[cur_idx]);
                            printf("Outgoing message is:\n");
                            tree_messages[cur_idx]->print();
                            printf("\n");
                            printf("Current node = %zu. Current proof verifies = %s\n", cur_idx, ans ? "YES" : "NO");
                            printf(
                                "\n\n\n "
                                "================================================================================"
                                "\n\n\n");
                        }
                    }

                    return all_accept;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_R1CS_MP_PPZKPCD_HPP

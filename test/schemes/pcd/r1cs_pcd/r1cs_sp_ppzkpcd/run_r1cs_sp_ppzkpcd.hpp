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
// @file Declaration of functionality that runs the R1CS single-predicate ppzkPCD
// for a compliance predicate example.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_R1CS_SP_PPZKPCD_HPP
#define CRYPTO3_RUN_R1CS_SP_PPZKPCD_HPP

#include <cstddef>
#include <vector>

#include "tally_cp.hpp"

#include <nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the single-predicate ppzkPCD (generator, prover, and verifier) for the
                 * "tally compliance predicate", of a given wordsize, arity, and depth.
                 */
                template<typename PCD_ppT>
                bool run_r1cs_sp_ppzkpcd_tally_example(std::size_t wordsize, std::size_t arity, std::size_t depth) {

                    typedef algebra::Fr<typename PCD_ppT::curve_A_pp> FieldType;

                    bool all_accept = true;

                    std::size_t tree_size = 0;
                    std::size_t nodes_in_layer = 1;
                    for (std::size_t layer = 0; layer <= depth; ++layer) {
                        tree_size += nodes_in_layer;
                        nodes_in_layer *= arity;
                    }
                    std::vector<std::size_t> tree_elems(tree_size);
                    for (std::size_t i = 0; i < tree_size; ++i) {
                        tree_elems[i] = std::rand() % 10;
                        printf("tree_elems[%zu] = %zu\n", i, tree_elems[i]);
                    }

                    std::vector<r1cs_sp_ppzkpcd_proof<PCD_ppT>> tree_proofs(tree_size);
                    std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> tree_messages(tree_size);

                    const std::size_t type = 1;
                    tally_cp_handler<FieldType> tally(type, arity, wordsize);
                    tally.generate_r1cs_constraints();
                    r1cs_pcd_compliance_predicate<FieldType> tally_cp = tally.get_compliance_predicate();

                    r1cs_sp_ppzkpcd_keypair<PCD_ppT> keypair = r1cs_sp_ppzkpcd_generator<PCD_ppT>(tally_cp);

                    r1cs_sp_ppzkpcd_processed_verification_key<PCD_ppT> pvk =
                        r1cs_sp_ppzkpcd_process_vk<PCD_ppT>(keypair.vk);

                    std::shared_ptr<r1cs_pcd_message<FieldType>> base_msg = tally.get_base_case_message();
                    nodes_in_layer /= arity;
                    for (long layer = depth; layer >= 0; --layer, nodes_in_layer /= arity) {
                        for (std::size_t i = 0; i < nodes_in_layer; ++i) {
                            const std::size_t cur_idx = (nodes_in_layer - 1) / (arity - 1) + i;

                            std::vector<std::shared_ptr<r1cs_pcd_message<FieldType>>> msgs(arity, base_msg);
                            std::vector<r1cs_sp_ppzkpcd_proof<PCD_ppT>> proofs(arity);

                            const bool base_case = (arity * cur_idx + arity >= tree_size);

                            if (!base_case) {
                                for (std::size_t i = 0; i < arity; ++i) {
                                    msgs[i] = tree_messages[arity * cur_idx + i + 1];
                                    proofs[i] = tree_proofs[arity * cur_idx + i + 1];
                                }
                            }

                            std::shared_ptr<r1cs_pcd_local_data<FieldType>> ld;
                            ld.reset(new tally_pcd_local_data<FieldType>(tree_elems[cur_idx]));
                            tally.generate_r1cs_witness(msgs, ld);

                            const r1cs_pcd_compliance_predicate_primary_input<FieldType> tally_primary_input(
                                tally.get_outgoing_message());
                            const r1cs_pcd_compliance_predicate_auxiliary_input<FieldType> tally_auxiliary_input(
                                msgs, ld, tally.get_witness());

                            r1cs_sp_ppzkpcd_proof<PCD_ppT> proof = r1cs_sp_ppzkpcd_prover<PCD_ppT>(
                                keypair.pk, tally_primary_input, tally_auxiliary_input, proofs);

                            tree_proofs[cur_idx] = proof;
                            tree_messages[cur_idx] = tally.get_outgoing_message();

                            const r1cs_sp_ppzkpcd_primary_input<PCD_ppT> pcd_verifier_input(tree_messages[cur_idx]);
                            const bool ans =
                                r1cs_sp_ppzkpcd_verifier<PCD_ppT>(keypair.vk, pcd_verifier_input, tree_proofs[cur_idx]);

                            const bool ans2 =
                                r1cs_sp_ppzkpcd_online_verifier<PCD_ppT>(pvk, pcd_verifier_input, tree_proofs[cur_idx]);
                            BOOST_CHECK(ans == ans2);

                            all_accept = all_accept && ans;

                            printf("\n");
                            for (std::size_t i = 0; i < arity; ++i) {
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

#endif    // CRYPTO3_RUN_R1CS_SP_PPZKPCD_HPP

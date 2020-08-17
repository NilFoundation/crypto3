//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef RUN_USCS_PPZKSNARK_HPP_
#define RUN_USCS_PPZKSNARK_HPP_

#include <nil/algebra/curves/public_params.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs/examples/uscs_examples.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the ppzkSNARK (generator, prover, and verifier) for a given
                 * USCS example (specified by a constraint system, input, and witness).
                 *
                 * Optionally, also test the serialization routines for keys and proofs.
                 * (This takes additional time.)
                 */
                template<typename ppT>
                bool run_uscs_ppzksnark(const uscs_example<algebra::Fr<ppT>> &example, const bool test_serialization);

                /**
                 * The code below provides an example of all stages of running a USCS ppzkSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkSNARK generator on input a given
                 *     constraint system CS to create a proving and a verification key for CS.
                 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
                 *     a primary input for CS, and an auxiliary input for CS.
                 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
                 *     a primary input for CS, and a proof.
                 */
                template<typename ppT>
                bool run_uscs_ppzksnark(const uscs_example<algebra::Fr<ppT>> &example, const bool test_serialization) {
                    algebra::enter_block("Call to run_uscs_ppzksnark");

                    algebra::print_header("USCS ppzkSNARK Generator");
                    uscs_ppzksnark_keypair<ppT> keypair = uscs_ppzksnark_generator<ppT>(example.constraint_system);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after generator");

                    algebra::print_header("Preprocess verification key");
                    uscs_ppzksnark_processed_verification_key<ppT> pvk =
                        uscs_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

                    if (test_serialization) {
                        algebra::enter_block("Test serialization of keys");
                        keypair.pk = algebra::reserialize<uscs_ppzksnark_proving_key<ppT>>(keypair.pk);
                        keypair.vk = algebra::reserialize<uscs_ppzksnark_verification_key<ppT>>(keypair.vk);
                        pvk = algebra::reserialize<uscs_ppzksnark_processed_verification_key<ppT>>(pvk);
                        algebra::leave_block("Test serialization of keys");
                    }

                    algebra::print_header("USCS ppzkSNARK Prover");
                    uscs_ppzksnark_proof<ppT> proof =
                        uscs_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after prover");

                    if (test_serialization) {
                        algebra::enter_block("Test serialization of proof");
                        proof = algebra::reserialize<uscs_ppzksnark_proof<ppT>>(proof);
                        algebra::leave_block("Test serialization of proof");
                    }

                    algebra::print_header("USCS ppzkSNARK Verifier");
                    bool ans = uscs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after verifier");
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    algebra::print_header("USCS ppzkSNARK Online Verifier");
                    bool ans2 = uscs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
                    assert(ans == ans2);

                    algebra::leave_block("Call to run_uscs_ppzksnark");

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RUN_USCS_PPZKSNARK_HPP_

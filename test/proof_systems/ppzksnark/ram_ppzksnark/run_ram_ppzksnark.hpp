//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef RUN_RAM_PPZKSNARK_HPP_
#define RUN_RAM_PPZKSNARK_HPP_

#include <nil/crypto3/zk/snark/relations/ram_computations/rams/examples/ram_examples.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/ram_ppzksnark/ram_ppzksnark_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the ppzkSNARK (generator, prover, and verifier) for a given
                 * RAM example (specified by an architecture, boot trace, auxiliary input, and time bound).
                 *
                 * Optionally, also test the serialization routines for keys and proofs.
                 * (This takes additional time.)
                 */
                template<typename ram_ppzksnark_ppT>
                bool run_ram_ppzksnark(const ram_example<ram_ppzksnark_machine_pp<ram_ppzksnark_ppT>> &example,
                                       const bool test_serialization);

                /**
                 * The code below provides an example of all stages of running a RAM ppzkSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkSNARK generator on input a given
                 *     architecture and bounds on the computation.
                 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
                 *     a boot trace, and an auxiliary input.
                 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
                 *     a boot trace, and a proof.
                 */
                template<typename ram_ppzksnark_ppT>
                bool run_ram_ppzksnark(const ram_example<ram_ppzksnark_machine_pp<ram_ppzksnark_ppT>> &example,
                                       const bool test_serialization) {
                    algebra::enter_block("Call to run_ram_ppzksnark");

                    printf("This run uses an example with the following parameters:\n");
                    example.ap.print();
                    printf("* Primary input size bound (L): %zu\n", example.boot_trace_size_bound);
                    printf("* Time bound (T): %zu\n", example.time_bound);
                    printf("Hence, algebra::algebra::log2(L+2*T) equals %zu\n",
                        algebra::log2(example.boot_trace_size_bound + 2 * example.time_bound));

                    algebra::print_header("RAM ppzkSNARK Generator");
                    ram_ppzksnark_keypair<ram_ppzksnark_ppT> keypair = ram_ppzksnark_generator<ram_ppzksnark_ppT>(
                        example.ap, example.boot_trace_size_bound, example.time_bound);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after generator");

                    if (test_serialization) {
                        algebra::enter_block("Test serialization of keys");
                        keypair.pk = algebra::reserialize<ram_ppzksnark_proving_key<ram_ppzksnark_ppT>>(keypair.pk);
                        keypair.vk = algebra::reserialize<ram_ppzksnark_verification_key<ram_ppzksnark_ppT>>(keypair.vk);
                        algebra::leave_block("Test serialization of keys");
                    }

                    algebra::print_header("RAM ppzkSNARK Prover");
                    ram_ppzksnark_proof<ram_ppzksnark_ppT> proof = ram_ppzksnark_prover<ram_ppzksnark_ppT>(
                        keypair.pk, example.boot_trace, example.auxiliary_input);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after prover");

                    if (test_serialization) {
                        algebra::enter_block("Test serialization of proof");
                        proof = algebra::reserialize<ram_ppzksnark_proof<ram_ppzksnark_ppT>>(proof);
                        algebra::leave_block("Test serialization of proof");
                    }

                    algebra::print_header("RAM ppzkSNARK Verifier");
                    bool ans = ram_ppzksnark_verifier<ram_ppzksnark_ppT>(keypair.vk, example.boot_trace, proof);
                    printf("\n");
                    algebra::print_indent();
                    algebra::print_mem("after verifier");
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    algebra::leave_block("Call to run_ram_ppzksnark");

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RUN_RAM_PPZKSNARK_HPP_

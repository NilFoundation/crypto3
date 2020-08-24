//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_RAM_ZKSNARK_HPP
#define CRYPTO3_RUN_RAM_ZKSNARK_HPP

#include <nil/crypto3/zk/snark/relations/ram_computations/rams/examples/ram_examples.hpp>
#include <nil/crypto3/zk/snark/proof_systems/zksnark/ram_zksnark/ram_zksnark_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the zkSNARK (generator, prover, and verifier) for a given
                 * RAM example (specified by an architecture, boot trace, auxiliary input, and time bound).
                 *
                 * Optionally, also test the serialization routines for keys and proofs.
                 * (This takes additional time.)
                 */
                template<typename ram_zksnark_ppT>
                bool run_ram_zksnark(const ram_example<ram_zksnark_machine_pp<ram_zksnark_ppT>> &example,
                                     const bool test_serialization);

                /**
                 * The code below provides an example of all stages of running a RAM zkSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the zkSNARK generator on input a given
                 *     architecture.
                 * (2) The "prover", which runs the zkSNARK prover on input the proving key,
                 *     a boot trace, and an auxiliary input.
                 * (3) The "verifier", which runs the zkSNARK verifier on input the verification key,
                 *     a boot trace, a time bound, and a proof.
                 */
                template<typename ram_zksnark_ppT>
                bool run_ram_zksnark(const ram_example<ram_zksnark_machine_pp<ram_zksnark_ppT>> &example,
                                     const bool test_serialization) {
                    std::cout << "Call to run_ram_zksnark" << std::endl;

                    printf("This run uses an example with the following parameters:\n");
                    example.ap.print();
                    printf("* Time bound (T): %zu\n", example.time_bound);

                    std::cout << "RAM zkSNARK Generator" << std::endl;
                    ram_zksnark_keypair<ram_zksnark_ppT> keypair = ram_zksnark_generator<ram_zksnark_ppT>(example.ap);

                    if (test_serialization) {
                        std::cout << "Test serialization of keys" << std::endl;
                        keypair.pk = algebra::reserialize<ram_zksnark_proving_key<ram_zksnark_ppT>>(keypair.pk);
                        keypair.vk = algebra::reserialize<ram_zksnark_verification_key<ram_zksnark_ppT>>(keypair.vk);
                    }

                    std::cout << "RAM zkSNARK Prover" << std::endl;
                    ram_zksnark_proof<ram_zksnark_ppT> proof = ram_zksnark_prover<ram_zksnark_ppT>(
                        keypair.pk, example.boot_trace, example.time_bound, example.auxiliary_input);

                    if (test_serialization) {
                        std::cout << "Test serialization of proof" << std::endl;
                        proof = algebra::reserialize<ram_zksnark_proof<ram_zksnark_ppT>>(proof);
                    }

                    std::cout << "RAM zkSNARK Verifier" << std::endl;
                    bool ans = ram_zksnark_verifier<ram_zksnark_ppT>(
                        keypair.vk, example.boot_trace, example.time_bound, proof);
                    
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_RAM_ZKSNARK_HPP

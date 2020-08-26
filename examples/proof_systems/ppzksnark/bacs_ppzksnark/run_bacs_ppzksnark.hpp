//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_BACS_PPZKSNARK_HPP
#define CRYPTO3_RUN_BACS_PPZKSNARK_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/examples/bacs_examples.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the ppzkSNARK (generator, prover, and verifier) for a given
                 * BACS example (specified by a circuit, primary input, and auxiliary input).
                 */
                template<typename CurveType>
                bool run_bacs_ppzksnark(const bacs_example<typename CurveType::scalar_field_type> &example);

                /**
                 * The code below provides an example of all stages of running a BACS ppzkSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkSNARK generator on input a given
                 *     circuit C to create a proving and a verification key for C.
                 * (2) The "prover", which runs the ppzkSNARK prover on input the proving key,
                 *     a primary input for C, and an auxiliary input for C.
                 * (3) The "verifier", which runs the ppzkSNARK verifier on input the verification key,
                 *     a primary input for C, and a proof.
                 */
                template<typename CurveType>
                bool run_bacs_ppzksnark(const bacs_example<typename CurveType::scalar_field_type> &example) {
                    std::cout << "Call to run_bacs_ppzksnark" << std::endl;

                    std::cout << "BACS ppzkSNARK Generator" << std::endl;
                    bacs_ppzksnark_keypair<CurveType> keypair = bacs_ppzksnark_generator<CurveType>(example.circuit);

                    std::cout << "Preprocess verification key" << std::endl;
                    bacs_ppzksnark_processed_verification_key<CurveType> pvk =
                        bacs_ppzksnark_verifier_process_vk<CurveType>(keypair.vk);

                    std::cout << "BACS ppzkSNARK Prover" << std::endl;
                    bacs_ppzksnark_proof<CurveType> proof =
                        bacs_ppzksnark_prover<CurveType>(keypair.pk, example.primary_input, example.auxiliary_input);

                    std::cout << "BACS ppzkSNARK Verifier" << std::endl;
                    bool ans = bacs_ppzksnark_verifier_strong_IC<CurveType>(keypair.vk, example.primary_input, proof);
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    std::cout << "BACS ppzkSNARK Online Verifier" << std::endl;
                    bool ans2 = bacs_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, example.primary_input, proof);
                    assert(ans == ans2);

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_BACS_PPZKSNARK_HPP

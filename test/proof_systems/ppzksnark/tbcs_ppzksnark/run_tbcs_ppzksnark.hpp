//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_TBCS_PPZKSNARK_HPP
#define CRYPTO3_RUN_TBCS_PPZKSNARK_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs/examples/tbcs_examples.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the ppzkSNARK (generator, prover, and verifier) for a given
                 * TBCS example (specified by a circuit, primary input, and auxiliary input).
                 */
                template<typename CurveType>
                bool run_tbcs_ppzksnark(const tbcs_example &example);

                /**
                 * The code below provides an example of all stages of running a TBCS ppzkSNARK.
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
                bool run_tbcs_ppzksnark(const tbcs_example &example) {
                    std::cout << "Call to run_tbcs_ppzksnark" << std::endl;

                    std::cout << "TBCS ppzkSNARK Generator" << std::endl;
                    tbcs_ppzksnark_keypair<CurveType> keypair = tbcs_ppzksnark_generator<CurveType>(example.circuit);

                    std::cout << "Preprocess verification key" << std::endl;
                    tbcs_ppzksnark_processed_verification_key<CurveType> pvk =
                        tbcs_ppzksnark_verifier_process_vk<CurveType>(keypair.vk);

                    std::cout << "TBCS ppzkSNARK Prover" << std::endl;
                    tbcs_ppzksnark_proof<CurveType> proof =
                        tbcs_ppzksnark_prover<CurveType>(keypair.pk, example.primary_input, example.auxiliary_input);

                    std::cout << "TBCS ppzkSNARK Verifier" << std::endl;
                    bool ans = tbcs_ppzksnark_verifier_strong_IC<CurveType>(keypair.vk, example.primary_input, proof);
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    std::cout << "TBCS ppzkSNARK Online Verifier" << std::endl;
                    bool ans2 = tbcs_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, example.primary_input, proof);
                    BOOST_CHECK(ans == ans2);

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_TBCS_PPZKSNARK_HPP

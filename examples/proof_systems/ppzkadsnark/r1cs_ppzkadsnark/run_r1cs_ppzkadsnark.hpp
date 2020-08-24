//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_R1CS_PPZKADSNARK_HPP
#define CRYPTO3_RUN_R1CS_PPZKADSNARK_HPP

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

              using nil::algebra;

                /**
                 * Runs the ppzkADSNARK (generator, prover, and verifier) for a given
                 * R1CS example (specified by a constraint system, input, and witness).
                 *
                 * Optionally, also test the serialization routines for keys and proofs.
                 * (This takes additional time.)
                 */
                template<typename CurveType>
                bool run_r1cs_ppzkadsnark(const r1cs_example<curves::CurveType::scalar_field_type> &example,
                                          const bool test_serialization);

                /**
                 * The code below provides an example of all stages of running a R1CS ppzkADSNARK.
                 *
                 * Of course, in a real-life scenario, we would have three distinct entities,
                 * mangled into one in the demonstration below. The three entities are as follows.
                 * (1) The "generator", which runs the ppzkADSNARK generator on input a given
                 *     constraint system CS to create a proving and a verification key for CS.
                 * (2) The "prover", which runs the ppzkADSNARK prover on input the proving key,
                 *     a primary input for CS, and an auxiliary input for CS.
                 * (3) The "verifier", which runs the ppzkADSNARK verifier on input the verification key,
                 *     a primary input for CS, and a proof.
                 */
                template<typename CurveType>
                bool run_r1cs_ppzkadsnark(const r1cs_example<curves::CurveType::scalar_field_type> &example,
                                          const bool test_serialization) {

                    r1cs_ppzkadsnark_auth_keys<CurveType> auth_keys = r1cs_ppzkadsnark_auth_generator<CurveType>();

                    r1cs_ppzkadsnark_keypair<CurveType> keypair =
                        r1cs_ppzkadsnark_generator<CurveType>(example.constraint_system, auth_keys.pap);
                    
                    r1cs_ppzkadsnark_processed_verification_key<CurveType> pvk =
                        r1cs_ppzkadsnark_verifier_process_vk<CurveType>(keypair.vk);

                    if (test_serialization) {;
                        keypair.pk = algebra::reserialize<r1cs_ppzkadsnark_proving_key<CurveType>>(keypair.pk);
                        keypair.vk = algebra::reserialize<r1cs_ppzkadsnark_verification_key<CurveType>>(keypair.vk);
                        pvk = algebra::reserialize<r1cs_ppzkadsnark_processed_verification_key<CurveType>>(pvk);
                    }

                    std::vector<algebra::Fr<snark_pp<CurveType>>> data;
                    data.reserve(example.constraint_system.num_inputs());
                    std::vector<labelT> labels;
                    labels.reserve(example.constraint_system.num_inputs());
                    for (std::size_t i = 0; i < example.constraint_system.num_inputs(); i++) {
                        labels.emplace_back(labelT());
                        data.emplace_back(example.primary_input[i]);
                    }
                    std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> auth_data =
                                                                     r1cs_ppzkadsnark_auth_sign<CurveType>(data, auth_keys.sak, labels);

                    bool auth_res = r1cs_ppzkadsnark_auth_verify<CurveType>(data, auth_data, auth_keys.sak, labels);
                    printf("* The verification result is: %s\n", (auth_res ? "PASS" : "FAIL"));

                    bool auth_resp = r1cs_ppzkadsnark_auth_verify<CurveType>(data, auth_data, auth_keys.pak, labels);
                    assert(auth_res == auth_resp);

                    r1cs_ppzkadsnark_proof<CurveType> proof = r1cs_ppzkadsnark_prover<CurveType>(
                        keypair.pk, example.primary_input, example.auxiliary_input, auth_data);
                    

                    if (test_serialization) {
                        proof = algebra::reserialize<r1cs_ppzkadsnark_proof<CurveType>>(proof);
                    }

                    bool ans = r1cs_ppzkadsnark_verifier<CurveType>(keypair.vk, proof, auth_keys.sak, labels);
                    
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    bool ans2 = r1cs_ppzkadsnark_online_verifier<CurveType>(pvk, proof, auth_keys.sak, labels);
                    assert(ans == ans2);

                    ans = r1cs_ppzkadsnark_verifier<CurveType>(keypair.vk, auth_data, proof, auth_keys.pak, labels);
                    
                    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

                    ans2 = r1cs_ppzkadsnark_online_verifier<CurveType>(pvk, auth_data, proof, auth_keys.pak, labels);
                    assert(ans == ans2);

                    return ans;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_R1CS_PPZKADSNARK_HPP

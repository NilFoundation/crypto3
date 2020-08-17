//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of functionality that runs the R1CS GG-ppzkSNARK for
// a given R1CS example.
//---------------------------------------------------------------------------//

#ifndef RUN_R1CS_GG_PPZKSNARK_HPP_
#define RUN_R1CS_GG_PPZKSNARK_HPP_

#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>

#include "r1cs_examples.hpp"

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Runs the ppzkSNARK (generator, prover, and verifier) for a given
                 * R1CS example (specified by a constraint system, input, and witness).
                 *
                 * Optionally, also test the serialization routines for keys and proofs.
                 * (This takes additional time.)
                 */
                template<typename ppT>
                bool run_r1cs_gg_ppzksnark(const r1cs_example<algebra::Fr<ppT>> &example, bool test_serialization);

                template<typename ppT>
                typename std::enable_if<ppT::has_affine_pairing, void>::type
                    test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                                         const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                                         const r1cs_gg_ppzksnark_proof<ppT> &proof,
                                         const bool expected_answer) {
                    const bool answer = r1cs_gg_ppzksnark_affine_verifier_weak_IC<ppT>(vk, primary_input, proof);
                    BOOST_CHECK(answer == expected_answer);
                }

                template<typename ppT>
                typename std::enable_if<!ppT::has_affine_pairing, void>::type
                    test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
                                         const r1cs_gg_ppzksnark_primary_input<ppT> &primary_input,
                                         const r1cs_gg_ppzksnark_proof<ppT> &proof,
                                         const bool expected_answer) {
                    BOOST_ATTRIBUTE_UNUSED(vk, primary_input, proof, expected_answer);
                }

                /**
                 * The code below provides an example of all stages of running a R1CS GG-ppzkSNARK.
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
                bool run_r1cs_gg_ppzksnark(const r1cs_example<algebra::Fr<ppT>> &example, bool test_serialization) {
                    r1cs_gg_ppzksnark_keypair<ppT> keypair =
                        r1cs_gg_ppzksnark_generator<ppT>(example.constraint_system);

                    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk =
                        r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

                    if (test_serialization) {
                        keypair.pk = algebra::reserialize<r1cs_gg_ppzksnark_proving_key<ppT>>(keypair.pk);
                        keypair.vk = algebra::reserialize<r1cs_gg_ppzksnark_verification_key<ppT>>(keypair.vk);
                        pvk = algebra::reserialize<r1cs_gg_ppzksnark_processed_verification_key<ppT>>(pvk);
                    }

                    r1cs_gg_ppzksnark_proof<ppT> proof =
                        r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, example.primary_input, example.auxiliary_input);

                    if (test_serialization) {
                        proof = algebra::reserialize<r1cs_gg_ppzksnark_proof<ppT>>(proof);
                    }

                    const bool ans =
                        r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, example.primary_input, proof);

                    const bool ans2 =
                        r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, example.primary_input, proof);
                    BOOST_CHECK(ans == ans2);

                    test_affine_verifier<ppT>(keypair.vk, example.primary_input, proof, ans);

                    return ans;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RUN_R1CS_GG_PPZKSNARK_HPP_

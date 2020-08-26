//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of functionality that runs the R1CS GG-ppzkSNARK for
// a given R1CS example.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RUN_R1CS_GG_PPZKSNARK_HPP
#define CRYPTO3_RUN_R1CS_GG_PPZKSNARK_HPP

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
                 */
                template<typename CurveType>
                bool run_r1cs_gg_ppzksnark(const r1cs_example<typename CurveType::scalar_field_type> &example);

                template<typename CurveType>
                typename std::enable_if<CurveType::has_affine_pairing, void>::type
                    test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<CurveType> &vk,
                                         const r1cs_gg_ppzksnark_primary_input<CurveType> &primary_input,
                                         const r1cs_gg_ppzksnark_proof<CurveType> &proof,
                                         const bool expected_answer) {
                    const bool answer = r1cs_gg_ppzksnark_affine_verifier_weak_IC<CurveType>(vk, primary_input, proof);
                    BOOST_CHECK(answer == expected_answer);
                }

                template<typename CurveType>
                typename std::enable_if<!CurveType::has_affine_pairing, void>::type
                    test_affine_verifier(const r1cs_gg_ppzksnark_verification_key<CurveType> &vk,
                                         const r1cs_gg_ppzksnark_primary_input<CurveType> &primary_input,
                                         const r1cs_gg_ppzksnark_proof<CurveType> &proof,
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
                template<typename CurveType>
                bool run_r1cs_gg_ppzksnark(const r1cs_example<typename CurveType::scalar_field_type> &example) {
                    r1cs_gg_ppzksnark_keypair<CurveType> keypair =
                        r1cs_gg_ppzksnark_generator<CurveType>(example.constraint_system);

                    r1cs_gg_ppzksnark_processed_verification_key<CurveType> pvk =
                        r1cs_gg_ppzksnark_verifier_process_vk<CurveType>(keypair.vk);

                    r1cs_gg_ppzksnark_proof<CurveType> proof =
                        r1cs_gg_ppzksnark_prover<CurveType>(keypair.pk, example.primary_input, example.auxiliary_input);

                    const bool ans =
                        r1cs_gg_ppzksnark_verifier_strong_IC<CurveType>(keypair.vk, example.primary_input, proof);

                    const bool ans2 =
                        r1cs_gg_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, example.primary_input, proof);
                    BOOST_CHECK(ans == ans2);

                    test_affine_verifier<CurveType>(keypair.vk, example.primary_input, proof, ans);

                    return ans;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_RUN_R1CS_GG_PPZKSNARK_HPP

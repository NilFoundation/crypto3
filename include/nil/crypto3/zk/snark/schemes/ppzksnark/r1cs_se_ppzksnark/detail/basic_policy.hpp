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
// @file Declaration of interfaces for a SEppzkSNARK for R1CS.
//
// This includes:
// - class for proving key
// - class for verification key
// - class for processed verification key
// - class for key pair (proving key & verification key)
// - class for proof
// - generator algorithm
// - prover algorithm
// - verifier algorithm (with strong or weak input consistency)
// - online verifier algorithm (with strong or weak input consistency)
//
// The implementation instantiates (a modification of) the protocol of \[GM17],
// by following extending, and optimizing the approach described in \[BCTV14].
//
//
// Acronyms:
//
// - R1CS = "Rank-1 Constraint Systems"
// - SEppzkSNARK = "Simulation-Extractable PreProcessing Zero-Knowledge Succinct
//     Non-interactive ARgument of Knowledge"
//
// References:
//
// \[BCTV14]:
// "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// USENIX Security 2014,
// <http://eprint.iacr.org/2013/879>
//
// \[GM17]:
// "Snarky Signatures: Minimal Signatures of Knowledge from
//  Simulation-Extractable SNARKs",
// Jens Groth and Mary Maller,
// IACR-CRYPTO-2017,
// <https://eprint.iacr.org/2017/540>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_SE_PPZKSNARK_TYPES_POLICY_HPP
#define CRYPTO3_R1CS_SE_PPZKSNARK_TYPES_POLICY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_se_ppzksnark/proving_key.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_se_ppzksnark/verification_key.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_se_ppzksnark/proof.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_se_ppzksnark/keypair.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_sap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct r1cs_se_ppzksnark_types_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        typedef r1cs_constraint_system<typename CurveType::scalar_field_type> constraint_system_type;

                        typedef r1cs_primary_input<typename CurveType::scalar_field_type> primary_input_type;

                        typedef r1cs_auxiliary_input<typename CurveType::scalar_field_type> auxiliary_input_type;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the R1CS SEppzkSNARK.
                         */
                        typedef r1cs_se_ppzksnark_proving_key<CurveType, constraint_system_type> proving_key_type;

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the R1CS SEppzkSNARK.
                         */
                        typedef r1cs_se_ppzksnark_verification_key<CurveType> verification_key_type;

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the R1CS SEppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        typedef r1cs_se_ppzksnark_processed_verification_key<CurveType> processed_verification_key_type;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the R1CS SEppzkSNARK, which consists of a proving key and a verification key.
                         */
                        typedef r1cs_se_ppzksnark_keypair<proving_key_type, verification_key_type> keypair_type;

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the R1CS SEppzkSNARK.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        typedef r1cs_se_ppzksnark_proof<CurveType> proof_type;
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_SE_PPZKSNARK_TYPES_POLICY_HPP

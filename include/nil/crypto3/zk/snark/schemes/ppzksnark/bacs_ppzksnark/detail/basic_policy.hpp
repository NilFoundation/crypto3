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
// @file Declaration of interfaces for a ppzkSNARK for BACS.
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
// The implementation is a straightforward combination of:
// (1) a BACS-to-R1CS reduction, and
// (2) a ppzkSNARK for R1CS.
//
//
// Acronyms:
//
// - BACS = "Bilinear Arithmetic Circuit Satisfiability"
// - R1CS = "Rank-1 Constraint System"
// - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_TYPES_POLICY_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_TYPES_POLICY_HPP

#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark/proving_key.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark/keypair.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct bacs_ppzksnark_policy {
                        typedef CurveType curve_type;

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        typedef bacs_circuit<typename curve_type::scalar_field_type> circuit_type;

                        typedef bacs_primary_input<typename curve_type::scalar_field_type> primary_input_type;

                        typedef bacs_auxiliary_input<typename curve_type::scalar_field_type> auxiliary_input_type;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the BACS ppzkSNARK.
                         */
                        typedef bacs_ppzksnark_proving_key<curve_type, circuit_type> proving_key_type;

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the BACS ppzkSNARK.
                         */
                        typedef typename r1cs_ppzksnark<curve_type>::verification_key_type verification_key_type;

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the BACS ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        typedef typename r1cs_ppzksnark<CurveType>::processed_verification_key_type
                            processed_verification_key_type;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the BACS ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        typedef bacs_ppzksnark_keypair<proving_key_type, verification_key_type> keypair_type;

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the BACS ppzkSNARK.
                         */
                        typedef typename r1cs_ppzksnark<CurveType>::proof_type proof_type;
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_TYPES_POLICY_HPP

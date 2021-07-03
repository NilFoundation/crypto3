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
// @file Declaration of interfaces for a ppzkSNARK for TBCS.
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
// (1) a TBCS-to-USCS reduction, and
// (2) a ppzkSNARK for USCS.
//
//
// Acronyms:
//
// - TBCS = "Two-input Boolean Circuit Satisfiability"
// - USCS = "Unitary-Square Constraint System"
// - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TBCS_PPZKSNARK_TYPES_POLICY_HPP
#define CRYPTO3_ZK_TBCS_PPZKSNARK_TYPES_POLICY_HPP

#include <nil/crypto3/zk/snark/schemes/ppzksnark/tbcs_ppzksnark/proving_key.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/tbcs_ppzksnark/keypair.hpp>

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct tbcs_ppzksnark_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various typedefs aliases (used for uniformity with other proof systems).
                         */

                        typedef tbcs_circuit circuit_type;

                        typedef tbcs_primary_input primary_input_type;

                        typedef tbcs_auxiliary_input auxiliary_input_type;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the TBCS ppzkSNARK.
                         */
                        typedef tbcs_ppzksnark_proving_key<CurveType, circuit_type> proving_key_type;

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the TBCS ppzkSNARK.
                         */
                        typedef typename uscs_ppzksnark<CurveType>::verification_key_type verification_key_type;

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the TBCS ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        typedef typename uscs_ppzksnark<CurveType>::processed_verification_key_type
                            processed_verification_key_type;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the TBCS ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        typedef tbcs_ppzksnark_keypair<proving_key_type, verification_key_type> keypair_type;

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the TBCS ppzkSNARK.
                         */
                        typedef typename uscs_ppzksnark<CurveType>::proof_type proof_type;
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_TYPES_POLICY_HPP

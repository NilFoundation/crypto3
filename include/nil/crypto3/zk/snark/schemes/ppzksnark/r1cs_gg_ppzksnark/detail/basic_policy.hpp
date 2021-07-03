//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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
// @file Declaration of interfaces for a ppzkSNARK for R1CS with a security proof
// in the generic group (GG) model.
//
// This includes:
//- class for proving key
//- class for verification key
//- class for processed verification key
//- class for key pair (proving key & verification key)
//- class for proof
//- generator algorithm
//- prover algorithm
//- verifier algorithm (with strong or weak input consistency)
//- online verifier algorithm (with strong or weak input consistency)
//
// The implementation instantiates the protocol of \[Gro16].
//
//
// Acronyms:
//
//- R1CS = "Rank-1 Constraint Systems"
//- ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//
// References:
//
//\[Gro16]:
// "On the Size of Pairing-based Non-interactive Arguments",
// Jens Groth,
// EUROCRYPT 2016,
// <https://eprint.iacr.org/2016/260>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_BASIC_POLICY_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_BASIC_POLICY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/modes.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/proving_key.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/verification_key.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/keypair.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/proof.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/proof.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/verification_key.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark/ipp2/srs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {
                    template<typename CurveType, ProvingMode mode = ProvingMode::Basic>
                    struct r1cs_gg_ppzksnark_basic_policy;

                    template<typename CurveType>
                    struct r1cs_gg_ppzksnark_basic_policy<CurveType, ProvingMode::Basic> {
                        typedef CurveType curve_type;

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        typedef r1cs_constraint_system<typename curve_type::scalar_field_type> constraint_system_type;

                        typedef r1cs_primary_input<typename curve_type::scalar_field_type> primary_input_type;

                        typedef r1cs_auxiliary_input<typename curve_type::scalar_field_type> auxiliary_input_type;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the R1CS GG-ppzkSNARK.
                         */
                        typedef r1cs_gg_ppzksnark_proving_key<curve_type, constraint_system_type> proving_key_type;

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the R1CS GG-ppzkSNARK.
                         */
                        typedef r1cs_gg_ppzksnark_verification_key<curve_type> verification_key_type;

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the R1CS GG-ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        typedef r1cs_gg_ppzksnark_processed_verification_key<curve_type>
                            processed_verification_key_type;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the R1CS GG-ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        typedef r1cs_gg_ppzksnark_keypair<proving_key_type, verification_key_type> keypair_type;

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the R1CS GG-ppzkSNARK.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        typedef r1cs_gg_ppzksnark_proof<CurveType> proof_type;
                    };

                    template<typename CurveType>
                    struct r1cs_gg_ppzksnark_basic_policy<CurveType, ProvingMode::Aggregate> {
                        typedef CurveType curve_type;

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        typedef r1cs_constraint_system<typename curve_type::scalar_field_type> constraint_system_type;

                        typedef r1cs_primary_input<typename curve_type::scalar_field_type> primary_input_type;

                        typedef r1cs_auxiliary_input<typename curve_type::scalar_field_type> auxiliary_input_type;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the R1CS GG-ppzkSNARK.
                         */
                        typedef r1cs_gg_ppzksnark_proving_key<curve_type, constraint_system_type> proving_key_type;

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the R1CS GG-ppzkSNARK.
                         */
                        typedef r1cs_gg_ppzksnark_aggregate_verification_key<curve_type> verification_key_type;

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the R1CS GG-ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        typedef r1cs_gg_ppzksnark_processed_verification_key<curve_type>
                            processed_verification_key_type;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the R1CS GG-ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        typedef r1cs_gg_ppzksnark_keypair<proving_key_type, verification_key_type> keypair_type;

                        /********************************** Aggregation SRS *********************************/

                        /**
                         * A SRS (Structured Reference String) for the R1CS GG-ppzkSNARK aggregation scheme.
                         */
                        typedef r1cs_gg_pp_zksnark_aggregate_srs<CurveType> srs_type;

                        /******************************** Proving SRS for aggregation ********************************/

                        /**
                         * A proving SRS for the R1CS GG-ppzkSNARK aggregation scheme.
                         */
                        typedef typename srs_type::proving_srs_type proving_srs_type;

                        /**************************** Verification SRS for aggregation ********************************/

                        /**
                         * A verification SRS for the R1CS GG-ppzkSNARK aggregation scheme.
                         */
                        typedef typename srs_type::verification_srs_type verification_srs_type;

                        /********************************** Aggregation SRS pair *********************************/

                        /**
                         * A SRS pair for the R1CS GG-ppzkSNARK aggregation scheme consisting of a proving SRS and
                         * a verification SRS.
                         */
                        typedef typename srs_type::srs_pair_type srs_pair_type;

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the R1CS GG-ppzkSNARK.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        typedef r1cs_gg_ppzksnark_proof<CurveType> proof_type;

                        /*********************************** Aggregated proof ***********************************/

                        /**
                         * A proof for the R1CS GG-ppzkSNARK aggregation scheme.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        typedef r1cs_gg_ppzksnark_aggregate_proof<CurveType> aggregate_proof_type;
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP

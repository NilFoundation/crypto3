//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_POLICY_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_POLICY_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct bacs_ppzksnark_basic_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        using circuit = bacs_circuit<typename CurveType::scalar_field_type>;

                        using primary_input = bacs_primary_input<typename CurveType::scalar_field_type>;

                        using auxiliary_input = bacs_auxiliary_input<typename CurveType::scalar_field_type>;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the BACS ppzkSNARK.
                         */
                        struct proving_key {
                            circuit crct;
                            typename r1cs_ppzksnark<CurveType>::proving_key_type r1cs_pk;

                            proving_key() {};
                            proving_key(const proving_key &other) = default;
                            proving_key(proving_key &&other) = default;
                            proving_key(const circuit &crct,
                                        const typename r1cs_ppzksnark<CurveType>::proving_key_type &r1cs_pk) :
                                circuit(crct),
                                r1cs_pk(r1cs_pk) {
                            }
                            proving_key(circuit &&crct,
                                        typename r1cs_ppzksnark<CurveType>::proving_key_type &&r1cs_pk) :
                                circuit(std::move(crct)),
                                r1cs_pk(std::move(r1cs_pk)) {
                            }

                            proving_key &operator=(const proving_key &other) = default;

                            std::size_t G1_size() const {
                                return r1cs_pk.G1_size();
                            }

                            std::size_t G2_size() const {
                                return r1cs_pk.G2_size();
                            }

                            std::size_t G1_sparse_size() const {
                                return r1cs_pk.G1_sparse_size();
                            }

                            std::size_t G2_sparse_size() const {
                                return r1cs_pk.G2_sparse_size();
                            }

                            std::size_t size_in_bits() const {
                                return r1cs_pk.size_in_bits();
                            }

                            /*
                             Below are four variants of verifier algorithm for the BACS ppzkSNARK.

                             These are the four cases that arise from the following two choices:

                             (1) The verifier accepts a (non-processed) verification key or, instead, a processed
                             verification key. In the latter case, we call the algorithm an "online verifier".

                             (2) The verifier checks for "weak" input consistency or, instead, "strong" input
                             consistency. Strong input consistency requires that |primary_input| = C.num_inputs, whereas
                                 weak input consistency requires that |primary_input| <= C.num_inputs (and
                                 the primary input is implicitly padded with zeros up to length C.num_inputs).
                             */
                            bool operator==(const proving_key &other) const {
                                return (this->crct == other.crct && this->r1cs_pk == other.r1cs_pk);
                            }
                        };

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the BACS ppzkSNARK.
                         */
                        using verification_key = typename r1cs_ppzksnark<CurveType>::verification_key_type;

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the BACS ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        using processed_verification_key =
                            typename r1cs_ppzksnark<CurveType>::processed_verification_key_type;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the BACS ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        struct keypair {
                            proving_key pk;
                            verification_key vk;

                            keypair() {};
                            keypair(keypair &&other) = default;
                            keypair(const proving_key &pk, const verification_key &vk) : pk(pk), vk(vk) {
                            }

                            keypair(proving_key &&pk, verification_key &&vk) : pk(std::move(pk)), vk(std::move(vk)) {
                            }
                        };

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the BACS ppzkSNARK.
                         */
                        using proof = typename r1cs_ppzksnark<CurveType>::proof_type;
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_POLICY_HPP

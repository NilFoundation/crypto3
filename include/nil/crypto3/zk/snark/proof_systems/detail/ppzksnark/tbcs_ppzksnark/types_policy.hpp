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

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct tbcs_ppzksnark_types_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various typedefs aliases (used for uniformity with other proof systems).
                         */

                        using circuit = tbcs_circuit;

                        using primary_input = tbcs_primary_input;

                        using auxiliary_input = tbcs_auxiliary_input;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the TBCS ppzkSNARK.
                         */
                        struct proving_key {
                            typedef typename CurveType::scalar_field_type FieldType;

                            circuit crct;
                            typename uscs_ppzksnark<CurveType>::proving_key_type uscs_pk;

                            proving_key() {};
                            proving_key(const proving_key &other) = default;
                            proving_key(proving_key &&other) = default;
                            proving_key(const circuit &crct,
                                        typename const uscs_ppzksnark<CurveType>::proving_key_type &uscs_pk) :
                                circuit(crct),
                                uscs_pk(uscs_pk) {
                            }
                            proving_key(circuit &&crct,
                                        typename uscs_ppzksnark<CurveType>::proving_key_type &&uscs_pk) :
                                crct(std::move(crct)),
                                uscs_pk(std::move(uscs_pk)) {
                            }

                            proving_key &operator=(const proving_key &other) = default;

                            std::size_t G1_size() const {
                                return uscs_pk.G1_size();
                            }

                            std::size_t G2_size() const {
                                return uscs_pk.G2_size();
                            }

                            std::size_t G1_sparse_size() const {
                                return uscs_pk.G1_sparse_size();
                            }

                            std::size_t G2_sparse_size() const {
                                return uscs_pk.G2_sparse_size();
                            }

                            std::size_t size_in_bits() const {
                                return uscs_pk.size_in_bits();
                            }

                            bool operator==(const proving_key &other) const {
                                return (this->crct == other.crct && this->uscs_pk == other.uscs_pk);
                            }
                        };

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the TBCS ppzkSNARK.
                         */
                        using verification_key = typename uscs_ppzksnark<CurveType>::verification_key_type;

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the TBCS ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        using processed_verification_key =
                            typename uscs_ppzksnark<CurveType>::processed_verification_key_type;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the TBCS ppzkSNARK, which consists of a proving key and a verification key.
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
                         * A proof for the TBCS ppzkSNARK.
                         */
                        using proof = typename uscs_ppzksnark<CurveType>::proof_type;
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_TYPES_POLICY_HPP

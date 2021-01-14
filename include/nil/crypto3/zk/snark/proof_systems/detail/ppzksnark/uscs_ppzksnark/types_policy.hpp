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
// @file Declaration of interfaces for a ppzkSNARK for USCS.
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
// The implementation instantiates the protocol of \[DFGK14], by following
// extending, and optimizing the approach described in \[BCTV14].
//
//
// Acronyms:
//
// - "ppzkSNARK" = "Pre-Processing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
// - "USCS" = "Unitary-Square Constraint Systems"
//
// References:
//
// \[BCTV14]:
// "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// USENIX Security 2014,
// <http://eprint.iacr.org/2013/879>
//
// \[DFGK14]:
// "Square Span Programs with Applications to Succinct NIZK Arguments"
// George Danezis, Cedric Fournet, Jens Groth, Markulf Kohlweiss,
// ASIACRYPT 2014,
// <http://eprint.iacr.org/2014/718>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_USCS_PPZKSNARK_TYPES_POLICY_HPP
#define CRYPTO3_USCS_PPZKSNARK_TYPES_POLICY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs.hpp>

#include <nil/crypto3/zk/snark/reductions/uscs_to_ssp.hpp>
#include <nil/crypto3/zk/snark/relations/arithmetic_programs/ssp.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct uscs_ppzksnark_types_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        using constraint_system = uscs_constraint_system<typename CurveType::scalar_field_type>;

                        using primary_input = uscs_primary_input<typename CurveType::scalar_field_type>;

                        using auxiliary_input = uscs_auxiliary_input<typename CurveType::scalar_field_type>;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the USCS ppzkSNARK.
                         */
                        struct proving_key {
                            typename std::vector<typename CurveType::g1_type::value_type> V_g1_query;
                            typename std::vector<typename CurveType::g1_type::value_type> alpha_V_g1_query;
                            typename std::vector<typename CurveType::g1_type::value_type> H_g1_query;
                            typename std::vector<typename CurveType::g2_type::value_type> V_g2_query;

                            constraint_system cs;

                            proving_key() {};
                            proving_key &operator=(const proving_key &other) = default;
                            proving_key(const proving_key &other) = default;
                            proving_key(proving_key &&other) = default;
                            proving_key(
                                typename std::vector<typename CurveType::g1_type::value_type> &&V_g1_query,
                                typename std::vector<typename CurveType::g1_type::value_type> &&alpha_V_g1_query,
                                typename std::vector<typename CurveType::g1_type::value_type> &&H_g1_query,
                                typename std::vector<typename CurveType::g2_type::value_type> &&V_g2_query,
                                constraint_system &&cs) :
                                V_g1_query(std::move(V_g1_query)),
                                alpha_V_g1_query(std::move(alpha_V_g1_query)), H_g1_query(std::move(H_g1_query)),
                                V_g2_query(std::move(V_g2_query)), cs(std::move(cs)) {};

                            std::size_t G1_size() const {
                                return V_g1_query.size() + alpha_V_g1_query.size() + H_g1_query.size();
                            }

                            std::size_t G2_size() const {
                                return V_g2_query.size();
                            }

                            std::size_t G1_sparse_size() const {
                                return G1_size();
                            }

                            std::size_t G2_sparse_size() const {
                                return G2_size();
                            }

                            std::size_t size_in_bits() const {
                                return CurveType::g1_type::value_bits * G1_size() +
                                       CurveType::g2_type::value_bits * G2_size();
                            }

                            bool operator==(const proving_key &other) const {
                                return (this->V_g1_query == other.V_g1_query &&
                                        this->alpha_V_g1_query == other.alpha_V_g1_query &&
                                        this->H_g1_query == other.H_g1_query && this->V_g2_query == other.V_g2_query &&
                                        this->cs == other.cs);
                            }
                        };

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the USCS ppzkSNARK.
                         */
                        struct verification_key {
                            typename CurveType::g2_type::value_type tilde_g2;
                            typename CurveType::g2_type::value_type alpha_tilde_g2;
                            typename CurveType::g2_type::value_type Z_g2;

                            accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                            verification_key() = default;
                            verification_key(const typename CurveType::g2_type::value_type &tilde_g2,
                                             const typename CurveType::g2_type::value_type &alpha_tilde_g2,
                                             const typename CurveType::g2_type::value_type &Z_g2,
                                             const accumulation_vector<typename CurveType::g1_type> &eIC) :
                                tilde_g2(tilde_g2),
                                alpha_tilde_g2(alpha_tilde_g2), Z_g2(Z_g2), encoded_IC_query(eIC) {};

                            std::size_t G1_size() const {
                                return encoded_IC_query.size();
                            }

                            std::size_t G2_size() const {
                                return 3;
                            }

                            std::size_t size_in_bits() const {
                                return encoded_IC_query.size_in_bits() + 3 * CurveType::g2_type::value_bits;
                            }

                            bool operator==(const verification_key &other) const {
                                return (this->tilde_g2 == other.tilde_g2 &&
                                        this->alpha_tilde_g2 == other.alpha_tilde_g2 && this->Z_g2 == other.Z_g2 &&
                                        this->encoded_IC_query == other.encoded_IC_query);
                            }

                            /*static verification_key dummy_verification_key(const std::size_t input_size) {
                                verification_key result;
                                result.tilde_g2 = algenra::random_element<typename CurveType::scalar_field_type>() *
                            typename CurveType::g2_type::value_type::one(); result.alpha_tilde_g2 =
                            algenra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g2_type::value_type::one(); result.Z_g2 = algenra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g2_type::value_type::one();

                                typename CurveType::g1_type::value_type base = algenra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g1_type::value_type::one();
                                typename std::vector<typename CurveType::g1_type::value_type> v; for (std::size_t i = 0;
                            i < input_size; ++i) { v.emplace_back(algenra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g1_type::value_type::one());
                                }

                                result.encoded_IC_query = accumulation_vector<typename CurveType::g1_type>(v);

                                return result;
                            }*/
                        };

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the USCS ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        class processed_verification_key {
                            typedef typename CurveType::pairing_policy pairing_policy;

                        public:
                            typename pairing_policy::G1_precomp pp_G1_one_precomp;
                            typename pairing_policy::G2_precomp pp_G2_one_precomp;
                            typename pairing_policy::G2_precomp vk_tilde_g2_precomp;
                            typename pairing_policy::G2_precomp vk_alpha_tilde_g2_precomp;
                            typename pairing_policy::G2_precomp vk_Z_g2_precomp;
                            typename CurveType::gt_type::value_type pairing_of_g1_and_g2;

                            accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                            bool operator==(const processed_verification_key &other) const {
                                return (this->pp_G1_one_precomp == other.pp_G1_one_precomp &&
                                        this->pp_G2_one_precomp == other.pp_G2_one_precomp &&
                                        this->vk_tilde_g2_precomp == other.vk_tilde_g2_precomp &&
                                        this->vk_alpha_tilde_g2_precomp == other.vk_alpha_tilde_g2_precomp &&
                                        this->vk_Z_g2_precomp == other.vk_Z_g2_precomp &&
                                        this->pairing_of_g1_and_g2 == other.pairing_of_g1_and_g2 &&
                                        this->encoded_IC_query == other.encoded_IC_query);
                            }
                        };

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the USCS ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        struct keypair {
                            proving_key pk;
                            verification_key vk;

                            keypair() {};
                            keypair(proving_key &&pk, verification_key &&vk) : pk(std::move(pk)), vk(std::move(vk)) {
                            }

                            keypair(keypair &&other) = default;
                        };

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the USCS ppzkSNARK.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        struct proof {
                            typename CurveType::g1_type::value_type V_g1;
                            typename CurveType::g1_type::value_type alpha_V_g1;
                            typename CurveType::g1_type::value_type H_g1;
                            typename CurveType::g2_type::value_type V_g2;

                            proof() {
                                // invalid proof with valid curve points
                                this->V_g1 = typename CurveType::g1_type::value_type::one();
                                this->alpha_V_g1 = typename CurveType::g1_type::value_type::one();
                                this->H_g1 = typename CurveType::g1_type::value_type::one();
                                this->V_g2 = typename CurveType::g2_type::value_type::one();
                            }
                            proof(typename CurveType::g1_type::value_type &&V_g1,
                                  typename CurveType::g1_type::value_type &&alpha_V_g1,
                                  typename CurveType::g1_type::value_type &&H_g1,
                                  typename CurveType::g2_type::value_type &&V_g2) :
                                V_g1(std::move(V_g1)),
                                alpha_V_g1(std::move(alpha_V_g1)), H_g1(std::move(H_g1)), V_g2(std::move(V_g2)) {};

                            std::size_t G1_size() const {
                                return 3;
                            }

                            std::size_t G2_size() const {
                                return 1;
                            }

                            std::size_t size_in_bits() const {
                                return G1_size() * CurveType::g1_type::value_bits +
                                       G2_size() * CurveType::g2_type::value_bits;
                            }

                            bool is_well_formed() const {
                                return (V_g1.is_well_formed() && alpha_V_g1.is_well_formed() && H_g1.is_well_formed() &&
                                        V_g2.is_well_formed());
                            }

                            bool operator==(const proof &other) const {
                                return (this->V_g1 == other.V_g1 && this->alpha_V_g1 == other.alpha_V_g1 &&
                                        this->H_g1 == other.H_g1 && this->V_g2 == other.V_g2);
                            }
                        };
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_USCS_PPZKSNARK_TYPES_POLICY_HPP

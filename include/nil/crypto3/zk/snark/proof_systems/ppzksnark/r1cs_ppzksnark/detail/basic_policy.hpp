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
// @file Declaration of interfaces for a ppzkSNARK for R1CS.
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
// The implementation instantiates (a modification of) the protocol of \[PGHR13],
// by following extending, and optimizing the approach described in \[BCTV14].
//
//
// Acronyms:
//
// - R1CS = "Rank-1 Constraint Systems"
// - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//
// References:
//
// \[BCTV14]:
// "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// USENIX Security 2014,
// <http://eprint.iacr.org/2013/879>
//
// \[PGHR13]:
// "Pinocchio: Nearly practical verifiable computation",
// Bryan Parno, Craig Gentry, Jon Howell, Mariana Raykova,
// IEEE S&P 2013,
// <https://eprint.iacr.org/2013/279>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_PPZKSNARK_TYPES_POLICY_HPP
#define CRYPTO3_R1CS_PPZKSNARK_TYPES_POLICY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct r1cs_ppzksnark_types_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        using constraint_system = r1cs_constraint_system<typename CurveType::scalar_field_type>;

                        using primary_input = r1cs_primary_input<typename CurveType::scalar_field_type>;

                        using auxiliary_input = r1cs_auxiliary_input<typename CurveType::scalar_field_type>;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the R1CS ppzkSNARK.
                         */
                        class proving_key {
                            using g1_type = typename CurveType::g1_type;
                            using g2_type = typename CurveType::g2_type;
                            using g1_value_type = typename g1_type::value_type;
                            using g2_value_type = typename g2_type::value_type;

                        public:
                            knowledge_commitment_vector<g1_type, g1_type> A_query;
                            knowledge_commitment_vector<g2_type, g1_type> B_query;
                            knowledge_commitment_vector<g1_type, g1_type> C_query;
                            typename std::vector<g1_value_type> H_query;
                            typename std::vector<g1_value_type> K_query;

                            constraint_system cs;

                            proving_key() {};
                            proving_key &operator=(const proving_key &other) = default;
                            proving_key(const proving_key &other) = default;
                            proving_key(proving_key &&other) = default;
                            proving_key(knowledge_commitment_vector<g1_type, g1_type> &&A_query,
                                        knowledge_commitment_vector<g2_type, g1_type> &&B_query,
                                        knowledge_commitment_vector<g1_type, g1_type> &&C_query,
                                        typename std::vector<g1_value_type> &&H_query,
                                        typename std::vector<g1_value_type> &&K_query,
                                        constraint_system &&cs) :
                                A_query(std::move(A_query)),
                                B_query(std::move(B_query)), C_query(std::move(C_query)), H_query(std::move(H_query)),
                                K_query(std::move(K_query)), cs(std::move(cs)) {};

                            std::size_t G1_size() const {
                                return 2 * (A_query.domain_size() + C_query.domain_size()) + B_query.domain_size() +
                                       H_query.size() + K_query.size();
                            }

                            std::size_t G2_size() const {
                                return B_query.domain_size();
                            }

                            std::size_t G1_sparse_size() const {
                                return 2 * (A_query.size() + C_query.size()) + B_query.size() + H_query.size() +
                                       K_query.size();
                            }

                            std::size_t G2_sparse_size() const {
                                return B_query.size();
                            }

                            std::size_t size_in_bits() const {
                                return A_query.size_in_bits() + B_query.size_in_bits() + C_query.size_in_bits() +
                                       H_query.size() * CurveType::g1_type::value_bits +
                                       K_query.size() * CurveType::g1_type::value_bits;
                            }

                            bool operator==(const proving_key &other) const {
                                return (this->A_query == other.A_query && this->B_query == other.B_query &&
                                        this->C_query == other.C_query && this->H_query == other.H_query &&
                                        this->K_query == other.K_query && this->cs == other.cs);
                            }
                        };

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the R1CS ppzkSNARK.
                         */
                        struct verification_key {
                            typename CurveType::g2_type::value_type alphaA_g2;
                            typename CurveType::g1_type::value_type alphaB_g1;
                            typename CurveType::g2_type::value_type alphaC_g2;
                            typename CurveType::g2_type::value_type gamma_g2;
                            typename CurveType::g1_type::value_type gamma_beta_g1;
                            typename CurveType::g2_type::value_type gamma_beta_g2;
                            typename CurveType::g2_type::value_type rC_Z_g2;

                            accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                            verification_key() = default;
                            verification_key(const typename CurveType::g2_type::value_type &alphaA_g2,
                                             const typename CurveType::g1_type::value_type &alphaB_g1,
                                             const typename CurveType::g2_type::value_type &alphaC_g2,
                                             const typename CurveType::g2_type::value_type &gamma_g2,
                                             const typename CurveType::g1_type::value_type &gamma_beta_g1,
                                             const typename CurveType::g2_type::value_type &gamma_beta_g2,
                                             const typename CurveType::g2_type::value_type &rC_Z_g2,
                                             const accumulation_vector<typename CurveType::g1_type> &eIC) :
                                alphaA_g2(alphaA_g2),
                                alphaB_g1(alphaB_g1), alphaC_g2(alphaC_g2), gamma_g2(gamma_g2),
                                gamma_beta_g1(gamma_beta_g1), gamma_beta_g2(gamma_beta_g2), rC_Z_g2(rC_Z_g2),
                                encoded_IC_query(eIC) {};

                            std::size_t G1_size() const {
                                return 2 + encoded_IC_query.size();
                            }

                            std::size_t G2_size() const {
                                return 5;
                            }

                            std::size_t size_in_bits() const {
                                return (2 * CurveType::g1_type::value_bits + encoded_IC_query.size_in_bits() +
                                        5 * CurveType::g2_type::value_bits);
                            }

                            bool operator==(const verification_key &other) const {
                                return (this->alphaA_g2 == other.alphaA_g2 && this->alphaB_g1 == other.alphaB_g1 &&
                                        this->alphaC_g2 == other.alphaC_g2 && this->gamma_g2 == other.gamma_g2 &&
                                        this->gamma_beta_g1 == other.gamma_beta_g1 &&
                                        this->gamma_beta_g2 == other.gamma_beta_g2 && this->rC_Z_g2 == other.rC_Z_g2 &&
                                        this->encoded_IC_query == other.encoded_IC_query);
                            }

                            /*static verification_key dummy_verification_key(const std::size_t input_size) {
                                verification_key result;
                                result.alphaA_g2 = algebra::random_element<typename CurveType::scalar_field_type>() *
                            typename CurveType::g2_type::value_type::one(); result.alphaB_g1 =
                            algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g1_type::value_type::one(); result.alphaC_g2 = algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g2_type::value_type::one();
                            result.gamma_g2 = algebra::random_element<typename CurveType::scalar_field_type>() *
                            typename CurveType::g2_type::value_type::one(); result.gamma_beta_g1 =
                            algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g1_type::value_type::one(); result.gamma_beta_g2 =
                            algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g2_type::value_type::one(); result.rC_Z_g2 = algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g2_type::value_type::one();

                                typename CurveType::g1_type::value_type base = algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g1_type::value_type::one();
                                typename std::vector<typename CurveType::g1_type::value_type> v; for (std::size_t i = 0;
                            i < input_size; ++i) { v.emplace_back(algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g1_type::value_type::one());
                                }

                                result.encoded_IC_query = accumulation_vector<typename
                            CurveType::g1_type>(std::move(base), std::move(v));

                                return result;
                            }*/
                        };

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the R1CS ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        class processed_verification_key {
                            typedef typename CurveType::pairing_policy pairing_policy;

                        public:
                            typename pairing_policy::G2_precomp pp_G2_one_precomp;
                            typename pairing_policy::G2_precomp vk_alphaA_g2_precomp;
                            typename pairing_policy::G1_precomp vk_alphaB_g1_precomp;
                            typename pairing_policy::G2_precomp vk_alphaC_g2_precomp;
                            typename pairing_policy::G2_precomp vk_rC_Z_g2_precomp;
                            typename pairing_policy::G2_precomp vk_gamma_g2_precomp;
                            typename pairing_policy::G1_precomp vk_gamma_beta_g1_precomp;
                            typename pairing_policy::G2_precomp vk_gamma_beta_g2_precomp;

                            accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                            bool operator==(const processed_verification_key &other) const {
                                return (this->pp_G2_one_precomp == other.pp_G2_one_precomp &&
                                        this->vk_alphaA_g2_precomp == other.vk_alphaA_g2_precomp &&
                                        this->vk_alphaB_g1_precomp == other.vk_alphaB_g1_precomp &&
                                        this->vk_alphaC_g2_precomp == other.vk_alphaC_g2_precomp &&
                                        this->vk_rC_Z_g2_precomp == other.vk_rC_Z_g2_precomp &&
                                        this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
                                        this->vk_gamma_beta_g1_precomp == other.vk_gamma_beta_g1_precomp &&
                                        this->vk_gamma_beta_g2_precomp == other.vk_gamma_beta_g2_precomp &&
                                        this->encoded_IC_query == other.encoded_IC_query);
                            }
                        };

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the R1CS ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        struct keypair {
                            proving_key pk;
                            verification_key vk;

                            keypair() = default;
                            keypair(const keypair &other) = default;
                            keypair(proving_key &&pk, verification_key &&vk) : pk(std::move(pk)), vk(std::move(vk)) {
                            }

                            keypair(keypair &&other) = default;
                        };

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the R1CS ppzkSNARK.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        class proof {
                            using g1_type = typename CurveType::g1_type;
                            using g2_type = typename CurveType::g2_type;
                            using g1_value_type = typename g1_type::value_type;
                            using g2_value_type = typename g2_type::value_type;

                        public:
                            typename knowledge_commitment<g1_type, g1_type>::value_type g_A;
                            typename knowledge_commitment<g2_type, g1_type>::value_type g_B;
                            typename knowledge_commitment<g1_type, g1_type>::value_type g_C;
                            g1_value_type g_H;
                            g1_value_type g_K;

                            proof() {
                                // invalid proof with valid curve points
                                this->g_A.g = g1_value_type::one();
                                this->g_A.h = g1_value_type::one();
                                this->g_B.g = g2_value_type::one();
                                this->g_B.h = g1_value_type::one();
                                this->g_C.g = g1_value_type::one();
                                this->g_C.h = g1_value_type::one();
                                this->g_H = g1_value_type::one();
                                this->g_K = g1_value_type::one();
                            }
                            proof(typename knowledge_commitment<g1_type, g1_type>::value_type &&g_A,
                                  typename knowledge_commitment<g2_type, g1_type>::value_type &&g_B,
                                  typename knowledge_commitment<g1_type, g1_type>::value_type &&g_C,
                                  g1_value_type &&g_H,
                                  g1_value_type &&g_K) :
                                g_A(std::move(g_A)),
                                g_B(std::move(g_B)), g_C(std::move(g_C)), g_H(std::move(g_H)), g_K(std::move(g_K)) {};

                            std::size_t G1_size() const {
                                return 7;
                            }

                            std::size_t G2_size() const {
                                return 1;
                            }

                            std::size_t size_in_bits() const {
                                return G1_size() * CurveType::g1_type::value_bits +
                                       G2_size() * CurveType::g2_type::value_bits;
                            }

                            bool is_well_formed() const {
                                return (g_A.g.is_well_formed() && g_A.h.is_well_formed() && g_B.g.is_well_formed() &&
                                        g_B.h.is_well_formed() && g_C.g.is_well_formed() && g_C.h.is_well_formed() &&
                                        g_H.is_well_formed() && g_K.is_well_formed());
                            }

                            bool operator==(const proof &other) const {
                                return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C &&
                                        this->g_H == other.g_H && this->g_K == other.g_K);
                            }
                        };
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_TYPES_POLICY_HPP

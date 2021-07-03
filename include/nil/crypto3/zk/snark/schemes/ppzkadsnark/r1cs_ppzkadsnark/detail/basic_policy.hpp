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
// @file Declaration of interfaces for a ppzkADSNARK for R1CS.
//
// This includes:
// - class for authentication key (public and symmetric)
// - class for authentication verification key (public and symmetric)
// - class for proving key
// - class for verification key
// - class for processed verification key
// - class for key tuple (authentication key & proving key & verification key)
// - class for authenticated data
// - class for proof
// - generator algorithm
// - authentication key generator algorithm
// - prover algorithm
// - verifier algorithm (public and symmetric)
// - online verifier algorithm (public and symmetric)
//
// The implementation instantiates the construction in \[BBFR15], which in turn
// is based on the r1cs_ppzkadsnark proof system.
//
// Acronyms:
//
// - R1CS = "Rank-1 Constraint Systems"
// - ppzkADSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge Over Authenticated Data"
//
// References:
//
//\[BBFR15]
//"ADSNARK: Nearly Practical and Privacy-Preserving Proofs on Authenticated Data",
// Michael Backes, Manuel Barbosa, Dario Fiore, Raphael M. Reischuk,
// IEEE Symposium on Security and Privacy 2015,
// <http://eprint.iacr.org/2014/617>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_PPZKADSNARK_BASIC_POLICY_HPP
#define CRYPTO3_R1CS_PPZKADSNARK_BASIC_POLICY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/commitments/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/commitments/knowledge_commitment_multiexp.hpp>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/prf.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/signature.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct r1cs_ppzkadsnark_basic_policy {

                        /******************************** Params ********************************/

                        struct label_type {
                            unsigned char label_bytes[16];
                            label_type() {};
                        };

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        template<typename r1cs_ppzkadsnark_ppT>
                        using snark_pp = typename r1cs_ppzkadsnark_ppT::snark_pp;

                        template<typename r1cs_ppzkadsnark_ppT>
                        using constraint_system = r1cs_constraint_system<algebra::Fr<snark_pp<r1cs_ppzkadsnark_ppT>>>;

                        template<typename r1cs_ppzkadsnark_ppT>
                        using primary_input = r1cs_primary_input<algebra::Fr<snark_pp<r1cs_ppzkadsnark_ppT>>>;

                        template<typename r1cs_ppzkadsnark_ppT>
                        using auxiliary_input = r1cs_auxiliary_input<algebra::Fr<snark_pp<r1cs_ppzkadsnark_ppT>>>;

                        template<typename r1cs_ppzkadsnark_ppT>
                        using secret_key = typename r1cs_ppzkadsnark_ppT::skT;

                        template<typename r1cs_ppzkadsnark_ppT>
                        using vkT = typename r1cs_ppzkadsnark_ppT::vkT;

                        template<typename r1cs_ppzkadsnark_ppT>
                        using signature = typename r1cs_ppzkadsnark_ppT::sigT;

                        template<typename r1cs_ppzkadsnark_ppT>
                        using prf_key = typename r1cs_ppzkadsnark_ppT::prfKeyT;

                        /******************************** Public authentication parameters
                         * ********************************/

                        /**
                         * Public authentication parameters for the R1CS ppzkADSNARK
                         */
                        struct pub_auth_prms {

                            typename CurveType::g1_type::value_type I1;

                            pub_auth_prms() {};
                            pub_auth_prms<CurveType> &operator=(const pub_auth_prms<CurveType> &other) = default;
                            pub_auth_prms(const pub_auth_prms<CurveType> &other) = default;
                            pub_auth_prms(pub_auth_prms<CurveType> &&other) = default;
                            pub_auth_prms(typename CurveType::g1_type::value_type &&I1) : I1(std::move(I1)) {};

                            bool operator==(const pub_auth_prms<CurveType> &other) const {
                                return (this->I1 == other.I1);
                            }
                        };

                        /******************************** Secret authentication key ********************************/

                        /**
                         * Secret authentication key for the R1CS ppzkADSNARK
                         */
                        struct sec_auth_key {

                            typename CurveType::scalar_field_type::value_type i;

                            secret_key<CurveType> skp;
                            prf_key<CurveType> S;

                            sec_auth_key() {};
                            sec_auth_key<CurveType> &operator=(const sec_auth_key<CurveType> &other) = default;
                            sec_auth_key(const sec_auth_key<CurveType> &other) = default;
                            sec_auth_key(sec_auth_key<CurveType> &&other) = default;
                            sec_auth_key(typename CurveType::scalar_field_type::value_type &&i,
                                         secret_key<CurveType> &&skp,
                                         prf_key<CurveType> &&S) :
                                i(std::move(i)),
                                skp(std::move(skp)), S(std::move(S)) {};

                            bool operator==(const sec_auth_key<CurveType> &other) const {
                                return (this->i == other.i) && (this->skp == other.skp) && (this->S == other.S);
                            }
                        };

                        /******************************** Public authentication key ********************************/

                        /**
                         * Public authentication key for the R1CS ppzkADSNARK
                         */
                        struct pub_auth_key {

                            typename CurveType::g2_type::value_type minusI2;
                            vkT<CurveType> vkp;

                            pub_auth_key() {};
                            pub_auth_key<CurveType> &operator=(const pub_auth_key<CurveType> &other) = default;
                            pub_auth_key(const pub_auth_key<CurveType> &other) = default;
                            pub_auth_key(pub_auth_key<CurveType> &&other) = default;
                            pub_auth_key(typename CurveType::g2_type::value_type &&minusI2, vkT<CurveType> &&vkp) :
                                minusI2(std::move(minusI2)), vkp(std::move(vkp)) {};

                            bool operator==(const pub_auth_key<CurveType> &other) const {
                                return (this->minusI2 == other.minusI2) && (this->vkp == other.vkp);
                            }
                        };

                        /******************************** Authentication key material ********************************/
                        struct auth_keys {

                            pub_auth_prms<CurveType> pap;
                            pub_auth_key<CurveType> pak;
                            sec_auth_key<CurveType> sak;

                            auth_keys() {};
                            auth_keys(auth_keys<CurveType> &&other) = default;
                            auth_keys(pub_auth_prms<CurveType> &&pap,
                                      pub_auth_key<CurveType> &&pak,
                                      sec_auth_key<CurveType> &&sak) :
                                pap(std::move(pap)),
                                pak(std::move(pak)), sak(std::move(sak)) {
                            }
                        };

                        /******************************** Authenticated data ********************************/

                        /**
                         * Authenticated data for the R1CS ppzkADSNARK
                         */
                        struct auth_data {

                            typename CurveType::scalar_field_type::value_type mu;
                            typename CurveType::g2_type::value_type Lambda;

                            signature<CurveType> sigma;

                            auth_data() {};
                            auth_data<CurveType> &operator=(const auth_data<CurveType> &other) = default;
                            auth_data(const auth_data<CurveType> &other) = default;
                            auth_data(auth_data<CurveType> &&other) = default;

                            auth_data(typename CurveType::scalar_field_type::value_type &&mu,
                                      typename CurveType::g2_type::value_type &&Lambda,

                                      signature<CurveType> &&sigma) :
                                mu(std::move(mu)),
                                Lambda(std::move(Lambda)), sigma(std::move(sigma)) {};

                            bool operator==(const auth_data<CurveType> &other) const {
                                return (this->mu == other.mu) && (this->Lambda == other.Lambda) &&
                                       (this->sigma == other.sigma);
                            }
                        };

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the R1CS ppzkADSNARK.
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

                            typename std::vector<g1_value_type> H_query;    // t powers
                            typename std::vector<g1_value_type> K_query;
                            /* Now come the additional elements for ad */
                            typename g1_value_type rA_i_Z_g1;

                            constraint_system<CurveType> constraint_system;

                            proving_key() {};
                            proving_key &operator=(const proving_key &other) = default;
                            proving_key(const proving_key &other) = default;
                            proving_key(proving_key &&other) = default;
                            proving_key(knowledge_commitment_vector<g1_type, g1_type> &&A_query,
                                        knowledge_commitment_vector<g2_type, g1_type> &&B_query,
                                        knowledge_commitment_vector<g1_type, g1_type> &&C_query,
                                        typename std::vector<g1_value_type> &&H_query,
                                        typename std::vector<g1_value_type> &&K_query,
                                        g1_value_type &&rA_i_Z_g1,
                                        constraint_system<CurveType> &&constraint_system) :
                                A_query(std::move(A_query)),
                                B_query(std::move(B_query)), C_query(std::move(C_query)), H_query(std::move(H_query)),
                                K_query(std::move(K_query)), rA_i_Z_g1(std::move(rA_i_Z_g1)),
                                constraint_system(std::move(constraint_system)) {};

                            std::size_t G1_size() const {
                                return 2 * (A_query.domain_size() + C_query.domain_size()) + B_query.domain_size() +
                                       H_query.size() + K_query.size() + 1;
                            }

                            std::size_t G2_size() const {
                                return B_query.domain_size();
                            }

                            std::size_t G1_sparse_size() const {
                                return 2 * (A_query.size() + C_query.size()) + B_query.size() + H_query.size() +
                                       K_query.size() + 1;
                            }

                            std::size_t G2_sparse_size() const {
                                return B_query.size();
                            }

                            std::size_t size_in_bits() const {
                                return A_query.size_in_bits() + B_query.size_in_bits() + C_query.size_in_bits() +
                                       H_query.size() * g1_type::value_bits + K_query.size() * g1_type::value_bits +
                                       g1_type::value_bits;
                            }

                            bool operator==(const proving_key<CurveType> &other) const {
                                return (this->A_query == other.A_query && this->B_query == other.B_query &&
                                        this->C_query == other.C_query && this->H_query == other.H_query &&
                                        this->K_query == other.K_query && this->rA_i_Z_g1 == other.rA_i_Z_g1 &&
                                        this->constraint_system == other.constraint_system);
                            }
                        };

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the R1CS ppzkADSNARK.
                         */
                        struct verification_key {

                            typename CurveType::g2_type::value_type alphaA_g2;
                            typename CurveType::g1_type::value_type alphaB_g1;
                            typename CurveType::g2_type::value_type alphaC_g2;
                            typename CurveType::g2_type::value_type gamma_g2;
                            typename CurveType::g1_type::value_type gamma_beta_g1;
                            typename CurveType::g2_type::value_type gamma_beta_g2;
                            typename CurveType::g2_type::value_type rC_Z_g2;

                            typename CurveType::g1_type::value_type A0;
                            typename std::vector<typename CurveType::g1_type::value_type> Ain;

                            verification_key() = default;
                            verification_key(const typename CurveType::g2_type::value_type &alphaA_g2,
                                             const typename CurveType::g1_type::value_type &alphaB_g1,
                                             const typename CurveType::g2_type::value_type &alphaC_g2,
                                             const typename CurveType::g2_type::value_type &gamma_g2,
                                             const typename CurveType::g1_type::value_type &gamma_beta_g1,
                                             const typename CurveType::g2_type::value_type &gamma_beta_g2,
                                             const typename CurveType::g2_type::value_type &rC_Z_g2,
                                             const typename CurveType::g1_type::value_type A0,
                                             const typename std::vector<typename CurveType::g1_type::value_type>
                                                 Ain) :
                                alphaA_g2(alphaA_g2),
                                alphaB_g1(alphaB_g1), alphaC_g2(alphaC_g2), gamma_g2(gamma_g2),
                                gamma_beta_g1(gamma_beta_g1), gamma_beta_g2(gamma_beta_g2), rC_Z_g2(rC_Z_g2), A0(A0),
                                Ain(Ain) {};

                            std::size_t G1_size() const {
                                return 3 + Ain.size();
                            }

                            std::size_t G2_size() const {
                                return 5;
                            }

                            std::size_t size_in_bits() const {
                                return G1_size() * CurveType::g1_type::value_type::value_bits +
                                       G2_size() *
                                           CurveType::g2_type::value_type::value_bits;    // possible zksnark bug
                            }

                            bool operator==(const verification_key<CurveType> &other) const {
                                return (this->alphaA_g2 == other.alphaA_g2 && this->alphaB_g1 == other.alphaB_g1 &&
                                        this->alphaC_g2 == other.alphaC_g2 && this->gamma_g2 == other.gamma_g2 &&
                                        this->gamma_beta_g1 == other.gamma_beta_g1 &&
                                        this->gamma_beta_g2 == other.gamma_beta_g2 && this->rC_Z_g2 == other.rC_Z_g2 &&
                                        this->A0 == other.A0 && this->Ain == other.Ain);
                            }

                            /*static verification_key<CurveType> dummy_verification_key(const std::size_t input_size) {

                                verification_key<CurveType> result;
                                result.alphaA_g2 =
                                    algebra::random_element<typename CurveType::scalar_field_type>() *
                            CurveType::g2_type::value_type::one(); result.alphaB_g1 = algebra::random_element<typename
                            CurveType::scalar_field_type>() *  CurveType::g1_type::value_type::one();
                                result.alphaC_g2 =
                                    algebra::random_element<typename CurveType::scalar_field_type>() * 
                            CurveType::g2_type::value_type::one(); result.gamma_g2 = algebra::random_element<typename
                            CurveType::scalar_field_type>() * CurveType::g2_type::value_type::one();
                                result.gamma_beta_g1 =
                                    algebra::random_element<typename CurveType::scalar_field_type>() *
                            CurveType::g1_type::value_type::one(); result.gamma_beta_g2 =
                                    algebra::random_element<typename CurveType::scalar_field_type>() * 
                            CurveType::g2_type::value_type::one(); result.rC_Z_g2 = algebra::random_element<typename
                            CurveType::scalar_field_type>() * CurveType::g2_type::value_type::one();

                                result.A0 = algebra::random_element<typename CurveType::scalar_field_type>() * 
                            CurveType::g1_type::value_type::one(); for (std::size_t i = 0; i < input_size; ++i) {
                                    result.Ain.emplace_back(algebra::random_element<typename
                            CurveType::scalar_field_type>() * CurveType::g1_type::value_type::one());
                                }

                                return result;
                            }*/
                        };

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the R1CS ppzkADSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        class processed_verification_key {
                            using pairing_policy = typename snark_pp<CurveType>::pairing;

                        public:
                            typename pairing_policy::g2_precomp::value_type pp_G2_one_precomp;
                            typename pairing_policy::g2_precomp::value_type vk_alphaA_g2_precomp;
                            typename pairing_policy::g1_precomp::value_type vk_alphaB_g1_precomp;
                            typename pairing_policy::g2_precomp::value_type vk_alphaC_g2_precomp;
                            typename pairing_policy::g2_precomp::value_type vk_rC_Z_g2_precomp;
                            typename pairing_policy::g2_precomp::value_type vk_gamma_g2_precomp;
                            typename pairing_policy::g1_precomp::value_type vk_gamma_beta_g1_precomp;
                            typename pairing_policy::g2_precomp::value_type vk_gamma_beta_g2_precomp;
                            typename pairing_policy::g2_precomp::value_type vk_rC_i_g2_precomp;

                            typename CurveType::g1_type::value_type A0;
                            typename std::vector<typename CurveType::g1_type::value_type> Ain;

                            std::vector<pairing_policy::g1_precomp::value_type> proof_g_vki_precomp;

                            bool operator==(const processed_verification_key &other) const {
                                bool result = (this->pp_G2_one_precomp == other.pp_G2_one_precomp &&
                                               this->vk_alphaA_g2_precomp == other.vk_alphaA_g2_precomp &&
                                               this->vk_alphaB_g1_precomp == other.vk_alphaB_g1_precomp &&
                                               this->vk_alphaC_g2_precomp == other.vk_alphaC_g2_precomp &&
                                               this->vk_rC_Z_g2_precomp == other.vk_rC_Z_g2_precomp &&
                                               this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
                                               this->vk_gamma_beta_g1_precomp == other.vk_gamma_beta_g1_precomp &&
                                               this->vk_gamma_beta_g2_precomp == other.vk_gamma_beta_g2_precomp &&
                                               this->vk_rC_i_g2_precomp == other.vk_rC_i_g2_precomp &&
                                               this->A0 == other.A0 && this->Ain == other.Ain &&
                                               this->proof_g_vki_precomp.size() == other.proof_g_vki_precomp.size());
                                if (result) {
                                    for (std::size_t i = 0; i < this->proof_g_vki_precomp.size(); i++)
                                        result &= this->proof_g_vki_precomp[i] == other.proof_g_vki_precomp[i];
                                }
                                return result;
                            }
                        };

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the R1CS ppzkADSNARK, which consists of a proving key and a verification key.
                         */
                        struct keypair {

                            proving_key<CurveType> pk;
                            verification_key<CurveType> vk;

                            keypair() = default;
                            keypair(const keypair<CurveType> &other) = default;
                            keypair(proving_key<CurveType> &&pk, verification_key<CurveType> &&vk) :
                                pk(std::move(pk)), vk(std::move(vk)) {
                            }

                            keypair(keypair<CurveType> &&other) = default;
                        };

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the R1CS ppzkADSNARK.
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
                            typename knowledge_commitment<g1_value_type, g1_value_type>::value_type g_A;
                            typename knowledge_commitment<g2_value_type, g1_value_type>::value_type g_B;
                            typename knowledge_commitment<g1_value_type, g1_value_type>::value_type g_C;
                            g1_value_type g_H;
                            g1_value_type g_K;
                            typename knowledge_commitment<g1_value_type, g1_value_type>::value_type g_Aau;
                            g1_value_type muA;

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
                                g_Aau = typename knowledge_commitment<g1_type, g1_type>::value_type(
                                    g1_value_type::one(), g1_value_type::one());

                                this->muA = g1_value_type::one();
                            }
                            proof(typename knowledge_commitment<g1_type, g1_type>::value_type &&g_A,
                                  typename knowledge_commitment<g2_type, g1_type>::value_type &&g_B,
                                  typename knowledge_commitment<g1_type, g1_type>::value_type &&g_C,
                                  g1_value_type &&g_H,
                                  g1_value_type &&g_K,
                                  typename knowledge_commitment<g1_type, g1_type>::value_type &&g_Aau,
                                  g1_value_type &&muA) :
                                g_A(std::move(g_A)),
                                g_B(std::move(g_B)), g_C(std::move(g_C)), g_H(std::move(g_H)), g_K(std::move(g_K)),
                                g_Aau(std::move(g_Aau)), muA(std::move(muA)) {};

                            std::size_t G1_size() const {
                                return 10;
                            }

                            std::size_t G2_size() const {
                                return 1;
                            }

                            std::size_t size_in_bits() const {
                                return G1_size() * g1_value_type::value_bits + G2_size() * g2_value_type::value_bits;
                            }

                            bool is_well_formed() const {
                                return (g_A.g.is_well_formed() && g_A.h.is_well_formed() && g_B.g.is_well_formed() &&
                                        g_B.h.is_well_formed() && g_C.g.is_well_formed() && g_C.h.is_well_formed() &&
                                        g_H.is_well_formed() && g_K.is_well_formed() && g_Aau.g.is_well_formed() &&
                                        g_Aau.h.is_well_formed() && muA.is_well_formed());
                            }

                            bool operator==(const proof<CurveType> &other) const {
                                return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C &&
                                        this->g_H == other.g_H && this->g_K == other.g_K &&
                                        this->g_Aau == other.g_Aau && this->muA == other.muA);
                            }
                        };

                        /***************************** Main algorithms *******************************/

                        /**
                         * R1CS ppZKADSNARK authentication parameters generator algorithm.
                         */
                        static auth_keys<CurveType> auth_generator(void) {
                            kpT<CurveType> sigkp = sigGen<CurveType>();
                            prf_key<CurveType> prfseed = prfGen<CurveType>();
                            CurveType i = algebra::random_element<typename CurveType::scalar_field_type>();
                            typename CurveType::g1_type::value_type I1 =
                                i * CurveType::g1_type::value_type::one();
                            typename CurveType::g2_type::value_type minusI2 =
                                CurveType::g2_type::value_type::zero() -
                                i * CurveType::g2_type::value_type::one();
                            return auth_keys<CurveType>(
                                pub_auth_prms<CurveType>(std::move(I1)),
                                pub_auth_key<CurveType>(std::move(minusI2), std::move(sigkp.vk)),
                                sec_auth_key<CurveType>(std::move(i), std::move(sigkp.sk), std::move(prfseed)));
                        }

                        /**
                         * R1CS ppZKADSNARK authentication algorithm.
                         */
                        static std::vector<auth_data<CurveType>>
                            auth_sign(const std::vector<typename CurveType::scalar_field_type::value_type> &ins,
                                      const sec_auth_key<CurveType> &sk,
                                      const std::vector<label_type>
                                          labels) {
                            assert(labels.size() == ins.size());
                            std::vector<auth_data<CurveType>> res;
                            res.reserve(ins.size());
                            for (std::size_t i = 0; i < ins.size(); i++) {
                                typename CurveType::scalar_field_type::value_type lambda =
                                    prfCompute<CurveType>(sk.S, labels[i]);
                                typename CurveType::g2_type::value_type Lambda =
                                    lambda * CurveType::g2_type::value_type::one();
                                signature<CurveType> sig = sigSign<CurveType>(sk.skp, labels[i], Lambda);
                                auth_data<CurveType> val(std::move(lambda + sk.i * ins[i]), std::move(Lambda),
                                                         std::move(sig));
                                res.emplace_back(val);
                            }
                            return std::move(res);
                        }

                        /**
                         * R1CS ppZKADSNARK authentication verification algorithms.
                         */
                        // symmetric
                        static bool
                            auth_verify(const std::vector<typename CurveType::scalar_field_type::value_type> &data,
                                        const std::vector<auth_data<CurveType>> &auth_data,
                                        const sec_auth_key<CurveType> &sak,
                                        const std::vector<label_type> &labels) {
                            assert((data.size() == labels.size()) && (auth_data.size() == labels.size()));
                            bool res = true;
                            for (std::size_t i = 0; i < data.size(); i++) {
                                typename CurveType::scalar_field_type::value_type lambda =
                                    prfCompute<CurveType>(sak.S, labels[i]);
                                typename CurveType::scalar_field_type::value_type mup = lambda + sak.i * data[i];
                                res = res && (auth_data[i].mu == mup);
                            }
                            return res;
                        }

                        // public
                        static bool
                            auth_verify(const std::vector<typename CurveType::scalar_field_type::value_type> &data,
                                        const std::vector<auth_data<CurveType>> &auth_data,
                                        const pub_auth_key<CurveType> &pak,
                                        const std::vector<label_type> &labels) {
                            assert((data.size() == labels.size()) && (data.size() == auth_data.size()));
                            bool res = true;
                            for (std::size_t i = 0; i < auth_data.size(); i++) {
                                typename CurveType::g2_type::value_type Mup =
                                    auth_data[i].Lambda - data[i] * pak.minusI2;
                                res = res && (auth_data[i].mu * CurveType::g2_type::value_type::one() == Mup);
                                res = res &&
                                      sigVerif<CurveType>(pak.vkp, labels[i], auth_data[i].Lambda, auth_data[i].sigma);
                            }
                            return res;
                        }

                        /**
                         * A generator algorithm for the R1CS ppzkADSNARK.
                         *
                         * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for
                         * CS.
                         */
                        static keypair<CurveType> generator(const constraint_system<CurveType> &cs,
                                                            const pub_auth_prms<CurveType> &prms) {

                            /* make the B_query "lighter" if possible */
                            constraint_system<CurveType> cs_copy(cs);
                            cs_copy.swap_AB_if_beneficial();

                            /* draw random element at which the QAP is evaluated */
                            const typename CurveType::scalar_field_type::value_type t =
                                algebra::random_element<typename CurveType::scalar_field_type>();

                            qap_instance_evaluation<typename CurveType::scalar_field_type::value_type> qap_inst =
                                r1cs_to_qap::instance_map_with_evaluation(cs_copy, t);

                            printf("* QAP number of variables: %zu\n", qap_inst.num_variables());
                            printf("* QAP pre degree: %zu\n", cs_copy.constraints.size());
                            printf("* QAP degree: %zu\n", qap_inst.degree());
                            printf("* QAP number of input variables: %zu\n", qap_inst.num_inputs());

                            std::size_t non_zero_At = 0, non_zero_Bt = 0, non_zero_Ct = 0, non_zero_Ht = 0;
                            for (std::size_t i = 0; i < qap_inst.num_variables() + 1; ++i) {
                                if (!qap_inst.At[i].is_zero()) {
                                    ++non_zero_At;
                                }
                                if (!qap_inst.Bt[i].is_zero()) {
                                    ++non_zero_Bt;
                                }
                                if (!qap_inst.Ct[i].is_zero()) {
                                    ++non_zero_Ct;
                                }
                            }
                            for (std::size_t i = 0; i < qap_inst.degree() + 1; ++i) {
                                if (!qap_inst.Ht[i].is_zero()) {
                                    ++non_zero_Ht;
                                }
                            }

                            algebra::Fr_vector<snark_pp<CurveType>> At = std::move(
                                qap_inst.At);    // qap_inst.At is now in unspecified state, but we do not use it later
                            algebra::Fr_vector<snark_pp<CurveType>> Bt = std::move(
                                qap_inst.Bt);    // qap_inst.Bt is now in unspecified state, but we do not use it later
                            algebra::Fr_vector<snark_pp<CurveType>> Ct = std::move(
                                qap_inst.Ct);    // qap_inst.Ct is now in unspecified state, but we do not use it later
                            algebra::Fr_vector<snark_pp<CurveType>> Ht = std::move(
                                qap_inst.Ht);    // qap_inst.Ht is now in unspecified state, but we do not use it later

                            /* append Zt to At,Bt,Ct with */
                            At.emplace_back(qap_inst.Zt);
                            Bt.emplace_back(qap_inst.Zt);
                            Ct.emplace_back(qap_inst.Zt);

                            const typename CurveType::scalar_field_type::value_type
                                alphaA = algebra::random_element<typename CurveType::scalar_field_type>(),
                                alphaB = algebra::random_element<typename CurveType::scalar_field_type>(),
                                alphaC = algebra::random_element<typename CurveType::scalar_field_type>(),
                                rA = algebra::random_element<typename CurveType::scalar_field_type>(),
                                rB = algebra::random_element<typename CurveType::scalar_field_type>(),
                                beta = algebra::random_element<typename CurveType::scalar_field_type>(),
                                gamma = algebra::random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type::value_type rC = rA * rB;

                            // construct the same-coefficient-check query (must happen before zeroing out the prefix of
                            // At)
                            algebra::Fr_vector<snark_pp<CurveType>> Kt;
                            Kt.reserve(qap_inst.num_variables() + 4);
                            for (std::size_t i = 0; i < qap_inst.num_variables() + 1; ++i) {
                                Kt.emplace_back(beta * (rA * At[i] + rB * Bt[i] + rC * Ct[i]));
                            }
                            Kt.emplace_back(beta * rA * qap_inst.Zt);
                            Kt.emplace_back(beta * rB * qap_inst.Zt);
                            Kt.emplace_back(beta * rC * qap_inst.Zt);

                            const std::size_t g1_exp_count = 2 * (non_zero_At - qap_inst.num_inputs() + non_zero_Ct) +
                                                             non_zero_Bt + non_zero_Ht + Kt.size();
                            const std::size_t g2_exp_count = non_zero_Bt;

                            std::size_t g1_window =
                                algebra::get_exp_window_size<typename CurveType::g1_type::value_type>(g1_exp_count);
                            std::size_t g2_window =
                                algebra::get_exp_window_size<typename CurveType::g2_type::value_type>(g2_exp_count);
                            printf("* G1 window: %zu\n", g1_window);
                            printf("* G2 window: %zu\n", g2_window);

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            algebra::window_table<typename CurveType::g1_type> g1_table =
                                algebra::get_window_table<typename CurveType::g1_type>(CurveType::scalar_field_type::value_bits, g1_window,
                                                 CurveType::g1_type::value_type::one());

                            algebra::window_table<typename algebra::CurveType::g2_type> g2_table =
                                algebra::get_window_table<typename CurveType::g2_type>(CurveType::scalar_field_type::value_bits, g2_window,
                                                 CurveType::g2_type::value_type::one());

                            knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                A_query = kc_batch_exp(CurveType::scalar_field_type::value_bits, g1_window, g1_window,
                                                       g1_table, g1_table, rA, rA * alphaA, At, chunks);

                            knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type>
                                B_query = kc_batch_exp(CurveType::scalar_field_type::value_bits, g2_window, g1_window,
                                                       g2_table, g1_table, rB, rB * alphaB, Bt, chunks);

                            knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                C_query = kc_batch_exp(CurveType::scalar_field_type::value_bits, g1_window, g1_window,
                                                       g1_table, g1_table, rC, rC * alphaC, Ct, chunks);

                            typename std::vector<typename CurveType::g1_type::value_type> H_query =
                                batch_exp(CurveType::scalar_field_type::value_bits, g1_window, g1_table, Ht);
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(H_query);
#endif

                            typename std::vector<typename CurveType::g1_type::value_type> K_query =
                                batch_exp(CurveType::scalar_field_type::value_bits, g1_window, g1_table, Kt);
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(K_query);
#endif

                            typename CurveType::g2_type::value_type alphaA_g2 =
                                alphaA * CurveType::g2_type::value_type::one();
                            typename CurveType::g1_type::value_type alphaB_g1 =
                                alphaB * CurveType::g1_type::value_type::one();
                            typename CurveType::g2_type::value_type alphaC_g2 =
                                alphaC * CurveType::g2_type::value_type::one();
                            typename CurveType::g2_type::value_type gamma_g2 =
                                gamma * CurveType::g2_type::value_type::one();
                            typename CurveType::g1_type::value_type gamma_beta_g1 =
                                (gamma * beta) * CurveType::g1_type::value_type::one();
                            typename CurveType::g2_type::value_type gamma_beta_g2 =
                                (gamma * beta) * CurveType::g2_type::value_type::one();
                            typename CurveType::g2_type::value_type rC_Z_g2 =
                                (rC * qap_inst.Zt) * CurveType::g2_type::value_type::one();

                            typename CurveType::g1_type::value_type rA_i_Z_g1 = (rA * qap_inst.Zt) * prms.I1;

                            typename CurveType::g1_type::value_type A0 = A_query[0].g;
                            typename std::vector<typename CurveType::g1_type::value_type> Ain;
                            Ain.reserve(qap_inst.num_inputs());
                            for (std::size_t i = 0; i < qap_inst.num_inputs(); ++i) {
                                Ain.emplace_back(A_query[1 + i].g);
                            }

                            verification_key<CurveType> vk =
                                verification_key<CurveType>(alphaA_g2, alphaB_g1, alphaC_g2, gamma_g2, gamma_beta_g1,
                                                            gamma_beta_g2, rC_Z_g2, A0, Ain);
                            proving_key<CurveType> pk = proving_key<CurveType>(std::move(A_query),
                                                                               std::move(B_query),
                                                                               std::move(C_query),
                                                                               std::move(H_query),
                                                                               std::move(K_query),
                                                                               std::move(rA_i_Z_g1),
                                                                               std::move(cs_copy));

                            return keypair<CurveType>(std::move(pk), std::move(vk));
                        }

                        /**
                         * A prover algorithm for the R1CS ppzkADSNARK.
                         *
                         * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                         * produces a proof (of knowledge) that attests to the following statement:
                         *               ``there exists Y such that CS(X,Y)=0''.
                         * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                         */
                        static proof<CurveType> prover(const proving_key<CurveType> &pk,
                                                       const primary_input<CurveType> &primary_input,
                                                       const auxiliary_input<CurveType> &auxiliary_input,
                                                       const std::vector<auth_data<CurveType>> &auth_data) {

                            const typename CurveType::scalar_field_type::value_type
                                d1 = algebra::random_element<typename CurveType::scalar_field_type>(),
                                d2 = algebra::random_element<typename CurveType::scalar_field_type>(),
                                d3 = algebra::random_element<typename CurveType::scalar_field_type>(),
                                dauth = algebra::random_element<typename CurveType::scalar_field_type>();

                            const qap_witness<typename CurveType::scalar_field_type> qap_wit = reductions::r1cs_to_qap<typename CurveType::scalar_field_type>::witness_map(
                                pk.constraint_system, primary_input, auxiliary_input, d1 + dauth, d2, d3);

                            typename knowledge_commitment<typename CurveType::g1_type,
                                                          typename CurveType::g1_type>::value_type g_A =
                                /* pk.A_query[0] + */ d1 * pk.A_query[qap_wit.num_variables + 1];
                            typename knowledge_commitment<typename CurveType::g2_type,
                                                          typename CurveType::g1_type>::value_type g_B =
                                pk.B_query[0] + qap_wit.d2 * pk.B_query[qap_wit.num_variables + 1];
                            typename knowledge_commitment<typename CurveType::g1_type,
                                                          typename CurveType::g1_type>::value_type g_C =
                                pk.C_query[0] + qap_wit.d3 * pk.C_query[qap_wit.num_variables + 1];

                            typename knowledge_commitment<typename CurveType::g1_type,
                                                          typename CurveType::g1_type>::value_type g_Ain =
                                dauth * pk.A_query[qap_wit.num_variables + 1];

                            typename CurveType::g1_type::value_type g_H =
                                CurveType::g1_type::value_type::zero();
                            typename CurveType::g1_type::value_type g_K =
                                (pk.K_query[0] + qap_wit.d1 * pk.K_query[qap_wit.num_variables + 1] +
                                 qap_wit.d2 * pk.K_query[qap_wit.num_variables + 2] +
                                 qap_wit.d3 * pk.K_query[qap_wit.num_variables + 3]);

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            g_A = g_A + kc_multiexp_with_mixed_addition<
                                            typename CurveType::g1_type, typename CurveType::g1_type,
                                            typename CurveType::scalar_field_type,
                                            algebra::policies::multiexp_method_bos_coster<
                                                typename knowledge_commitment<typename CurveType::g1_type,
                                                                              typename CurveType::g1_type>::value_type,
                                                typename CurveType::scalar_field_type>>(
                                            pk.A_query, 1 + qap_wit.num_inputs, 1 + qap_wit.num_variables,
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_inputs,
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables, chunks);

                            g_Ain = g_Ain +
                                    kc_multiexp_with_mixed_addition<
                                        typename CurveType::g1_type, typename CurveType::g1_type,
                                        typename CurveType::scalar_field_type,
                                        algebra::policies::multiexp_method_bos_coster<
                                            typename knowledge_commitment<typename CurveType::g1_type,
                                                                          typename CurveType::g1_type>::value_type,
                                            typename CurveType::scalar_field_type>>(
                                        pk.A_query, 1, 1 + qap_wit.num_inputs, qap_wit.coefficients_for_ABCs.begin(),
                                        qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_inputs, chunks);
                            // std :: cout << "The input proof term: " << g_Ain << "\n";

                            g_B = g_B + kc_multiexp_with_mixed_addition<
                                            typename CurveType::g2_type, typename CurveType::g1_type,
                                            typename CurveType::scalar_field_type,
                                            algebra::policies::multiexp_method_bos_coster<
                                                typename knowledge_commitment<typename CurveType::g1_type,
                                                                              typename CurveType::g1_type>::value_type,
                                                typename CurveType::scalar_field_type>>(
                                            pk.B_query, 1, 1 + qap_wit.num_variables,
                                            qap_wit.coefficients_for_ABCs.begin(),
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables, chunks);

                            g_C = g_C + kc_multiexp_with_mixed_addition<
                                            typename CurveType::g1_type, typename CurveType::g1_type,
                                            typename CurveType::scalar_field_type,
                                            algebra::policies::multiexp_method_bos_coster<
                                                typename knowledge_commitment<typename CurveType::g1_type,
                                                                              typename CurveType::g1_type>::value_type,
                                                typename CurveType::scalar_field_type>>(
                                            pk.C_query, 1, 1 + qap_wit.num_variables,
                                            qap_wit.coefficients_for_ABCs.begin(),
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables, chunks);

                            g_H = g_H +
                                  algebra::multiexp<
                                      typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                      algebra::policies::multiexp_method_BDLO12<typename CurveType::g1_type,
                                                                                typename CurveType::scalar_field_type>>(
                                      pk.H_query.begin(),
                                      pk.H_query.begin() + qap_wit.degree + 1,
                                      qap_wit.coefficients_for_H.begin(),
                                      qap_wit.coefficients_for_H.begin() + qap_wit.degree + 1,
                                      chunks);

                            g_K = g_K + algebra::multiexp_with_mixed_addition<
                                            typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                            algebra::policies::multiexp_method_bos_coster<
                                                typename CurveType::g1_type, typename CurveType::scalar_field_type>>(
                                            pk.K_query.begin() + 1,
                                            pk.K_query.begin() + 1 + qap_wit.num_variables,
                                            qap_wit.coefficients_for_ABCs.begin(),
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables,
                                            chunks);

                            std::vector<typename CurveType::scalar_field_type::value_type> mus;
                            std::vector<typename CurveType::g1_type::value_type> Ains;
                            mus.reserve(qap_wit.num_inputs);
                            Ains.reserve(qap_wit.num_inputs);
                            for (std::size_t i = 0; i < qap_wit.num_inputs; i++) {
                                mus.emplace_back(auth_data[i].mu);
                                Ains.emplace_back(pk.A_query[i + 1].g);
                            }
                            typename CurveType::g1_type::value_type muA = dauth * pk.rA_i_Z_g1;
                            muA = muA + algebra::multiexp<
                                            typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                            algebra::policies::multiexp_method_bos_coster<
                                                typename CurveType::g1_type, typename CurveType::scalar_field_type>>(
                                            Ains.begin(), Ains.begin() + qap_wit.num_inputs, mus.begin(),
                                            mus.begin() + qap_wit.num_inputs, chunks);

                            // To Do: Decide whether to include relevant parts of auth_data in proof

                            proof<CurveType> proof = proof<CurveType>(std::move(g_A),
                                                                      std::move(g_B),
                                                                      std::move(g_C),
                                                                      std::move(g_H),
                                                                      std::move(g_K),
                                                                      std::move(g_Ain),
                                                                      std::move(muA));

                            return proof;
                        }

                        /*
                         Below are two variants of verifier algorithm for the R1CS ppzkADSNARK.

                         These are the four cases that arise from the following choices:

                        1) The verifier accepts a (non-processed) verification key or, instead, a processed verification
                        key. In the latter case, we call the algorithm an "online verifier".

                        2) The verifier uses the symmetric key or the public verification key.
                             In the former case we call the algorithm a "symmetric verifier".

                        */

                        /**
                         * Convert a (non-processed) verification key into a processed verification key.
                         */
                        static processed_verification_key<CurveType>
                            verifier_process_vk(const verification_key<CurveType> &vk) {

                            using pairing_policy = typename snark_pp<CurveType>::pairing;

                            processed_verification_key<CurveType> pvk;
                            pvk.pp_G2_one_precomp =
                                pairing_policy::precompute_g2(CurveType::g2_type::value_type::one());
                            pvk.vk_alphaA_g2_precomp = pairing_policy::precompute_g2(vk.alphaA_g2);
                            pvk.vk_alphaB_g1_precomp = pairing_policy::precompute_g1(vk.alphaB_g1);
                            pvk.vk_alphaC_g2_precomp = pairing_policy::precompute_g2(vk.alphaC_g2);
                            pvk.vk_rC_Z_g2_precomp = pairing_policy::precompute_g2(vk.rC_Z_g2);
                            pvk.vk_gamma_g2_precomp = pairing_policy::precompute_g2(vk.gamma_g2);
                            pvk.vk_gamma_beta_g1_precomp = pairing_policy::precompute_g1(vk.gamma_beta_g1);
                            pvk.vk_gamma_beta_g2_precomp = pairing_policy::precompute_g2(vk.gamma_beta_g2);

                            typename pairing_policy::g2_precomp::value_type vk_rC_z_g2_precomp =
                                pairing_policy::precompute_g2(vk.rC_Z_g2);

                            pvk.A0 = typename CurveType::g1_type::value_type(vk.A0);
                            pvk.Ain = typename std::vector<typename CurveType::g1_type::value_type>(vk.Ain);

                            pvk.proof_g_vki_precomp.reserve(pvk.Ain.size());
                            for (std::size_t i = 0; i < pvk.Ain.size(); i++) {
                                pvk.proof_g_vki_precomp.emplace_back(pairing_policy::precompute_g1(pvk.Ain[i]));
                            }

                            return pvk;
                        }

                        /**
                         * A symmetric verifier algorithm for the R1CS ppzkADSNARK that
                         * accepts a processed verification key.
                         */
                        // symmetric
                        static bool online_verifier(const processed_verification_key<CurveType> &pvk,
                                                    const proof<CurveType> &proof,
                                                    const sec_auth_key<CurveType> &sak,
                                                    const std::vector<label_type> &labels) {

                            using pairing_policy = typename snark_pp<CurveType>::pairing;

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }

                            std::vector<typename CurveType::scalar_field_type::value_type> lambdas;
                            lambdas.reserve(labels.size());
                            for (std::size_t i = 0; i < labels.size(); i++) {
                                lambdas.emplace_back(prfCompute<CurveType>(sak.S, labels[i]));
                            }
                            typename CurveType::g1_type::value_type prodA = sak.i * proof.g_Aau.g;
                            prodA =
                                prodA + algebra::multiexp<
                                            typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                            algebra::policies::multiexp_method_bos_coster<
                                                typename CurveType::g1_type, typename CurveType::scalar_field_type>>(
                                            pvk.Ain.begin(), pvk.Ain.begin() + labels.size(), lambdas.begin(),
                                            lambdas.begin() + labels.size(), 1);

                            bool result_auth = true;

                            if (!(prodA == proof.muA)) {
                                result_auth = false;
                            }

                            typename pairing_policy::g1_precomp::value_type proof_g_Aau_g_precomp =
                                pairing_policy::precompute_g1(proof.g_Aau.g);
                            typename pairing_policy::g1_precomp::value_type proof_g_Aau_h_precomp =
                                pairing_policy::precompute_g1(proof.g_Aau.h);

                            typename pairing_policy::fqk_type::value_type kc_Aau_1 =
                                pairing_policy:: ::miller_loop(proof_g_Aau_g_precomp, pvk.vk_alphaA_g2_precomp);
                            typename pairing_policy::fqk_type::value_type kc_Aau_2 =
                                pairing_policy::miller_loop(proof_g_Aau_h_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type kc_Aau =
                                pairing_policy::final_exponentiation(kc_Aau_1 * kc_Aau_2.unitary_inversed());
                            if (kc_Aau != pairing_policy::gt_type::one()) {
                                result_auth = false;
                            }

                            result &= result_auth;

                            typename pairing_policy::g1_precomp::value_type proof_g_A_g_precomp =
                                pairing_policy::precompute_g1(proof.g_A.g);
                            typename pairing_policy::g1_precomp::value_type proof_g_A_h_precomp =
                                pairing_policy::precompute_g1(proof.g_A.h);
                            typename pairing_policy::fqk_type::value_type kc_A_1 =
                                pairing_policy::miller_loop(proof_g_A_g_precomp, pvk.vk_alphaA_g2_precomp);
                            typename pairing_policy::fqk_type::value_type kc_A_2 =
                                pairing_policy::miller_loop(proof_g_A_h_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type kc_A =
                                pairing_policy::final_exponentiation(kc_A_1 * kc_A_2.unitary_inversed());
                            if (kc_A != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::g2_precomp::value_type proof_g_B_g_precomp =
                                pairing_policy::precompute_g2(proof.g_B.g);
                            typename pairing_policy::g1_precomp::value_type proof_g_B_h_precomp =
                                pairing_policy::precompute_g1(proof.g_B.h);
                            typename pairing_policy::fqk_type::value_type kc_B_1 =
                                pairing_policy::miller_loop(pvk.vk_alphaB_g1_precomp, proof_g_B_g_precomp);
                            typename pairing_policy::fqk_type::value_type kc_B_2 =
                                pairing_policy::miller_loop(proof_g_B_h_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type kc_B =
                                pairing_policy::final_exponentiation(kc_B_1 * kc_B_2.unitary_inversed());
                            if (kc_B != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::g1_precomp::value_type proof_g_C_g_precomp =
                                pairing_policy::precompute_g1(proof.g_C.g);
                            typename pairing_policy::g1_precomp::value_type proof_g_C_h_precomp =
                                pairing_policy::precompute_g1(proof.g_C.h);
                            typename pairing_policy::fqk_type::value_type kc_C_1 =
                                pairing_policy::miller_loop(proof_g_C_g_precomp, pvk.vk_alphaC_g2_precomp);
                            typename pairing_policy::fqk_type::value_type kc_C_2 =
                                pairing_policy::miller_loop(proof_g_C_h_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type kc_C =
                                pairing_policy::final_exponentiation(kc_C_1 * kc_C_2.unitary_inversed());
                            if (kc_C != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            typename CurveType::g1_type::value_type Aacc = pvk.A0 + proof.g_Aau.g + proof.g_A.g;

                            typename pairing_policy::g1_precomp::value_type proof_g_Aacc_precomp =
                                pairing_policy::precompute_g1(Aacc);
                            typename pairing_policy::g1_precomp::value_type proof_g_H_precomp =
                                pairing_policy::precompute_g1(proof.g_H);
                            typename pairing_policy::fqk_type::value_type QAP_1 =
                                pairing_policy::miller_loop(proof_g_Aacc_precomp, proof_g_B_g_precomp);
                            typename pairing_policy::fqk_type::value_type QAP_23 = pairing_policy::double_miller_loop(
                                proof_g_H_precomp, pvk.vk_rC_Z_g2_precomp, proof_g_C_g_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type QAP =
                                pairing_policy::final_exponentiation(QAP_1 * QAP_23.unitary_inversed());
                            if (QAP != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::g1_precomp::value_type proof_g_K_precomp =
                                pairing_policy::precompute_g1(proof.g_K);
                            typename pairing_policy::g1_precomp::value_type proof_g_Aacc_C_precomp =
                                pairing_policy::precompute_g1(Aacc + proof.g_C.g);
                            typename pairing_policy::fqk_type::value_type K_1 =
                                pairing_policy::miller_loop(proof_g_K_precomp, pvk.vk_gamma_g2_precomp);
                            typename pairing_policy::fqk_type::value_type K_23 =
                                pairing_policy::double_miller_loop(proof_g_Aacc_C_precomp, pvk.vk_gamma_beta_g2_precomp,
                                                                   pvk.vk_gamma_beta_g1_precomp, proof_g_B_g_precomp);
                            typename pairing_policy::gt_type K =
                                pairing_policy::final_exponentiation(K_1 * K_23.unitary_inversed());
                            if (K != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            return result;
                        }

                        /**
                         * A symmetric verifier algorithm for the R1CS ppzkADSNARK that
                         * accepts a non-processed verification key
                         */
                        static bool verifier(const verification_key<CurveType> &vk,
                                             const proof<CurveType> &proof,
                                             const sec_auth_key<CurveType> &sak,
                                             const std::vector<label_type> &labels) {
                            processed_verification_key<CurveType> pvk = verifier_process_vk<CurveType>(vk);
                            bool result = online_verifier<CurveType>(pvk, proof, sak, labels);
                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS ppzkADSNARK that
                         * accepts a processed verification key.
                         */
                        // public
                        static bool online_verifier(const processed_verification_key<CurveType> &pvk,
                                                    const std::vector<auth_data<CurveType>> &auth_data,
                                                    const proof<CurveType> &proof,
                                                    const pub_auth_key<CurveType> &pak,
                                                    const std::vector<label_type> &labels) {

                            using pairing_policy = typename snark_pp<CurveType>::pairing;

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }

                            assert(labels.size() == auth_data.size());

                            std::vector<typename CurveType::g2_type> Lambdas;
                            std::vector<signature<CurveType>> sigs;
                            Lambdas.reserve(labels.size());
                            sigs.reserve(labels.size());
                            for (std::size_t i = 0; i < labels.size(); i++) {
                                Lambdas.emplace_back(auth_data[i].Lambda);
                                sigs.emplace_back(auth_data[i].sigma);
                            }
                            bool result_auth = sigBatchVerif<CurveType>(pak.vkp, labels, Lambdas, sigs);
                            if (!result_auth) {
                            }

                            // To Do: Decide whether to move pak and lambda preprocessing to offline
                            std::vector<pairing_policy::g2_precomp> g_Lambdas_precomp;
                            g_Lambdas_precomp.reserve(auth_data.size());
                            for (std::size_t i = 0; i < auth_data.size(); i++)
                                g_Lambdas_precomp.emplace_back(pairing_policy::precompute_g2(auth_data[i].Lambda));
                            typename pairing_policy::g2_precomp::value_type g_minusi_precomp =
                                pairing_policy::precompute_g2(pak.minusI2);

                            typename pairing_policy::fqk_type::value_type accum;
                            if (auth_data.size() % 2 == 1) {
                                pairing_policy::miller_loop(pvk.proof_g_vki_precomp[0], g_Lambdas_precomp[0]);
                            } else {
                                accum = pairing_policy::fqk_type::value_type::one();
                            }
                            for (std::size_t i = auth_data.size() % 2; i < labels.size(); i = i + 2) {
                                accum = accum * pairing_policy::double_miller_loop(
                                                    pvk.proof_g_vki_precomp[i], g_Lambdas_precomp[i],
                                                    pvk.proof_g_vki_precomp[i + 1], g_Lambdas_precomp[i + 1]);
                            }

                            typename pairing_policy::g1_precomp::value_type proof_g_muA_precomp =
                                pairing_policy::precompute_g1(proof.muA);
                            typename pairing_policy::g1_precomp::value_type proof_g_Aau_precomp =
                                pairing_policy::precompute_g1(proof.g_Aau.g);
                            typename pairing_policy::fqk_type::value_type accum2 = pairing_policy::double_miller_loop(
                                proof_g_muA_precomp, pvk.pp_G2_one_precomp, proof_g_Aau_precomp, g_minusi_precomp);
                            typename pairing_policy::gt_type authPair =
                                pairing_policy::final_exponentiation(accum * accum2.unitary_inversed());
                            if (authPair != pairing_policy::gt_type::one()) {
                                result_auth = false;
                            }

                            if (!(result_auth)) {
                            }

                            typename pairing_policy::g1_precomp::value_type proof_g_Aau_g_precomp =
                                pairing_policy::precompute_g1(proof.g_Aau.g);
                            typename pairing_policy::g1_precomp::value_type proof_g_Aau_h_precomp =
                                pairing_policy::precompute_g1(proof.g_Aau.h);
                            typename pairing_policy::fqk_type::value_type kc_Aau_1 =
                                pairing_policy::miller_loop(proof_g_Aau_g_precomp, pvk.vk_alphaA_g2_precomp);
                            typename pairing_policy::fqk_type::value_type kc_Aau_2 =
                                pairing_policy::miller_loop(proof_g_Aau_h_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type kc_Aau =
                                typename ::final_exponentiation(kc_Aau_1 * kc_Aau_2.unitary_inversed());
                            if (kc_Aau != pairing_policy::gt_type::one()) {
                                result_auth = false;
                            }

                            result &= result_auth;

                            typename pairing_policy::g1_precomp::value_type proof_g_A_g_precomp =
                                pairing_policy::precompute_g1(proof.g_A.g);
                            typename pairing_policy::g1_precomp::value_type proof_g_A_h_precomp =
                                pairing_policy::precompute_g1(proof.g_A.h);
                            typename pairing_policy::fqk_type::value_type kc_A_1 =
                                pairing_policy::miller_loop(proof_g_A_g_precomp, pvk.vk_alphaA_g2_precomp);
                            typename pairing_policy::fqk_type::value_type kc_A_2 =
                                pairing_policy::miller_loop(proof_g_A_h_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type kc_A =
                                pairing_policy::final_exponentiation(kc_A_1 * kc_A_2.unitary_inversed());
                            if (kc_A != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::g2_precomp::value_type proof_g_B_g_precomp =
                                pairing_policy::precompute_g2(proof.g_B.g);
                            typename pairing_policy::g1_precomp::value_type proof_g_B_h_precomp =
                                pairing_policy::precompute_g1(proof.g_B.h);
                            typename pairing_policy::fqk_type::value_type kc_B_1 =
                                pairing_policy::miller_loop(pvk.vk_alphaB_g1_precomp, proof_g_B_g_precomp);
                            typename pairing_policy::fqk_type::value_type kc_B_2 =
                                pairing_policy::miller_loop(proof_g_B_h_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type kc_B =
                                pairing_policy::final_exponentiation(kc_B_1 * kc_B_2.unitary_inversed());
                            if (kc_B != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::g1_precomp::value_type proof_g_C_g_precomp =
                                pairing_policy::precompute_g1(proof.g_C.g);
                            typename pairing_policy::g1_precomp::value_type proof_g_C_h_precomp =
                                pairing_policy::precompute_g1(proof.g_C.h);
                            typename pairing_policy::fqk_type::value_type kc_C_1 =
                                pairing_policy::miller_loop(proof_g_C_g_precomp, pvk.vk_alphaC_g2_precomp);
                            typename pairing_policy::fqk_type::value_type kc_C_2 =
                                pairing_policy::miller_loop(proof_g_C_h_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type kc_C =
                                pairing_policy::final_exponentiation(kc_C_1 * kc_C_2.unitary_inversed());
                            if (kc_C != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            typename CurveType::g1_type::value_type Aacc = pvk.A0 + proof.g_Aau.g + proof.g_A.g;

                            typename pairing_policy::g1_precomp::value_type proof_g_Aacc_precomp =
                                pairing_policy::precompute_g1(Aacc);
                            typename pairing_policy::g1_precomp::value_type proof_g_H_precomp =
                                pairing_policy::precompute_g1(proof.g_H);
                            typename pairing_policy::fqk_type::value_type QAP_1 =
                                pairing_policy::miller_loop(proof_g_Aacc_precomp, proof_g_B_g_precomp);
                            typename pairing_policy::fqk_type::value_type QAP_23 = pairing_policy::double_miller_loop(
                                proof_g_H_precomp, pvk.vk_rC_Z_g2_precomp, proof_g_C_g_precomp, pvk.pp_G2_one_precomp);
                            typename pairing_policy::gt_type QAP =
                                pairing_policy::final_exponentiation(QAP_1 * QAP_23.unitary_inversed());
                            if (QAP != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::g1_precomp::value_type proof_g_K_precomp =
                                pairing_policy::precompute_g1(proof.g_K);
                            typename pairing_policy::g1_precomp::value_type proof_g_Aacc_C_precomp =
                                pairing_policy::precompute_g1(Aacc + proof.g_C.g);
                            typename pairing_policy::fqk_type::value_type K_1 =
                                pairing_policy::miller_loop(proof_g_K_precomp, pvk.vk_gamma_g2_precomp);
                            typename pairing_policy::fqk_type::value_type K_23 =
                                pairing_policy::double_miller_loop(proof_g_Aacc_C_precomp, pvk.vk_gamma_beta_g2_precomp,
                                                                   pvk.vk_gamma_beta_g1_precomp, proof_g_B_g_precomp);
                            typename pairing_policy::gt_type K =
                                pairing_policy::final_exponentiation(K_1 * K_23.unitary_inversed());
                            if (K != pairing_policy::gt_type::one()) {
                                result = false;
                            }

                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS ppzkADSNARK that
                         * accepts a non-processed verification key
                         */
                        // public
                        static bool verifier(const verification_key<CurveType> &vk,
                                             const std::vector<auth_data<CurveType>> &auth_data,
                                             const proof<CurveType> &proof,
                                             const pub_auth_key<CurveType> &pak,
                                             const std::vector<label_type> &labels) {
                            assert(labels.size() == auth_data.size());
                            processed_verification_key<CurveType> pvk = verifier_process_vk<CurveType>(vk);
                            bool result = online_verifier<CurveType>(pvk, auth_data, proof, pak, labels);
                            return result;
                        }
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKADSNARK_BASIC_POLICY_HPP

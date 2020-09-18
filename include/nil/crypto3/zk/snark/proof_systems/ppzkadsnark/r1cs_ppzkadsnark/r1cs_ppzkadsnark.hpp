//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

#ifndef CRYPTO3_R1CS_PPZKADSNARK_HPP
#define CRYPTO3_R1CS_PPZKADSNARK_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_params.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_prf.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_signature.hpp>

#include <nil/algebra/multiexp/multiexp.hpp>

#include <nil/algebra/utils/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Public authentication parameters ********************************/

                template<typename CurveType>
                class r1cs_ppzkadsnark_pub_auth_prms;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_pub_auth_prms<CurveType> &pap);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_pub_auth_prms<CurveType> &pap);

                /**
                 * Public authentication parameters for the R1CS ppzkADSNARK
                 */
                template<typename CurveType>
                class r1cs_ppzkadsnark_pub_auth_prms {
                public:
                    typename CurveType::g1_type I1;

                    r1cs_ppzkadsnark_pub_auth_prms() {};
                    r1cs_ppzkadsnark_pub_auth_prms<CurveType> &
                        operator=(const r1cs_ppzkadsnark_pub_auth_prms<CurveType> &other) = default;
                    r1cs_ppzkadsnark_pub_auth_prms(const r1cs_ppzkadsnark_pub_auth_prms<CurveType> &other) = default;
                    r1cs_ppzkadsnark_pub_auth_prms(r1cs_ppzkadsnark_pub_auth_prms<CurveType> &&other) = default;
                    r1cs_ppzkadsnark_pub_auth_prms(typename CurveType::g1_type &&I1) : I1(std::move(I1)) {};

                    bool operator==(const r1cs_ppzkadsnark_pub_auth_prms<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                               const r1cs_ppzkadsnark_pub_auth_prms<CurveType> &pap);
                    friend std::istream &operator>>
                        <CurveType>(std::istream &in, r1cs_ppzkadsnark_pub_auth_prms<CurveType> &pap);
                };

                /******************************** Secret authentication key ********************************/

                template<typename CurveType>
                class r1cs_ppzkadsnark_sec_auth_key;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_sec_auth_key<CurveType> &key);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_sec_auth_key<CurveType> &key);

                /**
                 * Secret authentication key for the R1CS ppzkADSNARK
                 */
                template<typename CurveType>
                class r1cs_ppzkadsnark_sec_auth_key {
                public:
                    typename CurveType::scalar_field_type::value_type i;

                    r1cs_ppzkadsnark_secret_key<CurveType> skp;
                    r1cs_ppzkadsnark_prf_key<CurveType> S;

                    r1cs_ppzkadsnark_sec_auth_key() {};
                    r1cs_ppzkadsnark_sec_auth_key<CurveType> &
                        operator=(const r1cs_ppzkadsnark_sec_auth_key<CurveType> &other) = default;
                    r1cs_ppzkadsnark_sec_auth_key(const r1cs_ppzkadsnark_sec_auth_key<CurveType> &other) = default;
                    r1cs_ppzkadsnark_sec_auth_key(r1cs_ppzkadsnark_sec_auth_key<CurveType> &&other) = default;
                    r1cs_ppzkadsnark_sec_auth_key(CurveType::scalar_field_type::value_type &&i,
                                                  r1cs_ppzkadsnark_secret_key<CurveType> &&skp,
                                                  r1cs_ppzkadsnark_prf_key<CurveType> &&S) :
                        i(std::move(i)),
                        skp(std::move(skp)), S(std::move(S)) {};

                    bool operator==(const r1cs_ppzkadsnark_sec_auth_key<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                               const r1cs_ppzkadsnark_sec_auth_key<CurveType> &key);
                    friend std::istream &operator>>
                        <CurveType>(std::istream &in, r1cs_ppzkadsnark_sec_auth_key<CurveType> &key);
                };

                /******************************** Public authentication key ********************************/

                template<typename CurveType>
                class r1cs_ppzkadsnark_pub_auth_key;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_pub_auth_key<CurveType> &key);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_pub_auth_key<CurveType> &key);

                /**
                 * Public authentication key for the R1CS ppzkADSNARK
                 */
                template<typename CurveType>
                class r1cs_ppzkadsnark_pub_auth_key {
                public:
                    typename CurveType::g2_type minusI2;
                    r1cs_ppzkadsnark_vkT<CurveType> vkp;

                    r1cs_ppzkadsnark_pub_auth_key() {};
                    r1cs_ppzkadsnark_pub_auth_key<CurveType> &
                        operator=(const r1cs_ppzkadsnark_pub_auth_key<CurveType> &other) = default;
                    r1cs_ppzkadsnark_pub_auth_key(const r1cs_ppzkadsnark_pub_auth_key<CurveType> &other) = default;
                    r1cs_ppzkadsnark_pub_auth_key(r1cs_ppzkadsnark_pub_auth_key<CurveType> &&other) = default;
                    r1cs_ppzkadsnark_pub_auth_key(typename CurveType::g2_type &&minusI2,
                                                  r1cs_ppzkadsnark_vkT<CurveType> &&vkp) :
                        minusI2(std::move(minusI2)),
                        vkp(std::move(vkp)) {};

                    bool operator==(const r1cs_ppzkadsnark_pub_auth_key<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                               const r1cs_ppzkadsnark_pub_auth_key<CurveType> &key);
                    friend std::istream &operator>>
                        <CurveType>(std::istream &in, r1cs_ppzkadsnark_pub_auth_key<CurveType> &key);
                };

                /******************************** Authentication key material ********************************/

                template<typename CurveType>
                class r1cs_ppzkadsnark_auth_keys {
                public:
                    r1cs_ppzkadsnark_pub_auth_prms<CurveType> pap;
                    r1cs_ppzkadsnark_pub_auth_key<CurveType> pak;
                    r1cs_ppzkadsnark_sec_auth_key<CurveType> sak;

                    r1cs_ppzkadsnark_auth_keys() {};
                    r1cs_ppzkadsnark_auth_keys(r1cs_ppzkadsnark_auth_keys<CurveType> &&other) = default;
                    r1cs_ppzkadsnark_auth_keys(r1cs_ppzkadsnark_pub_auth_prms<CurveType> &&pap,
                                               r1cs_ppzkadsnark_pub_auth_key<CurveType> &&pak,
                                               r1cs_ppzkadsnark_sec_auth_key<CurveType> &&sak) :
                        pap(std::move(pap)),
                        pak(std::move(pak)), sak(std::move(sak)) {
                    }
                };

                /******************************** Authenticated data ********************************/

                template<typename CurveType>
                class r1cs_ppzkadsnark_auth_data;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_auth_data<CurveType> &data);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_auth_data<CurveType> &data);

                /**
                 * Authenticated data for the R1CS ppzkADSNARK
                 */
                template<typename CurveType>
                class r1cs_ppzkadsnark_auth_data {
                public:
                    typename CurveType::scalar_field_type::value_type mu;
                    typename CurveType::g2_type Lambda;

                    r1cs_ppzkadsnark_signature<CurveType> sigma;

                    r1cs_ppzkadsnark_auth_data() {};
                    r1cs_ppzkadsnark_auth_data<CurveType> &
                        operator=(const r1cs_ppzkadsnark_auth_data<CurveType> &other) = default;
                    r1cs_ppzkadsnark_auth_data(const r1cs_ppzkadsnark_auth_data<CurveType> &other) = default;
                    r1cs_ppzkadsnark_auth_data(r1cs_ppzkadsnark_auth_data<CurveType> &&other) = default;

                    r1cs_ppzkadsnark_auth_data(typename CurveType::scalar_field_type::value_type &&mu,
                                               typename CurveType::g2_type &&Lambda,

                                               r1cs_ppzkadsnark_signature<CurveType> &&sigma) :
                        mu(std::move(mu)),
                        Lambda(std::move(Lambda)), sigma(std::move(sigma)) {};

                    bool operator==(const r1cs_ppzkadsnark_auth_data<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                               const r1cs_ppzkadsnark_auth_data<CurveType> &key);
                    friend std::istream &operator>>
                        <CurveType>(std::istream &in, r1cs_ppzkadsnark_auth_data<CurveType> &key);
                };

                /******************************** Proving key ********************************/

                template<typename CurveType>
                class r1cs_ppzkadsnark_proving_key;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_proving_key<CurveType> &pk);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_proving_key<CurveType> &pk);

                /**
                 * A proving key for the R1CS ppzkADSNARK.
                 */
                template<typename CurveType>
                class r1cs_ppzkadsnark_proving_key {
                public:
                    knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> A_query;
                    knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> B_query;
                    knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> C_query;
                    typename CurveType::g1_vector H_query;    // t powers
                    typename CurveType::g1_vector K_query;
                    /* Now come the additional elements for ad */
                    typename CurveType::g1_type rA_i_Z_g1;

                    r1cs_ppzkadsnark_constraint_system<CurveType> constraint_system;

                    r1cs_ppzkadsnark_proving_key() {};
                    r1cs_ppzkadsnark_proving_key<CurveType> &
                        operator=(const r1cs_ppzkadsnark_proving_key<CurveType> &other) = default;
                    r1cs_ppzkadsnark_proving_key(const r1cs_ppzkadsnark_proving_key<CurveType> &other) = default;
                    r1cs_ppzkadsnark_proving_key(r1cs_ppzkadsnark_proving_key<CurveType> &&other) = default;
                    r1cs_ppzkadsnark_proving_key(
                        knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> &&A_query,
                        knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> &&B_query,
                        knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> &&C_query,
                        typename CurveType::g1_vector &&H_query,
                        typename CurveType::g1_vector &&K_query,
                        typename CurveType::g1_type &&rA_i_Z_g1,
                        r1cs_ppzkadsnark_constraint_system<CurveType> &&constraint_system) :
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
                               algebra::size_in_bits(H_query) + algebra::size_in_bits(K_query) +
                               typename CurveType::g1_type::size_in_bits();
                    }

                    void print_size() const {
                        printf("* G1 elements in PK: %zu\n", this->G1_size());
                        printf("* Non-zero G1 elements in PK: %zu\n", this->G1_sparse_size());
                        printf("* G2 elements in PK: %zu\n", this->G2_size());
                        printf("* Non-zero G2 elements in PK: %zu\n", this->G2_sparse_size());
                        printf("* PK size in bits: %zu\n", this->size_in_bits());
                    }

                    bool operator==(const r1cs_ppzkadsnark_proving_key<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                               const r1cs_ppzkadsnark_proving_key<CurveType> &pk);
                    friend std::istream &operator>>
                        <CurveType>(std::istream &in, r1cs_ppzkadsnark_proving_key<CurveType> &pk);
                };

                /******************************* Verification key ****************************/

                template<typename CurveType>
                class r1cs_ppzkadsnark_verification_key;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_verification_key<CurveType> &vk);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_verification_key<CurveType> &vk);

                /**
                 * A verification key for the R1CS ppzkADSNARK.
                 */
                template<typename CurveType>
                class r1cs_ppzkadsnark_verification_key {
                public:
                    typename CurveType::g2_type alphaA_g2;
                    typename CurveType::g1_type alphaB_g1;
                    typename CurveType::g2_type alphaC_g2;
                    typename CurveType::g2_type gamma_g2;
                    typename CurveType::g1_type gamma_beta_g1;
                    typename CurveType::g2_type gamma_beta_g2;
                    typename CurveType::g2_type rC_Z_g2;

                    typename CurveType::g1_type A0;
                    typename CurveType::g1_vector Ain;

                    r1cs_ppzkadsnark_verification_key() = default;
                    r1cs_ppzkadsnark_verification_key(const typename CurveType::g2_type &alphaA_g2,
                                                      const typename CurveType::g1_type &alphaB_g1,
                                                      const typename CurveType::g2_type &alphaC_g2,
                                                      const typename CurveType::g2_type &gamma_g2,
                                                      const typename CurveType::g1_type &gamma_beta_g1,
                                                      const typename CurveType::g2_type &gamma_beta_g2,
                                                      const typename CurveType::g2_type &rC_Z_g2,
                                                      const typename CurveType::g1_type A0,
                                                      const typename CurveType::g1_vector Ain) :
                        alphaA_g2(alphaA_g2),
                        alphaB_g1(alphaB_g1), alphaC_g2(alphaC_g2), gamma_g2(gamma_g2), gamma_beta_g1(gamma_beta_g1),
                        gamma_beta_g2(gamma_beta_g2), rC_Z_g2(rC_Z_g2), A0(A0), Ain(Ain) {};

                    std::size_t G1_size() const {
                        return 3 + Ain.size();
                    }

                    std::size_t G2_size() const {
                        return 5;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * typename CurveType::g1_type::size_in_bits() +
                               G2_size() * typename CurveType::g2_type::size_in_bits();    // possible zksnark bug
                    }

                    void print_size() const {
                        printf("* G1 elements in VK: %zu\n", this->G1_size());
                        printf("* G2 elements in VK: %zu\n", this->G2_size());
                        printf("* VK size in bits: %zu\n", this->size_in_bits());
                    }

                    bool operator==(const r1cs_ppzkadsnark_verification_key<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                               const r1cs_ppzkadsnark_verification_key<CurveType> &vk);
                    friend std::istream &operator>>
                        <CurveType>(std::istream &in, r1cs_ppzkadsnark_verification_key<CurveType> &vk);

                    static r1cs_ppzkadsnark_verification_key<CurveType>
                        dummy_verification_key(const std::size_t input_size);
                };

                /************************ Processed verification key *************************/

                template<typename CurveType>
                class r1cs_ppzkadsnark_processed_verification_key;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out,
                                         const r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk);

                /**
                 * A processed verification key for the R1CS ppzkADSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename CurveType>
                class r1cs_ppzkadsnark_processed_verification_key {
                public:
                    algebra::G2_precomp<snark_pp<CurveType>> pp_G2_one_precomp;
                    algebra::G2_precomp<snark_pp<CurveType>> vk_alphaA_g2_precomp;
                    algebra::G1_precomp<snark_pp<CurveType>> vk_alphaB_g1_precomp;
                    algebra::G2_precomp<snark_pp<CurveType>> vk_alphaC_g2_precomp;
                    algebra::G2_precomp<snark_pp<CurveType>> vk_rC_Z_g2_precomp;
                    algebra::G2_precomp<snark_pp<CurveType>> vk_gamma_g2_precomp;
                    algebra::G1_precomp<snark_pp<CurveType>> vk_gamma_beta_g1_precomp;
                    algebra::G2_precomp<snark_pp<CurveType>> vk_gamma_beta_g2_precomp;
                    algebra::G2_precomp<snark_pp<CurveType>> vk_rC_i_g2_precomp;

                    typename CurveType::g1_type A0;
                    typename CurveType::g1_vector Ain;

                    std::vector<algebra::G1_precomp<snark_pp<CurveType>>> proof_g_vki_precomp;

                    bool operator==(const r1cs_ppzkadsnark_processed_verification_key &other) const;
                    friend std::ostream &
                        operator<<<CurveType>(std::ostream &out,
                                              const r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk);
                    friend std::istream &operator>>
                        <CurveType>(std::istream &in, r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk);
                };

                /********************************** Key pair *********************************/

                /**
                 * A key pair for the R1CS ppzkADSNARK, which consists of a proving key and a verification key.
                 */
                template<typename CurveType>
                class r1cs_ppzkadsnark_keypair {
                public:
                    r1cs_ppzkadsnark_proving_key<CurveType> pk;
                    r1cs_ppzkadsnark_verification_key<CurveType> vk;

                    r1cs_ppzkadsnark_keypair() = default;
                    r1cs_ppzkadsnark_keypair(const r1cs_ppzkadsnark_keypair<CurveType> &other) = default;
                    r1cs_ppzkadsnark_keypair(r1cs_ppzkadsnark_proving_key<CurveType> &&pk,
                                             r1cs_ppzkadsnark_verification_key<CurveType> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {
                    }

                    r1cs_ppzkadsnark_keypair(r1cs_ppzkadsnark_keypair<CurveType> &&other) = default;
                };

                /*********************************** Proof ***********************************/

                template<typename CurveType>
                class r1cs_ppzkadsnark_proof;

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_proof<CurveType> &proof);

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_proof<CurveType> &proof);

                /**
                 * A proof for the R1CS ppzkADSNARK.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for statistics purposes.
                 */
                template<typename CurveType>
                class r1cs_ppzkadsnark_proof {
                public:
                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_A;
                    knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> g_B;
                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_C;
                    typename CurveType::g1_type g_H;
                    typename CurveType::g1_type g_K;
                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_Aau;
                    typename CurveType::g1_type muA;

                    r1cs_ppzkadsnark_proof() {
                        // invalid proof with valid curve points
                        this->g_A.g = typename CurveType::g1_type::one();
                        this->g_A.h = typename CurveType::g1_type::one();
                        this->g_B.g = typename CurveType::g2_type::one();
                        this->g_B.h = typename CurveType::g1_type::one();
                        this->g_C.g = typename CurveType::g1_type::one();
                        this->g_C.h = typename CurveType::g1_type::one();
                        this->g_H = typename CurveType::g1_type::one();
                        this->g_K = typename CurveType::g1_type::one();
                        g_Aau = knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type>(
                            typename CurveType::g1_type::one(), typename CurveType::g1_type::one());
                        this->muA = typename CurveType::g1_type::one();
                    }
                    r1cs_ppzkadsnark_proof(
                        knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> &&g_A,
                        knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> &&g_B,
                        knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> &&g_C,
                        typename CurveType::g1_type &&g_H,
                        typename CurveType::g1_type &&g_K,
                        knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> &&g_Aau,
                        typename CurveType::g1_type &&muA) :
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
                        return G1_size() * typename CurveType::g1_type::size_in_bits() +
                               G2_size() * typename CurveType::g2_type::size_in_bits();
                    }

                    void print_size() const {
                        printf("* G1 elements in proof: %zu\n", this->G1_size());
                        printf("* G2 elements in proof: %zu\n", this->G2_size());
                        printf("* Proof size in bits: %zu\n", this->size_in_bits());
                    }

                    bool is_well_formed() const {
                        return (g_A.g.is_well_formed() && g_A.h.is_well_formed() && g_B.g.is_well_formed() &&
                                g_B.h.is_well_formed() && g_C.g.is_well_formed() && g_C.h.is_well_formed() &&
                                g_H.is_well_formed() && g_K.is_well_formed() && g_Aau.g.is_well_formed() &&
                                g_Aau.h.is_well_formed() && muA.is_well_formed());
                    }

                    bool operator==(const r1cs_ppzkadsnark_proof<CurveType> &other) const;
                    friend std::ostream &operator<<<CurveType>(std::ostream &out,
                                                               const r1cs_ppzkadsnark_proof<CurveType> &proof);
                    friend std::istream &operator>>
                        <CurveType>(std::istream &in, r1cs_ppzkadsnark_proof<CurveType> &proof);
                };

                /***************************** Main algorithms *******************************/

                /**
                 * R1CS ppZKADSNARK authentication parameters generator algorithm.
                 */
                template<typename CurveType>
                r1cs_ppzkadsnark_auth_keys<CurveType> r1cs_ppzkadsnark_auth_generator(void);

                /**
                 * R1CS ppZKADSNARK authentication algorithm.
                 */
                template<typename CurveType>
                std::vector<r1cs_ppzkadsnark_auth_data<CurveType>>
                    r1cs_ppzkadsnark_auth_sign(const std::vector<CurveType::scalar_field_type::value_type> &ins,
                                               const r1cs_ppzkadsnark_sec_auth_key<CurveType> &sk,
                                               const std::vector<label_type>
                                                   labels);

                /**
                 * R1CS ppZKADSNARK authentication verification algorithms.
                 */
                template<typename CurveType>
                bool r1cs_ppzkadsnark_auth_verify(const std::vector<CurveType::scalar_field_type::value_type> &data,
                                                  const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data,
                                                  const r1cs_ppzkadsnark_sec_auth_key<CurveType> &sak,
                                                  const std::vector<label_type> &labels);

                template<typename CurveType>
                bool r1cs_ppzkadsnark_auth_verify(const std::vector<CurveType::scalar_field_type::value_type> &data,
                                                  const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data,
                                                  const r1cs_ppzkadsnark_pub_auth_key<CurveType> &pak,
                                                  const std::vector<label_type> &labels);

                /**
                 * A generator algorithm for the R1CS ppzkADSNARK.
                 *
                 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
                 */
                template<typename CurveType>
                r1cs_ppzkadsnark_keypair<CurveType>
                    r1cs_ppzkadsnark_generator(const r1cs_ppzkadsnark_constraint_system<CurveType> &cs,
                                               const r1cs_ppzkadsnark_pub_auth_prms<CurveType> &prms);

                /**
                 * A prover algorithm for the R1CS ppzkADSNARK.
                 *
                 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                 */
                template<typename CurveType>
                r1cs_ppzkadsnark_proof<CurveType>
                    r1cs_ppzkadsnark_prover(const r1cs_ppzkadsnark_proving_key<CurveType> &pk,
                                            const r1cs_ppzkadsnark_primary_input<CurveType> &primary_input,
                                            const r1cs_ppzkadsnark_auxiliary_input<CurveType> &auxiliary_input,
                                            const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data);

                /*
                 Below are two variants of verifier algorithm for the R1CS ppzkADSNARK.

                 These are the four cases that arise from the following choices:

                1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
                     In the latter case, we call the algorithm an "online verifier".

                2) The verifier uses the symmetric key or the public verification key.
                     In the former case we call the algorithm a "symmetric verifier".

                */

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename CurveType>
                r1cs_ppzkadsnark_processed_verification_key<CurveType>
                    r1cs_ppzkadsnark_verifier_process_vk(const r1cs_ppzkadsnark_verification_key<CurveType> &vk);

                /**
                 * A symmetric verifier algorithm for the R1CS ppzkADSNARK that
                 * accepts a non-processed verification key
                 */
                template<typename CurveType>
                bool r1cs_ppzkadsnark_verifier(const r1cs_ppzkadsnark_verification_key<CurveType> &vk,
                                               const r1cs_ppzkadsnark_proof<CurveType> &proof,
                                               const r1cs_ppzkadsnark_sec_auth_key<CurveType> &sak,
                                               const std::vector<label_type> &labels);

                /**
                 * A symmetric verifier algorithm for the R1CS ppzkADSNARK that
                 * accepts a processed verification key.
                 */
                template<typename CurveType>
                bool r1cs_ppzkadsnark_online_verifier(const r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk,
                                                      const r1cs_ppzkadsnark_proof<CurveType> &proof,
                                                      const r1cs_ppzkadsnark_sec_auth_key<CurveType> &sak,
                                                      const std::vector<label_type> &labels);

                /**
                 * A verifier algorithm for the R1CS ppzkADSNARK that
                 * accepts a non-processed verification key
                 */
                template<typename CurveType>
                bool r1cs_ppzkadsnark_verifier(const r1cs_ppzkadsnark_verification_key<CurveType> &vk,
                                               const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data,
                                               const r1cs_ppzkadsnark_proof<CurveType> &proof,
                                               const r1cs_ppzkadsnark_pub_auth_key<CurveType> &pak,
                                               const std::vector<label_type> &labels);

                /**
                 * A verifier algorithm for the R1CS ppzkADSNARK that
                 * accepts a processed verification key.
                 */
                template<typename CurveType>
                bool r1cs_ppzkadsnark_online_verifier(
                    const r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk,
                    const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data,
                    const r1cs_ppzkadsnark_proof<CurveType> &proof,
                    const r1cs_ppzkadsnark_pub_auth_key<CurveType> &pak,
                    const std::vector<label_type> &labels);

                template<typename CurveType>
                bool r1cs_ppzkadsnark_pub_auth_prms<CurveType>::operator==(
                    const r1cs_ppzkadsnark_pub_auth_prms<CurveType> &other) const {
                    return (this->I1 == other.I1);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_pub_auth_prms<CurveType> &pap) {
                    out << pap.I1;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_pub_auth_prms<CurveType> &pap) {
                    in >> pap.I1;

                    return in;
                }

                template<typename CurveType>
                bool r1cs_ppzkadsnark_sec_auth_key<CurveType>::operator==(
                    const r1cs_ppzkadsnark_sec_auth_key<CurveType> &other) const {
                    return (this->i == other.i) && (this->skp == other.skp) && (this->S == other.S);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_sec_auth_key<CurveType> &key) {
                    out << key.i;
                    out << key.skp;
                    out << key.S;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_sec_auth_key<CurveType> &key) {
                    in >> key.i;
                    in >> key.skp;
                    in >> key.S;

                    return in;
                }

                template<typename CurveType>
                bool r1cs_ppzkadsnark_pub_auth_key<CurveType>::operator==(
                    const r1cs_ppzkadsnark_pub_auth_key<CurveType> &other) const {
                    return (this->minusI2 == other.minusI2) && (this->vkp == other.vkp);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_pub_auth_key<CurveType> &key) {
                    out << key.minusI2;
                    out << key.vkp;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_pub_auth_key<CurveType> &key) {
                    in >> key.minusI2;
                    in >> key.vkp;

                    return in;
                }

                template<typename CurveType>
                bool r1cs_ppzkadsnark_auth_data<CurveType>::operator==(
                    const r1cs_ppzkadsnark_auth_data<CurveType> &other) const {
                    return (this->mu == other.mu) && (this->Lambda == other.Lambda) && (this->sigma == other.sigma);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_auth_data<CurveType> &data) {
                    out << data.mu;
                    out << data.Lambda;
                    out << data.sigma;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_auth_data<CurveType> &data) {
                    in >> data.mu;
                    in >> data.Lambda;
                    data.sigma;

                    return in;
                }

                template<typename CurveType>
                bool r1cs_ppzkadsnark_proving_key<CurveType>::operator==(
                    const r1cs_ppzkadsnark_proving_key<CurveType> &other) const {
                    return (this->A_query == other.A_query && this->B_query == other.B_query &&
                            this->C_query == other.C_query && this->H_query == other.H_query &&
                            this->K_query == other.K_query && this->rA_i_Z_g1 == other.rA_i_Z_g1 &&
                            this->constraint_system == other.constraint_system);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_proving_key<CurveType> &pk) {
                    out << pk.A_query;
                    out << pk.B_query;
                    out << pk.C_query;
                    out << pk.H_query;
                    out << pk.K_query;
                    out << pk.rA_i_Z_g1;
                    out << pk.constraint_system;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_proving_key<CurveType> &pk) {
                    in >> pk.A_query;
                    in >> pk.B_query;
                    in >> pk.C_query;
                    in >> pk.H_query;
                    in >> pk.K_query;
                    in >> pk.rA_i_Z_g1;
                    in >> pk.constraint_system;

                    return in;
                }

                template<typename CurveType>
                bool r1cs_ppzkadsnark_verification_key<CurveType>::operator==(
                    const r1cs_ppzkadsnark_verification_key<CurveType> &other) const {
                    return (this->alphaA_g2 == other.alphaA_g2 && this->alphaB_g1 == other.alphaB_g1 &&
                            this->alphaC_g2 == other.alphaC_g2 && this->gamma_g2 == other.gamma_g2 &&
                            this->gamma_beta_g1 == other.gamma_beta_g1 && this->gamma_beta_g2 == other.gamma_beta_g2 &&
                            this->rC_Z_g2 == other.rC_Z_g2 && this->A0 == other.A0 && this->Ain == other.Ain);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_verification_key<CurveType> &vk) {
                    out << vk.alphaA_g2 << OUTPUT_NEWLINE;
                    out << vk.alphaB_g1 << OUTPUT_NEWLINE;
                    out << vk.alphaC_g2 << OUTPUT_NEWLINE;
                    out << vk.gamma_g2 << OUTPUT_NEWLINE;
                    out << vk.gamma_beta_g1 << OUTPUT_NEWLINE;
                    out << vk.gamma_beta_g2 << OUTPUT_NEWLINE;
                    out << vk.rC_Z_g2 << OUTPUT_NEWLINE;
                    out << vk.A0 << OUTPUT_NEWLINE;
                    out << vk.Ain << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_verification_key<CurveType> &vk) {
                    in >> vk.alphaA_g2;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.alphaB_g1;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.alphaC_g2;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.gamma_g2;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.gamma_beta_g1;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.gamma_beta_g2;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.rC_Z_g2;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.A0;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> vk.Ain;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename CurveType>
                bool r1cs_ppzkadsnark_processed_verification_key<CurveType>::operator==(
                    const r1cs_ppzkadsnark_processed_verification_key<CurveType> &other) const {
                    bool result = (this->pp_G2_one_precomp == other.pp_G2_one_precomp &&
                                   this->vk_alphaA_g2_precomp == other.vk_alphaA_g2_precomp &&
                                   this->vk_alphaB_g1_precomp == other.vk_alphaB_g1_precomp &&
                                   this->vk_alphaC_g2_precomp == other.vk_alphaC_g2_precomp &&
                                   this->vk_rC_Z_g2_precomp == other.vk_rC_Z_g2_precomp &&
                                   this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
                                   this->vk_gamma_beta_g1_precomp == other.vk_gamma_beta_g1_precomp &&
                                   this->vk_gamma_beta_g2_precomp == other.vk_gamma_beta_g2_precomp &&
                                   this->vk_rC_i_g2_precomp == other.vk_rC_i_g2_precomp && this->A0 == other.A0 &&
                                   this->Ain == other.Ain &&
                                   this->proof_g_vki_precomp.size() == other.proof_g_vki_precomp.size());
                    if (result) {
                        for (std::size_t i = 0; i < this->proof_g_vki_precomp.size(); i++)
                            result &= this->proof_g_vki_precomp[i] == other.proof_g_vki_precomp[i];
                    }
                    return result;
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out,
                                         const r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk) {
                    out << pvk.pp_G2_one_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_alphaA_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_alphaB_g1_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_alphaC_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_rC_Z_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_gamma_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_gamma_beta_g1_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_gamma_beta_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_rC_i_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.A0 << OUTPUT_NEWLINE;
                    out << pvk.Ain << OUTPUT_NEWLINE;
                    out << pvk.proof_g_vki_precomp << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in,
                                         r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk) {
                    in >> pvk.pp_G2_one_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.vk_alphaA_g2_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.vk_alphaB_g1_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.vk_alphaC_g2_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.vk_rC_Z_g2_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.vk_gamma_g2_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.vk_gamma_beta_g1_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.vk_gamma_beta_g2_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.vk_rC_i_g2_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.A0;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.Ain;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> pvk.proof_g_vki_precomp;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename CurveType>
                bool r1cs_ppzkadsnark_proof<CurveType>::operator==(
                    const r1cs_ppzkadsnark_proof<CurveType> &other) const {
                    return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C &&
                            this->g_H == other.g_H && this->g_K == other.g_K && this->g_Aau == other.g_Aau &&
                            this->muA == other.muA);
                }

                template<typename CurveType>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzkadsnark_proof<CurveType> &proof) {
                    out << proof.g_A << OUTPUT_NEWLINE;
                    out << proof.g_B << OUTPUT_NEWLINE;
                    out << proof.g_C << OUTPUT_NEWLINE;
                    out << proof.g_H << OUTPUT_NEWLINE;
                    out << proof.g_K << OUTPUT_NEWLINE;
                    out << proof.g_Aau << OUTPUT_NEWLINE;
                    out << proof.muA << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename CurveType>
                std::istream &operator>>(std::istream &in, r1cs_ppzkadsnark_proof<CurveType> &proof) {
                    in >> proof.g_A;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> proof.g_B;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> proof.g_C;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> proof.g_H;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> proof.g_K;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> proof.g_Aau;
                    algebra::consume_OUTPUT_NEWLINE(in);
                    in >> proof.muA;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename CurveType>
                r1cs_ppzkadsnark_verification_key<CurveType>
                    r1cs_ppzkadsnark_verification_key<CurveType>::dummy_verification_key(const std::size_t input_size) {
                    r1cs_ppzkadsnark_verification_key<CurveType> result;
                    result.alphaA_g2 =
                        random_element<CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.alphaB_g1 =
                        random_element<CurveType::scalar_field_type>() * typename CurveType::g1_type::one();
                    result.alphaC_g2 =
                        random_element<CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.gamma_g2 =
                        random_element<CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.gamma_beta_g1 =
                        random_element<CurveType::scalar_field_type>() * typename CurveType::g1_type::one();
                    result.gamma_beta_g2 =
                        random_element<CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.rC_Z_g2 =
                        random_element<CurveType::scalar_field_type>() * typename CurveType::g2_type::one();

                    result.A0 = random_element<CurveType::scalar_field_type>() * typename CurveType::g1_type::one();
                    for (std::size_t i = 0; i < input_size; ++i) {
                        result.Ain.emplace_back(random_element<CurveType::scalar_field_type>() *
                                                typename CurveType::g1_type::one());
                    }

                    return result;
                }

                template<typename CurveType>
                r1cs_ppzkadsnark_auth_keys<CurveType> r1cs_ppzkadsnark_auth_generator(void) {
                    kpT<CurveType> sigkp = sigGen<CurveType>();
                    r1cs_ppzkadsnark_prf_key<CurveType> prfseed = prfGen<CurveType>();
                    CurveType i = random_element<CurveType::scalar_field_type>();
                    typename CurveType::g1_type I1 = i * typename CurveType::g1_type::one();
                    typename CurveType::g2_type minusI2 =
                        typename CurveType::g2_type::zero() - i * typename CurveType::g2_type::one();
                    return r1cs_ppzkadsnark_auth_keys<CurveType>(
                        r1cs_ppzkadsnark_pub_auth_prms<CurveType>(std::move(I1)),
                        r1cs_ppzkadsnark_pub_auth_key<CurveType>(std::move(minusI2), std::move(sigkp.vk)),
                        r1cs_ppzkadsnark_sec_auth_key<CurveType>(std::move(i), std::move(sigkp.sk),
                                                                 std::move(prfseed)));
                }

                template<typename CurveType>
                std::vector<r1cs_ppzkadsnark_auth_data<CurveType>>
                    r1cs_ppzkadsnark_auth_sign(const std::vector<CurveType::scalar_field_type::value_type> &ins,
                                               const r1cs_ppzkadsnark_sec_auth_key<CurveType> &sk,
                                               const std::vector<label_type>
                                                   labels) {
                    assert(labels.size() == ins.size());
                    std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> res;
                    res.reserve(ins.size());
                    for (std::size_t i = 0; i < ins.size(); i++) {
                        CurveType::scalar_field_type::value_type lambda = prfCompute<CurveType>(sk.S, labels[i]);
                        typename CurveType::g2_type Lambda = lambda * typename CurveType::g2_type::one();
                        r1cs_ppzkadsnark_signature<CurveType> sig = sigSign<CurveType>(sk.skp, labels[i], Lambda);
                        r1cs_ppzkadsnark_auth_data<CurveType> val(std::move(lambda + sk.i * ins[i]), std::move(Lambda),
                                                                  std::move(sig));
                        res.emplace_back(val);
                    }
                    return std::move(res);
                }

                // symmetric
                template<typename CurveType>
                bool r1cs_ppzkadsnark_auth_verify(const std::vector<CurveType::scalar_field_type::value_type> &data,
                                                  const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data,
                                                  const r1cs_ppzkadsnark_sec_auth_key<CurveType> &sak,
                                                  const std::vector<label_type> &labels) {
                    assert((data.size() == labels.size()) && (auth_data.size() == labels.size()));
                    bool res = true;
                    for (std::size_t i = 0; i < data.size(); i++) {
                        CurveType::scalar_field_type::value_type lambda = prfCompute<CurveType>(sak.S, labels[i]);
                        CurveType::scalar_field_type::value_type mup = lambda + sak.i * data[i];
                        res = res && (auth_data[i].mu == mup);
                    }
                    return res;
                }

                // public
                template<typename CurveType>
                bool r1cs_ppzkadsnark_auth_verify(const std::vector<CurveType::scalar_field_type::value_type> &data,
                                                  const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data,
                                                  const r1cs_ppzkadsnark_pub_auth_key<CurveType> &pak,
                                                  const std::vector<label_type> &labels) {
                    assert((data.size() == labels.size()) && (data.size() == auth_data.size()));
                    bool res = true;
                    for (std::size_t i = 0; i < auth_data.size(); i++) {
                        typename CurveType::g2_type Mup = auth_data[i].Lambda - data[i] * pak.minusI2;
                        res = res && (auth_data[i].mu * typename CurveType::g2_type::one() == Mup);
                        res = res && sigVerif<CurveType>(pak.vkp, labels[i], auth_data[i].Lambda, auth_data[i].sigma);
                    }
                    return res;
                }

                template<typename CurveType>
                r1cs_ppzkadsnark_keypair<CurveType>
                    r1cs_ppzkadsnark_generator(const r1cs_ppzkadsnark_constraint_system<CurveType> &cs,
                                               const r1cs_ppzkadsnark_pub_auth_prms<CurveType> &prms) {

                    /* make the B_query "lighter" if possible */
                    r1cs_ppzkadsnark_constraint_system<CurveType> cs_copy(cs);
                    cs_copy.swap_AB_if_beneficial();

                    /* draw random element at which the QAP is evaluated */
                    const CurveType t = random_element<CurveType::scalar_field_type>();

                    qap_instance_evaluation<CurveType::scalar_field_type::value_type> qap_inst =
                        r1cs_to_qap_instance_map_with_evaluation(cs_copy, t);

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

                    const CurveType::scalar_field_type::value_type
                        alphaA = random_element<CurveType::scalar_field_type::value_type>(),
                        alphaB = random_element<CurveType::scalar_field_type::value_type>,
                        alphaC = random_element<CurveType::scalar_field_type::value_type>,
                        rA = random_element<CurveType::scalar_field_type::value_type>,
                        rB = random_element<CurveType::scalar_field_type::value_type>,
                        beta = random_element<CurveType::scalar_field_type::value_type>,
                        gamma = random_element<CurveType::scalar_field_type::value_type>;
                    const CurveType::scalar_field_type::value_type rC = rA * rB;

                    // construct the same-coefficient-check query (must happen before zeroing out the prefix of At)
                    algebra::Fr_vector<snark_pp<CurveType>> Kt;
                    Kt.reserve(qap_inst.num_variables() + 4);
                    for (std::size_t i = 0; i < qap_inst.num_variables() + 1; ++i) {
                        Kt.emplace_back(beta * (rA * At[i] + rB * Bt[i] + rC * Ct[i]));
                    }
                    Kt.emplace_back(beta * rA * qap_inst.Zt);
                    Kt.emplace_back(beta * rB * qap_inst.Zt);
                    Kt.emplace_back(beta * rC * qap_inst.Zt);

                    const std::size_t g1_exp_count =
                        2 * (non_zero_At - qap_inst.num_inputs() + non_zero_Ct) + non_zero_Bt + non_zero_Ht + Kt.size();
                    const std::size_t g2_exp_count = non_zero_Bt;

                    std::size_t g1_window = algebra::get_exp_window_size<typename CurveType::g1_type>(g1_exp_count);
                    std::size_t g2_window = algebra::get_exp_window_size<typename CurveType::g2_type>(g2_exp_count);
                    printf("* G1 window: %zu\n", g1_window);
                    printf("* G2 window: %zu\n", g2_window);

#ifdef MULTICORE
                    const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or
                                                                         // call omp_set_num_threads()
#else
                    const std::size_t chunks = 1;
#endif

                    algebra::window_table<typename CurveType::g1_type> g1_table =
                        get_window_table(CurveType::scalar_field_type::value_type::size_in_bits(), g1_window,
                                         typename CurveType::g1_type::one());

                    algebra::window_table<typename CurveType::g2_type> g2_table =
                        get_window_table(CurveType::scalar_field_type::value_type::size_in_bits(), g2_window,
                                         typename CurveType::g2_type::one());

                    knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> A_query =
                        kc_batch_exp(CurveType::scalar_field_type::value_type::size_in_bits(), g1_window, g1_window,
                                     g1_table, g1_table, rA, rA * alphaA, At, chunks);

                    knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> B_query =
                        kc_batch_exp(CurveType::scalar_field_type::value_type::size_in_bits(), g2_window, g1_window,
                                     g2_table, g1_table, rB, rB * alphaB, Bt, chunks);

                    knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> C_query =
                        kc_batch_exp(CurveType::scalar_field_type::value_type::size_in_bits(), g1_window, g1_window,
                                     g1_table, g1_table, rC, rC * alphaC, Ct, chunks);

                    typename CurveType::g1_vector H_query =
                        batch_exp(CurveType::scalar_field_type::value_type::size_in_bits(), g1_window, g1_table, Ht);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(H_query);
#endif

                    typename CurveType::g1_vector K_query =
                        batch_exp(CurveType::scalar_field_type::value_type::size_in_bits(), g1_window, g1_table, Kt);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(K_query);
#endif

                    typename CurveType::g2_type alphaA_g2 = alphaA * typename CurveType::g2_type::one();
                    typename CurveType::g1_type alphaB_g1 = alphaB * typename CurveType::g1_type::one();
                    typename CurveType::g2_type alphaC_g2 = alphaC * typename CurveType::g2_type::one();
                    typename CurveType::g2_type gamma_g2 = gamma * typename CurveType::g2_type::one();
                    typename CurveType::g1_type gamma_beta_g1 = (gamma * beta) * typename CurveType::g1_type::one();
                    typename CurveType::g2_type gamma_beta_g2 = (gamma * beta) * typename CurveType::g2_type::one();
                    typename CurveType::g2_type rC_Z_g2 = (rC * qap_inst.Zt) * typename CurveType::g2_type::one();

                    typename CurveType::g1_type rA_i_Z_g1 = (rA * qap_inst.Zt) * prms.I1;

                    typename CurveType::g1_type A0 = A_query[0].g;
                    typename CurveType::g1_vector Ain;
                    Ain.reserve(qap_inst.num_inputs());
                    for (std::size_t i = 0; i < qap_inst.num_inputs(); ++i) {
                        Ain.emplace_back(A_query[1 + i].g);
                    }

                    r1cs_ppzkadsnark_verification_key<CurveType> vk = r1cs_ppzkadsnark_verification_key<CurveType>(
                        alphaA_g2, alphaB_g1, alphaC_g2, gamma_g2, gamma_beta_g1, gamma_beta_g2, rC_Z_g2, A0, Ain);
                    r1cs_ppzkadsnark_proving_key<CurveType> pk =
                        r1cs_ppzkadsnark_proving_key<CurveType>(std::move(A_query),
                                                                std::move(B_query),
                                                                std::move(C_query),
                                                                std::move(H_query),
                                                                std::move(K_query),
                                                                std::move(rA_i_Z_g1),
                                                                std::move(cs_copy));

                    pk.print_size();
                    vk.print_size();

                    return r1cs_ppzkadsnark_keypair<CurveType>(std::move(pk), std::move(vk));
                }

                template<typename CurveType>
                r1cs_ppzkadsnark_proof<CurveType>
                    r1cs_ppzkadsnark_prover(const r1cs_ppzkadsnark_proving_key<CurveType> &pk,
                                            const r1cs_ppzkadsnark_primary_input<CurveType> &primary_input,
                                            const r1cs_ppzkadsnark_auxiliary_input<CurveType> &auxiliary_input,
                                            const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data) {

#ifdef DEBUG
                    assert(pk.constraint_system.is_satisfied(primary_input, auxiliary_input));
#endif

                    const CurveType d1 = random_element<CurveType::scalar_field_type>(),
                                    d2 = random_element<CurveType::scalar_field_type>(),
                                    d3 = random_element<CurveType::scalar_field_type>(),
                                    dauth = random_element<CurveType::scalar_field_type>();

                    const qap_witness<CurveType::scalar_field_type::value_type> qap_wit = r1cs_to_qap_witness_map(
                        pk.constraint_system, primary_input, auxiliary_input, d1 + dauth, d2, d3);

#ifdef DEBUG
                    const CurveType t = random_element<CurveType::scalar_field_type>();
                    qap_instance_evaluation<CurveType::scalar_field_type::value_type> qap_inst =
                        r1cs_to_qap_instance_map_with_evaluation(pk.constraint_system, t);
                    assert(qap_inst.is_satisfied(qap_wit));
#endif

                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_A =
                        /* pk.A_query[0] + */ d1 * pk.A_query[qap_wit.num_variables() + 1];
                    knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> g_B =
                        pk.B_query[0] + qap_wit.d2 * pk.B_query[qap_wit.num_variables() + 1];
                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_C =
                        pk.C_query[0] + qap_wit.d3 * pk.C_query[qap_wit.num_variables() + 1];

                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_Ain =
                        dauth * pk.A_query[qap_wit.num_variables() + 1];

                    typename CurveType::g1_type g_H = typename CurveType::g1_type::zero();
                    typename CurveType::g1_type g_K =
                        (pk.K_query[0] + qap_wit.d1 * pk.K_query[qap_wit.num_variables() + 1] +
                         qap_wit.d2 * pk.K_query[qap_wit.num_variables() + 2] +
                         qap_wit.d3 * pk.K_query[qap_wit.num_variables() + 3]);

#ifdef DEBUG
                    for (std::size_t i = 0; i < qap_wit.num_inputs() + 1; ++i) {
                        assert(pk.A_query[i].g == typename CurveType::g1_type::zero());
                    }
                    assert(pk.A_query.domain_size() == qap_wit.num_variables() + 2);
                    assert(pk.B_query.domain_size() == qap_wit.num_variables() + 2);
                    assert(pk.C_query.domain_size() == qap_wit.num_variables() + 2);
                    assert(pk.H_query.size() == qap_wit.degree() + 1);
                    assert(pk.K_query.size() == qap_wit.num_variables() + 4);
#endif

#ifdef MULTICORE
                    const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or
                                                                         // call omp_set_num_threads()
#else
                    const std::size_t chunks = 1;
#endif

                    g_A =
                        g_A + kc_multi_exp_with_mixed_addition<typename CurveType::g1_type, typename CurveType::g1_type,
                                                               CurveType::scalar_field_type,
                                                               algebra::multi_exp_method_bos_coster>(
                                  pk.A_query, 1 + qap_wit.num_inputs(), 1 + qap_wit.num_variables(),
                                  qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_inputs(),
                                  qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    g_Ain = g_Ain +
                            kc_multi_exp_with_mixed_addition<typename CurveType::g1_type, typename CurveType::g1_type,
                                                             CurveType::scalar_field_type,
                                                             algebra::multi_exp_method_bos_coster>(
                                pk.A_query, 1, 1 + qap_wit.num_inputs(), qap_wit.coefficients_for_ABCs.begin(),
                                qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_inputs(), chunks);
                    // std :: cout << "The input proof term: " << g_Ain << "\n";

                    g_B =
                        g_B + kc_multi_exp_with_mixed_addition<typename CurveType::g2_type, typename CurveType::g1_type,
                                                               CurveType::scalar_field_type,
                                                               algebra::multi_exp_method_bos_coster>(
                                  pk.B_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                  qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    g_C =
                        g_C + kc_multi_exp_with_mixed_addition<typename CurveType::g1_type, typename CurveType::g1_type,
                                                               CurveType::scalar_field_type,
                                                               algebra::multi_exp_method_bos_coster>(
                                  pk.C_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                  qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    g_H = g_H + algebra::multi_exp<typename CurveType::g1_type, CurveType::scalar_field_type,
                                                   algebra::multi_exp_method_BDLO12>(
                                    pk.H_query.begin(),
                                    pk.H_query.begin() + qap_wit.degree() + 1,
                                    qap_wit.coefficients_for_H.begin(),
                                    qap_wit.coefficients_for_H.begin() + qap_wit.degree() + 1,
                                    chunks);

                    g_K = g_K + algebra::multi_exp_with_mixed_addition<typename CurveType::g1_type,
                                                                       CurveType::scalar_field_type,
                                                                       algebra::multi_exp_method_bos_coster>(
                                    pk.K_query.begin() + 1,
                                    pk.K_query.begin() + 1 + qap_wit.num_variables(),
                                    qap_wit.coefficients_for_ABCs.begin(),
                                    qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(),
                                    chunks);

                    std::vector<CurveType::scalar_field_type::value_type> mus;
                    std::vector<typename CurveType::g1_type> Ains;
                    mus.reserve(qap_wit.num_inputs());
                    Ains.reserve(qap_wit.num_inputs());
                    for (std::size_t i = 0; i < qap_wit.num_inputs(); i++) {
                        mus.emplace_back(auth_data[i].mu);
                        Ains.emplace_back(pk.A_query[i + 1].g);
                    }
                    typename CurveType::g1_type muA = dauth * pk.rA_i_Z_g1;
                    muA = muA + algebra::multi_exp<typename CurveType::g1_type, CurveType::scalar_field_type,
                                                   algebra::multi_exp_method_bos_coster>(
                                    Ains.begin(), Ains.begin() + qap_wit.num_inputs(), mus.begin(),
                                    mus.begin() + qap_wit.num_inputs(), chunks);

                    // To Do: Decide whether to include relevant parts of auth_data in proof

                    r1cs_ppzkadsnark_proof<CurveType> proof = r1cs_ppzkadsnark_proof<CurveType>(std::move(g_A),
                                                                                                std::move(g_B),
                                                                                                std::move(g_C),
                                                                                                std::move(g_H),
                                                                                                std::move(g_K),
                                                                                                std::move(g_Ain),
                                                                                                std::move(muA));
                    proof.print_size();

                    return proof;
                }

                template<typename CurveType>
                r1cs_ppzkadsnark_processed_verification_key<CurveType>
                    r1cs_ppzkadsnark_verifier_process_vk(const r1cs_ppzkadsnark_verification_key<CurveType> &vk) {

                    r1cs_ppzkadsnark_processed_verification_key<CurveType> pvk;
                    pvk.pp_G2_one_precomp = snark_pp<CurveType>::precompute_G2(typename CurveType::g2_type::one());
                    pvk.vk_alphaA_g2_precomp = snark_pp<CurveType>::precompute_G2(vk.alphaA_g2);
                    pvk.vk_alphaB_g1_precomp = snark_pp<CurveType>::precompute_G1(vk.alphaB_g1);
                    pvk.vk_alphaC_g2_precomp = snark_pp<CurveType>::precompute_G2(vk.alphaC_g2);
                    pvk.vk_rC_Z_g2_precomp = snark_pp<CurveType>::precompute_G2(vk.rC_Z_g2);
                    pvk.vk_gamma_g2_precomp = snark_pp<CurveType>::precompute_G2(vk.gamma_g2);
                    pvk.vk_gamma_beta_g1_precomp = snark_pp<CurveType>::precompute_G1(vk.gamma_beta_g1);
                    pvk.vk_gamma_beta_g2_precomp = snark_pp<CurveType>::precompute_G2(vk.gamma_beta_g2);

                    algebra::G2_precomp<snark_pp<CurveType>> vk_rC_z_g2_precomp =
                        snark_pp<CurveType>::precompute_G2(vk.rC_Z_g2);

                    pvk.A0 = typename CurveType::g1_type(vk.A0);
                    pvk.Ain = typename CurveType::g1_vector(vk.Ain);

                    pvk.proof_g_vki_precomp.reserve(pvk.Ain.size());
                    for (std::size_t i = 0; i < pvk.Ain.size(); i++) {
                        pvk.proof_g_vki_precomp.emplace_back(snark_pp<CurveType>::precompute_G1(pvk.Ain[i]));
                    }

                    return pvk;
                }

                // symmetric
                template<typename CurveType>
                bool r1cs_ppzkadsnark_online_verifier(const r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk,
                                                      const r1cs_ppzkadsnark_proof<CurveType> &proof,
                                                      const r1cs_ppzkadsnark_sec_auth_key<CurveType> &sak,
                                                      const std::vector<label_type> &labels) {
                    bool result = true;

                    if (!proof.is_well_formed()) {
                        result = false;
                    }

                    std::vector<CurveType::scalar_field_type::value_type> lambdas;
                    lambdas.reserve(labels.size());
                    for (std::size_t i = 0; i < labels.size(); i++) {
                        lambdas.emplace_back(prfCompute<CurveType>(sak.S, labels[i]));
                    }
                    typename CurveType::g1_type prodA = sak.i * proof.g_Aau.g;
                    prodA = prodA + algebra::multi_exp<typename CurveType::g1_type, CurveType::scalar_field_type,
                                                       algebra::multi_exp_method_bos_coster>(
                                        pvk.Ain.begin(), pvk.Ain.begin() + labels.size(), lambdas.begin(),
                                        lambdas.begin() + labels.size(), 1);

                    bool result_auth = true;

                    if (!(prodA == proof.muA)) {
                        result_auth = false;
                    }

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_Aau_g_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_Aau.g);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_Aau_h_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_Aau.h);
                    algebra::Fqk<snark_pp<CurveType>> kc_Aau_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_Aau_g_precomp, pvk.vk_alphaA_g2_precomp);
                    algebra::Fqk<snark_pp<CurveType>> kc_Aau_2 =
                        snark_pp<CurveType>::miller_loop(proof_g_Aau_h_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type kc_Aau =
                        snark_pp<CurveType>::final_exponentiation(kc_Aau_1 * kc_Aau_2.unitary_inverse());
                    if (kc_Aau != snark_pp<CurveType>::gt_type::one()) {
                        result_auth = false;
                    }

                    result &= result_auth;

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_A_g_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_A.g);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_A_h_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_A.h);
                    algebra::Fqk<snark_pp<CurveType>> kc_A_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_A_g_precomp, pvk.vk_alphaA_g2_precomp);
                    algebra::Fqk<snark_pp<CurveType>> kc_A_2 =
                        snark_pp<CurveType>::miller_loop(proof_g_A_h_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type kc_A =
                        snark_pp<CurveType>::final_exponentiation(kc_A_1 * kc_A_2.unitary_inverse());
                    if (kc_A != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    algebra::G2_precomp<snark_pp<CurveType>> proof_g_B_g_precomp =
                        snark_pp<CurveType>::precompute_G2(proof.g_B.g);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_B_h_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_B.h);
                    algebra::Fqk<snark_pp<CurveType>> kc_B_1 =
                        snark_pp<CurveType>::miller_loop(pvk.vk_alphaB_g1_precomp, proof_g_B_g_precomp);
                    algebra::Fqk<snark_pp<CurveType>> kc_B_2 =
                        snark_pp<CurveType>::miller_loop(proof_g_B_h_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type kc_B =
                        snark_pp<CurveType>::final_exponentiation(kc_B_1 * kc_B_2.unitary_inverse());
                    if (kc_B != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_C_g_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_C.g);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_C_h_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_C.h);
                    algebra::Fqk<snark_pp<CurveType>> kc_C_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_C_g_precomp, pvk.vk_alphaC_g2_precomp);
                    algebra::Fqk<snark_pp<CurveType>> kc_C_2 =
                        snark_pp<CurveType>::miller_loop(proof_g_C_h_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type kc_C =
                        snark_pp<CurveType>::final_exponentiation(kc_C_1 * kc_C_2.unitary_inverse());
                    if (kc_C != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    typename CurveType::g1_type Aacc = pvk.A0 + proof.g_Aau.g + proof.g_A.g;

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_Aacc_precomp =
                        snark_pp<CurveType>::precompute_G1(Aacc);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_H_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_H);
                    algebra::Fqk<snark_pp<CurveType>> QAP_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_Aacc_precomp, proof_g_B_g_precomp);
                    algebra::Fqk<snark_pp<CurveType>> QAP_23 = double_miller_loop<snark_pp<CurveType>>(
                        proof_g_H_precomp, pvk.vk_rC_Z_g2_precomp, proof_g_C_g_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type QAP =
                        snark_pp<CurveType>::final_exponentiation(QAP_1 * QAP_23.unitary_inverse());
                    if (QAP != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_K_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_K);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_Aacc_C_precomp =
                        snark_pp<CurveType>::precompute_G1(Aacc + proof.g_C.g);
                    algebra::Fqk<snark_pp<CurveType>> K_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_K_precomp, pvk.vk_gamma_g2_precomp);
                    algebra::Fqk<snark_pp<CurveType>> K_23 =
                        double_miller_loop<snark_pp<CurveType>>(proof_g_Aacc_C_precomp, pvk.vk_gamma_beta_g2_precomp,
                                                                pvk.vk_gamma_beta_g1_precomp, proof_g_B_g_precomp);
                    snark_pp<CurveType>::gt_type K =
                        snark_pp<CurveType>::final_exponentiation(K_1 * K_23.unitary_inverse());
                    if (K != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    return result;
                }

                template<typename CurveType>
                bool r1cs_ppzkadsnark_verifier(const r1cs_ppzkadsnark_verification_key<CurveType> &vk,
                                               const r1cs_ppzkadsnark_proof<CurveType> &proof,
                                               const r1cs_ppzkadsnark_sec_auth_key<CurveType> &sak,
                                               const std::vector<label_type> &labels) {
                    r1cs_ppzkadsnark_processed_verification_key<CurveType> pvk =
                        r1cs_ppzkadsnark_verifier_process_vk<CurveType>(vk);
                    bool result = r1cs_ppzkadsnark_online_verifier<CurveType>(pvk, proof, sak, labels);
                    return result;
                }

                // public
                template<typename CurveType>
                bool r1cs_ppzkadsnark_online_verifier(
                    const r1cs_ppzkadsnark_processed_verification_key<CurveType> &pvk,
                    const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data,
                    const r1cs_ppzkadsnark_proof<CurveType> &proof,
                    const r1cs_ppzkadsnark_pub_auth_key<CurveType> &pak,
                    const std::vector<label_type> &labels) {
                    bool result = true;

                    if (!proof.is_well_formed()) {
                        result = false;
                    }

                    assert(labels.size() == auth_data.size());

                    std::vector<typename CurveType::g2_type> Lambdas;
                    std::vector<r1cs_ppzkadsnark_signature<CurveType>> sigs;
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
                    std::vector<algebra::G2_precomp<snark_pp<CurveType>>> g_Lambdas_precomp;
                    g_Lambdas_precomp.reserve(auth_data.size());
                    for (std::size_t i = 0; i < auth_data.size(); i++)
                        g_Lambdas_precomp.emplace_back(snark_pp<CurveType>::precompute_G2(auth_data[i].Lambda));
                    algebra::G2_precomp<snark_pp<CurveType>> g_minusi_precomp =
                        snark_pp<CurveType>::precompute_G2(pak.minusI2);

                    algebra::Fqk<snark_pp<CurveType>> accum;
                    if (auth_data.size() % 2 == 1) {
                        accum = snark_pp<CurveType>::miller_loop(pvk.proof_g_vki_precomp[0], g_Lambdas_precomp[0]);
                    } else {
                        accum = algebra::Fqk<snark_pp<CurveType>>::one();
                    }
                    for (std::size_t i = auth_data.size() % 2; i < labels.size(); i = i + 2) {
                        accum = accum * double_miller_loop<snark_pp<CurveType>>(
                                            pvk.proof_g_vki_precomp[i], g_Lambdas_precomp[i],
                                            pvk.proof_g_vki_precomp[i + 1], g_Lambdas_precomp[i + 1]);
                    }
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_muA_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.muA);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_Aau_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_Aau.g);
                    algebra::Fqk<snark_pp<CurveType>> accum2 = double_miller_loop<snark_pp<CurveType>>(
                        proof_g_muA_precomp, pvk.pp_G2_one_precomp, proof_g_Aau_precomp, g_minusi_precomp);
                    snark_pp<CurveType>::gt_type authPair =
                        snark_pp<CurveType>::final_exponentiation(accum * accum2.unitary_inverse());
                    if (authPair != snark_pp<CurveType>::gt_type::one()) {
                        result_auth = false;
                    }

                    if (!(result_auth)) {
                    }

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_Aau_g_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_Aau.g);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_Aau_h_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_Aau.h);
                    algebra::Fqk<snark_pp<CurveType>> kc_Aau_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_Aau_g_precomp, pvk.vk_alphaA_g2_precomp);
                    algebra::Fqk<snark_pp<CurveType>> kc_Aau_2 =
                        snark_pp<CurveType>::miller_loop(proof_g_Aau_h_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type kc_Aau =
                        snark_pp<CurveType>::final_exponentiation(kc_Aau_1 * kc_Aau_2.unitary_inverse());
                    if (kc_Aau != snark_pp<CurveType>::gt_type::one()) {
                        result_auth = false;
                    }

                    result &= result_auth;

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_A_g_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_A.g);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_A_h_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_A.h);
                    algebra::Fqk<snark_pp<CurveType>> kc_A_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_A_g_precomp, pvk.vk_alphaA_g2_precomp);
                    algebra::Fqk<snark_pp<CurveType>> kc_A_2 =
                        snark_pp<CurveType>::miller_loop(proof_g_A_h_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type kc_A =
                        snark_pp<CurveType>::final_exponentiation(kc_A_1 * kc_A_2.unitary_inverse());
                    if (kc_A != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    algebra::G2_precomp<snark_pp<CurveType>> proof_g_B_g_precomp =
                        snark_pp<CurveType>::precompute_G2(proof.g_B.g);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_B_h_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_B.h);
                    algebra::Fqk<snark_pp<CurveType>> kc_B_1 =
                        snark_pp<CurveType>::miller_loop(pvk.vk_alphaB_g1_precomp, proof_g_B_g_precomp);
                    algebra::Fqk<snark_pp<CurveType>> kc_B_2 =
                        snark_pp<CurveType>::miller_loop(proof_g_B_h_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type kc_B =
                        snark_pp<CurveType>::final_exponentiation(kc_B_1 * kc_B_2.unitary_inverse());
                    if (kc_B != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_C_g_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_C.g);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_C_h_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_C.h);
                    algebra::Fqk<snark_pp<CurveType>> kc_C_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_C_g_precomp, pvk.vk_alphaC_g2_precomp);
                    algebra::Fqk<snark_pp<CurveType>> kc_C_2 =
                        snark_pp<CurveType>::miller_loop(proof_g_C_h_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type kc_C =
                        snark_pp<CurveType>::final_exponentiation(kc_C_1 * kc_C_2.unitary_inverse());
                    if (kc_C != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    typename CurveType::g1_type Aacc = pvk.A0 + proof.g_Aau.g + proof.g_A.g;

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_Aacc_precomp =
                        snark_pp<CurveType>::precompute_G1(Aacc);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_H_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_H);
                    algebra::Fqk<snark_pp<CurveType>> QAP_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_Aacc_precomp, proof_g_B_g_precomp);
                    algebra::Fqk<snark_pp<CurveType>> QAP_23 = double_miller_loop<snark_pp<CurveType>>(
                        proof_g_H_precomp, pvk.vk_rC_Z_g2_precomp, proof_g_C_g_precomp, pvk.pp_G2_one_precomp);
                    snark_pp<CurveType>::gt_type QAP =
                        snark_pp<CurveType>::final_exponentiation(QAP_1 * QAP_23.unitary_inverse());
                    if (QAP != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_K_precomp =
                        snark_pp<CurveType>::precompute_G1(proof.g_K);
                    algebra::G1_precomp<snark_pp<CurveType>> proof_g_Aacc_C_precomp =
                        snark_pp<CurveType>::precompute_G1(Aacc + proof.g_C.g);
                    algebra::Fqk<snark_pp<CurveType>> K_1 =
                        snark_pp<CurveType>::miller_loop(proof_g_K_precomp, pvk.vk_gamma_g2_precomp);
                    algebra::Fqk<snark_pp<CurveType>> K_23 =
                        double_miller_loop<snark_pp<CurveType>>(proof_g_Aacc_C_precomp, pvk.vk_gamma_beta_g2_precomp,
                                                                pvk.vk_gamma_beta_g1_precomp, proof_g_B_g_precomp);
                    snark_pp<CurveType>::gt_type K =
                        snark_pp<CurveType>::final_exponentiation(K_1 * K_23.unitary_inverse());
                    if (K != snark_pp<CurveType>::gt_type::one()) {
                        result = false;
                    }

                    return result;
                }

                // public
                template<typename CurveType>
                bool r1cs_ppzkadsnark_verifier(const r1cs_ppzkadsnark_verification_key<CurveType> &vk,
                                               const std::vector<r1cs_ppzkadsnark_auth_data<CurveType>> &auth_data,
                                               const r1cs_ppzkadsnark_proof<CurveType> &proof,
                                               const r1cs_ppzkadsnark_pub_auth_key<CurveType> &pak,
                                               const std::vector<label_type> &labels) {
                    assert(labels.size() == auth_data.size());
                    r1cs_ppzkadsnark_processed_verification_key<CurveType> pvk =
                        r1cs_ppzkadsnark_verifier_process_vk<CurveType>(vk);
                    bool result = r1cs_ppzkadsnark_online_verifier<CurveType>(pvk, auth_data, proof, pak, labels);
                    return result;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKADSNARK_HPP

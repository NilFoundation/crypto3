//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

#ifndef CRYPTO3_R1CS_PPZKSNARK_HPP
#define CRYPTO3_R1CS_PPZKSNARK_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark_params.hpp>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Proving key ********************************/

                /**
                 * A proving key for the R1CS ppzkSNARK.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_proving_key {
                public:
                    knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> A_query;
                    knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> B_query;
                    knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> C_query;
                    typename CurveType::g1_vector H_query;
                    typename CurveType::g1_vector K_query;

                    r1cs_ppzksnark_constraint_system<CurveType> constraint_system;

                    r1cs_ppzksnark_proving_key() {};
                    r1cs_ppzksnark_proving_key<CurveType> &operator=(const r1cs_ppzksnark_proving_key<CurveType> &other) = default;
                    r1cs_ppzksnark_proving_key(const r1cs_ppzksnark_proving_key<CurveType> &other) = default;
                    r1cs_ppzksnark_proving_key(r1cs_ppzksnark_proving_key<CurveType> &&other) = default;
                    r1cs_ppzksnark_proving_key(
                        knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> &&A_query,
                        knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> &&B_query,
                        knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> &&C_query,
                        typename CurveType::g1_vector &&H_query,
                        typename CurveType::g1_vector &&K_query,
                        r1cs_ppzksnark_constraint_system<CurveType> &&constraint_system) :
                        A_query(std::move(A_query)),
                        B_query(std::move(B_query)), C_query(std::move(C_query)), H_query(std::move(H_query)),
                        K_query(std::move(K_query)), constraint_system(std::move(constraint_system)) {};

                    std::size_t G1_size() const {
                        return 2 * (A_query.domain_size() + C_query.domain_size()) + B_query.domain_size() +
                               H_query.size() + K_query.size();
                    }

                    std::size_t G2_size() const {
                        return B_query.domain_size();
                    }

                    std::size_t G1_sparse_size() const {
                        return 2 * (A_query.size() + C_query.size()) + B_query.size() + H_query.size() + K_query.size();
                    }

                    std::size_t G2_sparse_size() const {
                        return B_query.size();
                    }

                    std::size_t size_in_bits() const {
                        return A_query.size_in_bits() + B_query.size_in_bits() + C_query.size_in_bits() +
                               algebra::size_in_bits(H_query) + algebra::size_in_bits(K_query);
                    }

                    bool operator==(const r1cs_ppzksnark_proving_key<CurveType> &other) const;
                };

                /******************************* Verification key ****************************/

                /**
                 * A verification key for the R1CS ppzkSNARK.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_verification_key {
                public:
                    typename CurveType::g2_type alphaA_g2;
                    typename CurveType::g1_type alphaB_g1;
                    typename CurveType::g2_type alphaC_g2;
                    typename CurveType::g2_type gamma_g2;
                    typename CurveType::g1_type gamma_beta_g1;
                    typename CurveType::g2_type gamma_beta_g2;
                    typename CurveType::g2_type rC_Z_g2;

                    accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                    r1cs_ppzksnark_verification_key() = default;
                    r1cs_ppzksnark_verification_key(const typename CurveType::g2_type &alphaA_g2,
                                                    const typename CurveType::g1_type &alphaB_g1,
                                                    const typename CurveType::g2_type &alphaC_g2,
                                                    const typename CurveType::g2_type &gamma_g2,
                                                    const typename CurveType::g1_type &gamma_beta_g1,
                                                    const typename CurveType::g2_type &gamma_beta_g2,
                                                    const typename CurveType::g2_type &rC_Z_g2,
                                                    const accumulation_vector<typename CurveType::g1_type> &eIC) :
                        alphaA_g2(alphaA_g2),
                        alphaB_g1(alphaB_g1), alphaC_g2(alphaC_g2), gamma_g2(gamma_g2), gamma_beta_g1(gamma_beta_g1),
                        gamma_beta_g2(gamma_beta_g2), rC_Z_g2(rC_Z_g2), encoded_IC_query(eIC) {};

                    std::size_t G1_size() const {
                        return 2 + encoded_IC_query.size();
                    }

                    std::size_t G2_size() const {
                        return 5;
                    }

                    std::size_t size_in_bits() const {
                        return (2 * typename CurveType::g1_type::size_in_bits() + encoded_IC_query.size_in_bits() +
                                5 * typename CurveType::g2_type::size_in_bits());
                    }

                    bool operator==(const r1cs_ppzksnark_verification_key<CurveType> &other) const;

                    static r1cs_ppzksnark_verification_key<CurveType> dummy_verification_key(const std::size_t input_size);
                };

                /************************ Processed verification key *************************/

                /**
                 * A processed verification key for the R1CS ppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_processed_verification_key {
                public:
                    algebra::G2_precomp<CurveType> pp_G2_one_precomp;
                    algebra::G2_precomp<CurveType> vk_alphaA_g2_precomp;
                    algebra::G1_precomp<CurveType> vk_alphaB_g1_precomp;
                    algebra::G2_precomp<CurveType> vk_alphaC_g2_precomp;
                    algebra::G2_precomp<CurveType> vk_rC_Z_g2_precomp;
                    algebra::G2_precomp<CurveType> vk_gamma_g2_precomp;
                    algebra::G1_precomp<CurveType> vk_gamma_beta_g1_precomp;
                    algebra::G2_precomp<CurveType> vk_gamma_beta_g2_precomp;

                    accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                    bool operator==(const r1cs_ppzksnark_processed_verification_key &other) const;
                };

                /********************************** Key pair *********************************/

                /**
                 * A key pair for the R1CS ppzkSNARK, which consists of a proving key and a verification key.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_keypair {
                public:
                    r1cs_ppzksnark_proving_key<CurveType> pk;
                    r1cs_ppzksnark_verification_key<CurveType> vk;

                    r1cs_ppzksnark_keypair() = default;
                    r1cs_ppzksnark_keypair(const r1cs_ppzksnark_keypair<CurveType> &other) = default;
                    r1cs_ppzksnark_keypair(r1cs_ppzksnark_proving_key<CurveType> &&pk,
                                           r1cs_ppzksnark_verification_key<CurveType> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {
                    }

                    r1cs_ppzksnark_keypair(r1cs_ppzksnark_keypair<CurveType> &&other) = default;
                };

                /*********************************** Proof ***********************************/

                /**
                 * A proof for the R1CS ppzkSNARK.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for statistics purposes.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_proof {
                public:
                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_A;
                    knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> g_B;
                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_C;
                    typename CurveType::g1_type g_H;
                    typename CurveType::g1_type g_K;

                    r1cs_ppzksnark_proof() {
                        // invalid proof with valid curve points
                        this->g_A.g = typename CurveType::g1_type::one();
                        this->g_A.h = typename CurveType::g1_type::one();
                        this->g_B.g = typename CurveType::g2_type::one();
                        this->g_B.h = typename CurveType::g1_type::one();
                        this->g_C.g = typename CurveType::g1_type::one();
                        this->g_C.h = typename CurveType::g1_type::one();
                        this->g_H = typename CurveType::g1_type::one();
                        this->g_K = typename CurveType::g1_type::one();
                    }
                    r1cs_ppzksnark_proof(knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> &&g_A,
                                         knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> &&g_B,
                                         knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> &&g_C,
                                         typename CurveType::g1_type &&g_H,
                                         typename CurveType::g1_type &&g_K) :
                        g_A(std::move(g_A)),
                        g_B(std::move(g_B)), g_C(std::move(g_C)), g_H(std::move(g_H)), g_K(std::move(g_K)) {};

                    std::size_t G1_size() const {
                        return 7;
                    }

                    std::size_t G2_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * typename CurveType::g1_type::size_in_bits() +
                               G2_size() * typename CurveType::g2_type::size_in_bits();
                    }

                    bool is_well_formed() const {
                        return (g_A.g.is_well_formed() && g_A.h.is_well_formed() && g_B.g.is_well_formed() &&
                                g_B.h.is_well_formed() && g_C.g.is_well_formed() && g_C.h.is_well_formed() &&
                                g_H.is_well_formed() && g_K.is_well_formed());
                    }

                    bool operator==(const r1cs_ppzksnark_proof<CurveType> &other) const;
                };

                /***************************** Main algorithms *******************************/

                /**
                 * A generator algorithm for the R1CS ppzkSNARK.
                 *
                 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
                 */
                template<typename CurveType>
                r1cs_ppzksnark_keypair<CurveType> r1cs_ppzksnark_generator(const r1cs_ppzksnark_constraint_system<CurveType> &cs);

                /**
                 * A prover algorithm for the R1CS ppzkSNARK.
                 *
                 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                 */
                template<typename CurveType>
                r1cs_ppzksnark_proof<CurveType>
                    r1cs_ppzksnark_prover(const r1cs_ppzksnark_proving_key<CurveType> &pk,
                                          const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                          const r1cs_ppzksnark_auxiliary_input<CurveType> &auxiliary_input);

                /*
                 Below are four variants of verifier algorithm for the R1CS ppzkSNARK.

                 These are the four cases that arise from the following two choices:

                 (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
                     In the latter case, we call the algorithm an "online verifier".

                 (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                     Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                     weak input consistency requires that |primary_input| <= CS.num_inputs (and
                     the primary input is implicitly padded with zeros up to length CS.num_inputs).
                 */

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename CurveType>
                bool r1cs_ppzksnark_verifier_weak_IC(const r1cs_ppzksnark_verification_key<CurveType> &vk,
                                                     const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                                     const r1cs_ppzksnark_proof<CurveType> &proof);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename CurveType>
                bool r1cs_ppzksnark_verifier_strong_IC(const r1cs_ppzksnark_verification_key<CurveType> &vk,
                                                       const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                                       const r1cs_ppzksnark_proof<CurveType> &proof);

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename CurveType>
                r1cs_ppzksnark_processed_verification_key<CurveType>
                    r1cs_ppzksnark_verifier_process_vk(const r1cs_ppzksnark_verification_key<CurveType> &vk);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename CurveType>
                bool r1cs_ppzksnark_online_verifier_weak_IC(const r1cs_ppzksnark_processed_verification_key<CurveType> &pvk,
                                                            const r1cs_ppzksnark_primary_input<CurveType> &input,
                                                            const r1cs_ppzksnark_proof<CurveType> &proof);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename CurveType>
                bool r1cs_ppzksnark_online_verifier_strong_IC(const r1cs_ppzksnark_processed_verification_key<CurveType> &pvk,
                                                              const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                                              const r1cs_ppzksnark_proof<CurveType> &proof);

                /****************************** Miscellaneous ********************************/

                /**
                 * For debugging purposes (of r1cs_ppzksnark_r1cs_ppzksnark_verifier_component):
                 *
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a non-processed verification key,
                 * (2) has weak input consistency, and
                 * (3) uses affine coordinates for elliptic-curve computations.
                 */
                template<typename CurveType>
                bool r1cs_ppzksnark_affine_verifier_weak_IC(const r1cs_ppzksnark_verification_key<CurveType> &vk,
                                                            const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                                            const r1cs_ppzksnark_proof<CurveType> &proof);

                template<typename CurveType>
                bool r1cs_ppzksnark_proving_key<CurveType>::operator==(const r1cs_ppzksnark_proving_key<CurveType> &other) const {
                    return (this->A_query == other.A_query && this->B_query == other.B_query &&
                            this->C_query == other.C_query && this->H_query == other.H_query &&
                            this->K_query == other.K_query && this->constraint_system == other.constraint_system);
                }

                template<typename CurveType>
                bool r1cs_ppzksnark_verification_key<CurveType>::operator==(
                    const r1cs_ppzksnark_verification_key<CurveType> &other) const {
                    return (this->alphaA_g2 == other.alphaA_g2 && this->alphaB_g1 == other.alphaB_g1 &&
                            this->alphaC_g2 == other.alphaC_g2 && this->gamma_g2 == other.gamma_g2 &&
                            this->gamma_beta_g1 == other.gamma_beta_g1 && this->gamma_beta_g2 == other.gamma_beta_g2 &&
                            this->rC_Z_g2 == other.rC_Z_g2 && this->encoded_IC_query == other.encoded_IC_query);
                }

                template<typename CurveType>
                bool r1cs_ppzksnark_processed_verification_key<CurveType>::operator==(
                    const r1cs_ppzksnark_processed_verification_key<CurveType> &other) const {
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

                template<typename CurveType>
                bool r1cs_ppzksnark_proof<CurveType>::operator==(const r1cs_ppzksnark_proof<CurveType> &other) const {
                    return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C &&
                            this->g_H == other.g_H && this->g_K == other.g_K);
                }

                template<typename CurveType>
                r1cs_ppzksnark_verification_key<CurveType>
                    r1cs_ppzksnark_verification_key<CurveType>::dummy_verification_key(const std::size_t input_size) {
                    r1cs_ppzksnark_verification_key<CurveType> result;
                    result.alphaA_g2 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.alphaB_g1 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g1_type::one();
                    result.alphaC_g2 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.gamma_g2 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.gamma_beta_g1 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g1_type::one();
                    result.gamma_beta_g2 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.rC_Z_g2 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();

                    typename CurveType::g1_type base = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g1_type::one();
                    typename CurveType::g1_vector v;
                    for (std::size_t i = 0; i < input_size; ++i) {
                        v.emplace_back(random_element<typename CurveType::scalar_field_type>() * typename CurveType::g1_type::one());
                    }

                    result.encoded_IC_query = accumulation_vector<typename CurveType::g1_type>(std::move(base), std::move(v));

                    return result;
                }

                template<typename CurveType>
                r1cs_ppzksnark_keypair<CurveType> r1cs_ppzksnark_generator(const r1cs_ppzksnark_constraint_system<CurveType> &cs) {

                    /* make the B_query "lighter" if possible */
                    r1cs_ppzksnark_constraint_system<CurveType> cs_copy(cs);
                    cs_copy.swap_AB_if_beneficial();

                    /* draw random element at which the QAP is evaluated */
                    const typename CurveType::scalar_field_type t = random_element<typename CurveType::scalar_field_type>();

                    qap_instance_evaluation<typename CurveType::scalar_field_type> qap_inst =
                        r1cs_to_qap_instance_map_with_evaluation(cs_copy, t);

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

                    std::vector<typename CurveType::scalar_field_type::value_type> At = std::move(
                        qap_inst.At);    // qap_inst.At is now in unspecified state, but we do not use it later
                    std::vector<typename CurveType::scalar_field_type::value_type> Bt = std::move(
                        qap_inst.Bt);    // qap_inst.Bt is now in unspecified state, but we do not use it later
                    std::vector<typename CurveType::scalar_field_type::value_type> Ct = std::move(
                        qap_inst.Ct);    // qap_inst.Ct is now in unspecified state, but we do not use it later
                    std::vector<typename CurveType::scalar_field_type::value_type> Ht = std::move(
                        qap_inst.Ht);    // qap_inst.Ht is now in unspecified state, but we do not use it later

                    /* append Zt to At,Bt,Ct with */
                    At.emplace_back(qap_inst.Zt);
                    Bt.emplace_back(qap_inst.Zt);
                    Ct.emplace_back(qap_inst.Zt);

                    const typename CurveType::scalar_field_type alphaA = random_element<typename CurveType::scalar_field_type>(),
                                           alphaB = random_element<typename CurveType::scalar_field_type>(),
                                           alphaC = random_element<typename CurveType::scalar_field_type>(),
                                           rA = random_element<typename CurveType::scalar_field_type>(),
                                           rB = random_element<typename CurveType::scalar_field_type>(),
                                           beta = random_element<typename CurveType::scalar_field_type>(),
                                           gamma = random_element<typename CurveType::scalar_field_type>();
                    const typename CurveType::scalar_field_type rC = rA * rB;

                    // consrtuct the same-coefficient-check query (must happen before zeroing out the prefix of At)
                    std::vector<typename CurveType::scalar_field_type::value_type> Kt;
                    Kt.reserve(qap_inst.num_variables() + 4);
                    for (std::size_t i = 0; i < qap_inst.num_variables() + 1; ++i) {
                        Kt.emplace_back(beta * (rA * At[i] + rB * Bt[i] + rC * Ct[i]));
                    }
                    Kt.emplace_back(beta * rA * qap_inst.Zt);
                    Kt.emplace_back(beta * rB * qap_inst.Zt);
                    Kt.emplace_back(beta * rC * qap_inst.Zt);

                    /* zero out prefix of At and stick it into IC coefficients */
                    std::vector<typename CurveType::scalar_field_type::value_type> IC_coefficients;
                    IC_coefficients.reserve(qap_inst.num_inputs() + 1);
                    for (std::size_t i = 0; i < qap_inst.num_inputs() + 1; ++i) {
                        IC_coefficients.emplace_back(At[i]);
                        assert(!IC_coefficients[i].is_zero());
                        At[i] = typename CurveType::scalar_field_type::zero();
                    }

                    const std::size_t g1_exp_count =
                        2 * (non_zero_At - qap_inst.num_inputs() + non_zero_Ct) + non_zero_Bt + non_zero_Ht + Kt.size();
                    const std::size_t g2_exp_count = non_zero_Bt;

                    std::size_t g1_window = algebra::get_exp_window_size<typename CurveType::g1_type>(g1_exp_count);
                    std::size_t g2_window = algebra::get_exp_window_size<typename CurveType::g2_type>(g2_exp_count);

#ifdef MULTICORE
                    const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or call
                                                                    // omp_set_num_threads()
#else
                    const std::size_t chunks = 1;
#endif

                    algebra::window_table<typename CurveType::g1_type> g1_table =
                        get_window_table(typename CurveType::scalar_field_type::size_in_bits(), g1_window, typename CurveType::g1_type::one());

                    algebra::window_table<typename CurveType::g2_type> g2_table =
                        get_window_table(typename CurveType::scalar_field_type::size_in_bits(), g2_window, typename CurveType::g2_type::one());

                    knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> A_query =
                        kc_batch_exp(typename CurveType::scalar_field_type::size_in_bits(), g1_window, g1_window, g1_table, g1_table, rA,
                                     rA * alphaA, At, chunks);

                    knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type> B_query =
                        kc_batch_exp(typename CurveType::scalar_field_type::size_in_bits(), g2_window, g1_window, g2_table, g1_table, rB,
                                     rB * alphaB, Bt, chunks);

                    knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type> C_query =
                        kc_batch_exp(typename CurveType::scalar_field_type::size_in_bits(), g1_window, g1_window, g1_table, g1_table, rC,
                                     rC * alphaC, Ct, chunks);

                    typename CurveType::g1_vector H_query =
                        batch_exp(typename CurveType::scalar_field_type::size_in_bits(), g1_window, g1_table, Ht);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(H_query);
#endif

                    typename CurveType::g1_vector K_query =
                        batch_exp(typename CurveType::scalar_field_type::size_in_bits(), g1_window, g1_table, Kt);
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

                    typename CurveType::g1_type encoded_IC_base = (rA * IC_coefficients[0]) * typename CurveType::g1_type::one();
                    std::vector<typename CurveType::scalar_field_type::value_type> multiplied_IC_coefficients;
                    multiplied_IC_coefficients.reserve(qap_inst.num_inputs());
                    for (std::size_t i = 1; i < qap_inst.num_inputs() + 1; ++i) {
                        multiplied_IC_coefficients.emplace_back(rA * IC_coefficients[i]);
                    }
                    typename CurveType::g1_vector encoded_IC_values =
                        batch_exp(typename CurveType::scalar_field_type::size_in_bits(), g1_window, g1_table, multiplied_IC_coefficients);

                    accumulation_vector<typename CurveType::g1_type> encoded_IC_query(std::move(encoded_IC_base),
                                                                           std::move(encoded_IC_values));

                    r1cs_ppzksnark_verification_key<CurveType> vk =
                        r1cs_ppzksnark_verification_key<CurveType>(alphaA_g2, alphaB_g1, alphaC_g2, gamma_g2, gamma_beta_g1,
                                                             gamma_beta_g2, rC_Z_g2, encoded_IC_query);
                    r1cs_ppzksnark_proving_key<CurveType> pk = r1cs_ppzksnark_proving_key<CurveType>(std::move(A_query),
                                                                                         std::move(B_query),
                                                                                         std::move(C_query),
                                                                                         std::move(H_query),
                                                                                         std::move(K_query),
                                                                                         std::move(cs_copy));

                    pk.print_size();
                    vk.print_size();

                    return r1cs_ppzksnark_keypair<CurveType>(std::move(pk), std::move(vk));
                }

                template<typename CurveType>
                r1cs_ppzksnark_proof<CurveType>
                    r1cs_ppzksnark_prover(const r1cs_ppzksnark_proving_key<CurveType> &pk,
                                          const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                          const r1cs_ppzksnark_auxiliary_input<CurveType> &auxiliary_input) {

                    const typename CurveType::scalar_field_type d1 = random_element<typename CurveType::scalar_field_type>(),
                                           d2 = random_element<typename CurveType::scalar_field_type>(),
                                           d3 = random_element<typename CurveType::scalar_field_type>();

                    const qap_witness<typename CurveType::scalar_field_type> qap_wit =
                        r1cs_to_qap_witness_map(pk.constraint_system, primary_input, auxiliary_input, d1, d2, d3);

                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_A =
                        pk.A_query[0] + qap_wit.d1 * pk.A_query[qap_wit.num_variables() + 1];
                    knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> g_B =
                        pk.B_query[0] + qap_wit.d2 * pk.B_query[qap_wit.num_variables() + 1];
                    knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_C =
                        pk.C_query[0] + qap_wit.d3 * pk.C_query[qap_wit.num_variables() + 1];

                    typename CurveType::g1_type g_H = typename CurveType::g1_type::zero();
                    typename CurveType::g1_type g_K = (pk.K_query[0] + qap_wit.d1 * pk.K_query[qap_wit.num_variables() + 1] +
                                            qap_wit.d2 * pk.K_query[qap_wit.num_variables() + 2] +
                                            qap_wit.d3 * pk.K_query[qap_wit.num_variables() + 3]);

#ifdef MULTICORE
                    const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or call
                                                                    // omp_set_num_threads()
#else
                    const std::size_t chunks = 1;
#endif

                    g_A = g_A + kc_multi_exp_with_mixed_addition<typename CurveType::g1_type, typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                                 algebra::multi_exp_method_bos_coster>(
                                    pk.A_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                    qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    g_B = g_B + kc_multi_exp_with_mixed_addition<typename CurveType::g2_type, typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                                 algebra::multi_exp_method_bos_coster>(
                                    pk.B_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                    qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    g_C = g_C + kc_multi_exp_with_mixed_addition<typename CurveType::g1_type, typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                                 algebra::multi_exp_method_bos_coster>(
                                    pk.C_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                    qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    g_H =
                        g_H + algebra::multi_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                                  pk.H_query.begin(), pk.H_query.begin() + qap_wit.degree() + 1,
                                  qap_wit.coefficients_for_H.begin(),
                                  qap_wit.coefficients_for_H.begin() + qap_wit.degree() + 1, chunks);

                    g_K = g_K + algebra::multi_exp_with_mixed_addition<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                                       algebra::multi_exp_method_bos_coster>(
                                    pk.K_query.begin() + 1, pk.K_query.begin() + 1 + qap_wit.num_variables(),
                                    qap_wit.coefficients_for_ABCs.begin(),
                                    qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    r1cs_ppzksnark_proof<CurveType> proof = r1cs_ppzksnark_proof<CurveType>(
                        std::move(g_A), std::move(g_B), std::move(g_C), std::move(g_H), std::move(g_K));
                    proof.print_size();

                    return proof;
                }

                template<typename CurveType>
                r1cs_ppzksnark_processed_verification_key<CurveType>
                    r1cs_ppzksnark_verifier_process_vk(const r1cs_ppzksnark_verification_key<CurveType> &vk) {
                    r1cs_ppzksnark_processed_verification_key<CurveType> pvk;
                    pvk.pp_G2_one_precomp = CurveType::precompute_G2(typename CurveType::g2_type::one());
                    pvk.vk_alphaA_g2_precomp = CurveType::precompute_G2(vk.alphaA_g2);
                    pvk.vk_alphaB_g1_precomp = CurveType::precompute_G1(vk.alphaB_g1);
                    pvk.vk_alphaC_g2_precomp = CurveType::precompute_G2(vk.alphaC_g2);
                    pvk.vk_rC_Z_g2_precomp = CurveType::precompute_G2(vk.rC_Z_g2);
                    pvk.vk_gamma_g2_precomp = CurveType::precompute_G2(vk.gamma_g2);
                    pvk.vk_gamma_beta_g1_precomp = CurveType::precompute_G1(vk.gamma_beta_g1);
                    pvk.vk_gamma_beta_g2_precomp = CurveType::precompute_G2(vk.gamma_beta_g2);

                    pvk.encoded_IC_query = vk.encoded_IC_query;

                    return pvk;
                }

                template<typename CurveType>
                bool r1cs_ppzksnark_online_verifier_weak_IC(const r1cs_ppzksnark_processed_verification_key<CurveType> &pvk,
                                                            const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                                            const r1cs_ppzksnark_proof<CurveType> &proof) {
                    assert(pvk.encoded_IC_query.domain_size() >= primary_input.size());

                    const accumulation_vector<typename CurveType::g1_type> accumulated_IC =
                        pvk.encoded_IC_query.template accumulate_chunk<typename CurveType::scalar_field_type>(primary_input.begin(),
                                                                                         primary_input.end(), 0);
                    const typename CurveType::g1_type &acc = accumulated_IC.first;

                    bool result = true;

                    if (!proof.is_well_formed()) {
                        result = false;
                    }
                    algebra::G1_precomp<CurveType> proof_g_A_g_precomp = CurveType::precompute_G1(proof.g_A.g);
                    algebra::G1_precomp<CurveType> proof_g_A_h_precomp = CurveType::precompute_G1(proof.g_A.h);
                    algebra::Fqk<CurveType> kc_A_1 = miller_loop<CurveType>(proof_g_A_g_precomp, pvk.vk_alphaA_g2_precomp);
                    algebra::Fqk<CurveType> kc_A_2 = miller_loop<CurveType>(proof_g_A_h_precomp, pvk.pp_G2_one_precomp);
                    typename CurveType::gt_type kc_A = final_exponentiation<CurveType>(kc_A_1 * kc_A_2.unitary_inverse());
                    if (kc_A != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    algebra::G2_precomp<CurveType> proof_g_B_g_precomp = CurveType::precompute_G2(proof.g_B.g);
                    algebra::G1_precomp<CurveType> proof_g_B_h_precomp = CurveType::precompute_G1(proof.g_B.h);
                    algebra::Fqk<CurveType> kc_B_1 = miller_loop<CurveType>(pvk.vk_alphaB_g1_precomp, proof_g_B_g_precomp);
                    algebra::Fqk<CurveType> kc_B_2 = miller_loop<CurveType>(proof_g_B_h_precomp, pvk.pp_G2_one_precomp);
                    typename CurveType::gt_type kc_B = final_exponentiation<CurveType>(kc_B_1 * kc_B_2.unitary_inverse());
                    if (kc_B != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<CurveType> proof_g_C_g_precomp = CurveType::precompute_G1(proof.g_C.g);
                    algebra::G1_precomp<CurveType> proof_g_C_h_precomp = CurveType::precompute_G1(proof.g_C.h);
                    algebra::Fqk<CurveType> kc_C_1 = miller_loop<CurveType>(proof_g_C_g_precomp, pvk.vk_alphaC_g2_precomp);
                    algebra::Fqk<CurveType> kc_C_2 = miller_loop<CurveType>(proof_g_C_h_precomp, pvk.pp_G2_one_precomp);
                    typename CurveType::gt_type kc_C = final_exponentiation<CurveType>(kc_C_1 * kc_C_2.unitary_inverse());
                    if (kc_C != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    // check that g^((A+acc)*B)=g^(H*\Prod(t-\sigma)+C)
                    // equivalently, via pairings, that e(g^(A+acc), g^B) = e(g^H, g^Z) + e(g^C, g^1)
                    algebra::G1_precomp<CurveType> proof_g_A_g_acc_precomp = CurveType::precompute_G1(proof.g_A.g + acc);
                    algebra::G1_precomp<CurveType> proof_g_H_precomp = CurveType::precompute_G1(proof.g_H);
                    algebra::Fqk<CurveType> QAP_1 = miller_loop<CurveType>(proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                    algebra::Fqk<CurveType> QAP_23 = double_miller_loop<CurveType>(proof_g_H_precomp, pvk.vk_rC_Z_g2_precomp,
                                                                       proof_g_C_g_precomp, pvk.pp_G2_one_precomp);
                    typename CurveType::gt_type QAP = final_exponentiation<CurveType>(QAP_1 * QAP_23.unitary_inverse());
                    if (QAP != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<CurveType> proof_g_K_precomp = CurveType::precompute_G1(proof.g_K);
                    algebra::G1_precomp<CurveType> proof_g_A_g_acc_C_precomp =
                        CurveType::precompute_G1((proof.g_A.g + acc) + proof.g_C.g);
                    algebra::Fqk<CurveType> K_1 = miller_loop<CurveType>(proof_g_K_precomp, pvk.vk_gamma_g2_precomp);
                    algebra::Fqk<CurveType> K_23 =
                        double_miller_loop<CurveType>(proof_g_A_g_acc_C_precomp, pvk.vk_gamma_beta_g2_precomp,
                                                pvk.vk_gamma_beta_g1_precomp, proof_g_B_g_precomp);
                    typename CurveType::gt_type K = final_exponentiation<CurveType>(K_1 * K_23.unitary_inverse());
                    if (K != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    return result;
                }

                template<typename CurveType>
                bool r1cs_ppzksnark_verifier_weak_IC(const r1cs_ppzksnark_verification_key<CurveType> &vk,
                                                     const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                                     const r1cs_ppzksnark_proof<CurveType> &proof) {
                    r1cs_ppzksnark_processed_verification_key<CurveType> pvk = r1cs_ppzksnark_verifier_process_vk<CurveType>(vk);
                    bool result = r1cs_ppzksnark_online_verifier_weak_IC<CurveType>(pvk, primary_input, proof);
                    return result;
                }

                template<typename CurveType>
                bool r1cs_ppzksnark_online_verifier_strong_IC(const r1cs_ppzksnark_processed_verification_key<CurveType> &pvk,
                                                              const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                                              const r1cs_ppzksnark_proof<CurveType> &proof) {
                    bool result = true;

                    if (pvk.encoded_IC_query.domain_size() != primary_input.size()) {
                        result = false;
                    } else {
                        result = r1cs_ppzksnark_online_verifier_weak_IC(pvk, primary_input, proof);
                    }

                    return result;
                }

                template<typename CurveType>
                bool r1cs_ppzksnark_verifier_strong_IC(const r1cs_ppzksnark_verification_key<CurveType> &vk,
                                                       const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                                       const r1cs_ppzksnark_proof<CurveType> &proof) {
                    r1cs_ppzksnark_processed_verification_key<CurveType> pvk = r1cs_ppzksnark_verifier_process_vk<CurveType>(vk);
                    bool result = r1cs_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, primary_input, proof);
                    return result;
                }

                template<typename CurveType>
                bool r1cs_ppzksnark_affine_verifier_weak_IC(const r1cs_ppzksnark_verification_key<CurveType> &vk,
                                                            const r1cs_ppzksnark_primary_input<CurveType> &primary_input,
                                                            const r1cs_ppzksnark_proof<CurveType> &proof) {
                    assert(vk.encoded_IC_query.domain_size() >= primary_input.size());

                    algebra::affine_ate_G2_precomp<CurveType> pvk_pp_G2_one_precomp =
                        CurveType::affine_ate_precompute_G2(typename CurveType::g2_type::one());
                    algebra::affine_ate_G2_precomp<CurveType> pvk_vk_alphaA_g2_precomp =
                        CurveType::affine_ate_precompute_G2(vk.alphaA_g2);
                    algebra::affine_ate_G1_precomp<CurveType> pvk_vk_alphaB_g1_precomp =
                        CurveType::affine_ate_precompute_G1(vk.alphaB_g1);
                    algebra::affine_ate_G2_precomp<CurveType> pvk_vk_alphaC_g2_precomp =
                        CurveType::affine_ate_precompute_G2(vk.alphaC_g2);
                    algebra::affine_ate_G2_precomp<CurveType> pvk_vk_rC_Z_g2_precomp =
                        CurveType::affine_ate_precompute_G2(vk.rC_Z_g2);
                    algebra::affine_ate_G2_precomp<CurveType> pvk_vk_gamma_g2_precomp =
                        CurveType::affine_ate_precompute_G2(vk.gamma_g2);
                    algebra::affine_ate_G1_precomp<CurveType> pvk_vk_gamma_beta_g1_precomp =
                        CurveType::affine_ate_precompute_G1(vk.gamma_beta_g1);
                    algebra::affine_ate_G2_precomp<CurveType> pvk_vk_gamma_beta_g2_precomp =
                        CurveType::affine_ate_precompute_G2(vk.gamma_beta_g2);

                    const accumulation_vector<typename CurveType::g1_type> accumulated_IC =
                        vk.encoded_IC_query.template accumulate_chunk<typename CurveType::scalar_field_type>(primary_input.begin(),
                                                                                        primary_input.end(), 0);
                    assert(accumulated_IC.is_fully_accumulated());
                    const typename CurveType::g1_type &acc = accumulated_IC.first;

                    bool result = true;
                    algebra::affine_ate_G1_precomp<CurveType> proof_g_A_g_precomp =
                        CurveType::affine_ate_precompute_G1(proof.g_A.g);
                    algebra::affine_ate_G1_precomp<CurveType> proof_g_A_h_precomp =
                        CurveType::affine_ate_precompute_G1(proof.g_A.h);
                    algebra::Fqk<CurveType> kc_A_miller = CurveType::affine_ate_e_over_e_miller_loop(
                        proof_g_A_g_precomp, pvk_vk_alphaA_g2_precomp, proof_g_A_h_precomp, pvk_pp_G2_one_precomp);
                    typename CurveType::gt_type kc_A = final_exponentiation<CurveType>(kc_A_miller);

                    if (kc_A != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    algebra::affine_ate_G2_precomp<CurveType> proof_g_B_g_precomp =
                        CurveType::affine_ate_precompute_G2(proof.g_B.g);
                    algebra::affine_ate_G1_precomp<CurveType> proof_g_B_h_precomp =
                        CurveType::affine_ate_precompute_G1(proof.g_B.h);
                    algebra::Fqk<CurveType> kc_B_miller = CurveType::affine_ate_e_over_e_miller_loop(
                        pvk_vk_alphaB_g1_precomp, proof_g_B_g_precomp, proof_g_B_h_precomp, pvk_pp_G2_one_precomp);
                    typename CurveType::gt_type kc_B = final_exponentiation<CurveType>(kc_B_miller);
                    if (kc_B != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    algebra::affine_ate_G1_precomp<CurveType> proof_g_C_g_precomp =
                        CurveType::affine_ate_precompute_G1(proof.g_C.g);
                    algebra::affine_ate_G1_precomp<CurveType> proof_g_C_h_precomp =
                        CurveType::affine_ate_precompute_G1(proof.g_C.h);
                    algebra::Fqk<CurveType> kc_C_miller = CurveType::affine_ate_e_over_e_miller_loop(
                        proof_g_C_g_precomp, pvk_vk_alphaC_g2_precomp, proof_g_C_h_precomp, pvk_pp_G2_one_precomp);
                    typename CurveType::gt_type kc_C = final_exponentiation<CurveType>(kc_C_miller);
                    if (kc_C != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    algebra::affine_ate_G1_precomp<CurveType> proof_g_A_g_acc_precomp =
                        CurveType::affine_ate_precompute_G1(proof.g_A.g + acc);
                    algebra::affine_ate_G1_precomp<CurveType> proof_g_H_precomp = CurveType::affine_ate_precompute_G1(proof.g_H);
                    algebra::Fqk<CurveType> QAP_miller = CurveType::affine_ate_e_times_e_over_e_miller_loop(
                        proof_g_H_precomp, pvk_vk_rC_Z_g2_precomp, proof_g_C_g_precomp, pvk_pp_G2_one_precomp,
                        proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                    typename CurveType::gt_type QAP = final_exponentiation<CurveType>(QAP_miller);
                    if (QAP != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    algebra::affine_ate_G1_precomp<CurveType> proof_g_K_precomp = CurveType::affine_ate_precompute_G1(proof.g_K);
                    algebra::affine_ate_G1_precomp<CurveType> proof_g_A_g_acc_C_precomp =
                        CurveType::affine_ate_precompute_G1((proof.g_A.g + acc) + proof.g_C.g);
                    algebra::Fqk<CurveType> K_miller = CurveType::affine_ate_e_times_e_over_e_miller_loop(
                        proof_g_A_g_acc_C_precomp, pvk_vk_gamma_beta_g2_precomp, pvk_vk_gamma_beta_g1_precomp,
                        proof_g_B_g_precomp, proof_g_K_precomp, pvk_vk_gamma_g2_precomp);
                    typename CurveType::gt_type K = final_exponentiation<CurveType>(K_miller);
                    if (K != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_HPP

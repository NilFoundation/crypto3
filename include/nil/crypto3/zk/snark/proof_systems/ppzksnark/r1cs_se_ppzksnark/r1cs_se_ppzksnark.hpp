//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a SEppzkSNARK for R1CS.
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
// The implementation instantiates (a modification of) the protocol of \[GM17],
// by following extending, and optimizing the approach described in \[BCTV14].
//
//
// Acronyms:
//
// - R1CS = "Rank-1 Constraint Systems"
// - SEppzkSNARK = "Simulation-Extractable PreProcessing Zero-Knowledge Succinct
//     Non-interactive ARgument of Knowledge"
//
// References:
//
// \[BCTV14]:
// "Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture",
// Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, Madars Virza,
// USENIX Security 2014,
// <http://eprint.iacr.org/2013/879>
//
// \[GM17]:
// "Snarky Signatures: Minimal Signatures of Knowledge from
//  Simulation-Extractable SNARKs",
// Jens Groth and Mary Maller,
// IACR-CRYPTO-2017,
// <https://eprint.iacr.org/2017/540>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_SE_PPZKSNARK_HPP
#define CRYPTO3_R1CS_SE_PPZKSNARK_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark_params.hpp>

//#include <nil/crypto3/algebra/multiexp/multiexp.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_sap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Proving key ********************************/

                /**
                 * A proving key for the R1CS SEppzkSNARK.
                 */
                template<typename CurveType>
                struct r1cs_se_ppzksnark_proving_key {
                    // G^{gamma * A_i(t)} for 0 <= i <= sap.num_variables()
                    typename CurveType::g1_vector A_query;

                    // H^{gamma * A_i(t)} for 0 <= i <= sap.num_variables()
                    typename CurveType::g2_vector B_query;

                    // G^{gamma^2 * C_i(t) + (alpha + beta) * gamma * A_i(t)}
                    // for sap.num_inputs() + 1 < i <= sap.num_variables()
                    typename CurveType::g1_vector C_query_1;

                    // G^{2 * gamma^2 * Z(t) * A_i(t)} for 0 <= i <= sap.num_variables()
                    typename CurveType::g1_vector C_query_2;

                    // G^{gamma * Z(t)}
                    typename CurveType::g1_type G_gamma_Z;

                    // H^{gamma * Z(t)}
                    typename CurveType::g2_type H_gamma_Z;

                    // G^{(alpha + beta) * gamma * Z(t)}
                    typename CurveType::g1_type G_ab_gamma_Z;

                    // G^{gamma^2 * Z(t)^2}
                    typename CurveType::g1_type G_gamma2_Z2;

                    // G^{gamma^2 * Z(t) * t^i} for 0 <= i < sap.degree
                    typename CurveType::g1_vector G_gamma2_Z_t;

                    r1cs_se_ppzksnark_constraint_system<CurveType> constraint_system;

                    r1cs_se_ppzksnark_proving_key() {};
                    r1cs_se_ppzksnark_proving_key<CurveType> &
                        operator=(const r1cs_se_ppzksnark_proving_key<CurveType> &other) = default;
                    r1cs_se_ppzksnark_proving_key(const r1cs_se_ppzksnark_proving_key<CurveType> &other) = default;
                    r1cs_se_ppzksnark_proving_key(r1cs_se_ppzksnark_proving_key<CurveType> &&other) = default;
                    r1cs_se_ppzksnark_proving_key(typename CurveType::g1_vector &&A_query,
                                                  typename CurveType::g2_vector &&B_query,
                                                  typename CurveType::g1_vector &&C_query_1,
                                                  typename CurveType::g1_vector &&C_query_2,
                                                  typename CurveType::g1_type &G_gamma_Z,
                                                  typename CurveType::g2_type &H_gamma_Z,
                                                  typename CurveType::g1_type &G_ab_gamma_Z,
                                                  typename CurveType::g1_type &G_gamma2_Z2,
                                                  typename CurveType::g1_vector &&G_gamma2_Z_t,
                                                  r1cs_se_ppzksnark_constraint_system<CurveType> &&constraint_system) :
                        A_query(std::move(A_query)),
                        B_query(std::move(B_query)), C_query_1(std::move(C_query_1)), C_query_2(std::move(C_query_2)),
                        G_gamma_Z(G_gamma_Z), H_gamma_Z(H_gamma_Z), G_ab_gamma_Z(G_ab_gamma_Z),
                        G_gamma2_Z2(G_gamma2_Z2), G_gamma2_Z_t(std::move(G_gamma2_Z_t)),
                        constraint_system(std::move(constraint_system)) {};

                    std::size_t G1_size() const {
                        return A_query.size() + C_query_1.size() + C_query_2.size() + 3 + G_gamma2_Z_t.size();
                    }

                    std::size_t G2_size() const {
                        return B_query.size() + 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * CurveType::g1_type::value_bits +
                               G2_size() * CurveType::g2_type::value_bits;
                    }

                    bool operator==(const r1cs_se_ppzksnark_proving_key<CurveType> &other) const;
                };

                /******************************* Verification key ****************************/

                /**
                 * A verification key for the R1CS SEppzkSNARK.
                 */
                template<typename CurveType>
                struct r1cs_se_ppzksnark_verification_key {
                    // H
                    typename CurveType::g2_type H;

                    // G^{alpha}
                    typename CurveType::g1_type G_alpha;

                    // H^{beta}
                    typename CurveType::g2_type H_beta;

                    // G^{gamma}
                    typename CurveType::g1_type G_gamma;

                    // H^{gamma}
                    typename CurveType::g2_type H_gamma;

                    // G^{gamma * A_i(t) + (alpha + beta) * A_i(t)}
                    // for 0 <= i <= sap.num_inputs()
                    typename CurveType::g1_vector query;

                    r1cs_se_ppzksnark_verification_key() = default;
                    r1cs_se_ppzksnark_verification_key(const typename CurveType::g2_type &H,
                                                       const typename CurveType::g1_type &G_alpha,
                                                       const typename CurveType::g2_type &H_beta,
                                                       const typename CurveType::g1_type &G_gamma,
                                                       const typename CurveType::g2_type &H_gamma,
                                                       typename CurveType::g1_vector &&query) :
                        H(H),
                        G_alpha(G_alpha), H_beta(H_beta), G_gamma(G_gamma), H_gamma(H_gamma),
                        query(std::move(query)) {};

                    std::size_t G1_size() const {
                        return 2 + query.size();
                    }

                    std::size_t G2_size() const {
                        return 3;
                    }

                    std::size_t size_in_bits() const {
                        return (G1_size() * CurveType::g1_type::value_bits +
                                G2_size() * CurveType::g2_type::value_bits);
                    }

                    bool operator==(const r1cs_se_ppzksnark_verification_key<CurveType> &other) const;

                    static r1cs_se_ppzksnark_verification_key<CurveType> dummy_verification_key(const std::size_t input_size);
                };

                /************************ Processed verification key *************************/

                /**
                 * A processed verification key for the R1CS SEppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename CurveType>
                struct r1cs_se_ppzksnark_processed_verification_key {
                    typename CurveType::g1_type G_alpha;
                    typename CurveType::g2_type H_beta;
                    algebra::Fqk<CurveType> G_alpha_H_beta_ml;
                    algebra::G1_precomp<CurveType> G_gamma_pc;
                    algebra::G2_precomp<CurveType> H_gamma_pc;
                    algebra::G2_precomp<CurveType> H_pc;

                    typename CurveType::g1_vector query;

                    bool operator==(const r1cs_se_ppzksnark_processed_verification_key &other) const;
                };

                /********************************** Key pair *********************************/

                /**
                 * A key pair for the R1CS SEppzkSNARK, which consists of a proving key and a verification key.
                 */
                template<typename CurveType>
                class r1cs_se_ppzksnark_keypair {
                public:
                    r1cs_se_ppzksnark_proving_key<CurveType> pk;
                    r1cs_se_ppzksnark_verification_key<CurveType> vk;

                    r1cs_se_ppzksnark_keypair() = default;
                    r1cs_se_ppzksnark_keypair(const r1cs_se_ppzksnark_keypair<CurveType> &other) = default;
                    r1cs_se_ppzksnark_keypair(r1cs_se_ppzksnark_proving_key<CurveType> &&pk,
                                              r1cs_se_ppzksnark_verification_key<CurveType> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {
                    }

                    r1cs_se_ppzksnark_keypair(r1cs_se_ppzksnark_keypair<CurveType> &&other) = default;
                };

                /*********************************** Proof ***********************************/

                /**
                 * A proof for the R1CS SEppzkSNARK.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for statistics purposes.
                 */
                template<typename CurveType>
                struct r1cs_se_ppzksnark_proof {
                    typename CurveType::g1_type A;
                    typename CurveType::g2_type B;
                    typename CurveType::g1_type C;

                    r1cs_se_ppzksnark_proof() {
                    }
                    r1cs_se_ppzksnark_proof(typename CurveType::g1_type &&A, typename CurveType::g2_type &&B, typename CurveType::g1_type &&C) :
                        A(std::move(A)), B(std::move(B)), C(std::move(C)) {};

                    std::size_t G1_size() const {
                        return 2;
                    }

                    std::size_t G2_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * CurveType::g1_type::value_bits +
                               G2_size() * CurveType::g2_type::value_bits;
                    }

                    bool is_well_formed() const {
                        return (A.is_well_formed() && B.is_well_formed() && C.is_well_formed());
                    }

                    bool operator==(const r1cs_se_ppzksnark_proof<CurveType> &other) const;
                };

                /***************************** Main algorithms *******************************/

                /**
                 * A generator algorithm for the R1CS SEppzkSNARK.
                 *
                 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
                 */
                template<typename CurveType>
                r1cs_se_ppzksnark_keypair<CurveType>
                    r1cs_se_ppzksnark_generator(const r1cs_se_ppzksnark_constraint_system<CurveType> &cs);

                /**
                 * A prover algorithm for the R1CS SEppzkSNARK.
                 *
                 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                 */
                template<typename CurveType>
                r1cs_se_ppzksnark_proof<CurveType>
                    r1cs_se_ppzksnark_prover(const r1cs_se_ppzksnark_proving_key<CurveType> &pk,
                                             const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                             const r1cs_se_ppzksnark_auxiliary_input<CurveType> &auxiliary_input);

                /*
                 Below are four variants of verifier algorithm for the R1CS SEppzkSNARK.

                 These are the four cases that arise from the following two choices:

                 (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
                     In the latter case, we call the algorithm an "online verifier".

                 (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                     Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                     weak input consistency requires that |primary_input| <= CS.num_inputs (and
                     the primary input is implicitly padded with zeros up to length CS.num_inputs).
                 */

                /**
                 * A verifier algorithm for the R1CS SEppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename CurveType>
                bool r1cs_se_ppzksnark_verifier_weak_IC(const r1cs_se_ppzksnark_verification_key<CurveType> &vk,
                                                        const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                                        const r1cs_se_ppzksnark_proof<CurveType> &proof);

                /**
                 * A verifier algorithm for the R1CS SEppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename CurveType>
                bool r1cs_se_ppzksnark_verifier_strong_IC(const r1cs_se_ppzksnark_verification_key<CurveType> &vk,
                                                          const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                                          const r1cs_se_ppzksnark_proof<CurveType> &proof);

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename CurveType>
                r1cs_se_ppzksnark_processed_verification_key<CurveType>
                    r1cs_se_ppzksnark_verifier_process_vk(const r1cs_se_ppzksnark_verification_key<CurveType> &vk);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename CurveType>
                bool r1cs_se_ppzksnark_online_verifier_weak_IC(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk,
                    const r1cs_se_ppzksnark_primary_input<CurveType> &input,
                    const r1cs_se_ppzksnark_proof<CurveType> &proof);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename CurveType>
                bool r1cs_se_ppzksnark_online_verifier_strong_IC(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk,
                    const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                    const r1cs_se_ppzksnark_proof<CurveType> &proof);

                template<typename CurveType>
                bool r1cs_se_ppzksnark_proving_key<CurveType>::operator==(
                    const r1cs_se_ppzksnark_proving_key<CurveType> &other) const {
                    return (this->A_query == other.A_query && this->B_query == other.B_query &&
                            this->C_query_1 == other.C_query_1 && this->C_query_2 == other.C_query_2 &&
                            this->G_gamma_Z == other.G_gamma_Z && this->H_gamma_Z == other.H_gamma_Z &&
                            this->G_ab_gamma_Z == other.G_ab_gamma_Z && this->G_gamma2_Z2 == other.G_gamma2_Z2 &&
                            this->G_gamma2_Z_t == other.G_gamma2_Z_t &&
                            this->constraint_system == other.constraint_system);
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_verification_key<CurveType>::operator==(
                    const r1cs_se_ppzksnark_verification_key<CurveType> &other) const {
                    return (this->H == other.H && this->G_alpha == other.G_alpha && this->H_beta == other.H_beta &&
                            this->G_gamma == other.G_gamma && this->H_gamma == other.H_gamma &&
                            this->query == other.query);
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_processed_verification_key<CurveType>::operator==(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &other) const {
                    return (this->G_alpha == other.G_alpha && this->H_beta == other.H_beta &&
                            this->G_alpha_H_beta_ml == other.G_alpha_H_beta_ml &&
                            this->G_gamma_pc == other.G_gamma_pc && this->H_gamma_pc == other.H_gamma_pc &&
                            this->H_pc == other.H_pc && this->query == other.query);
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_proof<CurveType>::operator==(const r1cs_se_ppzksnark_proof<CurveType> &other) const {
                    return (this->A == other.A && this->B == other.B && this->C == other.C);
                }

                template<typename CurveType>
                r1cs_se_ppzksnark_verification_key<CurveType>
                    r1cs_se_ppzksnark_verification_key<CurveType>::dummy_verification_key(const std::size_t input_size) {
                    r1cs_se_ppzksnark_verification_key<CurveType> result;
                    result.H = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.G_alpha = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g1_type::one();
                    result.H_beta = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.G_gamma = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g1_type::one();
                    result.H_gamma = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();

                    typename CurveType::g1_vector v;
                    for (std::size_t i = 0; i < input_size + 1; ++i) {
                        v.emplace_back(random_element<typename CurveType::scalar_field_type>() * typename CurveType::g1_type::one());
                    }
                    result.query = std::move(v);

                    return result;
                }

                template<typename CurveType>
                r1cs_se_ppzksnark_keypair<CurveType>
                    r1cs_se_ppzksnark_generator(const r1cs_se_ppzksnark_constraint_system<CurveType> &cs) {

                    /**
                     * draw random element t at which the SAP is evaluated.
                     * it should be the case that Z(t) != 0
                     */
                    const std::shared_ptr<fft::evaluation_domain<typename CurveType::scalar_field_type>> domain =
                        r1cs_to_sap_get_domain(cs);
                    typename CurveType::scalar_field_type t;
                    do {
                        t = random_element<typename CurveType::scalar_field_type>();
                    } while (domain->compute_vanishing_polynomial(t).is_zero());

                    sap_instance_evaluation<typename CurveType::scalar_field_type> sap_inst =
                        r1cs_to_sap_instance_map_with_evaluation(cs, t);

                    std::size_t non_zero_At = 0;
                    for (std::size_t i = 0; i < sap_inst.num_variables() + 1; ++i) {
                        if (!sap_inst.At[i].is_zero()) {
                            ++non_zero_At;
                        }
                    }

                    std::vector<typename CurveType::scalar_field_type::value_type> At = std::move(sap_inst.At);
                    std::vector<typename CurveType::scalar_field_type::value_type> Ct = std::move(sap_inst.Ct);
                    std::vector<typename CurveType::scalar_field_type::value_type> Ht = std::move(sap_inst.Ht);
                    /**
                     * sap_inst.{A,C,H}t are now in an unspecified state,
                     * but we do not use them below
                     */

                    const typename CurveType::scalar_field_type alpha = random_element<typename CurveType::scalar_field_type>(),
                                           beta = random_element<typename CurveType::scalar_field_type>(),
                                           gamma = random_element<typename CurveType::scalar_field_type>();
                    const typename CurveType::g1_type G = random_element<typename CurveType::g1_type>();
                    const typename CurveType::g2_type H = random_element<typename CurveType::g2_type>();

                    std::size_t G_exp_count = sap_inst.num_inputs() + 1    // verifier_query
                                         + non_zero_At                // A_query
                                         + sap_inst.degree() +
                                         1    // G_gamma2_Z_t
                                         // C_query_1
                                         + sap_inst.num_variables() - sap_inst.num_inputs() + sap_inst.num_variables() +
                                         1,    // C_query_2
                        G_window = algebra::get_exp_window_size<typename CurveType::g1_type>(G_exp_count);

                    algebra::window_table<typename CurveType::g1_type> G_table =
                        get_window_table(typename CurveType::scalar_field_type::value_bits, G_window, G);

                    typename CurveType::g2_type H_gamma = gamma * H;
                    std::size_t H_gamma_exp_count = non_zero_At,    // B_query
                        H_gamma_window = algebra::get_exp_window_size<typename CurveType::g2_type>(H_gamma_exp_count);
                    algebra::window_table<typename CurveType::g2_type> H_gamma_table =
                        get_window_table(typename CurveType::scalar_field_type::value_bits, H_gamma_window, H_gamma);

                    typename CurveType::g1_type G_alpha = alpha * G;
                    typename CurveType::g2_type H_beta = beta * H;

                    std::vector<typename CurveType::scalar_field_type::value_type> tmp_exponents;
                    tmp_exponents.reserve(sap_inst.num_inputs() + 1);
                    for (std::size_t i = 0; i <= sap_inst.num_inputs(); ++i) {
                        tmp_exponents.emplace_back(gamma * Ct[i] + (alpha + beta) * At[i]);
                    }
                    typename CurveType::g1_vector verifier_query = algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();

                    tmp_exponents.reserve(sap_inst.num_variables() + 1);
                    for (std::size_t i = 0; i < At.size(); i++) {
                        tmp_exponents.emplace_back(gamma * At[i]);
                    }

                    typename CurveType::g1_vector A_query = algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(A_query);
#endif
                    typename CurveType::g2_vector B_query = algebra::batch_exp<typename CurveType::g2_type, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::value_bits, H_gamma_window, H_gamma_table, At);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g2_type>(B_query);
#endif
                    typename CurveType::g1_type G_gamma = gamma * G;
                    typename CurveType::g1_type G_gamma_Z = sap_inst.Zt * G_gamma;
                    typename CurveType::g2_type H_gamma_Z = sap_inst.Zt * H_gamma;
                    typename CurveType::g1_type G_ab_gamma_Z = (alpha + beta) * G_gamma_Z;
                    typename CurveType::g1_type G_gamma2_Z2 = (sap_inst.Zt * gamma) * G_gamma_Z;

                    tmp_exponents.reserve(sap_inst.degree() + 1);

                    /* Compute the vector G_gamma2_Z_t := Z(t) * t^i * gamma^2 * G */
                    typename CurveType::scalar_field_type gamma2_Z_t = sap_inst.Zt * gamma.squared();
                    for (std::size_t i = 0; i < sap_inst.degree() + 1; ++i) {
                        tmp_exponents.emplace_back(gamma2_Z_t);
                        gamma2_Z_t *= t;
                    }
                    typename CurveType::g1_vector G_gamma2_Z_t = algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(G_gamma2_Z_t);
#endif
                    tmp_exponents.reserve(sap_inst.num_variables() - sap_inst.num_inputs());
                    for (std::size_t i = sap_inst.num_inputs() + 1; i <= sap_inst.num_variables(); ++i) {
                        tmp_exponents.emplace_back(gamma * (gamma * Ct[i] + (alpha + beta) * At[i]));
                    }
                    typename CurveType::g1_vector C_query_1 = algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(C_query_1);
#endif

                    tmp_exponents.reserve(sap_inst.num_variables() + 1);
                    typename CurveType::scalar_field_type double_gamma2_Z = gamma * gamma * sap_inst.Zt;
                    double_gamma2_Z = double_gamma2_Z + double_gamma2_Z;
                    for (std::size_t i = 0; i <= sap_inst.num_variables(); ++i) {
                        tmp_exponents.emplace_back(double_gamma2_Z * At[i]);
                    }
                    typename CurveType::g1_vector C_query_2 = algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                        typename CurveType::scalar_field_type::value_bits, G_window, G_table, tmp_exponents);
                    tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(C_query_2);
#endif

                    r1cs_se_ppzksnark_verification_key<CurveType> vk = r1cs_se_ppzksnark_verification_key<CurveType>(
                        H, G_alpha, H_beta, G_gamma, H_gamma, std::move(verifier_query));

                    r1cs_se_ppzksnark_constraint_system<CurveType> cs_copy(cs);

                    r1cs_se_ppzksnark_proving_key<CurveType> pk = r1cs_se_ppzksnark_proving_key<CurveType>(
                        std::move(A_query), std::move(B_query), std::move(C_query_1), std::move(C_query_2), G_gamma_Z,
                        H_gamma_Z, G_ab_gamma_Z, G_gamma2_Z2, std::move(G_gamma2_Z_t), std::move(cs_copy));

                    pk.print_size();
                    vk.print_size();

                    return r1cs_se_ppzksnark_keypair<CurveType>(std::move(pk), std::move(vk));
                }

                template<typename CurveType>
                r1cs_se_ppzksnark_proof<CurveType>
                    r1cs_se_ppzksnark_prover(const r1cs_se_ppzksnark_proving_key<CurveType> &pk,
                                             const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                             const r1cs_se_ppzksnark_auxiliary_input<CurveType> &auxiliary_input) {

                    const typename CurveType::scalar_field_type d1 = random_element<typename CurveType::scalar_field_type>(),
                                           d2 = random_element<typename CurveType::scalar_field_type>();

                    const sap_witness<typename CurveType::scalar_field_type> sap_wit =
                        r1cs_to_sap_witness_map(pk.constraint_system, primary_input, auxiliary_input, d1, d2);

#ifdef MULTICORE
                    const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or call
                                                                    // omp_set_num_threads()
#else
                    const std::size_t chunks = 1;
#endif

                    const typename CurveType::scalar_field_type r = random_element<typename CurveType::scalar_field_type>();

                    /**
                     * compute A = G^{gamma * (\sum_{i=0}^m input_i * A_i(t) + r * Z(t))}
                     *           = \prod_{i=0}^m (G^{gamma * A_i(t)})^{input_i)
                     *             * (G^{gamma * Z(t)})^r
                     *           = \prod_{i=0}^m A_query[i]^{input_i} * G_gamma_Z^r
                     */
                    typename CurveType::g1_type A =
                        r * pk.G_gamma_Z + pk.A_query[0] +    // i = 0 is a special case because input_i = 1
                        sap_wit.d1 * pk.G_gamma_Z +           // ZK-patch
                        algebra::multi_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                            pk.A_query.begin() + 1,
                            pk.A_query.end(),
                            sap_wit.coefficients_for_ACs.begin(),
                            sap_wit.coefficients_for_ACs.end(),
                            chunks);

                    /**
                     * compute B exactly as A, except with H as the base
                     */
                    typename CurveType::g2_type B =
                        r * pk.H_gamma_Z + pk.B_query[0] +    // i = 0 is a special case because input_i = 1
                        sap_wit.d1 * pk.H_gamma_Z +           // ZK-patch
                        algebra::multi_exp<typename CurveType::g2_type, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                            pk.B_query.begin() + 1,
                            pk.B_query.end(),
                            sap_wit.coefficients_for_ACs.begin(),
                            sap_wit.coefficients_for_ACs.end(),
                            chunks);
                    /**
                     * compute C = G^{f(input) +
                     *                r^2 * gamma^2 * Z(t)^2 +
                     *                r * (alpha + beta) * gamma * Z(t) +
                     *                2 * r * gamma^2 * Z(t) * \sum_{i=0}^m input_i A_i(t) +
                     *                gamma^2 * Z(t) * H(t)}
                     * where G^{f(input)} = \prod_{i=l+1}^m C_query_1 * input_i
                     * and G^{2 * r * gamma^2 * Z(t) * \sum_{i=0}^m input_i A_i(t)} =
                     *              = \prod_{i=0}^m C_query_2 * input_i
                     */
                    typename CurveType::g1_type C =
                        algebra::multi_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                            pk.C_query_1.begin(),
                            pk.C_query_1.end(),
                            sap_wit.coefficients_for_ACs.begin() + sap_wit.num_inputs(),
                            sap_wit.coefficients_for_ACs.end(),
                            chunks) +
                        (r * r) * pk.G_gamma2_Z2 + r * pk.G_ab_gamma_Z + sap_wit.d1 * pk.G_ab_gamma_Z +    // ZK-patch
                        r * pk.C_query_2[0] +                      // i = 0 is a special case for C_query_2
                        (r + r) * sap_wit.d1 * pk.G_gamma2_Z2 +    // ZK-patch for C_query_2
                        r * algebra::multi_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                                pk.C_query_2.begin() + 1,
                                pk.C_query_2.end(),
                                sap_wit.coefficients_for_ACs.begin(),
                                sap_wit.coefficients_for_ACs.end(),
                                chunks) +
                        sap_wit.d2 * pk.G_gamma2_Z_t[0] +    // ZK-patch
                        algebra::multi_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                            pk.G_gamma2_Z_t.begin(),
                            pk.G_gamma2_Z_t.end(),
                            sap_wit.coefficients_for_H.begin(),
                            sap_wit.coefficients_for_H.end(),
                            chunks);

                    r1cs_se_ppzksnark_proof<CurveType> proof =
                        r1cs_se_ppzksnark_proof<CurveType>(std::move(A), std::move(B), std::move(C));
                    proof.print_size();

                    return proof;
                }

                template<typename CurveType>
                r1cs_se_ppzksnark_processed_verification_key<CurveType>
                    r1cs_se_ppzksnark_verifier_process_vk(const r1cs_se_ppzksnark_verification_key<CurveType> &vk) {

                    algebra::G1_precomp<CurveType> G_alpha_pc = CurveType::precompute_g1(vk.G_alpha);
                    algebra::G2_precomp<CurveType> H_beta_pc = CurveType::precompute_g2(vk.H_beta);

                    r1cs_se_ppzksnark_processed_verification_key<CurveType> pvk;
                    pvk.G_alpha = vk.G_alpha;
                    pvk.H_beta = vk.H_beta;
                    pvk.G_alpha_H_beta_ml = miller_loop<CurveType>(G_alpha_pc, H_beta_pc);
                    pvk.G_gamma_pc = CurveType::precompute_g1(vk.G_gamma);
                    pvk.H_gamma_pc = CurveType::precompute_g2(vk.H_gamma);
                    pvk.H_pc = CurveType::precompute_g2(vk.H);

                    pvk.query = vk.query;

                    return pvk;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_online_verifier_weak_IC(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk,
                    const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                    const r1cs_se_ppzksnark_proof<CurveType> &proof) {

                    bool result = true;

                    if (!proof.is_well_formed()) {
                        result = false;
                    }

#ifdef MULTICORE
                    const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or call
                                                                    // omp_set_num_threads()
#else
                    const std::size_t chunks = 1;
#endif

                    /**
                     * e(A*G^{alpha}, B*H^{beta}) = e(G^{alpha}, H^{beta}) * e(G^{psi}, H^{gamma})
                     *                              * e(C, H)
                     * where psi = \sum_{i=0}^l input_i pvk.query[i]
                     */
                    typename CurveType::g1_type G_psi =
                        pvk.query[0] +
                        algebra::multi_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type, algebra::multi_exp_method_bos_coster>(
                            pvk.query.begin() + 1, pvk.query.end(), primary_input.begin(), primary_input.end(), chunks);

                    algebra::Fqk<CurveType> test1_l = miller_loop<CurveType>(CurveType::precompute_g1(proof.A + pvk.G_alpha),
                                                                 CurveType::precompute_g2(proof.B + pvk.H_beta)),
                                      test1_r1 = pvk.G_alpha_H_beta_ml,
                                      test1_r2 = miller_loop<CurveType>(CurveType::precompute_g1(G_psi), pvk.H_gamma_pc),
                                      test1_r3 = miller_loop<CurveType>(CurveType::precompute_g1(proof.C), pvk.H_pc);
                    typename CurveType::gt_type test1 =
                        final_exponentiation<CurveType>(test1_l.unitary_inversed() * test1_r1 * test1_r2 * test1_r3);

                    if (test1 != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    /**
                     * e(A, H^{gamma}) = e(G^{gamma}, B)
                     */
                    algebra::Fqk<CurveType> test2_l = miller_loop<CurveType>(CurveType::precompute_g1(proof.A), pvk.H_gamma_pc),
                                      test2_r = miller_loop<CurveType>(pvk.G_gamma_pc, CurveType::precompute_g2(proof.B));
                    typename CurveType::gt_type test2 = final_exponentiation<CurveType>(test2_l * test2_r.unitary_inversed());

                    if (test2 != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    return result;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_verifier_weak_IC(const r1cs_se_ppzksnark_verification_key<CurveType> &vk,
                                                        const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                                        const r1cs_se_ppzksnark_proof<CurveType> &proof) {
                    r1cs_se_ppzksnark_processed_verification_key<CurveType> pvk =
                        r1cs_se_ppzksnark_verifier_process_vk<CurveType>(vk);
                    bool result = r1cs_se_ppzksnark_online_verifier_weak_IC<CurveType>(pvk, primary_input, proof);
                    return result;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_online_verifier_strong_IC(
                    const r1cs_se_ppzksnark_processed_verification_key<CurveType> &pvk,
                    const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                    const r1cs_se_ppzksnark_proof<CurveType> &proof) {
                    bool result = true;

                    if (pvk.query.size() != primary_input.size() + 1) {
                        result = false;
                    } else {
                        result = r1cs_se_ppzksnark_online_verifier_weak_IC(pvk, primary_input, proof);
                    }

                    return result;
                }

                template<typename CurveType>
                bool r1cs_se_ppzksnark_verifier_strong_IC(const r1cs_se_ppzksnark_verification_key<CurveType> &vk,
                                                          const r1cs_se_ppzksnark_primary_input<CurveType> &primary_input,
                                                          const r1cs_se_ppzksnark_proof<CurveType> &proof) {
                    r1cs_se_ppzksnark_processed_verification_key<CurveType> pvk =
                        r1cs_se_ppzksnark_verifier_process_vk<CurveType>(vk);
                    bool result = r1cs_se_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, primary_input, proof);
                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_SE_PPZKSNARK_HPP

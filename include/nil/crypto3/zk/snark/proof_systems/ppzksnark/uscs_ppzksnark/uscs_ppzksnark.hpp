//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
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

#ifndef CRYPTO3_USCS_PPZKSNARK_HPP
#define CRYPTO3_USCS_PPZKSNARK_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs/uscs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark/uscs_ppzksnark_params.hpp>

//#include <nil/crypto3/algebra/multiexp/multiexp.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/reductions/uscs_to_ssp/uscs_to_ssp.hpp>
#include <nil/crypto3/zk/snark/relations/arithmetic_programs/ssp/ssp.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /******************************** Proving key ********************************/

                /**
                 * A proving key for the USCS ppzkSNARK.
                 */
                template<typename CurveType>
                class uscs_ppzksnark_proving_key {
                public:
                    typename CurveType::g1_vector V_g1_query;
                    typename CurveType::g1_vector alpha_V_g1_query;
                    typename CurveType::g1_vector H_g1_query;
                    typename CurveType::g2_vector V_g2_query;

                    uscs_ppzksnark_constraint_system<CurveType> constraint_system;

                    uscs_ppzksnark_proving_key() {};
                    uscs_ppzksnark_proving_key<CurveType> &operator=(const uscs_ppzksnark_proving_key<CurveType> &other) = default;
                    uscs_ppzksnark_proving_key(const uscs_ppzksnark_proving_key<CurveType> &other) = default;
                    uscs_ppzksnark_proving_key(uscs_ppzksnark_proving_key<CurveType> &&other) = default;
                    uscs_ppzksnark_proving_key(typename CurveType::g1_vector &&V_g1_query,
                                               typename CurveType::g1_vector &&alpha_V_g1_query,
                                               typename CurveType::g1_vector &&H_g1_query,
                                               typename CurveType::g2_vector &&V_g2_query,
                                               uscs_ppzksnark_constraint_system<CurveType> &&constraint_system) :
                        V_g1_query(std::move(V_g1_query)),
                        alpha_V_g1_query(std::move(alpha_V_g1_query)), H_g1_query(std::move(H_g1_query)),
                        V_g2_query(std::move(V_g2_query)), constraint_system(std::move(constraint_system)) {};

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
                        return CurveType::g1_type::size_in_bits * G1_size() +
                               CurveType::g2_type::size_in_bits * G2_size();
                    }

                    bool operator==(const uscs_ppzksnark_proving_key<CurveType> &other) const;
                };

                /******************************* Verification key ****************************/

                /**
                 * A verification key for the USCS ppzkSNARK.
                 */
                template<typename CurveType>
                class uscs_ppzksnark_verification_key {
                public:
                    typename CurveType::g2_type tilde_g2;
                    typename CurveType::g2_type alpha_tilde_g2;
                    typename CurveType::g2_type Z_g2;

                    accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                    uscs_ppzksnark_verification_key() = default;
                    uscs_ppzksnark_verification_key(const typename CurveType::g2_type &tilde_g2,
                                                    const typename CurveType::g2_type &alpha_tilde_g2,
                                                    const typename CurveType::g2_type &Z_g2,
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
                        return encoded_IC_query.size_in_bits() + 3 * CurveType::g2_type::size_in_bits;
                    }

                    bool operator==(const uscs_ppzksnark_verification_key<CurveType> &other) const;

                    static uscs_ppzksnark_verification_key<CurveType> dummy_verification_key(const std::size_t input_size);
                };

                /************************ Processed verification key *************************/

                /**
                 * A processed verification key for the USCS ppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename CurveType>
                class uscs_ppzksnark_processed_verification_key {
                public:
                    algebra::G1_precomp<CurveType> pp_G1_one_precomp;
                    algebra::G2_precomp<CurveType> pp_G2_one_precomp;
                    algebra::G2_precomp<CurveType> vk_tilde_g2_precomp;
                    algebra::G2_precomp<CurveType> vk_alpha_tilde_g2_precomp;
                    algebra::G2_precomp<CurveType> vk_Z_g2_precomp;
                    typename CurveType::gt_type pairing_of_g1_and_g2;

                    accumulation_vector<typename CurveType::g1_type> encoded_IC_query;

                    bool operator==(const uscs_ppzksnark_processed_verification_key &other) const;
                };

                /********************************** Key pair *********************************/

                /**
                 * A key pair for the USCS ppzkSNARK, which consists of a proving key and a verification key.
                 */
                template<typename CurveType>
                class uscs_ppzksnark_keypair {
                public:
                    uscs_ppzksnark_proving_key<CurveType> pk;
                    uscs_ppzksnark_verification_key<CurveType> vk;

                    uscs_ppzksnark_keypair() {};
                    uscs_ppzksnark_keypair(uscs_ppzksnark_proving_key<CurveType> &&pk,
                                           uscs_ppzksnark_verification_key<CurveType> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {
                    }

                    uscs_ppzksnark_keypair(uscs_ppzksnark_keypair<CurveType> &&other) = default;
                };

                /*********************************** Proof ***********************************/

                /**
                 * A proof for the USCS ppzkSNARK.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for statistics purposes.
                 */
                template<typename CurveType>
                class uscs_ppzksnark_proof {
                public:
                    typename CurveType::g1_type V_g1;
                    typename CurveType::g1_type alpha_V_g1;
                    typename CurveType::g1_type H_g1;
                    typename CurveType::g2_type V_g2;

                    uscs_ppzksnark_proof() {
                        // invalid proof with valid curve points
                        this->V_g1 = typename CurveType::g1_type::one();
                        this->alpha_V_g1 = typename CurveType::g1_type::one();
                        this->H_g1 = typename CurveType::g1_type::one();
                        this->V_g2 = typename CurveType::g2_type::one();
                    }
                    uscs_ppzksnark_proof(typename CurveType::g1_type &&V_g1,
                                         typename CurveType::g1_type &&alpha_V_g1,
                                         typename CurveType::g1_type &&H_g1,
                                         typename CurveType::g2_type &&V_g2) :
                        V_g1(std::move(V_g1)),
                        alpha_V_g1(std::move(alpha_V_g1)), H_g1(std::move(H_g1)), V_g2(std::move(V_g2)) {};

                    std::size_t G1_size() const {
                        return 3;
                    }

                    std::size_t G2_size() const {
                        return 1;
                    }

                    std::size_t size_in_bits() const {
                        return G1_size() * CurveType::g1_type::size_in_bits +
                               G2_size() * CurveType::g2_type::size_in_bits;
                    }

                    bool is_well_formed() const {
                        return (V_g1.is_well_formed() && alpha_V_g1.is_well_formed() && H_g1.is_well_formed() &&
                                V_g2.is_well_formed());
                    }

                    bool operator==(const uscs_ppzksnark_proof<CurveType> &other) const;
                };

                /***************************** Main algorithms *******************************/

                /**
                 * A generator algorithm for the USCS ppzkSNARK.
                 *
                 * Given a USCS constraint system CS, this algorithm produces proving and verification keys for CS.
                 */
                template<typename CurveType>
                uscs_ppzksnark_keypair<CurveType> uscs_ppzksnark_generator(const uscs_ppzksnark_constraint_system<CurveType> &cs);

                /**
                 * A prover algorithm for the USCS ppzkSNARK.
                 *
                 * Given a USCS primary input X and a USCS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the USCS constraint system that was given as input to the generator algorithm.
                 */
                template<typename CurveType>
                uscs_ppzksnark_proof<CurveType>
                    uscs_ppzksnark_prover(const uscs_ppzksnark_proving_key<CurveType> &pk,
                                          const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                          const uscs_ppzksnark_auxiliary_input<CurveType> &auxiliary_input);

                /*
                 Below are four variants of verifier algorithm for the USCS ppzkSNARK.

                 These are the four cases that arise from the following two choices:

                 (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
                     In the latter case, we call the algorithm an "online verifier".

                 (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                     Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                     weak input consistency requires that |primary_input| <= CS.num_inputs (and
                     the primary input is implicitly padded with zeros up to length CS.num_inputs).
                 */

                /**
                 * A verifier algorithm for the USCS ppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename CurveType>
                bool uscs_ppzksnark_verifier_weak_IC(const uscs_ppzksnark_verification_key<CurveType> &vk,
                                                     const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                                     const uscs_ppzksnark_proof<CurveType> &proof);

                /**
                 * A verifier algorithm for the USCS ppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename CurveType>
                bool uscs_ppzksnark_verifier_strong_IC(const uscs_ppzksnark_verification_key<CurveType> &vk,
                                                       const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                                       const uscs_ppzksnark_proof<CurveType> &proof);

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename CurveType>
                uscs_ppzksnark_processed_verification_key<CurveType>
                    uscs_ppzksnark_verifier_process_vk(const uscs_ppzksnark_verification_key<CurveType> &vk);

                /**
                 * A verifier algorithm for the USCS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename CurveType>
                bool uscs_ppzksnark_online_verifier_weak_IC(const uscs_ppzksnark_processed_verification_key<CurveType> &pvk,
                                                            const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                                            const uscs_ppzksnark_proof<CurveType> &proof);

                /**
                 * A verifier algorithm for the USCS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename CurveType>
                bool uscs_ppzksnark_online_verifier_strong_IC(const uscs_ppzksnark_processed_verification_key<CurveType> &pvk,
                                                              const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                                              const uscs_ppzksnark_proof<CurveType> &proof);

                template<typename CurveType>
                bool uscs_ppzksnark_proving_key<CurveType>::operator==(const uscs_ppzksnark_proving_key<CurveType> &other) const {
                    return (this->V_g1_query == other.V_g1_query && this->alpha_V_g1_query == other.alpha_V_g1_query &&
                            this->H_g1_query == other.H_g1_query && this->V_g2_query == other.V_g2_query &&
                            this->constraint_system == other.constraint_system);
                }

                template<typename CurveType>
                bool uscs_ppzksnark_verification_key<CurveType>::operator==(
                    const uscs_ppzksnark_verification_key<CurveType> &other) const {
                    return (this->tilde_g2 == other.tilde_g2 && this->alpha_tilde_g2 == other.alpha_tilde_g2 &&
                            this->Z_g2 == other.Z_g2 && this->encoded_IC_query == other.encoded_IC_query);
                }

                template<typename CurveType>
                bool uscs_ppzksnark_processed_verification_key<CurveType>::operator==(
                    const uscs_ppzksnark_processed_verification_key<CurveType> &other) const {
                    return (this->pp_G1_one_precomp == other.pp_G1_one_precomp &&
                            this->pp_G2_one_precomp == other.pp_G2_one_precomp &&
                            this->vk_tilde_g2_precomp == other.vk_tilde_g2_precomp &&
                            this->vk_alpha_tilde_g2_precomp == other.vk_alpha_tilde_g2_precomp &&
                            this->vk_Z_g2_precomp == other.vk_Z_g2_precomp &&
                            this->pairing_of_g1_and_g2 == other.pairing_of_g1_and_g2 &&
                            this->encoded_IC_query == other.encoded_IC_query);
                }

                template<typename CurveType>
                bool uscs_ppzksnark_proof<CurveType>::operator==(const uscs_ppzksnark_proof<CurveType> &other) const {
                    return (this->V_g1 == other.V_g1 && this->alpha_V_g1 == other.alpha_V_g1 &&
                            this->H_g1 == other.H_g1 && this->V_g2 == other.V_g2);
                }

                template<typename CurveType>
                uscs_ppzksnark_verification_key<CurveType>
                    uscs_ppzksnark_verification_key<CurveType>::dummy_verification_key(const std::size_t input_size) {
                    uscs_ppzksnark_verification_key<CurveType> result;
                    result.tilde_g2 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.alpha_tilde_g2 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();
                    result.Z_g2 = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g2_type::one();

                    typename CurveType::g1_type base = random_element<typename CurveType::scalar_field_type>() * typename CurveType::g1_type::one();
                    typename CurveType::g1_vector v;
                    for (std::size_t i = 0; i < input_size; ++i) {
                        v.emplace_back(random_element<typename CurveType::scalar_field_type>() * typename CurveType::g1_type::one());
                    }

                    result.encoded_IC_query = accumulation_vector<typename CurveType::g1_type>(v);

                    return result;
                }

                template<typename CurveType>
                uscs_ppzksnark_keypair<CurveType> uscs_ppzksnark_generator(const uscs_ppzksnark_constraint_system<CurveType> &cs) {

                    /* draw random element at which the SSP is evaluated */

                    const typename CurveType::scalar_field_type t = random_element<typename CurveType::scalar_field_type>();

                    /* perform USCS-to-SSP reduction */

                    ssp_instance_evaluation<typename CurveType::scalar_field_type> ssp_inst =
                        uscs_to_ssp_instance_map_with_evaluation(cs, t);

                    /* construct various tables of typename FieldType::value_type elements */

                    std::vector<typename CurveType::scalar_field_type::value_type> Vt_table = std::move(
                        ssp_inst.Vt);    // ssp_inst.Vt is now in unspecified state, but we do not use it later
                    std::vector<typename CurveType::scalar_field_type::value_type> Ht_table = std::move(
                        ssp_inst.Ht);    // ssp_inst.Ht is now in unspecified state, but we do not use it later

                    Vt_table.emplace_back(ssp_inst.Zt);

                    std::vector<typename CurveType::scalar_field_type::value_type> Xt_table =
                        std::vector<typename CurveType::scalar_field_type::value_type>(Vt_table.begin(), Vt_table.begin() + ssp_inst.num_inputs() + 1);
                    std::vector<typename CurveType::scalar_field_type::value_type> Vt_table_minus_Xt_table =
                        std::vector<typename CurveType::scalar_field_type::value_type>(Vt_table.begin() + ssp_inst.num_inputs() + 1, Vt_table.end());

                    /* sanity checks */

                    assert(Vt_table.size() == ssp_inst.num_variables() + 2);
                    assert(Ht_table.size() == ssp_inst.degree() + 1);
                    assert(Xt_table.size() == ssp_inst.num_inputs() + 1);
                    assert(Vt_table_minus_Xt_table.size() == ssp_inst.num_variables() + 2 - ssp_inst.num_inputs() - 1);
                    for (std::size_t i = 0; i < ssp_inst.num_inputs() + 1; ++i) {
                        assert(!Xt_table[i].is_zero());
                    }

                    const typename CurveType::scalar_field_type alpha = random_element<typename CurveType::scalar_field_type>();

                    const std::size_t g1_exp_count = Vt_table.size() + Vt_table_minus_Xt_table.size() + Ht_table.size();
                    const std::size_t g2_exp_count = Vt_table_minus_Xt_table.size();

                    std::size_t g1_window = algebra::get_exp_window_size<typename CurveType::g1_type>(g1_exp_count);
                    std::size_t g2_window = algebra::get_exp_window_size<typename CurveType::g2_type>(g2_exp_count);

                    algebra::window_table<typename CurveType::g1_type> g1_table =
                        get_window_table(typename CurveType::scalar_field_type::size_in_bits, g1_window, typename CurveType::g1_type::one());

                    algebra::window_table<typename CurveType::g2_type> g2_table =
                        get_window_table(typename CurveType::scalar_field_type::size_in_bits, g2_window, typename CurveType::g2_type::one());

                    typename CurveType::g1_vector V_g1_query =
                        batch_exp(typename CurveType::scalar_field_type::size_in_bits, g1_window, g1_table, Vt_table_minus_Xt_table);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(V_g1_query);
#endif

                    typename CurveType::g1_vector alpha_V_g1_query = batch_exp_with_coeff(
                        typename CurveType::scalar_field_type::size_in_bits, g1_window, g1_table, alpha, Vt_table_minus_Xt_table);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(alpha_V_g1_query);
#endif

                    typename CurveType::g1_vector H_g1_query =
                        batch_exp(typename CurveType::scalar_field_type::size_in_bits, g1_window, g1_table, Ht_table);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g1_type>(H_g1_query);
#endif

                    typename CurveType::g2_vector V_g2_query =
                        batch_exp(typename CurveType::scalar_field_type::size_in_bits, g2_window, g2_table, Vt_table);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<typename CurveType::g2_type>(V_g2_query);
#endif
                    const typename CurveType::scalar_field_type tilde = random_element<typename CurveType::scalar_field_type>();
                    typename CurveType::g2_type tilde_g2 = tilde * typename CurveType::g2_type::one();
                    typename CurveType::g2_type alpha_tilde_g2 = (alpha * tilde) * typename CurveType::g2_type::one();
                    typename CurveType::g2_type Z_g2 = ssp_inst.Zt * typename CurveType::g2_type::one();

                    typename CurveType::g1_type encoded_IC_base = Xt_table[0] * typename CurveType::g1_type::one();
                    typename CurveType::g1_vector encoded_IC_values =
                        batch_exp(typename CurveType::scalar_field_type::size_in_bits, g1_window, g1_table,
                                  std::vector<typename CurveType::scalar_field_type::value_type>(Xt_table.begin() + 1, Xt_table.end()));

                    accumulation_vector<typename CurveType::g1_type> encoded_IC_query(std::move(encoded_IC_base),
                                                                           std::move(encoded_IC_values));

                    uscs_ppzksnark_verification_key<CurveType> vk =
                        uscs_ppzksnark_verification_key<CurveType>(tilde_g2, alpha_tilde_g2, Z_g2, encoded_IC_query);

                    uscs_ppzksnark_constraint_system<CurveType> cs_copy = cs;
                    uscs_ppzksnark_proving_key<CurveType> pk = uscs_ppzksnark_proving_key<CurveType>(std::move(V_g1_query),
                                                                                         std::move(alpha_V_g1_query),
                                                                                         std::move(H_g1_query),
                                                                                         std::move(V_g2_query),
                                                                                         std::move(cs_copy));

                    pk.print_size();
                    vk.print_size();

                    return uscs_ppzksnark_keypair<CurveType>(std::move(pk), std::move(vk));
                }

                template<typename CurveType>
                uscs_ppzksnark_proof<CurveType>
                    uscs_ppzksnark_prover(const uscs_ppzksnark_proving_key<CurveType> &pk,
                                          const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                          const uscs_ppzksnark_auxiliary_input<CurveType> &auxiliary_input) {

                    const typename CurveType::scalar_field_type d = random_element<typename CurveType::scalar_field_type>();

                    const ssp_witness<typename CurveType::scalar_field_type> ssp_wit =
                        uscs_to_ssp_witness_map(pk.constraint_system, primary_input, auxiliary_input, d);

                    /* sanity checks */
                    assert(pk.constraint_system.is_satisfied(primary_input, auxiliary_input));
                    assert(pk.V_g1_query.size() == ssp_wit.num_variables() + 2 - ssp_wit.num_inputs() - 1);
                    assert(pk.alpha_V_g1_query.size() == ssp_wit.num_variables() + 2 - ssp_wit.num_inputs() - 1);
                    assert(pk.H_g1_query.size() == ssp_wit.degree() + 1);
                    assert(pk.V_g2_query.size() == ssp_wit.num_variables() + 2);

                    typename CurveType::g1_type V_g1 = ssp_wit.d * pk.V_g1_query[pk.V_g1_query.size() - 1];
                    typename CurveType::g1_type alpha_V_g1 = ssp_wit.d * pk.alpha_V_g1_query[pk.alpha_V_g1_query.size() - 1];
                    typename CurveType::g1_type H_g1 = typename CurveType::g1_type::zero();
                    typename CurveType::g2_type V_g2 = pk.V_g2_query[0] + ssp_wit.d * pk.V_g2_query[pk.V_g2_query.size() - 1];

#ifdef MULTICORE
                    const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or call
                                                                    // omp_set_num_threads()
#else
                    const std::size_t chunks = 1;
#endif

                    // MAYBE LATER: do queries 1,2,4 at once for slightly better speed

                    V_g1 = V_g1 + algebra::multi_exp_with_mixed_addition<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                                         algebra::multi_exp_method_BDLO12>(
                                      pk.V_g1_query.begin(),
                                      pk.V_g1_query.begin() + (ssp_wit.num_variables() - ssp_wit.num_inputs()),
                                      ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_inputs(),
                                      ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_variables(), chunks);

                    alpha_V_g1 =
                        alpha_V_g1 + algebra::multi_exp_with_mixed_addition<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                                            algebra::multi_exp_method_BDLO12>(
                                         pk.alpha_V_g1_query.begin(),
                                         pk.alpha_V_g1_query.begin() + (ssp_wit.num_variables() - ssp_wit.num_inputs()),
                                         ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_inputs(),
                                         ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_variables(), chunks);

                    H_g1 =
                        H_g1 + algebra::multi_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                                   pk.H_g1_query.begin(), pk.H_g1_query.begin() + ssp_wit.degree() + 1,
                                   ssp_wit.coefficients_for_H.begin(),
                                   ssp_wit.coefficients_for_H.begin() + ssp_wit.degree() + 1, chunks);

                    V_g2 =
                        V_g2 + algebra::multi_exp<typename CurveType::g2_type, typename CurveType::scalar_field_type, algebra::multi_exp_method_BDLO12>(
                                   pk.V_g2_query.begin() + 1, pk.V_g2_query.begin() + ssp_wit.num_variables() + 1,
                                   ssp_wit.coefficients_for_Vs.begin(),
                                   ssp_wit.coefficients_for_Vs.begin() + ssp_wit.num_variables(), chunks);

                    uscs_ppzksnark_proof<CurveType> proof = uscs_ppzksnark_proof<CurveType>(std::move(V_g1), std::move(alpha_V_g1),
                                                                                std::move(H_g1), std::move(V_g2));

                    return proof;
                }

                template<typename CurveType>
                uscs_ppzksnark_processed_verification_key<CurveType>
                    uscs_ppzksnark_verifier_process_vk(const uscs_ppzksnark_verification_key<CurveType> &vk) {
                    uscs_ppzksnark_processed_verification_key<CurveType> pvk;

                    pvk.pp_G1_one_precomp = CurveType::precompute_g1(typename CurveType::g1_type::one());
                    pvk.pp_G2_one_precomp = CurveType::precompute_g2(typename CurveType::g2_type::one());

                    pvk.vk_tilde_g2_precomp = CurveType::precompute_g2(vk.tilde_g2);
                    pvk.vk_alpha_tilde_g2_precomp = CurveType::precompute_g2(vk.alpha_tilde_g2);
                    pvk.vk_Z_g2_precomp = CurveType::precompute_g2(vk.Z_g2);

                    pvk.pairing_of_g1_and_g2 = miller_loop<CurveType>(pvk.pp_G1_one_precomp, pvk.pp_G2_one_precomp);

                    pvk.encoded_IC_query = vk.encoded_IC_query;

                    return pvk;
                }

                template<typename CurveType>
                bool uscs_ppzksnark_online_verifier_weak_IC(const uscs_ppzksnark_processed_verification_key<CurveType> &pvk,
                                                            const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                                            const uscs_ppzksnark_proof<CurveType> &proof) {
                    assert(pvk.encoded_IC_query.domain_size() >= primary_input.size());

                    const accumulation_vector<typename CurveType::g1_type> accumulated_IC =
                        pvk.encoded_IC_query.template accumulate_chunk<typename CurveType::scalar_field_type>(primary_input.begin(),
                                                                                         primary_input.end(), 0);
                    assert(accumulated_IC.is_fully_accumulated());
                    const typename CurveType::g1_type &acc = accumulated_IC.first;

                    bool result = true;

                    if (!proof.is_well_formed()) {
                        result = false;
                    }

                    algebra::G1_precomp<CurveType> proof_V_g1_with_acc_precomp = CurveType::precompute_g1(proof.V_g1 + acc);
                    algebra::G2_precomp<CurveType> proof_V_g2_precomp = CurveType::precompute_g2(proof.V_g2);
                    algebra::Fqk<CurveType> V_1 = miller_loop<CurveType>(proof_V_g1_with_acc_precomp, pvk.pp_G2_one_precomp);
                    algebra::Fqk<CurveType> V_2 = miller_loop<CurveType>(pvk.pp_G1_one_precomp, proof_V_g2_precomp);
                    typename CurveType::gt_type V = final_exponentiation<CurveType>(V_1 * V_2.unitary_inversed());
                    if (V != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<CurveType> proof_H_g1_precomp = CurveType::precompute_g1(proof.H_g1);
                    algebra::Fqk<CurveType> SSP_1 = miller_loop<CurveType>(proof_V_g1_with_acc_precomp, proof_V_g2_precomp);
                    algebra::Fqk<CurveType> SSP_2 = miller_loop<CurveType>(proof_H_g1_precomp, pvk.vk_Z_g2_precomp);
                    typename CurveType::gt_type SSP =
                        final_exponentiation<CurveType>(SSP_1.unitary_inversed() * SSP_2 * pvk.pairing_of_g1_and_g2);
                    if (SSP != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<CurveType> proof_V_g1_precomp = CurveType::precompute_g1(proof.V_g1);
                    algebra::G1_precomp<CurveType> proof_alpha_V_g1_precomp = CurveType::precompute_g1(proof.alpha_V_g1);
                    algebra::Fqk<CurveType> alpha_V_1 = miller_loop<CurveType>(proof_V_g1_precomp, pvk.vk_alpha_tilde_g2_precomp);
                    algebra::Fqk<CurveType> alpha_V_2 = miller_loop<CurveType>(proof_alpha_V_g1_precomp, pvk.vk_tilde_g2_precomp);
                    typename CurveType::gt_type alpha_V = final_exponentiation<CurveType>(alpha_V_1 * alpha_V_2.unitary_inversed());
                    if (alpha_V != typename CurveType::gt_type::one()) {
                        result = false;
                    }

                    return result;
                }

                template<typename CurveType>
                bool uscs_ppzksnark_verifier_weak_IC(const uscs_ppzksnark_verification_key<CurveType> &vk,
                                                     const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                                     const uscs_ppzksnark_proof<CurveType> &proof) {
                    uscs_ppzksnark_processed_verification_key<CurveType> pvk = uscs_ppzksnark_verifier_process_vk<CurveType>(vk);
                    bool result = uscs_ppzksnark_online_verifier_weak_IC<CurveType>(pvk, primary_input, proof);
                    return result;
                }

                template<typename CurveType>
                bool uscs_ppzksnark_online_verifier_strong_IC(const uscs_ppzksnark_processed_verification_key<CurveType> &pvk,
                                                              const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                                              const uscs_ppzksnark_proof<CurveType> &proof) {
                    bool result = true;

                    if (pvk.encoded_IC_query.domain_size() != primary_input.size()) {
                        result = false;
                    } else {
                        result = uscs_ppzksnark_online_verifier_weak_IC(pvk, primary_input, proof);
                    }

                    return result;
                }

                template<typename CurveType>
                bool uscs_ppzksnark_verifier_strong_IC(const uscs_ppzksnark_verification_key<CurveType> &vk,
                                                       const uscs_ppzksnark_primary_input<CurveType> &primary_input,
                                                       const uscs_ppzksnark_proof<CurveType> &proof) {
                    uscs_ppzksnark_processed_verification_key<CurveType> pvk = uscs_ppzksnark_verifier_process_vk<CurveType>(vk);
                    bool result = uscs_ppzksnark_online_verifier_strong_IC<CurveType>(pvk, primary_input, proof);
                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_USCS_PPZKSNARK_HPP

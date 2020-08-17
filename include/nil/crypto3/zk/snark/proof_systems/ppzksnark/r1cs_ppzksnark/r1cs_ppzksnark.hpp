//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef R1CS_PPZKSNARK_HPP_
#define R1CS_PPZKSNARK_HPP_

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark_params.hpp>

#include <nil/algebra/scalar_multiplication/multiexp.hpp>

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

                template<typename ppT>
                class r1cs_ppzksnark_proving_key;

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzksnark_proving_key<ppT> &pk);

                template<typename ppT>
                std::istream &operator>>(std::istream &in, r1cs_ppzksnark_proving_key<ppT> &pk);

                /**
                 * A proving key for the R1CS ppzkSNARK.
                 */
                template<typename ppT>
                class r1cs_ppzksnark_proving_key {
                public:
                    knowledge_commitment_vector<algebra::G1<ppT>, algebra::G1<ppT>> A_query;
                    knowledge_commitment_vector<algebra::G2<ppT>, algebra::G1<ppT>> B_query;
                    knowledge_commitment_vector<algebra::G1<ppT>, algebra::G1<ppT>> C_query;
                    algebra::G1_vector<ppT> H_query;
                    algebra::G1_vector<ppT> K_query;

                    r1cs_ppzksnark_constraint_system<ppT> constraint_system;

                    r1cs_ppzksnark_proving_key() {};
                    r1cs_ppzksnark_proving_key<ppT> &operator=(const r1cs_ppzksnark_proving_key<ppT> &other) = default;
                    r1cs_ppzksnark_proving_key(const r1cs_ppzksnark_proving_key<ppT> &other) = default;
                    r1cs_ppzksnark_proving_key(r1cs_ppzksnark_proving_key<ppT> &&other) = default;
                    r1cs_ppzksnark_proving_key(
                        knowledge_commitment_vector<algebra::G1<ppT>, algebra::G1<ppT>> &&A_query,
                        knowledge_commitment_vector<algebra::G2<ppT>, algebra::G1<ppT>> &&B_query,
                        knowledge_commitment_vector<algebra::G1<ppT>, algebra::G1<ppT>> &&C_query,
                        algebra::G1_vector<ppT> &&H_query,
                        algebra::G1_vector<ppT> &&K_query,
                        r1cs_ppzksnark_constraint_system<ppT> &&constraint_system) :
                        A_query(std::move(A_query)),
                        B_query(std::move(B_query)), C_query(std::move(C_query)), H_query(std::move(H_query)),
                        K_query(std::move(K_query)), constraint_system(std::move(constraint_system)) {};

                    size_t G1_size() const {
                        return 2 * (A_query.domain_size() + C_query.domain_size()) + B_query.domain_size() +
                               H_query.size() + K_query.size();
                    }

                    size_t G2_size() const {
                        return B_query.domain_size();
                    }

                    size_t G1_sparse_size() const {
                        return 2 * (A_query.size() + C_query.size()) + B_query.size() + H_query.size() + K_query.size();
                    }

                    size_t G2_sparse_size() const {
                        return B_query.size();
                    }

                    size_t size_in_bits() const {
                        return A_query.size_in_bits() + B_query.size_in_bits() + C_query.size_in_bits() +
                               algebra::size_in_bits(H_query) + algebra::size_in_bits(K_query);
                    }

                    void print_size() const {
                        algebra::print_indent();
                        printf("* G1 elements in PK: %zu\n", this->G1_size());
                        algebra::print_indent();
                        printf("* Non-zero G1 elements in PK: %zu\n", this->G1_sparse_size());
                        algebra::print_indent();
                        printf("* G2 elements in PK: %zu\n", this->G2_size());
                        algebra::print_indent();
                        printf("* Non-zero G2 elements in PK: %zu\n", this->G2_sparse_size());
                        algebra::print_indent();
                        printf("* PK size in bits: %zu\n", this->size_in_bits());
                    }

                    bool operator==(const r1cs_ppzksnark_proving_key<ppT> &other) const;
                    friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_ppzksnark_proving_key<ppT> &pk);
                    friend std::istream &operator>><ppT>(std::istream &in, r1cs_ppzksnark_proving_key<ppT> &pk);
                };

                /******************************* Verification key ****************************/

                template<typename ppT>
                class r1cs_ppzksnark_verification_key;

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzksnark_verification_key<ppT> &vk);

                template<typename ppT>
                std::istream &operator>>(std::istream &in, r1cs_ppzksnark_verification_key<ppT> &vk);

                /**
                 * A verification key for the R1CS ppzkSNARK.
                 */
                template<typename ppT>
                class r1cs_ppzksnark_verification_key {
                public:
                    algebra::G2<ppT> alphaA_g2;
                    algebra::G1<ppT> alphaB_g1;
                    algebra::G2<ppT> alphaC_g2;
                    algebra::G2<ppT> gamma_g2;
                    algebra::G1<ppT> gamma_beta_g1;
                    algebra::G2<ppT> gamma_beta_g2;
                    algebra::G2<ppT> rC_Z_g2;

                    accumulation_vector<algebra::G1<ppT>> encoded_IC_query;

                    r1cs_ppzksnark_verification_key() = default;
                    r1cs_ppzksnark_verification_key(const algebra::G2<ppT> &alphaA_g2,
                                                    const algebra::G1<ppT> &alphaB_g1,
                                                    const algebra::G2<ppT> &alphaC_g2,
                                                    const algebra::G2<ppT> &gamma_g2,
                                                    const algebra::G1<ppT> &gamma_beta_g1,
                                                    const algebra::G2<ppT> &gamma_beta_g2,
                                                    const algebra::G2<ppT> &rC_Z_g2,
                                                    const accumulation_vector<algebra::G1<ppT>> &eIC) :
                        alphaA_g2(alphaA_g2),
                        alphaB_g1(alphaB_g1), alphaC_g2(alphaC_g2), gamma_g2(gamma_g2), gamma_beta_g1(gamma_beta_g1),
                        gamma_beta_g2(gamma_beta_g2), rC_Z_g2(rC_Z_g2), encoded_IC_query(eIC) {};

                    size_t G1_size() const {
                        return 2 + encoded_IC_query.size();
                    }

                    size_t G2_size() const {
                        return 5;
                    }

                    size_t size_in_bits() const {
                        return (2 * algebra::G1<ppT>::size_in_bits() + encoded_IC_query.size_in_bits() +
                                5 * algebra::G2<ppT>::size_in_bits());
                    }

                    void print_size() const {
                        algebra::print_indent();
                        printf("* G1 elements in VK: %zu\n", this->G1_size());
                        algebra::print_indent();
                        printf("* G2 elements in VK: %zu\n", this->G2_size());
                        algebra::print_indent();
                        printf("* VK size in bits: %zu\n", this->size_in_bits());
                    }

                    bool operator==(const r1cs_ppzksnark_verification_key<ppT> &other) const;
                    friend std::ostream &operator<<<ppT>(std::ostream &out,
                                                         const r1cs_ppzksnark_verification_key<ppT> &vk);
                    friend std::istream &operator>><ppT>(std::istream &in, r1cs_ppzksnark_verification_key<ppT> &vk);

                    static r1cs_ppzksnark_verification_key<ppT> dummy_verification_key(const size_t input_size);
                };

                /************************ Processed verification key *************************/

                template<typename ppT>
                class r1cs_ppzksnark_processed_verification_key;

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzksnark_processed_verification_key<ppT> &pvk);

                template<typename ppT>
                std::istream &operator>>(std::istream &in, r1cs_ppzksnark_processed_verification_key<ppT> &pvk);

                /**
                 * A processed verification key for the R1CS ppzkSNARK.
                 *
                 * Compared to a (non-processed) verification key, a processed verification key
                 * contains a small constant amount of additional pre-computed information that
                 * enables a faster verification time.
                 */
                template<typename ppT>
                class r1cs_ppzksnark_processed_verification_key {
                public:
                    algebra::G2_precomp<ppT> pp_G2_one_precomp;
                    algebra::G2_precomp<ppT> vk_alphaA_g2_precomp;
                    algebra::G1_precomp<ppT> vk_alphaB_g1_precomp;
                    algebra::G2_precomp<ppT> vk_alphaC_g2_precomp;
                    algebra::G2_precomp<ppT> vk_rC_Z_g2_precomp;
                    algebra::G2_precomp<ppT> vk_gamma_g2_precomp;
                    algebra::G1_precomp<ppT> vk_gamma_beta_g1_precomp;
                    algebra::G2_precomp<ppT> vk_gamma_beta_g2_precomp;

                    accumulation_vector<algebra::G1<ppT>> encoded_IC_query;

                    bool operator==(const r1cs_ppzksnark_processed_verification_key &other) const;
                    friend std::ostream &operator<<<ppT>(std::ostream &out,
                                                         const r1cs_ppzksnark_processed_verification_key<ppT> &pvk);
                    friend std::istream &operator>>
                        <ppT>(std::istream &in, r1cs_ppzksnark_processed_verification_key<ppT> &pvk);
                };

                /********************************** Key pair *********************************/

                /**
                 * A key pair for the R1CS ppzkSNARK, which consists of a proving key and a verification key.
                 */
                template<typename ppT>
                class r1cs_ppzksnark_keypair {
                public:
                    r1cs_ppzksnark_proving_key<ppT> pk;
                    r1cs_ppzksnark_verification_key<ppT> vk;

                    r1cs_ppzksnark_keypair() = default;
                    r1cs_ppzksnark_keypair(const r1cs_ppzksnark_keypair<ppT> &other) = default;
                    r1cs_ppzksnark_keypair(r1cs_ppzksnark_proving_key<ppT> &&pk,
                                           r1cs_ppzksnark_verification_key<ppT> &&vk) :
                        pk(std::move(pk)),
                        vk(std::move(vk)) {
                    }

                    r1cs_ppzksnark_keypair(r1cs_ppzksnark_keypair<ppT> &&other) = default;
                };

                /*********************************** Proof ***********************************/

                template<typename ppT>
                class r1cs_ppzksnark_proof;

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzksnark_proof<ppT> &proof);

                template<typename ppT>
                std::istream &operator>>(std::istream &in, r1cs_ppzksnark_proof<ppT> &proof);

                /**
                 * A proof for the R1CS ppzkSNARK.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for statistics purposes.
                 */
                template<typename ppT>
                class r1cs_ppzksnark_proof {
                public:
                    knowledge_commitment<algebra::G1<ppT>, algebra::G1<ppT>> g_A;
                    knowledge_commitment<algebra::G2<ppT>, algebra::G1<ppT>> g_B;
                    knowledge_commitment<algebra::G1<ppT>, algebra::G1<ppT>> g_C;
                    algebra::G1<ppT> g_H;
                    algebra::G1<ppT> g_K;

                    r1cs_ppzksnark_proof() {
                        // invalid proof with valid curve points
                        this->g_A.g = algebra::G1<ppT>::one();
                        this->g_A.h = algebra::G1<ppT>::one();
                        this->g_B.g = algebra::G2<ppT>::one();
                        this->g_B.h = algebra::G1<ppT>::one();
                        this->g_C.g = algebra::G1<ppT>::one();
                        this->g_C.h = algebra::G1<ppT>::one();
                        this->g_H = algebra::G1<ppT>::one();
                        this->g_K = algebra::G1<ppT>::one();
                    }
                    r1cs_ppzksnark_proof(knowledge_commitment<algebra::G1<ppT>, algebra::G1<ppT>> &&g_A,
                                         knowledge_commitment<algebra::G2<ppT>, algebra::G1<ppT>> &&g_B,
                                         knowledge_commitment<algebra::G1<ppT>, algebra::G1<ppT>> &&g_C,
                                         algebra::G1<ppT> &&g_H,
                                         algebra::G1<ppT> &&g_K) :
                        g_A(std::move(g_A)),
                        g_B(std::move(g_B)), g_C(std::move(g_C)), g_H(std::move(g_H)), g_K(std::move(g_K)) {};

                    size_t G1_size() const {
                        return 7;
                    }

                    size_t G2_size() const {
                        return 1;
                    }

                    size_t size_in_bits() const {
                        return G1_size() * algebra::G1<ppT>::size_in_bits() +
                               G2_size() * algebra::G2<ppT>::size_in_bits();
                    }

                    void print_size() const {
                        algebra::print_indent();
                        printf("* G1 elements in proof: %zu\n", this->G1_size());
                        algebra::print_indent();
                        printf("* G2 elements in proof: %zu\n", this->G2_size());
                        algebra::print_indent();
                        printf("* Proof size in bits: %zu\n", this->size_in_bits());
                    }

                    bool is_well_formed() const {
                        return (g_A.g.is_well_formed() && g_A.h.is_well_formed() && g_B.g.is_well_formed() &&
                                g_B.h.is_well_formed() && g_C.g.is_well_formed() && g_C.h.is_well_formed() &&
                                g_H.is_well_formed() && g_K.is_well_formed());
                    }

                    bool operator==(const r1cs_ppzksnark_proof<ppT> &other) const;
                    friend std::ostream &operator<<<ppT>(std::ostream &out, const r1cs_ppzksnark_proof<ppT> &proof);
                    friend std::istream &operator>><ppT>(std::istream &in, r1cs_ppzksnark_proof<ppT> &proof);
                };

                /***************************** Main algorithms *******************************/

                /**
                 * A generator algorithm for the R1CS ppzkSNARK.
                 *
                 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
                 */
                template<typename ppT>
                r1cs_ppzksnark_keypair<ppT> r1cs_ppzksnark_generator(const r1cs_ppzksnark_constraint_system<ppT> &cs);

                /**
                 * A prover algorithm for the R1CS ppzkSNARK.
                 *
                 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                 */
                template<typename ppT>
                r1cs_ppzksnark_proof<ppT>
                    r1cs_ppzksnark_prover(const r1cs_ppzksnark_proving_key<ppT> &pk,
                                          const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                          const r1cs_ppzksnark_auxiliary_input<ppT> &auxiliary_input);

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
                template<typename ppT>
                bool r1cs_ppzksnark_verifier_weak_IC(const r1cs_ppzksnark_verification_key<ppT> &vk,
                                                     const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                                     const r1cs_ppzksnark_proof<ppT> &proof);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a non-processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename ppT>
                bool r1cs_ppzksnark_verifier_strong_IC(const r1cs_ppzksnark_verification_key<ppT> &vk,
                                                       const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                                       const r1cs_ppzksnark_proof<ppT> &proof);

                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename ppT>
                r1cs_ppzksnark_processed_verification_key<ppT>
                    r1cs_ppzksnark_verifier_process_vk(const r1cs_ppzksnark_verification_key<ppT> &vk);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has weak input consistency.
                 */
                template<typename ppT>
                bool r1cs_ppzksnark_online_verifier_weak_IC(const r1cs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                            const r1cs_ppzksnark_primary_input<ppT> &input,
                                                            const r1cs_ppzksnark_proof<ppT> &proof);

                /**
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a processed verification key, and
                 * (2) has strong input consistency.
                 */
                template<typename ppT>
                bool r1cs_ppzksnark_online_verifier_strong_IC(const r1cs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                              const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                                              const r1cs_ppzksnark_proof<ppT> &proof);

                /****************************** Miscellaneous ********************************/

                /**
                 * For debugging purposes (of r1cs_ppzksnark_r1cs_ppzksnark_verifier_gadget):
                 *
                 * A verifier algorithm for the R1CS ppzkSNARK that:
                 * (1) accepts a non-processed verification key,
                 * (2) has weak input consistency, and
                 * (3) uses affine coordinates for elliptic-curve computations.
                 */
                template<typename ppT>
                bool r1cs_ppzksnark_affine_verifier_weak_IC(const r1cs_ppzksnark_verification_key<ppT> &vk,
                                                            const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                                            const r1cs_ppzksnark_proof<ppT> &proof);

                template<typename ppT>
                bool r1cs_ppzksnark_proving_key<ppT>::operator==(const r1cs_ppzksnark_proving_key<ppT> &other) const {
                    return (this->A_query == other.A_query && this->B_query == other.B_query &&
                            this->C_query == other.C_query && this->H_query == other.H_query &&
                            this->K_query == other.K_query && this->constraint_system == other.constraint_system);
                }

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzksnark_proving_key<ppT> &pk) {
                    out << pk.A_query;
                    out << pk.B_query;
                    out << pk.C_query;
                    out << pk.H_query;
                    out << pk.K_query;
                    out << pk.constraint_system;

                    return out;
                }

                template<typename ppT>
                std::istream &operator>>(std::istream &in, r1cs_ppzksnark_proving_key<ppT> &pk) {
                    in >> pk.A_query;
                    in >> pk.B_query;
                    in >> pk.C_query;
                    in >> pk.H_query;
                    in >> pk.K_query;
                    in >> pk.constraint_system;

                    return in;
                }

                template<typename ppT>
                bool r1cs_ppzksnark_verification_key<ppT>::operator==(
                    const r1cs_ppzksnark_verification_key<ppT> &other) const {
                    return (this->alphaA_g2 == other.alphaA_g2 && this->alphaB_g1 == other.alphaB_g1 &&
                            this->alphaC_g2 == other.alphaC_g2 && this->gamma_g2 == other.gamma_g2 &&
                            this->gamma_beta_g1 == other.gamma_beta_g1 && this->gamma_beta_g2 == other.gamma_beta_g2 &&
                            this->rC_Z_g2 == other.rC_Z_g2 && this->encoded_IC_query == other.encoded_IC_query);
                }

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzksnark_verification_key<ppT> &vk) {
                    out << vk.alphaA_g2 << OUTPUT_NEWLINE;
                    out << vk.alphaB_g1 << OUTPUT_NEWLINE;
                    out << vk.alphaC_g2 << OUTPUT_NEWLINE;
                    out << vk.gamma_g2 << OUTPUT_NEWLINE;
                    out << vk.gamma_beta_g1 << OUTPUT_NEWLINE;
                    out << vk.gamma_beta_g2 << OUTPUT_NEWLINE;
                    out << vk.rC_Z_g2 << OUTPUT_NEWLINE;
                    out << vk.encoded_IC_query << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename ppT>
                std::istream &operator>>(std::istream &in, r1cs_ppzksnark_verification_key<ppT> &vk) {
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
                    in >> vk.encoded_IC_query;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename ppT>
                bool r1cs_ppzksnark_processed_verification_key<ppT>::operator==(
                    const r1cs_ppzksnark_processed_verification_key<ppT> &other) const {
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

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzksnark_processed_verification_key<ppT> &pvk) {
                    out << pvk.pp_G2_one_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_alphaA_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_alphaB_g1_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_alphaC_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_rC_Z_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_gamma_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_gamma_beta_g1_precomp << OUTPUT_NEWLINE;
                    out << pvk.vk_gamma_beta_g2_precomp << OUTPUT_NEWLINE;
                    out << pvk.encoded_IC_query << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename ppT>
                std::istream &operator>>(std::istream &in, r1cs_ppzksnark_processed_verification_key<ppT> &pvk) {
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
                    in >> pvk.encoded_IC_query;
                    algebra::consume_OUTPUT_NEWLINE(in);

                    return in;
                }

                template<typename ppT>
                bool r1cs_ppzksnark_proof<ppT>::operator==(const r1cs_ppzksnark_proof<ppT> &other) const {
                    return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C &&
                            this->g_H == other.g_H && this->g_K == other.g_K);
                }

                template<typename ppT>
                std::ostream &operator<<(std::ostream &out, const r1cs_ppzksnark_proof<ppT> &proof) {
                    out << proof.g_A << OUTPUT_NEWLINE;
                    out << proof.g_B << OUTPUT_NEWLINE;
                    out << proof.g_C << OUTPUT_NEWLINE;
                    out << proof.g_H << OUTPUT_NEWLINE;
                    out << proof.g_K << OUTPUT_NEWLINE;

                    return out;
                }

                template<typename ppT>
                std::istream &operator>>(std::istream &in, r1cs_ppzksnark_proof<ppT> &proof) {
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

                    return in;
                }

                template<typename ppT>
                r1cs_ppzksnark_verification_key<ppT>
                    r1cs_ppzksnark_verification_key<ppT>::dummy_verification_key(const size_t input_size) {
                    r1cs_ppzksnark_verification_key<ppT> result;
                    result.alphaA_g2 = algebra::Fr<ppT>::random_element() * algebra::G2<ppT>::one();
                    result.alphaB_g1 = algebra::Fr<ppT>::random_element() * algebra::G1<ppT>::one();
                    result.alphaC_g2 = algebra::Fr<ppT>::random_element() * algebra::G2<ppT>::one();
                    result.gamma_g2 = algebra::Fr<ppT>::random_element() * algebra::G2<ppT>::one();
                    result.gamma_beta_g1 = algebra::Fr<ppT>::random_element() * algebra::G1<ppT>::one();
                    result.gamma_beta_g2 = algebra::Fr<ppT>::random_element() * algebra::G2<ppT>::one();
                    result.rC_Z_g2 = algebra::Fr<ppT>::random_element() * algebra::G2<ppT>::one();

                    algebra::G1<ppT> base = algebra::Fr<ppT>::random_element() * algebra::G1<ppT>::one();
                    algebra::G1_vector<ppT> v;
                    for (size_t i = 0; i < input_size; ++i) {
                        v.emplace_back(algebra::Fr<ppT>::random_element() * algebra::G1<ppT>::one());
                    }

                    result.encoded_IC_query = accumulation_vector<algebra::G1<ppT>>(std::move(base), std::move(v));

                    return result;
                }

                template<typename ppT>
                r1cs_ppzksnark_keypair<ppT> r1cs_ppzksnark_generator(const r1cs_ppzksnark_constraint_system<ppT> &cs) {

                    /* make the B_query "lighter" if possible */
                    r1cs_ppzksnark_constraint_system<ppT> cs_copy(cs);
                    cs_copy.swap_AB_if_beneficial();

                    /* draw random element at which the QAP is evaluated */
                    const algebra::Fr<ppT> t = algebra::Fr<ppT>::random_element();

                    qap_instance_evaluation<algebra::Fr<ppT>> qap_inst =
                        r1cs_to_qap_instance_map_with_evaluation(cs_copy, t);

                    size_t non_zero_At = 0, non_zero_Bt = 0, non_zero_Ct = 0, non_zero_Ht = 0;
                    for (size_t i = 0; i < qap_inst.num_variables() + 1; ++i) {
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
                    for (size_t i = 0; i < qap_inst.degree() + 1; ++i) {
                        if (!qap_inst.Ht[i].is_zero()) {
                            ++non_zero_Ht;
                        }
                    }

                    algebra::Fr_vector<ppT> At = std::move(
                        qap_inst.At);    // qap_inst.At is now in unspecified state, but we do not use it later
                    algebra::Fr_vector<ppT> Bt = std::move(
                        qap_inst.Bt);    // qap_inst.Bt is now in unspecified state, but we do not use it later
                    algebra::Fr_vector<ppT> Ct = std::move(
                        qap_inst.Ct);    // qap_inst.Ct is now in unspecified state, but we do not use it later
                    algebra::Fr_vector<ppT> Ht = std::move(
                        qap_inst.Ht);    // qap_inst.Ht is now in unspecified state, but we do not use it later

                    /* append Zt to At,Bt,Ct with */
                    At.emplace_back(qap_inst.Zt);
                    Bt.emplace_back(qap_inst.Zt);
                    Ct.emplace_back(qap_inst.Zt);

                    const algebra::Fr<ppT> alphaA = algebra::Fr<ppT>::random_element(),
                                           alphaB = algebra::Fr<ppT>::random_element(),
                                           alphaC = algebra::Fr<ppT>::random_element(),
                                           rA = algebra::Fr<ppT>::random_element(),
                                           rB = algebra::Fr<ppT>::random_element(),
                                           beta = algebra::Fr<ppT>::random_element(),
                                           gamma = algebra::Fr<ppT>::random_element();
                    const algebra::Fr<ppT> rC = rA * rB;

                    // consrtuct the same-coefficient-check query (must happen before zeroing out the prefix of At)
                    algebra::Fr_vector<ppT> Kt;
                    Kt.reserve(qap_inst.num_variables() + 4);
                    for (size_t i = 0; i < qap_inst.num_variables() + 1; ++i) {
                        Kt.emplace_back(beta * (rA * At[i] + rB * Bt[i] + rC * Ct[i]));
                    }
                    Kt.emplace_back(beta * rA * qap_inst.Zt);
                    Kt.emplace_back(beta * rB * qap_inst.Zt);
                    Kt.emplace_back(beta * rC * qap_inst.Zt);

                    /* zero out prefix of At and stick it into IC coefficients */
                    algebra::Fr_vector<ppT> IC_coefficients;
                    IC_coefficients.reserve(qap_inst.num_inputs() + 1);
                    for (size_t i = 0; i < qap_inst.num_inputs() + 1; ++i) {
                        IC_coefficients.emplace_back(At[i]);
                        assert(!IC_coefficients[i].is_zero());
                        At[i] = algebra::Fr<ppT>::zero();
                    }

                    const size_t g1_exp_count =
                        2 * (non_zero_At - qap_inst.num_inputs() + non_zero_Ct) + non_zero_Bt + non_zero_Ht + Kt.size();
                    const size_t g2_exp_count = non_zero_Bt;

                    size_t g1_window = algebra::get_exp_window_size<algebra::G1<ppT>>(g1_exp_count);
                    size_t g2_window = algebra::get_exp_window_size<algebra::G2<ppT>>(g2_exp_count);

#ifdef MULTICORE
                    const size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or call
                                                                    // omp_set_num_threads()
#else
                    const size_t chunks = 1;
#endif

                    algebra::window_table<algebra::G1<ppT>> g1_table =
                        get_window_table(algebra::Fr<ppT>::size_in_bits(), g1_window, algebra::G1<ppT>::one());

                    algebra::window_table<algebra::G2<ppT>> g2_table =
                        get_window_table(algebra::Fr<ppT>::size_in_bits(), g2_window, algebra::G2<ppT>::one());

                    knowledge_commitment_vector<algebra::G1<ppT>, algebra::G1<ppT>> A_query =
                        kc_batch_exp(algebra::Fr<ppT>::size_in_bits(), g1_window, g1_window, g1_table, g1_table, rA,
                                     rA * alphaA, At, chunks);

                    knowledge_commitment_vector<algebra::G2<ppT>, algebra::G1<ppT>> B_query =
                        kc_batch_exp(algebra::Fr<ppT>::size_in_bits(), g2_window, g1_window, g2_table, g1_table, rB,
                                     rB * alphaB, Bt, chunks);

                    knowledge_commitment_vector<algebra::G1<ppT>, algebra::G1<ppT>> C_query =
                        kc_batch_exp(algebra::Fr<ppT>::size_in_bits(), g1_window, g1_window, g1_table, g1_table, rC,
                                     rC * alphaC, Ct, chunks);

                    algebra::G1_vector<ppT> H_query =
                        batch_exp(algebra::Fr<ppT>::size_in_bits(), g1_window, g1_table, Ht);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<algebra::G1<ppT>>(H_query);
#endif

                    algebra::G1_vector<ppT> K_query =
                        batch_exp(algebra::Fr<ppT>::size_in_bits(), g1_window, g1_table, Kt);
#ifdef USE_MIXED_ADDITION
                    algebra::batch_to_special<algebra::G1<ppT>>(K_query);
#endif

                    algebra::G2<ppT> alphaA_g2 = alphaA * algebra::G2<ppT>::one();
                    algebra::G1<ppT> alphaB_g1 = alphaB * algebra::G1<ppT>::one();
                    algebra::G2<ppT> alphaC_g2 = alphaC * algebra::G2<ppT>::one();
                    algebra::G2<ppT> gamma_g2 = gamma * algebra::G2<ppT>::one();
                    algebra::G1<ppT> gamma_beta_g1 = (gamma * beta) * algebra::G1<ppT>::one();
                    algebra::G2<ppT> gamma_beta_g2 = (gamma * beta) * algebra::G2<ppT>::one();
                    algebra::G2<ppT> rC_Z_g2 = (rC * qap_inst.Zt) * algebra::G2<ppT>::one();

                    algebra::G1<ppT> encoded_IC_base = (rA * IC_coefficients[0]) * algebra::G1<ppT>::one();
                    algebra::Fr_vector<ppT> multiplied_IC_coefficients;
                    multiplied_IC_coefficients.reserve(qap_inst.num_inputs());
                    for (size_t i = 1; i < qap_inst.num_inputs() + 1; ++i) {
                        multiplied_IC_coefficients.emplace_back(rA * IC_coefficients[i]);
                    }
                    algebra::G1_vector<ppT> encoded_IC_values =
                        batch_exp(algebra::Fr<ppT>::size_in_bits(), g1_window, g1_table, multiplied_IC_coefficients);

                    accumulation_vector<algebra::G1<ppT>> encoded_IC_query(std::move(encoded_IC_base),
                                                                           std::move(encoded_IC_values));

                    r1cs_ppzksnark_verification_key<ppT> vk =
                        r1cs_ppzksnark_verification_key<ppT>(alphaA_g2, alphaB_g1, alphaC_g2, gamma_g2, gamma_beta_g1,
                                                             gamma_beta_g2, rC_Z_g2, encoded_IC_query);
                    r1cs_ppzksnark_proving_key<ppT> pk = r1cs_ppzksnark_proving_key<ppT>(std::move(A_query),
                                                                                         std::move(B_query),
                                                                                         std::move(C_query),
                                                                                         std::move(H_query),
                                                                                         std::move(K_query),
                                                                                         std::move(cs_copy));

                    pk.print_size();
                    vk.print_size();

                    return r1cs_ppzksnark_keypair<ppT>(std::move(pk), std::move(vk));
                }

                template<typename ppT>
                r1cs_ppzksnark_proof<ppT>
                    r1cs_ppzksnark_prover(const r1cs_ppzksnark_proving_key<ppT> &pk,
                                          const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                          const r1cs_ppzksnark_auxiliary_input<ppT> &auxiliary_input) {

                    const algebra::Fr<ppT> d1 = algebra::Fr<ppT>::random_element(),
                                           d2 = algebra::Fr<ppT>::random_element(),
                                           d3 = algebra::Fr<ppT>::random_element();

                    const qap_witness<algebra::Fr<ppT>> qap_wit =
                        r1cs_to_qap_witness_map(pk.constraint_system, primary_input, auxiliary_input, d1, d2, d3);

                    knowledge_commitment<algebra::G1<ppT>, algebra::G1<ppT>> g_A =
                        pk.A_query[0] + qap_wit.d1 * pk.A_query[qap_wit.num_variables() + 1];
                    knowledge_commitment<algebra::G2<ppT>, algebra::G1<ppT>> g_B =
                        pk.B_query[0] + qap_wit.d2 * pk.B_query[qap_wit.num_variables() + 1];
                    knowledge_commitment<algebra::G1<ppT>, algebra::G1<ppT>> g_C =
                        pk.C_query[0] + qap_wit.d3 * pk.C_query[qap_wit.num_variables() + 1];

                    algebra::G1<ppT> g_H = algebra::G1<ppT>::zero();
                    algebra::G1<ppT> g_K = (pk.K_query[0] + qap_wit.d1 * pk.K_query[qap_wit.num_variables() + 1] +
                                            qap_wit.d2 * pk.K_query[qap_wit.num_variables() + 2] +
                                            qap_wit.d3 * pk.K_query[qap_wit.num_variables() + 3]);

#ifdef MULTICORE
                    const size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env var or call
                                                                    // omp_set_num_threads()
#else
                    const size_t chunks = 1;
#endif

                    g_A = g_A + kc_multi_exp_with_mixed_addition<algebra::G1<ppT>, algebra::G1<ppT>, algebra::Fr<ppT>,
                                                                 algebra::multi_exp_method_bos_coster>(
                                    pk.A_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                    qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    g_B = g_B + kc_multi_exp_with_mixed_addition<algebra::G2<ppT>, algebra::G1<ppT>, algebra::Fr<ppT>,
                                                                 algebra::multi_exp_method_bos_coster>(
                                    pk.B_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                    qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    g_C = g_C + kc_multi_exp_with_mixed_addition<algebra::G1<ppT>, algebra::G1<ppT>, algebra::Fr<ppT>,
                                                                 algebra::multi_exp_method_bos_coster>(
                                    pk.C_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                    qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    g_H =
                        g_H + algebra::multi_exp<algebra::G1<ppT>, algebra::Fr<ppT>, algebra::multi_exp_method_BDLO12>(
                                  pk.H_query.begin(), pk.H_query.begin() + qap_wit.degree() + 1,
                                  qap_wit.coefficients_for_H.begin(),
                                  qap_wit.coefficients_for_H.begin() + qap_wit.degree() + 1, chunks);

                    g_K = g_K + algebra::multi_exp_with_mixed_addition<algebra::G1<ppT>, algebra::Fr<ppT>,
                                                                       algebra::multi_exp_method_bos_coster>(
                                    pk.K_query.begin() + 1, pk.K_query.begin() + 1 + qap_wit.num_variables(),
                                    qap_wit.coefficients_for_ABCs.begin(),
                                    qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                    r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_proof<ppT>(
                        std::move(g_A), std::move(g_B), std::move(g_C), std::move(g_H), std::move(g_K));
                    proof.print_size();

                    return proof;
                }

                template<typename ppT>
                r1cs_ppzksnark_processed_verification_key<ppT>
                    r1cs_ppzksnark_verifier_process_vk(const r1cs_ppzksnark_verification_key<ppT> &vk) {
                    r1cs_ppzksnark_processed_verification_key<ppT> pvk;
                    pvk.pp_G2_one_precomp = ppT::precompute_G2(algebra::G2<ppT>::one());
                    pvk.vk_alphaA_g2_precomp = ppT::precompute_G2(vk.alphaA_g2);
                    pvk.vk_alphaB_g1_precomp = ppT::precompute_G1(vk.alphaB_g1);
                    pvk.vk_alphaC_g2_precomp = ppT::precompute_G2(vk.alphaC_g2);
                    pvk.vk_rC_Z_g2_precomp = ppT::precompute_G2(vk.rC_Z_g2);
                    pvk.vk_gamma_g2_precomp = ppT::precompute_G2(vk.gamma_g2);
                    pvk.vk_gamma_beta_g1_precomp = ppT::precompute_G1(vk.gamma_beta_g1);
                    pvk.vk_gamma_beta_g2_precomp = ppT::precompute_G2(vk.gamma_beta_g2);

                    pvk.encoded_IC_query = vk.encoded_IC_query;

                    return pvk;
                }

                template<typename ppT>
                bool r1cs_ppzksnark_online_verifier_weak_IC(const r1cs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                            const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                                            const r1cs_ppzksnark_proof<ppT> &proof) {
                    assert(pvk.encoded_IC_query.domain_size() >= primary_input.size());

                    const accumulation_vector<algebra::G1<ppT>> accumulated_IC =
                        pvk.encoded_IC_query.template accumulate_chunk<algebra::Fr<ppT>>(primary_input.begin(),
                                                                                         primary_input.end(), 0);
                    const algebra::G1<ppT> &acc = accumulated_IC.first;

                    bool result = true;

                    if (!proof.is_well_formed()) {
                        result = false;
                    }
                    algebra::G1_precomp<ppT> proof_g_A_g_precomp = ppT::precompute_G1(proof.g_A.g);
                    algebra::G1_precomp<ppT> proof_g_A_h_precomp = ppT::precompute_G1(proof.g_A.h);
                    algebra::Fqk<ppT> kc_A_1 = ppT::miller_loop(proof_g_A_g_precomp, pvk.vk_alphaA_g2_precomp);
                    algebra::Fqk<ppT> kc_A_2 = ppT::miller_loop(proof_g_A_h_precomp, pvk.pp_G2_one_precomp);
                    algebra::GT<ppT> kc_A = ppT::final_exponentiation(kc_A_1 * kc_A_2.unitary_inverse());
                    if (kc_A != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    algebra::G2_precomp<ppT> proof_g_B_g_precomp = ppT::precompute_G2(proof.g_B.g);
                    algebra::G1_precomp<ppT> proof_g_B_h_precomp = ppT::precompute_G1(proof.g_B.h);
                    algebra::Fqk<ppT> kc_B_1 = ppT::miller_loop(pvk.vk_alphaB_g1_precomp, proof_g_B_g_precomp);
                    algebra::Fqk<ppT> kc_B_2 = ppT::miller_loop(proof_g_B_h_precomp, pvk.pp_G2_one_precomp);
                    algebra::GT<ppT> kc_B = ppT::final_exponentiation(kc_B_1 * kc_B_2.unitary_inverse());
                    if (kc_B != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<ppT> proof_g_C_g_precomp = ppT::precompute_G1(proof.g_C.g);
                    algebra::G1_precomp<ppT> proof_g_C_h_precomp = ppT::precompute_G1(proof.g_C.h);
                    algebra::Fqk<ppT> kc_C_1 = ppT::miller_loop(proof_g_C_g_precomp, pvk.vk_alphaC_g2_precomp);
                    algebra::Fqk<ppT> kc_C_2 = ppT::miller_loop(proof_g_C_h_precomp, pvk.pp_G2_one_precomp);
                    algebra::GT<ppT> kc_C = ppT::final_exponentiation(kc_C_1 * kc_C_2.unitary_inverse());
                    if (kc_C != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    // check that g^((A+acc)*B)=g^(H*\Prod(t-\sigma)+C)
                    // equivalently, via pairings, that e(g^(A+acc), g^B) = e(g^H, g^Z) + e(g^C, g^1)
                    algebra::G1_precomp<ppT> proof_g_A_g_acc_precomp = ppT::precompute_G1(proof.g_A.g + acc);
                    algebra::G1_precomp<ppT> proof_g_H_precomp = ppT::precompute_G1(proof.g_H);
                    algebra::Fqk<ppT> QAP_1 = ppT::miller_loop(proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                    algebra::Fqk<ppT> QAP_23 = ppT::double_miller_loop(proof_g_H_precomp, pvk.vk_rC_Z_g2_precomp,
                                                                       proof_g_C_g_precomp, pvk.pp_G2_one_precomp);
                    algebra::GT<ppT> QAP = ppT::final_exponentiation(QAP_1 * QAP_23.unitary_inverse());
                    if (QAP != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    algebra::G1_precomp<ppT> proof_g_K_precomp = ppT::precompute_G1(proof.g_K);
                    algebra::G1_precomp<ppT> proof_g_A_g_acc_C_precomp =
                        ppT::precompute_G1((proof.g_A.g + acc) + proof.g_C.g);
                    algebra::Fqk<ppT> K_1 = ppT::miller_loop(proof_g_K_precomp, pvk.vk_gamma_g2_precomp);
                    algebra::Fqk<ppT> K_23 =
                        ppT::double_miller_loop(proof_g_A_g_acc_C_precomp, pvk.vk_gamma_beta_g2_precomp,
                                                pvk.vk_gamma_beta_g1_precomp, proof_g_B_g_precomp);
                    algebra::GT<ppT> K = ppT::final_exponentiation(K_1 * K_23.unitary_inverse());
                    if (K != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    return result;
                }

                template<typename ppT>
                bool r1cs_ppzksnark_verifier_weak_IC(const r1cs_ppzksnark_verification_key<ppT> &vk,
                                                     const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                                     const r1cs_ppzksnark_proof<ppT> &proof) {
                    r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(vk);
                    bool result = r1cs_ppzksnark_online_verifier_weak_IC<ppT>(pvk, primary_input, proof);
                    return result;
                }

                template<typename ppT>
                bool r1cs_ppzksnark_online_verifier_strong_IC(const r1cs_ppzksnark_processed_verification_key<ppT> &pvk,
                                                              const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                                              const r1cs_ppzksnark_proof<ppT> &proof) {
                    bool result = true;

                    if (pvk.encoded_IC_query.domain_size() != primary_input.size()) {
                        result = false;
                    } else {
                        result = r1cs_ppzksnark_online_verifier_weak_IC(pvk, primary_input, proof);
                    }

                    return result;
                }

                template<typename ppT>
                bool r1cs_ppzksnark_verifier_strong_IC(const r1cs_ppzksnark_verification_key<ppT> &vk,
                                                       const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                                       const r1cs_ppzksnark_proof<ppT> &proof) {
                    r1cs_ppzksnark_processed_verification_key<ppT> pvk = r1cs_ppzksnark_verifier_process_vk<ppT>(vk);
                    bool result = r1cs_ppzksnark_online_verifier_strong_IC<ppT>(pvk, primary_input, proof);
                    return result;
                }

                template<typename ppT>
                bool r1cs_ppzksnark_affine_verifier_weak_IC(const r1cs_ppzksnark_verification_key<ppT> &vk,
                                                            const r1cs_ppzksnark_primary_input<ppT> &primary_input,
                                                            const r1cs_ppzksnark_proof<ppT> &proof) {
                    assert(vk.encoded_IC_query.domain_size() >= primary_input.size());

                    algebra::affine_ate_G2_precomp<ppT> pvk_pp_G2_one_precomp =
                        ppT::affine_ate_precompute_G2(algebra::G2<ppT>::one());
                    algebra::affine_ate_G2_precomp<ppT> pvk_vk_alphaA_g2_precomp =
                        ppT::affine_ate_precompute_G2(vk.alphaA_g2);
                    algebra::affine_ate_G1_precomp<ppT> pvk_vk_alphaB_g1_precomp =
                        ppT::affine_ate_precompute_G1(vk.alphaB_g1);
                    algebra::affine_ate_G2_precomp<ppT> pvk_vk_alphaC_g2_precomp =
                        ppT::affine_ate_precompute_G2(vk.alphaC_g2);
                    algebra::affine_ate_G2_precomp<ppT> pvk_vk_rC_Z_g2_precomp =
                        ppT::affine_ate_precompute_G2(vk.rC_Z_g2);
                    algebra::affine_ate_G2_precomp<ppT> pvk_vk_gamma_g2_precomp =
                        ppT::affine_ate_precompute_G2(vk.gamma_g2);
                    algebra::affine_ate_G1_precomp<ppT> pvk_vk_gamma_beta_g1_precomp =
                        ppT::affine_ate_precompute_G1(vk.gamma_beta_g1);
                    algebra::affine_ate_G2_precomp<ppT> pvk_vk_gamma_beta_g2_precomp =
                        ppT::affine_ate_precompute_G2(vk.gamma_beta_g2);

                    const accumulation_vector<algebra::G1<ppT>> accumulated_IC =
                        vk.encoded_IC_query.template accumulate_chunk<algebra::Fr<ppT>>(primary_input.begin(),
                                                                                        primary_input.end(), 0);
                    assert(accumulated_IC.is_fully_accumulated());
                    const algebra::G1<ppT> &acc = accumulated_IC.first;

                    bool result = true;
                    algebra::affine_ate_G1_precomp<ppT> proof_g_A_g_precomp =
                        ppT::affine_ate_precompute_G1(proof.g_A.g);
                    algebra::affine_ate_G1_precomp<ppT> proof_g_A_h_precomp =
                        ppT::affine_ate_precompute_G1(proof.g_A.h);
                    algebra::Fqk<ppT> kc_A_miller = ppT::affine_ate_e_over_e_miller_loop(
                        proof_g_A_g_precomp, pvk_vk_alphaA_g2_precomp, proof_g_A_h_precomp, pvk_pp_G2_one_precomp);
                    algebra::GT<ppT> kc_A = ppT::final_exponentiation(kc_A_miller);

                    if (kc_A != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    algebra::affine_ate_G2_precomp<ppT> proof_g_B_g_precomp =
                        ppT::affine_ate_precompute_G2(proof.g_B.g);
                    algebra::affine_ate_G1_precomp<ppT> proof_g_B_h_precomp =
                        ppT::affine_ate_precompute_G1(proof.g_B.h);
                    algebra::Fqk<ppT> kc_B_miller = ppT::affine_ate_e_over_e_miller_loop(
                        pvk_vk_alphaB_g1_precomp, proof_g_B_g_precomp, proof_g_B_h_precomp, pvk_pp_G2_one_precomp);
                    algebra::GT<ppT> kc_B = ppT::final_exponentiation(kc_B_miller);
                    if (kc_B != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    algebra::affine_ate_G1_precomp<ppT> proof_g_C_g_precomp =
                        ppT::affine_ate_precompute_G1(proof.g_C.g);
                    algebra::affine_ate_G1_precomp<ppT> proof_g_C_h_precomp =
                        ppT::affine_ate_precompute_G1(proof.g_C.h);
                    algebra::Fqk<ppT> kc_C_miller = ppT::affine_ate_e_over_e_miller_loop(
                        proof_g_C_g_precomp, pvk_vk_alphaC_g2_precomp, proof_g_C_h_precomp, pvk_pp_G2_one_precomp);
                    algebra::GT<ppT> kc_C = ppT::final_exponentiation(kc_C_miller);
                    if (kc_C != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    algebra::affine_ate_G1_precomp<ppT> proof_g_A_g_acc_precomp =
                        ppT::affine_ate_precompute_G1(proof.g_A.g + acc);
                    algebra::affine_ate_G1_precomp<ppT> proof_g_H_precomp = ppT::affine_ate_precompute_G1(proof.g_H);
                    algebra::Fqk<ppT> QAP_miller = ppT::affine_ate_e_times_e_over_e_miller_loop(
                        proof_g_H_precomp, pvk_vk_rC_Z_g2_precomp, proof_g_C_g_precomp, pvk_pp_G2_one_precomp,
                        proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                    algebra::GT<ppT> QAP = ppT::final_exponentiation(QAP_miller);
                    if (QAP != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    algebra::affine_ate_G1_precomp<ppT> proof_g_K_precomp = ppT::affine_ate_precompute_G1(proof.g_K);
                    algebra::affine_ate_G1_precomp<ppT> proof_g_A_g_acc_C_precomp =
                        ppT::affine_ate_precompute_G1((proof.g_A.g + acc) + proof.g_C.g);
                    algebra::Fqk<ppT> K_miller = ppT::affine_ate_e_times_e_over_e_miller_loop(
                        proof_g_A_g_acc_C_precomp, pvk_vk_gamma_beta_g2_precomp, pvk_vk_gamma_beta_g1_precomp,
                        proof_g_B_g_precomp, proof_g_K_precomp, pvk_vk_gamma_g2_precomp);
                    algebra::GT<ppT> K = ppT::final_exponentiation(K_miller);
                    if (K != algebra::GT<ppT>::one()) {
                        result = false;
                    }

                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // R1CS_PPZKSNARK_HPP_

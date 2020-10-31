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

#ifndef CRYPTO3_R1CS_PPZKSNARK_BASIC_POLICY_HPP
#define CRYPTO3_R1CS_PPZKSNARK_BASIC_POLICY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/knowledge_commitment/knowledge_commitment.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

//#include <nil/crypto3/algebra/multiexp/multiexp.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <nil/crypto3/zk/snark/knowledge_commitment/kc_multiexp.hpp>
#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct r1cs_ppzksnark_basic_policy {

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
                        struct proving_key {
                            knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                A_query;
                            knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type>
                                B_query;
                            knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                C_query;
                            typename CurveType::g1_vector H_query;
                            typename CurveType::g1_vector K_query;

                            constraint_system constraint_system;

                            proving_key() {};
                            proving_key &operator=(const proving_key &other) = default;
                            proving_key(const proving_key &other) = default;
                            proving_key(proving_key &&other) = default;
                            proving_key(
                                knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                    &&A_query,
                                knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type>
                                    &&B_query,
                                knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                    &&C_query,
                                typename CurveType::g1_vector &&H_query,
                                typename CurveType::g1_vector &&K_query,
                                constraint_system &&constraint_system) :
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
                                        this->K_query == other.K_query &&
                                        this->constraint_system == other.constraint_system);
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
                                result.alphaA_g2 = algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g2_type::value_type::one(); result.alphaB_g1 = algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g1_type::value_type::one(); result.alphaC_g2 =
                            algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g2_type::value_type::one(); result.gamma_g2 = algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g2_type::value_type::one(); result.gamma_beta_g1 =
                            algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g1_type::value_type::one(); result.gamma_beta_g2 = algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g2_type::value_type::one(); result.rC_Z_g2 =
                            algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g2_type::value_type::one();

                                typename CurveType::g1_type::value_type base = algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g1_type::value_type::one(); typename
                            CurveType::g1_vector v; for (std::size_t i = 0; i < input_size; ++i) {
                                    v.emplace_back(algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g1_type::value_type::one());
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
                            using pairing_policy = typename CurveType::pairing_policy;

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
                        struct proof {
                            knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_A;
                            knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> g_B;
                            knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_C;
                            typename CurveType::g1_type::value_type g_H;
                            typename CurveType::g1_type::value_type g_K;

                            proof() {
                                // invalid proof with valid curve points
                                this->g_A.g = typename CurveType::g1_type::value_type::one();
                                this->g_A.h = typename CurveType::g1_type::value_type::one();
                                this->g_B.g = typename CurveType::g2_type::value_type::one();
                                this->g_B.h = typename CurveType::g1_type::value_type::one();
                                this->g_C.g = typename CurveType::g1_type::value_type::one();
                                this->g_C.h = typename CurveType::g1_type::value_type::one();
                                this->g_H = typename CurveType::g1_type::value_type::one();
                                this->g_K = typename CurveType::g1_type::value_type::one();
                            }
                            proof(knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> &&g_A,
                                  knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> &&g_B,
                                  knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> &&g_C,
                                  typename CurveType::g1_type::value_type &&g_H,
                                  typename CurveType::g1_type::value_type &&g_K) :
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

                        /***************************** Main algorithms *******************************/

                        /*
                         Below are four variants of verifier algorithm for the R1CS ppzkSNARK.

                         These are the four cases that arise from the following two choices:

                         (1) The verifier accepts a (non-processed) verification key or, instead, a processed
                         verification key. In the latter case, we call the algorithm an "online verifier".

                         (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                             Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                             weak input consistency requires that |primary_input| <= CS.num_inputs (and
                             the primary input is implicitly padded with zeros up to length CS.num_inputs).
                         */

                        /****************************** Miscellaneous ********************************/

                        static keypair generator(const constraint_system &cs) {

                            /* make the B_query "lighter" if possible */
                            constraint_system cs_copy(cs);
                            cs_copy.swap_AB_if_beneficial();

                            /* draw random element at which the QAP is evaluated */
                            const typename CurveType::scalar_field_type::value_type t =
                                algebra::random_element<typename CurveType::scalar_field_type>();

                            qap_instance_evaluation<typename CurveType::scalar_field_type> qap_inst =
                                r1cs_to_qap::instance_map_with_evaluation(cs_copy, t);

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

                            const typename CurveType::scalar_field_type::value_type
                                alphaA = algebra::random_element<typename CurveType::scalar_field_type>(),
                                alphaB = algebra::random_element<typename CurveType::scalar_field_type>(),
                                alphaC = algebra::random_element<typename CurveType::scalar_field_type>(),
                                rA = algebra::random_element<typename CurveType::scalar_field_type>(),
                                rB = algebra::random_element<typename CurveType::scalar_field_type>(),
                                beta = algebra::random_element<typename CurveType::scalar_field_type>(),
                                gamma = algebra::random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::scalar_field_type rC = rA * rB;

                            // consrtuct the same-coefficient-check query (must happen before zeroing out the prefix of
                            // At)
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

                            const std::size_t g1_exp_count = 2 * (non_zero_At - qap_inst.num_inputs() + non_zero_Ct) +
                                                             non_zero_Bt + non_zero_Ht + Kt.size();
                            const std::size_t g2_exp_count = non_zero_Bt;

                            std::size_t g1_window =
                                algebra::get_exp_window_size<typename CurveType::g1_type>(g1_exp_count);
                            std::size_t g2_window =
                                algebra::get_exp_window_size<typename CurveType::g2_type>(g2_exp_count);

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            algebra::window_table<typename CurveType::g1_type> g1_table =
                                get_window_table(typename CurveType::scalar_field_type::value_bits, g1_window,
                                                 typename CurveType::g1_type::value_type::one());

                            algebra::window_table<typename CurveType::g2_type> g2_table =
                                get_window_table(typename CurveType::scalar_field_type::value_bits, g2_window,
                                                 typename CurveType::g2_type::value_type::one());

                            knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                A_query = kc_batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window,
                                                       g1_window, g1_table, g1_table, rA, rA * alphaA, At, chunks);

                            knowledge_commitment_vector<typename CurveType::g2_type, typename CurveType::g1_type>
                                B_query = kc_batch_exp(typename CurveType::scalar_field_type::value_bits, g2_window,
                                                       g1_window, g2_table, g1_table, rB, rB * alphaB, Bt, chunks);

                            knowledge_commitment_vector<typename CurveType::g1_type, typename CurveType::g1_type>
                                C_query = kc_batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window,
                                                       g1_window, g1_table, g1_table, rC, rC * alphaC, Ct, chunks);

                            typename CurveType::g1_vector H_query =
                                batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window, g1_table, Ht);
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(H_query);
#endif

                            typename CurveType::g1_vector K_query =
                                batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window, g1_table, Kt);
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(K_query);
#endif

                            typename CurveType::g2_type::value_type alphaA_g2 = alphaA * typename CurveType::g2_type::value_type::one();
                            typename CurveType::g1_type::value_type alphaB_g1 = alphaB * typename CurveType::g1_type::value_type::one();
                            typename CurveType::g2_type::value_type alphaC_g2 = alphaC * typename CurveType::g2_type::value_type::one();
                            typename CurveType::g2_type::value_type gamma_g2 = gamma * typename CurveType::g2_type::value_type::one();
                            typename CurveType::g1_type::value_type gamma_beta_g1 =
                                (gamma * beta) * typename CurveType::g1_type::value_type::one();
                            typename CurveType::g2_type::value_type gamma_beta_g2 =
                                (gamma * beta) * typename CurveType::g2_type::value_type::one();
                            typename CurveType::g2_type::value_type rC_Z_g2 =
                                (rC * qap_inst.Zt) * typename CurveType::g2_type::value_type::one();

                            typename CurveType::g1_type::value_type encoded_IC_base =
                                (rA * IC_coefficients[0]) * typename CurveType::g1_type::value_type::one();
                            std::vector<typename CurveType::scalar_field_type::value_type> multiplied_IC_coefficients;
                            multiplied_IC_coefficients.reserve(qap_inst.num_inputs());
                            for (std::size_t i = 1; i < qap_inst.num_inputs() + 1; ++i) {
                                multiplied_IC_coefficients.emplace_back(rA * IC_coefficients[i]);
                            }
                            typename CurveType::g1_vector encoded_IC_values =
                                batch_exp(typename CurveType::scalar_field_type::value_bits, g1_window, g1_table,
                                          multiplied_IC_coefficients);

                            accumulation_vector<typename CurveType::g1_type> encoded_IC_query(
                                std::move(encoded_IC_base), std::move(encoded_IC_values));

                            verification_key vk =
                                verification_key(alphaA_g2, alphaB_g1, alphaC_g2, gamma_g2, gamma_beta_g1,
                                                 gamma_beta_g2, rC_Z_g2, encoded_IC_query);
                            proving_key pk = proving_key(std::move(A_query),
                                                         std::move(B_query),
                                                         std::move(C_query),
                                                         std::move(H_query),
                                                         std::move(K_query),
                                                         std::move(cs_copy));

                            pk.print_size();
                            vk.print_size();

                            return keypair(std::move(pk), std::move(vk));
                        }

                        /**
                         * A prover algorithm for the R1CS ppzkSNARK.
                         *
                         * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                         * produces a proof (of knowledge) that attests to the following statement:
                         *               ``there exists Y such that CS(X,Y)=0''.
                         * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                         */
                        static proof prover(const proving_key &pk,
                                            const primary_input &primary_input,
                                            const auxiliary_input &auxiliary_input) {

                            const typename CurveType::scalar_field_type::value_type
                                d1 = algebra::random_element<typename CurveType::scalar_field_type>(),
                                d2 = algebra::random_element<typename CurveType::scalar_field_type>(),
                                d3 = algebra::random_element<typename CurveType::scalar_field_type>();

                            const qap_witness<typename CurveType::scalar_field_type> qap_wit = r1cs_to_qap::witness_map(
                                pk.constraint_system, primary_input, auxiliary_input, d1, d2, d3);

                            knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_A =
                                pk.A_query[0] + qap_wit.d1 * pk.A_query[qap_wit.num_variables() + 1];
                            knowledge_commitment<typename CurveType::g2_type, typename CurveType::g1_type> g_B =
                                pk.B_query[0] + qap_wit.d2 * pk.B_query[qap_wit.num_variables() + 1];
                            knowledge_commitment<typename CurveType::g1_type, typename CurveType::g1_type> g_C =
                                pk.C_query[0] + qap_wit.d3 * pk.C_query[qap_wit.num_variables() + 1];

                            typename CurveType::g1_type::value_type g_H = typename CurveType::g1_type::value_type::zero();
                            typename CurveType::g1_type::value_type g_K =
                                (pk.K_query[0] + qap_wit.d1 * pk.K_query[qap_wit.num_variables() + 1] +
                                 qap_wit.d2 * pk.K_query[qap_wit.num_variables() + 2] +
                                 qap_wit.d3 * pk.K_query[qap_wit.num_variables() + 3]);

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            g_A = g_A +
                                  kc_multi_exp_with_mixed_addition<
                                      typename CurveType::g1_type, typename CurveType::g1_type,
                                      typename CurveType::scalar_field_type, algebra::multi_exp_method_bos_coster>(
                                      pk.A_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                      qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                            g_B = g_B +
                                  kc_multi_exp_with_mixed_addition<
                                      typename CurveType::g2_type, typename CurveType::g1_type,
                                      typename CurveType::scalar_field_type, algebra::multi_exp_method_bos_coster>(
                                      pk.B_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                      qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                            g_C = g_C +
                                  kc_multi_exp_with_mixed_addition<
                                      typename CurveType::g1_type, typename CurveType::g1_type,
                                      typename CurveType::scalar_field_type, algebra::multi_exp_method_bos_coster>(
                                      pk.C_query, 1, 1 + qap_wit.num_variables(), qap_wit.coefficients_for_ABCs.begin(),
                                      qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                            g_H = g_H +
                                  algebra::multi_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                     algebra::multi_exp_method_BDLO12>(
                                      pk.H_query.begin(), pk.H_query.begin() + qap_wit.degree() + 1,
                                      qap_wit.coefficients_for_H.begin(),
                                      qap_wit.coefficients_for_H.begin() + qap_wit.degree() + 1, chunks);

                            g_K = g_K + algebra::multi_exp_with_mixed_addition<typename CurveType::g1_type,
                                                                               typename CurveType::scalar_field_type,
                                                                               algebra::multi_exp_method_bos_coster>(
                                            pk.K_query.begin() + 1, pk.K_query.begin() + 1 + qap_wit.num_variables(),
                                            qap_wit.coefficients_for_ABCs.begin(),
                                            qap_wit.coefficients_for_ABCs.begin() + qap_wit.num_variables(), chunks);

                            proof prf =
                                proof(std::move(g_A), std::move(g_B), std::move(g_C), std::move(g_H), std::move(g_K));
                            prf.print_size();

                            return prf;
                        }

                        /**
                         * Convert a (non-processed) verification key into a processed verification key.
                         */
                        static processed_verification_key verifier_process_vk(const verification_key &vk) {
                            processed_verification_key pvk;
                            pvk.pp_G2_one_precomp = CurveType::precompute_g2(typename CurveType::g2_type::value_type::one());
                            pvk.vk_alphaA_g2_precomp = CurveType::precompute_g2(vk.alphaA_g2);
                            pvk.vk_alphaB_g1_precomp = CurveType::precompute_g1(vk.alphaB_g1);
                            pvk.vk_alphaC_g2_precomp = CurveType::precompute_g2(vk.alphaC_g2);
                            pvk.vk_rC_Z_g2_precomp = CurveType::precompute_g2(vk.rC_Z_g2);
                            pvk.vk_gamma_g2_precomp = CurveType::precompute_g2(vk.gamma_g2);
                            pvk.vk_gamma_beta_g1_precomp = CurveType::precompute_g1(vk.gamma_beta_g1);
                            pvk.vk_gamma_beta_g2_precomp = CurveType::precompute_g2(vk.gamma_beta_g2);

                            pvk.encoded_IC_query = vk.encoded_IC_query;

                            return pvk;
                        }

                        /**
                         * A verifier algorithm for the R1CS ppzkSNARK that:
                         * (1) accepts a processed verification key, and
                         * (2) has weak input consistency.
                         */
                        static bool online_verifier_weak_IC(const processed_verification_key &pvk,
                                                            const primary_input &primary_input,
                                                            const proof &proof) {
                            using pairing_policy = typename CurveType::pairing_policy;

                            assert(pvk.encoded_IC_query.domain_size() >= primary_input.size());

                            const accumulation_vector<typename CurveType::g1_type> accumulated_IC =
                                pvk.encoded_IC_query.template accumulate_chunk<typename CurveType::scalar_field_type>(
                                    primary_input.begin(), primary_input.end(), 0);
                            const typename CurveType::g1_type::value_type &acc = accumulated_IC.first;

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }
                            typename pairing_policy::G1_precomp proof_g_A_g_precomp =
                                CurveType::precompute_g1(proof.g_A.g);
                            typename pairing_policy::G1_precomp proof_g_A_h_precomp =
                                CurveType::precompute_g1(proof.g_A.h);
                            typename pairing_policy::Fqk_type kc_A_1 =
                                pairing_policy::miller_loop(proof_g_A_g_precomp, pvk.vk_alphaA_g2_precomp);
                            typename pairing_policy::Fqk_type kc_A_2 =
                                pairing_policy::miller_loop(proof_g_A_h_precomp, pvk.pp_G2_one_precomp);
                            typename CurveType::gt_type kc_A =
                                pairing_policy::final_exponentiation(kc_A_1 * kc_A_2.unitary_inversed());
                            if (kc_A != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::G2_precomp proof_g_B_g_precomp =
                                CurveType::precompute_g2(proof.g_B.g);
                            typename pairing_policy::G1_precomp proof_g_B_h_precomp =
                                CurveType::precompute_g1(proof.g_B.h);
                            typename pairing_policy::Fqk_type kc_B_1 =
                                pairing_policy::miller_loop(pvk.vk_alphaB_g1_precomp, proof_g_B_g_precomp);
                            typename pairing_policy::Fqk_type kc_B_2 =
                                pairing_policy::miller_loop(proof_g_B_h_precomp, pvk.pp_G2_one_precomp);
                            typename CurveType::gt_type kc_B =
                                pairing_policy::final_exponentiation(kc_B_1 * kc_B_2.unitary_inversed());
                            if (kc_B != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::G1_precomp proof_g_C_g_precomp =
                                CurveType::precompute_g1(proof.g_C.g);
                            typename pairing_policy::G1_precomp proof_g_C_h_precomp =
                                CurveType::precompute_g1(proof.g_C.h);
                            typename pairing_policy::Fqk_type kc_C_1 =
                                pairing_policy::miller_loop(proof_g_C_g_precomp, pvk.vk_alphaC_g2_precomp);
                            typename pairing_policy::Fqk_type kc_C_2 =
                                pairing_policy::miller_loop(proof_g_C_h_precomp, pvk.pp_G2_one_precomp);
                            typename CurveType::gt_type kc_C =
                                pairing_policy::final_exponentiation(kc_C_1 * kc_C_2.unitary_inversed());
                            if (kc_C != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            // check that g^((A+acc)*B)=g^(H*\Prod(t-\sigma)+C)
                            // equivalently, via pairings, that e(g^(A+acc), g^B) = e(g^H, g^Z) + e(g^C, g^1)
                            typename pairing_policy::G1_precomp proof_g_A_g_acc_precomp =
                                CurveType::precompute_g1(proof.g_A.g + acc);
                            typename pairing_policy::G1_precomp proof_g_H_precomp = CurveType::precompute_g1(proof.g_H);
                            typename pairing_policy::Fqk_type QAP_1 =
                                pairing_policy::miller_loop(proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                            typename pairing_policy::Fqk_type QAP_23 = pairing_policy::double_miller_loop(
                                proof_g_H_precomp, pvk.vk_rC_Z_g2_precomp, proof_g_C_g_precomp, pvk.pp_G2_one_precomp);
                            typename CurveType::gt_type QAP =
                                pairing_policy::final_exponentiation(QAP_1 * QAP_23.unitary_inversed());
                            if (QAP != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::G1_precomp proof_g_K_precomp = CurveType::precompute_g1(proof.g_K);
                            typename pairing_policy::G1_precomp proof_g_A_g_acc_C_precomp =
                                CurveType::precompute_g1((proof.g_A.g + acc) + proof.g_C.g);
                            typename pairing_policy::Fqk_type K_1 =
                                pairing_policy::miller_loop(proof_g_K_precomp, pvk.vk_gamma_g2_precomp);
                            typename pairing_policy::Fqk_type K_23 = pairing_policy::double_miller_loop(
                                proof_g_A_g_acc_C_precomp, pvk.vk_gamma_beta_g2_precomp, pvk.vk_gamma_beta_g1_precomp,
                                proof_g_B_g_precomp);
                            typename CurveType::gt_type K =
                                pairing_policy::final_exponentiation(K_1 * K_23.unitary_inversed());
                            if (K != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS ppzkSNARK that:
                         * (1) accepts a non-processed verification key, and
                         * (2) has weak input consistency.
                         */
                        static bool verifier_weak_IC(const verification_key &vk,
                                                     const primary_input &primary_input,
                                                     const proof &proof) {
                            processed_verification_key pvk = verifier_process_vk(vk);
                            bool result = online_verifier_weak_IC(pvk, primary_input, proof);
                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS ppzkSNARK that:
                         * (1) accepts a processed verification key, and
                         * (2) has strong input consistency.
                         */
                        static bool online_verifier_strong_IC(const processed_verification_key &pvk,
                                                              const primary_input &primary_input,
                                                              const proof &proof) {
                            bool result = true;

                            if (pvk.encoded_IC_query.domain_size() != primary_input.size()) {
                                result = false;
                            } else {
                                result = online_verifier_weak_IC(pvk, primary_input, proof);
                            }

                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS ppzkSNARK that:
                         * (1) accepts a non-processed verification key, and
                         * (2) has strong input consistency.
                         */
                        static bool verifier_strong_IC(const verification_key &vk,
                                                       const primary_input &primary_input,
                                                       const proof &proof) {
                            processed_verification_key pvk = verifier_process_vk(vk);
                            bool result = online_verifier_strong_IC(pvk, primary_input, proof);
                            return result;
                        }

                        /**
                         * For debugging purposes (of verifier_component):
                         *
                         * A verifier algorithm for the R1CS ppzkSNARK that:
                         * (1) accepts a non-processed verification key,
                         * (2) has weak input consistency, and
                         * (3) uses affine coordinates for elliptic-curve computations.
                         */
                        static bool affine_verifier_weak_IC(const verification_key &vk,
                                                            const primary_input &primary_input,
                                                            const proof &proof) {
                            using pairing_policy = typename CurveType::pairing_policy;

                            assert(vk.encoded_IC_query.domain_size() >= primary_input.size());

                            typename pairing_policy::affine_ate_G2_precomp pvk_pp_G2_one_precomp =
                                pairing_policy::affine_ate_precompute_G2(typename CurveType::g2_type::value_type::one());
                            typename pairing_policy::affine_ate_G2_precomp pvk_vk_alphaA_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.alphaA_g2);
                            typename pairing_policy::affine_ate_G1_precomp pvk_vk_alphaB_g1_precomp =
                                CurveType::affine_ate_precompute_G1(vk.alphaB_g1);
                            typename pairing_policy::affine_ate_G2_precomp pvk_vk_alphaC_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.alphaC_g2);
                            typename pairing_policy::affine_ate_G2_precomp pvk_vk_rC_Z_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.rC_Z_g2);
                            typename pairing_policy::affine_ate_G2_precomp pvk_vk_gamma_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.gamma_g2);
                            typename pairing_policy::affine_ate_G1_precomp pvk_vk_gamma_beta_g1_precomp =
                                CurveType::affine_ate_precompute_G1(vk.gamma_beta_g1);
                            typename pairing_policy::affine_ate_G2_precomp pvk_vk_gamma_beta_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.gamma_beta_g2);

                            const accumulation_vector<typename CurveType::g1_type> accumulated_IC =
                                vk.encoded_IC_query.template accumulate_chunk<typename CurveType::scalar_field_type>(
                                    primary_input.begin(), primary_input.end(), 0);
                            assert(accumulated_IC.is_fully_accumulated());
                            const typename CurveType::g1_type::value_type &acc = accumulated_IC.first;

                            bool result = true;
                            typename pairing_policy::affine_ate_G1_precomp proof_g_A_g_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_A.g);
                            typename pairing_policy::affine_ate_G1_precomp proof_g_A_h_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_A.h);
                            typename pairing_policy::Fqk_type kc_A_miller = CurveType::affine_ate_e_over_e_miller_loop(
                                proof_g_A_g_precomp, pvk_vk_alphaA_g2_precomp, proof_g_A_h_precomp,
                                pvk_pp_G2_one_precomp);
                            typename CurveType::gt_type kc_A = pairing_policy::final_exponentiation(kc_A_miller);

                            if (kc_A != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::affine_ate_G2_precomp proof_g_B_g_precomp =
                                pairing_policy::affine_ate_precompute_G2(proof.g_B.g);
                            typename pairing_policy::affine_ate_G1_precomp proof_g_B_h_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_B.h);
                            typename pairing_policy::Fqk_type kc_B_miller = CurveType::affine_ate_e_over_e_miller_loop(
                                pvk_vk_alphaB_g1_precomp, proof_g_B_g_precomp, proof_g_B_h_precomp,
                                pvk_pp_G2_one_precomp);
                            typename CurveType::gt_type kc_B = pairing_policy::final_exponentiation(kc_B_miller);
                            if (kc_B != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::affine_ate_G1_precomp proof_g_C_g_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_C.g);
                            typename pairing_policy::affine_ate_G1_precomp proof_g_C_h_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_C.h);
                            typename pairing_policy::Fqk_type kc_C_miller = CurveType::affine_ate_e_over_e_miller_loop(
                                proof_g_C_g_precomp, pvk_vk_alphaC_g2_precomp, proof_g_C_h_precomp,
                                pvk_pp_G2_one_precomp);
                            typename CurveType::gt_type kc_C = pairing_policy::final_exponentiation(kc_C_miller);
                            if (kc_C != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::affine_ate_G1_precomp proof_g_A_g_acc_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_A.g + acc);
                            typename pairing_policy::affine_ate_G1_precomp proof_g_H_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_H);
                            typename pairing_policy::Fqk_type QAP_miller =
                                CurveType::affine_ate_e_times_e_over_e_miller_loop(
                                    proof_g_H_precomp, pvk_vk_rC_Z_g2_precomp, proof_g_C_g_precomp,
                                    pvk_pp_G2_one_precomp, proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                            typename CurveType::gt_type QAP = pairing_policy::final_exponentiation(QAP_miller);
                            if (QAP != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            typename pairing_policy::affine_ate_G1_precomp proof_g_K_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_K);
                            typename pairing_policy::affine_ate_G1_precomp proof_g_A_g_acc_C_precomp =
                                CurveType::affine_ate_precompute_G1((proof.g_A.g + acc) + proof.g_C.g);
                            typename pairing_policy::Fqk_type K_miller =
                                CurveType::affine_ate_e_times_e_over_e_miller_loop(
                                    proof_g_A_g_acc_C_precomp, pvk_vk_gamma_beta_g2_precomp,
                                    pvk_vk_gamma_beta_g1_precomp, proof_g_B_g_precomp, proof_g_K_precomp,
                                    pvk_vk_gamma_g2_precomp);
                            typename CurveType::gt_type K = pairing_policy::final_exponentiation(K_miller);
                            if (K != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            return result;
                        }
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_POLICY_HPP

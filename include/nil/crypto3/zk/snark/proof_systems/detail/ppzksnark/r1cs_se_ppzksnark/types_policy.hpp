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

#ifndef CRYPTO3_R1CS_SE_PPZKSNARK_BASIC_POLICY_HPP
#define CRYPTO3_R1CS_SE_PPZKSNARK_BASIC_POLICY_HPP

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
#include <nil/crypto3/zk/snark/reductions/r1cs_to_sap.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct r1cs_se_ppzksnark_types_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        using constraint_system = r1cs_constraint_system<typename CurveType::scalar_field_type>;

                        using primary_input = r1cs_primary_input<typename CurveType::scalar_field_type>;

                        using auxiliary_input = r1cs_auxiliary_input<typename CurveType::scalar_field_type>;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the R1CS SEppzkSNARK.
                         */
                        struct proving_key {
                            // G^{gamma * A_i(t)} for 0 <= i <= sap.num_variables()
                            typename std::vector<typename CurveType::g1_type::value_type> A_query;

                            // H^{gamma * A_i(t)} for 0 <= i <= sap.num_variables()
                            typename std::vector<typename CurveType::g2_type::value_type> B_query;

                            // G^{gamma^2 * C_i(t) + (alpha + beta) * gamma * A_i(t)}
                            // for sap.num_inputs() + 1 < i <= sap.num_variables()
                            typename std::vector<typename CurveType::g1_type::value_type> C_query_1;

                            // G^{2 * gamma^2 * Z(t) * A_i(t)} for 0 <= i <= sap.num_variables()
                            typename std::vector<typename CurveType::g1_type::value_type> C_query_2;

                            // G^{gamma * Z(t)}
                            typename CurveType::g1_type::value_type G_gamma_Z;

                            // H^{gamma * Z(t)}
                            typename CurveType::g2_type::value_type H_gamma_Z;

                            // G^{(alpha + beta) * gamma * Z(t)}
                            typename CurveType::g1_type::value_type G_ab_gamma_Z;

                            // G^{gamma^2 * Z(t)^2}
                            typename CurveType::g1_type::value_type G_gamma2_Z2;

                            // G^{gamma^2 * Z(t) * t^i} for 0 <= i < sap.degree
                            typename std::vector<typename CurveType::g1_type::value_type> G_gamma2_Z_t;

                            constraint_system cs;

                            proving_key() {};
                            proving_key &operator=(const proving_key &other) = default;
                            proving_key(const proving_key &other) = default;
                            proving_key(proving_key &&other) = default;
                            proving_key(typename std::vector<typename CurveType::g1_type::value_type> &&A_query,
                                        typename std::vector<typename CurveType::g2_type::value_type> &&B_query,
                                        typename std::vector<typename CurveType::g1_type::value_type> &&C_query_1,
                                        typename std::vector<typename CurveType::g1_type::value_type> &&C_query_2,
                                        typename CurveType::g1_type::value_type &G_gamma_Z,
                                        typename CurveType::g2_type::value_type &H_gamma_Z,
                                        typename CurveType::g1_type::value_type &G_ab_gamma_Z,
                                        typename CurveType::g1_type::value_type &G_gamma2_Z2,
                                        typename std::vector<typename CurveType::g1_type::value_type> &&G_gamma2_Z_t,
                                        constraint_system &&cs) :
                                A_query(std::move(A_query)),
                                B_query(std::move(B_query)), C_query_1(std::move(C_query_1)),
                                C_query_2(std::move(C_query_2)), G_gamma_Z(G_gamma_Z), H_gamma_Z(H_gamma_Z),
                                G_ab_gamma_Z(G_ab_gamma_Z), G_gamma2_Z2(G_gamma2_Z2),
                                G_gamma2_Z_t(std::move(G_gamma2_Z_t)), constraint_system(std::move(cs)) {};

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

                            bool operator==(const proving_key &other) const {
                                return (this->A_query == other.A_query && this->B_query == other.B_query &&
                                        this->C_query_1 == other.C_query_1 && this->C_query_2 == other.C_query_2 &&
                                        this->G_gamma_Z == other.G_gamma_Z && this->H_gamma_Z == other.H_gamma_Z &&
                                        this->G_ab_gamma_Z == other.G_ab_gamma_Z &&
                                        this->G_gamma2_Z2 == other.G_gamma2_Z2 &&
                                        this->G_gamma2_Z_t == other.G_gamma2_Z_t && this->cs == other.cs);
                            }
                        };

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the R1CS SEppzkSNARK.
                         */
                        struct verification_key {
                            // H
                            typename CurveType::g2_type::value_type H;

                            // G^{alpha}
                            typename CurveType::g1_type::value_type G_alpha;

                            // H^{beta}
                            typename CurveType::g2_type::value_type H_beta;

                            // G^{gamma}
                            typename CurveType::g1_type::value_type G_gamma;

                            // H^{gamma}
                            typename CurveType::g2_type::value_type H_gamma;

                            // G^{gamma * A_i(t) + (alpha + beta) * A_i(t)}
                            // for 0 <= i <= sap.num_inputs()
                            typename std::vector<typename CurveType::g1_type::value_type> query;

                            verification_key() = default;
                            verification_key(const typename CurveType::g2_type::value_type &H,
                                             const typename CurveType::g1_type::value_type &G_alpha,
                                             const typename CurveType::g2_type::value_type &H_beta,
                                             const typename CurveType::g1_type::value_type &G_gamma,
                                             const typename CurveType::g2_type::value_type &H_gamma,
                                             typename std::vector<typename CurveType::g1_type::value_type> &&query) :
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

                            bool operator==(const verification_key &other) const {
                                return (this->H == other.H && this->G_alpha == other.G_alpha &&
                                        this->H_beta == other.H_beta && this->G_gamma == other.G_gamma &&
                                        this->H_gamma == other.H_gamma && this->query == other.query);
                            }

                            /*static verification_key dummy_verification_key(const std::size_t input_size) {
                                verification_key result;
                                result.H = algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g2_type::value_type::one(); result.G_alpha = algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g1_type::value_type::one();
                            result.H_beta = algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g2_type::value_type::one(); result.G_gamma = algebra::random_element<typename
                            CurveType::scalar_field_type>() * typename CurveType::g1_type::value_type::one();
                            result.H_gamma = algebra::random_element<typename CurveType::scalar_field_type>() * typename
                            CurveType::g2_type::value_type::one();

                                typename std::vector<typename CurveType::g1_type::value_type> v;
                                for (std::size_t i = 0; i < input_size + 1; ++i) {
                                    v.emplace_back(algebra::random_element<typename CurveType::scalar_field_type>() *
                            typename CurveType::g1_type::value_type::one());
                                }
                                result.query = std::move(v);

                                return result;
                            }*/
                        };

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the R1CS SEppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        class processed_verification_key {
                            using pairing_policy = typename CurveType::pairing_policy;

                        public:
                            typename CurveType::g1_type::value_type G_alpha;
                            typename CurveType::g2_type::value_type H_beta;
                            typename pairing_policy::Fqk_type G_alpha_H_beta_ml;
                            typename pairing_policy::G1_precomp G_gamma_pc;
                            typename pairing_policy::G2_precomp H_gamma_pc;
                            typename pairing_policy::G2_precomp H_pc;

                            typename std::vector<typename CurveType::g1_type::value_type> query;

                            bool operator==(const processed_verification_key &other) const {
                                return (this->G_alpha == other.G_alpha && this->H_beta == other.H_beta &&
                                        this->G_alpha_H_beta_ml == other.G_alpha_H_beta_ml &&
                                        this->G_gamma_pc == other.G_gamma_pc && this->H_gamma_pc == other.H_gamma_pc &&
                                        this->H_pc == other.H_pc && this->query == other.query);
                            }
                        };

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the R1CS SEppzkSNARK, which consists of a proving key and a verification key.
                         */
                        class keypair {
                        public:
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
                         * A proof for the R1CS SEppzkSNARK.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        struct proof {
                            typename CurveType::g1_type::value_type A;
                            typename CurveType::g2_type::value_type B;
                            typename CurveType::g1_type::value_type C;

                            proof() {
                            }
                            proof(typename CurveType::g1_type::value_type &&A,
                                  typename CurveType::g2_type::value_type &&B,
                                  typename CurveType::g1_type::value_type &&C) :
                                A(std::move(A)),
                                B(std::move(B)), C(std::move(C)) {};

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

                            bool operator==(const proof &other) const {
                                return (this->A == other.A && this->B == other.B && this->C == other.C);
                            }
                        };

                        /***************************** Main algorithms *******************************/

                        /*
                         Below are four variants of verifier algorithm for the R1CS SEppzkSNARK.

                         These are the four cases that arise from the following two choices:

                         (1) The verifier accepts a (non-processed) verification key or, instead, a processed
                         verification key. In the latter case, we call the algorithm an "online verifier".

                         (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
                             Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
                             weak input consistency requires that |primary_input| <= CS.num_inputs (and
                             the primary input is implicitly padded with zeros up to length CS.num_inputs).
                         */

                        /**
                         * A generator algorithm for the R1CS SEppzkSNARK.
                         *
                         * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for
                         * CS.
                         */
                        static keypair generator(const constraint_system &cs) {

                            /**
                             * draw random element t at which the SAP is evaluated.
                             * it should be the case that Z(t) != 0
                             */
                            const std::shared_ptr<fft::evaluation_domain<typename CurveType::scalar_field_type>>
                                domain = r1cs_to_sap::get_domain(cs);
                            typename CurveType::scalar_field_type::value_type t;
                            do {
                                t = algebra::random_element<typename CurveType::scalar_field_type>();
                            } while (domain->compute_vanishing_polynomial(t).is_zero());

                            sap_instance_evaluation<typename CurveType::scalar_field_type> sap_inst =
                                r1cs_to_sap::instance_map_with_evaluation(cs, t);

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

                            const typename CurveType::scalar_field_type::value_type
                                alpha = algebra::random_element<typename CurveType::scalar_field_type>(),
                                beta = algebra::random_element<typename CurveType::scalar_field_type>(),
                                gamma = algebra::random_element<typename CurveType::scalar_field_type>();
                            const typename CurveType::g1_type::value_type G =
                                algebra::random_element<typename CurveType::g1_type>();
                            const typename CurveType::g2_type::value_type H =
                                algebra::random_element<typename CurveType::g2_type>();

                            std::size_t G_exp_count = sap_inst.num_inputs() + 1    // verifier_query
                                                      + non_zero_At                // A_query
                                                      + sap_inst.degree() +
                                                      1    // G_gamma2_Z_t
                                                      // C_query_1
                                                      + sap_inst.num_variables() - sap_inst.num_inputs() +
                                                      sap_inst.num_variables() + 1,    // C_query_2
                                G_window = algebra::get_exp_window_size<typename CurveType::g1_type>(G_exp_count);

                            algebra::window_table<typename CurveType::g1_type> G_table =
                                get_window_table(typename CurveType::scalar_field_type::value_bits, G_window, G);

                            typename CurveType::g2_type::value_type H_gamma = gamma * H;
                            std::size_t H_gamma_exp_count = non_zero_At,    // B_query
                                H_gamma_window =
                                    algebra::get_exp_window_size<typename CurveType::g2_type>(H_gamma_exp_count);
                            algebra::window_table<typename CurveType::g2_type> H_gamma_table = get_window_table(
                                typename CurveType::scalar_field_type::value_bits, H_gamma_window, H_gamma);

                            typename CurveType::g1_type::value_type G_alpha = alpha * G;
                            typename CurveType::g2_type::value_type H_beta = beta * H;

                            std::vector<typename CurveType::scalar_field_type::value_type> tmp_exponents;
                            tmp_exponents.reserve(sap_inst.num_inputs() + 1);
                            for (std::size_t i = 0; i <= sap_inst.num_inputs(); ++i) {
                                tmp_exponents.emplace_back(gamma * Ct[i] + (alpha + beta) * At[i]);
                            }
                            typename std::vector<typename CurveType::g1_type::value_type> verifier_query =
                                algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                    typename CurveType::scalar_field_type::value_bits, G_window, G_table,
                                    tmp_exponents);
                            tmp_exponents.clear();

                            tmp_exponents.reserve(sap_inst.num_variables() + 1);
                            for (std::size_t i = 0; i < At.size(); i++) {
                                tmp_exponents.emplace_back(gamma * At[i]);
                            }

                            typename std::vector<typename CurveType::g1_type::value_type> A_query =
                                algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                    typename CurveType::scalar_field_type::value_bits, G_window, G_table,
                                    tmp_exponents);
                            tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(A_query);
#endif
                            typename std::vector<typename CurveType::g2_type::value_type> B_query =
                                algebra::batch_exp<typename CurveType::g2_type, typename CurveType::scalar_field_type>(
                                    typename CurveType::scalar_field_type::value_bits, H_gamma_window, H_gamma_table,
                                    At);
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g2_type>(B_query);
#endif
                            typename CurveType::g1_type::value_type G_gamma = gamma * G;
                            typename CurveType::g1_type::value_type G_gamma_Z = sap_inst.Zt * G_gamma;
                            typename CurveType::g2_type::value_type H_gamma_Z = sap_inst.Zt * H_gamma;
                            typename CurveType::g1_type::value_type G_ab_gamma_Z = (alpha + beta) * G_gamma_Z;
                            typename CurveType::g1_type::value_type G_gamma2_Z2 = (sap_inst.Zt * gamma) * G_gamma_Z;

                            tmp_exponents.reserve(sap_inst.degree() + 1);

                            /* Compute the vector G_gamma2_Z_t := Z(t) * t^i * gamma^2 * G */
                            typename CurveType::scalar_field_type gamma2_Z_t = sap_inst.Zt * gamma.squared();
                            for (std::size_t i = 0; i < sap_inst.degree() + 1; ++i) {
                                tmp_exponents.emplace_back(gamma2_Z_t);
                                gamma2_Z_t *= t;
                            }
                            typename std::vector<typename CurveType::g1_type::value_type> G_gamma2_Z_t =
                                algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                    typename CurveType::scalar_field_type::value_bits, G_window, G_table,
                                    tmp_exponents);
                            tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(G_gamma2_Z_t);
#endif
                            tmp_exponents.reserve(sap_inst.num_variables() - sap_inst.num_inputs());
                            for (std::size_t i = sap_inst.num_inputs() + 1; i <= sap_inst.num_variables(); ++i) {
                                tmp_exponents.emplace_back(gamma * (gamma * Ct[i] + (alpha + beta) * At[i]));
                            }
                            typename std::vector<typename CurveType::g1_type::value_type> C_query_1 =
                                algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                    typename CurveType::scalar_field_type::value_bits, G_window, G_table,
                                    tmp_exponents);
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
                            typename std::vector<typename CurveType::g1_type::value_type> C_query_2 =
                                algebra::batch_exp<typename CurveType::g1_type, typename CurveType::scalar_field_type>(
                                    typename CurveType::scalar_field_type::value_bits, G_window, G_table,
                                    tmp_exponents);
                            tmp_exponents.clear();
#ifdef USE_MIXED_ADDITION
                            algebra::batch_to_special<typename CurveType::g1_type>(C_query_2);
#endif

                            verification_key vk =
                                verification_key(H, G_alpha, H_beta, G_gamma, H_gamma, std::move(verifier_query));

                            constraint_system cs_copy(cs);

                            proving_key pk = proving_key(std::move(A_query), std::move(B_query), std::move(C_query_1),
                                                         std::move(C_query_2), G_gamma_Z, H_gamma_Z, G_ab_gamma_Z,
                                                         G_gamma2_Z2, std::move(G_gamma2_Z_t), std::move(cs_copy));

                            pk.print_size();
                            vk.print_size();

                            return keypair(std::move(pk), std::move(vk));
                        }

                        /**
                         * A prover algorithm for the R1CS SEppzkSNARK.
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
                                d2 = algebra::random_element<typename CurveType::scalar_field_type>();

                            const sap_witness<typename CurveType::scalar_field_type> sap_wit =
                                r1cs_to_sap::witness_map(pk.constraint_system, primary_input, auxiliary_input, d1, d2);

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            const typename CurveType::scalar_field_type::value_type r =
                                algebra::random_element<typename CurveType::scalar_field_type>();

                            /**
                             * compute A = G^{gamma * (\sum_{i=0}^m input_i * A_i(t) + r * Z(t))}
                             *           = \prod_{i=0}^m (G^{gamma * A_i(t)})^{input_i)
                             *             * (G^{gamma * Z(t)})^r
                             *           = \prod_{i=0}^m A_query[i]^{input_i} * G_gamma_Z^r
                             */
                            typename CurveType::g1_type::value_type A =
                                r * pk.G_gamma_Z + pk.A_query[0] +    // i = 0 is a special case because input_i = 1
                                sap_wit.d1 * pk.G_gamma_Z +           // ZK-patch
                                algebra::multiexp<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                  algebra::multiexp_method_BDLO12>(pk.A_query.begin() + 1,
                                                                                   pk.A_query.end(),
                                                                                   sap_wit.coefficients_for_ACs.begin(),
                                                                                   sap_wit.coefficients_for_ACs.end(),
                                                                                   chunks);

                            /**
                             * compute B exactly as A, except with H as the base
                             */
                            typename CurveType::g2_type::value_type B =
                                r * pk.H_gamma_Z + pk.B_query[0] +    // i = 0 is a special case because input_i = 1
                                sap_wit.d1 * pk.H_gamma_Z +           // ZK-patch
                                algebra::multiexp<typename CurveType::g2_type, typename CurveType::scalar_field_type,
                                                  algebra::multiexp_method_BDLO12>(pk.B_query.begin() + 1,
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
                            typename CurveType::g1_type::value_type C =
                                algebra::multiexp<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                  algebra::multiexp_method_BDLO12>(
                                    pk.C_query_1.begin(),
                                    pk.C_query_1.end(),
                                    sap_wit.coefficients_for_ACs.begin() + sap_wit.num_inputs(),
                                    sap_wit.coefficients_for_ACs.end(),
                                    chunks) +
                                (r * r) * pk.G_gamma2_Z2 + r * pk.G_ab_gamma_Z +
                                sap_wit.d1 * pk.G_ab_gamma_Z +             // ZK-patch
                                r * pk.C_query_2[0] +                      // i = 0 is a special case for C_query_2
                                (r + r) * sap_wit.d1 * pk.G_gamma2_Z2 +    // ZK-patch for C_query_2
                                r * algebra::multiexp<typename CurveType::g1_type,
                                                      typename CurveType::scalar_field_type,
                                                      algebra::multiexp_method_BDLO12>(
                                        pk.C_query_2.begin() + 1,
                                        pk.C_query_2.end(),
                                        sap_wit.coefficients_for_ACs.begin(),
                                        sap_wit.coefficients_for_ACs.end(),
                                        chunks) +
                                sap_wit.d2 * pk.G_gamma2_Z_t[0] +    // ZK-patch
                                algebra::multiexp<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                  algebra::multiexp_method_BDLO12>(pk.G_gamma2_Z_t.begin(),
                                                                                   pk.G_gamma2_Z_t.end(),
                                                                                   sap_wit.coefficients_for_H.begin(),
                                                                                   sap_wit.coefficients_for_H.end(),
                                                                                   chunks);

                            proof prf = proof(std::move(A), std::move(B), std::move(C));
                            prf.print_size();

                            return prf;
                        }

                        /**
                         * Convert a (non-processed) verification key into a processed verification key.
                         */
                        static processed_verification_key verifier_process_vk(const verification_key &vk) {
                            using pairing_policy = typename CurveType::pairing_policy;

                            typename pairing_policy::G1_precomp G_alpha_pc = pairing_policy::precompute_g1(vk.G_alpha);
                            typename pairing_policy::G2_precomp H_beta_pc = pairing_policy::precompute_g2(vk.H_beta);

                            processed_verification_key pvk;
                            pvk.G_alpha = vk.G_alpha;
                            pvk.H_beta = vk.H_beta;
                            pvk.G_alpha_H_beta_ml = pairing_policy::miller_loop(G_alpha_pc, H_beta_pc);
                            pvk.G_gamma_pc = pairing_policy::precompute_g1(vk.G_gamma);
                            pvk.H_gamma_pc = pairing_policy::precompute_g2(vk.H_gamma);
                            pvk.H_pc = pairing_policy::precompute_g2(vk.H);

                            pvk.query = vk.query;

                            return pvk;
                        }

                        /**
                         * A verifier algorithm for the R1CS ppzkSNARK that:
                         * (1) accepts a processed verification key, and
                         * (2) has weak input consistency.
                         */
                        static bool online_verifier_weak_IC(using pairing_policy = typename CurveType::pairing_policy;

                                                            const processed_verification_key &pvk,
                                                            const primary_input &primary_input,
                                                            const proof &proof) {

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }

#ifdef MULTICORE
                            const std::size_t chunks = omp_get_max_threads();    // to override, set OMP_NUM_THREADS env
                                                                                 // var or call omp_set_num_threads()
#else
                            const std::size_t chunks = 1;
#endif

                            /**
                             * e(A*G^{alpha}, B*H^{beta}) = e(G^{alpha}, H^{beta}) * e(G^{psi}, H^{gamma})
                             *                              * e(C, H)
                             * where psi = \sum_{i=0}^l input_i pvk.query[i]
                             */
                            typename CurveType::g1_type::value_type G_psi =
                                pvk.query[0] +
                                algebra::multiexp<typename CurveType::g1_type, typename CurveType::scalar_field_type,
                                                  algebra::multiexp_method_bos_coster>(
                                    pvk.query.begin() + 1, pvk.query.end(), primary_input.begin(), primary_input.end(),
                                    chunks);

                            typename pairing_policy::Fqk_type test1_l = pairing_policy::miller_loop(
                                                                  pairing_policy::precompute_g1(proof.A + pvk.G_alpha),
                                                                  pairing_policy::precompute_g2(proof.B + pvk.H_beta)),
                                                              test1_r1 = pvk.G_alpha_H_beta_ml,
                                                              test1_r2 = pairing_policy::miller_loop(
                                                                  pairing_policy::precompute_g1(G_psi), pvk.H_gamma_pc),
                                                              test1_r3 = pairing_policy::miller_loop(
                                                                  pairing_policy::precompute_g1(proof.C), pvk.H_pc);
                            typename CurveType::gt_type test1 = pairing_policy::final_exponentiation(
                                test1_l.unitary_inversed() * test1_r1 * test1_r2 * test1_r3);

                            if (test1 != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            /**
                             * e(A, H^{gamma}) = e(G^{gamma}, B)
                             */
                            typename pairing_policy::Fqk_type test2_l = pairing_policy::miller_loop(
                                                                  pairing_policy::precompute_g1(proof.A),
                                                                  pvk.H_gamma_pc),
                                                              test2_r = pairing_policy::miller_loop(
                                                                  pvk.G_gamma_pc,
                                                                  pairing_policy::precompute_g2(proof.B));
                            typename CurveType::gt_type test2 =
                                pairing_policy::final_exponentiation(test2_l * test2_r.unitary_inversed());

                            if (test2 != typename CurveType::gt_type::one()) {
                                result = false;
                            }

                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS SEppzkSNARK that:
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

                            if (pvk.query.size() != primary_input.size() + 1) {
                                result = false;
                            } else {
                                result = online_verifier_weak_IC(pvk, primary_input, proof);
                            }

                            return result;
                        }

                        /**
                         * A verifier algorithm for the R1CS SEppzkSNARK that:
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
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_SE_PPZKSNARK_BASIC_POLICY_HPP

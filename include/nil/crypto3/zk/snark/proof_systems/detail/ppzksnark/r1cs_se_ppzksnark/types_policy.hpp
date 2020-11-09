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

#ifndef CRYPTO3_R1CS_SE_PPZKSNARK_TYPES_POLICY_HPP
#define CRYPTO3_R1CS_SE_PPZKSNARK_TYPES_POLICY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

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
                            typedef typename CurveType::pairing_policy pairing_policy;

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
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_SE_PPZKSNARK_TYPES_POLICY_HPP

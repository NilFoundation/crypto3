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
// @file Declaration of interfaces for a ppzkSNARK for R1CS with a security proof
// in the generic group (GG) model.
//
// This includes:
//- class for proving key
//- class for verification key
//- class for processed verification key
//- class for key pair (proving key & verification key)
//- class for proof
//- generator algorithm
//- prover algorithm
//- verifier algorithm (with strong or weak input consistency)
//- online verifier algorithm (with strong or weak input consistency)
//
// The implementation instantiates the protocol of \[Gro16].
//
//
// Acronyms:
//
//- R1CS = "Rank-1 Constraint Systems"
//- ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//
// References:
//
//\[Gro16]:
// "On the Size of Pairing-based Non-interactive Arguments",
// Jens Groth,
// EUROCRYPT 2016,
// <https://eprint.iacr.org/2016/260>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP

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
                    struct r1cs_gg_ppzksnark_types_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        using constraint_system = r1cs_constraint_system<typename CurveType::scalar_field_type>;

                        using primary_input = r1cs_primary_input<typename CurveType::scalar_field_type>;

                        using auxiliary_input = r1cs_auxiliary_input<typename CurveType::scalar_field_type>;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the R1CS GG-ppzkSNARK.
                         */
                        struct proving_key {

                            typename CurveType::g1_type::value_type alpha_g1;
                            typename CurveType::g1_type::value_type beta_g1;
                            typename CurveType::g2_type::value_type beta_g2;
                            typename CurveType::g1_type::value_type delta_g1;
                            typename CurveType::g2_type::value_type delta_g2;

                            typename std::vector<typename CurveType::g1_type::value_type>
                                A_query;    // this could be a sparse vector if we had multiexp for those
                            knowledge_commitment_vector<typename CurveType::g2_type, 
                                                        typename CurveType::g1_type> B_query;
                            typename std::vector<typename CurveType::g1_type::value_type> H_query;
                            typename std::vector<typename CurveType::g1_type::value_type> L_query;

                            constraint_system cs;

                            proving_key() {};
                            proving_key &operator=(const proving_key &other) = default;
                            proving_key(const proving_key &other) = default;
                            proving_key(proving_key &&other) = default;
                            proving_key(typename CurveType::g1_type::value_type &&alpha_g1,
                                        typename CurveType::g1_type::value_type &&beta_g1,
                                        typename CurveType::g2_type::value_type &&beta_g2,
                                        typename CurveType::g1_type::value_type &&delta_g1,
                                        typename CurveType::g2_type::value_type &&delta_g2,
                                        typename std::vector<typename CurveType::g1_type::value_type> &&A_query,
                                        knowledge_commitment_vector<typename CurveType::g2_type,
                                                                    typename CurveType::g1_type> &&B_query,
                                        typename std::vector<typename CurveType::g1_type::value_type> &&H_query,
                                        typename std::vector<typename CurveType::g1_type::value_type> &&L_query,
                                        constraint_system &&cs) :
                                alpha_g1(std::move(alpha_g1)),
                                beta_g1(std::move(beta_g1)), beta_g2(std::move(beta_g2)), delta_g1(std::move(delta_g1)),
                                delta_g2(std::move(delta_g2)), A_query(std::move(A_query)), B_query(std::move(B_query)),
                                H_query(std::move(H_query)), L_query(std::move(L_query)), cs(std::move(cs)) {};

                            std::size_t G1_size() const {
                                return 1 + A_query.size() + B_query.domain_size() + H_query.size() + L_query.size();
                            }

                            std::size_t G2_size() const {
                                return 1 + B_query.domain_size();
                            }

                            std::size_t G1_sparse_size() const {
                                return 1 + A_query.size() + B_query.size() + H_query.size() + L_query.size();
                            }

                            std::size_t G2_sparse_size() const {
                                return 1 + B_query.size();
                            }

                            std::size_t size_in_bits() const {
                                return A_query.size() * CurveType::g1_type::value_bits + B_query.size_in_bits() +
                                       H_query.size() * CurveType::g1_type::value_bits +
                                       L_query.size() * CurveType::g1_type::value_bits +
                                       1 * CurveType::g1_type::value_bits + 1 * CurveType::g2_type::value_bits;
                            }

                            bool operator==(const proving_key &other) const {
                                return (this->alpha_g1 == other.alpha_g1 && this->beta_g1 == other.beta_g1 &&
                                        this->beta_g2 == other.beta_g2 && this->delta_g1 == other.delta_g1 &&
                                        this->delta_g2 == other.delta_g2 && this->A_query == other.A_query &&
                                        this->B_query == other.B_query && this->H_query == other.H_query &&
                                        this->L_query == other.L_query && this->cs == other.cs);
                            }
                        };

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the R1CS GG-ppzkSNARK.
                         */
                        struct verification_key {

                            typename CurveType::gt_type::value_type alpha_g1_beta_g2;
                            typename CurveType::g2_type::value_type gamma_g2;
                            typename CurveType::g2_type::value_type delta_g2;

                            accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1;

                            verification_key() = default;
                            verification_key(const typename CurveType::gt_type::value_type &alpha_g1_beta_g2,
                                             const typename CurveType::g2_type::value_type &gamma_g2,
                                             const typename CurveType::g2_type::value_type &delta_g2,
                                             const accumulation_vector<typename CurveType::g1_type> &gamma_ABC_g1) :
                                alpha_g1_beta_g2(alpha_g1_beta_g2),
                                gamma_g2(gamma_g2), delta_g2(delta_g2), gamma_ABC_g1(gamma_ABC_g1) {};

                            std::size_t G1_size() const {
                                return gamma_ABC_g1.size();
                            }

                            std::size_t G2_size() const {
                                return 2;
                            }

                            std::size_t GT_size() const {
                                return 1;
                            }

                            std::size_t size_in_bits() const {
                                // TODO: include GT size
                                return (gamma_ABC_g1.size_in_bits() + 2 * CurveType::g2_type::value_bits);
                            }

                            bool operator==(const verification_key &other) const {
                                return (this->alpha_g1_beta_g2 == other.alpha_g1_beta_g2 &&
                                        this->gamma_g2 == other.gamma_g2 && this->delta_g2 == other.delta_g2 &&
                                        this->gamma_ABC_g1 == other.gamma_ABC_g1);
                            }

                            /*static verification_key dummy_verification_key(const std::size_t input_size) {
                                verification_key result;
                                result.alpha_g1_beta_g2 =
                                    algebra::random_element<typename CurveType::scalar_field_type>() *
                                    algebra::random_element<typename CurveType::gt_type>();
                                result.gamma_g2 = algebra::random_element<typename CurveType::g2_type>();
                                result.delta_g2 = algebra::random_element<typename CurveType::g2_type>();

                                typename CurveType::g1_type::value_type base =
                                    algebra::random_element<typename CurveType::g1_type>();
                                typename std::vector<typename CurveType::g1_type::value_type> v;
                                for (std::size_t i = 0; i < input_size; ++i) {
                                    v.emplace_back(algebra::random_element<typename CurveType::g1_type>());
                                }

                                result.gamma_ABC_g1 =
                                    accumulation_vector<typename CurveType::g1_type>(std::move(base), std::move(v));

                                return result;
                            }*/
                        };

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the R1CS GG-ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        class processed_verification_key {
                            typedef typename CurveType::pairing_policy pairing_policy;

                        public:
                            typename CurveType::gt_type::value_type vk_alpha_g1_beta_g2;
                            typename pairing_policy::G2_precomp vk_gamma_g2_precomp;
                            typename pairing_policy::G2_precomp vk_delta_g2_precomp;

                            accumulation_vector<typename CurveType::g1_type> gamma_ABC_g1;

                            bool operator==(const processed_verification_key &other) const {
                                return (this->vk_alpha_g1_beta_g2 == other.vk_alpha_g1_beta_g2 &&
                                        this->vk_gamma_g2_precomp == other.vk_gamma_g2_precomp &&
                                        this->vk_delta_g2_precomp == other.vk_delta_g2_precomp &&
                                        this->gamma_ABC_g1 == other.gamma_ABC_g1);
                            }
                        };

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the R1CS GG-ppzkSNARK, which consists of a proving key and a verification key.
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
                         * A proof for the R1CS GG-ppzkSNARK.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        struct proof {

                            typename CurveType::g1_type::value_type g_A;
                            typename CurveType::g2_type::value_type g_B;
                            typename CurveType::g1_type::value_type g_C;

                            proof() {
                                // invalid proof with valid curve points
                                this->g_A = typename CurveType::g1_type::value_type::one();
                                this->g_B = typename CurveType::g2_type::value_type::one();
                                this->g_C = typename CurveType::g1_type::value_type::one();
                            }
                            proof(typename CurveType::g1_type::value_type &&g_A,
                                  typename CurveType::g2_type::value_type &&g_B,
                                  typename CurveType::g1_type::value_type &&g_C) :
                                g_A(std::move(g_A)),
                                g_B(std::move(g_B)), g_C(std::move(g_C)) {};

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
                                // return (g_A.is_well_formed() && g_B.is_well_formed() && g_C.is_well_formed());
                                // uncomment
                                // when is_well_formed ready
                                return true;
                            }

                            bool operator==(const proof &other) const {
                                return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C);
                            }
                        };
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP

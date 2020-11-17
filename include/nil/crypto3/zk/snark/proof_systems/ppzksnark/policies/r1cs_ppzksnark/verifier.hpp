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

#ifndef CRYPTO3_R1CS_PPZKSNARK_BASIC_VERIFIER_HPP
#define CRYPTO3_R1CS_PPZKSNARK_BASIC_VERIFIER_HPP

#include <memory>

#include <nil/crypto3/zk/snark/accumulation_vector.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/crypto3/zk/snark/reductions/r1cs_to_qap.hpp>

#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_ppzksnark/types_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * Convert a (non-processed) verification key into a processed verification key.
                 */
                template<typename CurveType>
                class r1cs_ppzksnark_verifier_process_vk {
                    using types_policy = detail::r1cs_ppzksnark_types_policy<CurveType>;

                public:
                    typedef typename types_policy::constraint_system constraint_system_type;
                    typedef typename types_policy::primary_input primary_input_type;
                    typedef typename types_policy::auxiliary_input auxiliary_input_type;

                    typedef typename types_policy::proving_key proving_key_type;
                    typedef typename types_policy::verification_key verification_key_type;
                    typedef typename types_policy::processed_verification_key processed_verification_key_type;

                    typedef typename types_policy::keypair keypair_type;
                    typedef typename types_policy::proof proof_type;

                    static inline processed_verification_key_type
                        process(const verification_key_type &verification_key) {

                        typedef typename CurveType::pairing_policy pairing_policy;

                        processed_verification_key_type processed_verification_key;
                        processed_verification_key.pp_G2_one_precomp =
                            pairing_policy::precompute_g2(CurveType::g2_type::value_type::one());
                        processed_verification_key.vk_alphaA_g2_precomp =
                            pairing_policy::precompute_g2(verification_key.alphaA_g2);
                        processed_verification_key.vk_alphaB_g1_precomp =
                            pairing_policy::precompute_g1(verification_key.alphaB_g1);
                        processed_verification_key.vk_alphaC_g2_precomp =
                            pairing_policy::precompute_g2(verification_key.alphaC_g2);
                        processed_verification_key.vk_rC_Z_g2_precomp =
                            pairing_policy::precompute_g2(verification_key.rC_Z_g2);
                        processed_verification_key.vk_gamma_g2_precomp =
                            pairing_policy::precompute_g2(verification_key.gamma_g2);
                        processed_verification_key.vk_gamma_beta_g1_precomp =
                            pairing_policy::precompute_g1(verification_key.gamma_beta_g1);
                        processed_verification_key.vk_gamma_beta_g2_precomp =
                            pairing_policy::precompute_g2(verification_key.gamma_beta_g2);

                        processed_verification_key.encoded_IC_query = verification_key.encoded_IC_query;

                        return processed_verification_key;
                    }
                };

                namespace policies {

                    /**
                     * A verifier algorithm for the R1CS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has weak input consistency.
                     */
                    template<typename CurveType>
                    class r1cs_ppzksnark_online_verifier_weak_input_consistency {
                        using types_policy = detail::r1cs_ppzksnark_types_policy<CurveType>;

                        using pairing_policy = typename CurveType::pairing_policy;
                        using g1_type = typename CurveType::g1_type;
                        using g2_type = typename CurveType::g2_type;
                        using gt_type = typename CurveType::gt_type;
                        using g1_value_type = typename g1_type::value_type;
                        using g2_value_type = typename g2_type::value_type;
                        using gt_value_type = typename gt_type::value_type;
                        using scalar_field_type = typename CurveType::scalar_field_type;
                        using G1_precomp = typename pairing_policy::G1_precomp;
                        using G2_precomp = typename pairing_policy::G2_precomp;
                        using Fqk_type = typename pairing_policy::Fqk_type;
                    public:
                        typedef typename types_policy::constraint_system constraint_system_type;
                        typedef typename types_policy::primary_input primary_input_type;
                        typedef typename types_policy::auxiliary_input auxiliary_input_type;

                        typedef typename types_policy::proving_key proving_key_type;
                        typedef typename types_policy::verification_key verification_key_type;
                        typedef typename types_policy::processed_verification_key processed_verification_key_type;

                        typedef typename types_policy::keypair keypair_type;
                        typedef typename types_policy::proof proof_type;

                        static inline bool process(const processed_verification_key_type &processed_verification_key,
                                                   const primary_input_type &primary_input,
                                                   const proof_type &proof) {

                            assert(processed_verification_key.encoded_IC_query.domain_size() >= primary_input.size());

                            const accumulation_vector<g1_type> accumulated_IC =
                                processed_verification_key.encoded_IC_query
                                    .template accumulate_chunk<scalar_field_type>(
                                        primary_input.begin(), primary_input.end(), 0);
                            const g1_value_type &acc = accumulated_IC.first;

                            bool result = true;

                            if (!proof.is_well_formed()) {
                                result = false;
                            }
                            G1_precomp proof_g_A_g_precomp =
                                pairing_policy::precompute_g1(proof.g_A.g);
                            G1_precomp proof_g_A_h_precomp =
                                pairing_policy::precompute_g1(proof.g_A.h);
                            typename Fqk_type::value_type kc_A_1 = pairing_policy::miller_loop(
                                proof_g_A_g_precomp, processed_verification_key.vk_alphaA_g2_precomp);
                            typename Fqk_type::value_type kc_A_2 = pairing_policy::miller_loop(
                                proof_g_A_h_precomp, processed_verification_key.pp_G2_one_precomp);
                            gt_value_type kc_A =
                                pairing_policy::final_exponentiation(kc_A_1 * kc_A_2.unitary_inversed());
                            if (kc_A != gt_value_type::one()) {
                                result = false;
                            }

                            G2_precomp proof_g_B_g_precomp =
                                pairing_policy::precompute_g2(proof.g_B.g);
                            G1_precomp proof_g_B_h_precomp =
                                pairing_policy::precompute_g1(proof.g_B.h);
                            typename Fqk_type::value_type kc_B_1 = pairing_policy::miller_loop(
                                processed_verification_key.vk_alphaB_g1_precomp, proof_g_B_g_precomp);
                            typename Fqk_type::value_type kc_B_2 = pairing_policy::miller_loop(
                                proof_g_B_h_precomp, processed_verification_key.pp_G2_one_precomp);
                            gt_value_type kc_B =
                                pairing_policy::final_exponentiation(kc_B_1 * kc_B_2.unitary_inversed());
                            if (kc_B != gt_value_type::one()) {
                                result = false;
                            }

                            G1_precomp proof_g_C_g_precomp =
                                pairing_policy::precompute_g1(proof.g_C.g);
                            G1_precomp proof_g_C_h_precomp =
                                pairing_policy::precompute_g1(proof.g_C.h);
                            typename Fqk_type::value_type kc_C_1 = pairing_policy::miller_loop(
                                proof_g_C_g_precomp, processed_verification_key.vk_alphaC_g2_precomp);
                            typename Fqk_type::value_type kc_C_2 = pairing_policy::miller_loop(
                                proof_g_C_h_precomp, processed_verification_key.pp_G2_one_precomp);
                            gt_value_type kc_C =
                                pairing_policy::final_exponentiation(kc_C_1 * kc_C_2.unitary_inversed());
                            if (kc_C != gt_value_type::one()) {
                                result = false;
                            }

                            // check that g^((A+acc)*B)=g^(H*\Prod(t-\sigma)+C)
                            // equivalently, via pairings, that e(g^(A+acc), g^B) = e(g^H, g^Z) + e(g^C, g^1)
                            G1_precomp proof_g_A_g_acc_precomp =
                                pairing_policy::precompute_g1(proof.g_A.g + acc);
                            G1_precomp proof_g_H_precomp =
                                pairing_policy::precompute_g1(proof.g_H);
                            typename Fqk_type::value_type QAP_1 =
                                pairing_policy::miller_loop(proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                            typename Fqk_type::value_type QAP_23 = pairing_policy::double_miller_loop(
                                proof_g_H_precomp, processed_verification_key.vk_rC_Z_g2_precomp, proof_g_C_g_precomp,
                                processed_verification_key.pp_G2_one_precomp);
                            gt_value_type QAP =
                                pairing_policy::final_exponentiation(QAP_1 * QAP_23.unitary_inversed());
                            if (QAP != gt_value_type::one()) {
                                result = false;
                            }

                            G1_precomp proof_g_K_precomp =
                                pairing_policy::precompute_g1(proof.g_K);
                            G1_precomp proof_g_A_g_acc_C_precomp =
                                pairing_policy::precompute_g1((proof.g_A.g + acc) + proof.g_C.g);
                            typename Fqk_type::value_type K_1 = pairing_policy::miller_loop(
                                proof_g_K_precomp, processed_verification_key.vk_gamma_g2_precomp);
                            typename Fqk_type::value_type K_23 = pairing_policy::double_miller_loop(
                                proof_g_A_g_acc_C_precomp, processed_verification_key.vk_gamma_beta_g2_precomp,
                                processed_verification_key.vk_gamma_beta_g1_precomp, proof_g_B_g_precomp);
                            gt_value_type K =
                                pairing_policy::final_exponentiation(K_1 * K_23.unitary_inversed());
                            if (K != gt_value_type::one()) {
                                result = false;
                            }

                            return result;
                        }
                    };

                    /**
                     * A verifier algorithm for the R1CS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has weak input consistency.
                     */
                    template<typename CurveType>
                    class r1cs_ppzksnark_verifier_weak_input_consistency {
                        using types_policy = detail::r1cs_ppzksnark_types_policy<CurveType>;

                    public:
                        typedef typename types_policy::constraint_system constraint_system_type;
                        typedef typename types_policy::primary_input primary_input_type;
                        typedef typename types_policy::auxiliary_input auxiliary_input_type;

                        typedef typename types_policy::proving_key proving_key_type;
                        typedef typename types_policy::verification_key verification_key_type;
                        typedef typename types_policy::processed_verification_key processed_verification_key_type;

                        typedef typename types_policy::keypair keypair_type;
                        typedef typename types_policy::proof proof_type;

                        static inline bool process(const verification_key_type &verification_key,
                                                   const primary_input_type &primary_input,
                                                   const proof_type &proof) {
                            processed_verification_key_type processed_verification_key =
                                r1cs_ppzksnark_verifier_process_vk<CurveType>::process(verification_key);
                            bool result = r1cs_ppzksnark_online_verifier_weak_input_consistency<CurveType>::process(
                                processed_verification_key, primary_input, proof);
                            return result;
                        }
                    };

                    /**
                     * A verifier algorithm for the R1CS ppzkSNARK that:
                     * (1) accepts a processed verification key, and
                     * (2) has strong input consistency.
                     */
                    template<typename CurveType>
                    class r1cs_ppzksnark_online_verifier_strong_input_consistency {
                        using types_policy = detail::r1cs_ppzksnark_types_policy<CurveType>;

                    public:
                        typedef typename types_policy::constraint_system constraint_system_type;
                        typedef typename types_policy::primary_input primary_input_type;
                        typedef typename types_policy::auxiliary_input auxiliary_input_type;

                        typedef typename types_policy::proving_key proving_key_type;
                        typedef typename types_policy::verification_key verification_key_type;
                        typedef typename types_policy::processed_verification_key processed_verification_key_type;

                        typedef typename types_policy::keypair keypair_type;
                        typedef typename types_policy::proof proof_type;

                        static inline bool process(const processed_verification_key_type &processed_verification_key,
                                                   const primary_input_type &primary_input,
                                                   const proof_type &proof) {
                            bool result = true;

                            if (processed_verification_key.encoded_IC_query.domain_size() != primary_input.size()) {
                                result = false;
                            } else {
                                result = r1cs_ppzksnark_online_verifier_weak_input_consistency<CurveType>::process(
                                    processed_verification_key, primary_input, proof);
                            }

                            return result;
                        }
                    };

                    /**
                     * A verifier algorithm for the R1CS ppzkSNARK that:
                     * (1) accepts a non-processed verification key, and
                     * (2) has strong input consistency.
                     */
                    template<typename CurveType>
                    class r1cs_ppzksnark_verifier_strong_input_consistency {
                        using types_policy = detail::r1cs_ppzksnark_types_policy<CurveType>;

                    public:
                        typedef typename types_policy::constraint_system constraint_system_type;
                        typedef typename types_policy::primary_input primary_input_type;
                        typedef typename types_policy::auxiliary_input auxiliary_input_type;

                        typedef typename types_policy::proving_key proving_key_type;
                        typedef typename types_policy::verification_key verification_key_type;
                        typedef typename types_policy::processed_verification_key processed_verification_key_type;

                        typedef typename types_policy::keypair keypair_type;
                        typedef typename types_policy::proof proof_type;

                        static inline bool process(const verification_key_type &verification_key,
                                                   const primary_input_type &primary_input,
                                                   const proof_type &proof) {
                            processed_verification_key_type processed_verification_key =
                                r1cs_ppzksnark_verifier_process_vk<CurveType>::process(verification_key);
                            bool result = r1cs_ppzksnark_online_verifier_strong_input_consistency<CurveType>::process(
                                processed_verification_key, primary_input, proof);
                            return result;
                        }
                    };

                    /**
                     * For debugging purposes (of verifier_component):
                     *
                     * A verifier algorithm for the R1CS ppzkSNARK that:
                     * (1) accepts a non-processed verification key,
                     * (2) has weak input consistency, and
                     * (3) uses affine coordinates for elliptic-curve computations.
                     */
                    template<typename CurveType>
                    class r1cs_ppzksnark_affine_verifier_weak_input_consistency {
                        using types_policy = detail::r1cs_ppzksnark_types_policy<CurveType>;

                        using pairing_policy = typename CurveType::pairing_policy;
                        using g1_type = typename CurveType::g1_type;
                        using g2_type = typename CurveType::g2_type;
                        using gt_type = typename CurveType::gt_type;
                        using g1_value_type = typename g1_type::value_type;
                        using g2_value_type = typename g2_type::value_type;
                        using gt_value_type = typename gt_type::value_type;
                        using scalar_field_type = typename CurveType::scalar_field_type;
                        using G1_precomp = typename pairing_policy::G1_precomp;
                        using G2_precomp = typename pairing_policy::G2_precomp;
                        using affine_ate_G1_precomp = typename pairing_policy::affine_ate_G1_precomp;
                        using affine_ate_G2_precomp = typename pairing_policy::affine_ate_G2_precomp;
                        using Fqk_type = typename pairing_policy::Fqk_type;
                    public:
                        typedef typename types_policy::constraint_system constraint_system_type;
                        typedef typename types_policy::primary_input primary_input_type;
                        typedef typename types_policy::auxiliary_input auxiliary_input_type;

                        typedef typename types_policy::proving_key proving_key_type;
                        typedef typename types_policy::verification_key verification_key_type;
                        typedef typename types_policy::processed_verification_key processed_verification_key_type;

                        typedef typename types_policy::keypair keypair_type;
                        typedef typename types_policy::proof proof_type;

                        static inline bool process(const verification_key_type &vk,
                                                   const primary_input_type &primary_input,
                                                   const proof_type &proof) {
                            typedef typename CurveType::pairing_policy pairing_policy;

                            assert(vk.encoded_IC_query.domain_size() >= primary_input.size());

                            affine_ate_G2_precomp pvk_pp_G2_one_precomp =
                                pairing_policy::affine_ate_precompute_G2(
                                    g2_value_type::one());
                            affine_ate_G2_precomp pvk_vk_alphaA_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.alphaA_g2);
                            affine_ate_G1_precomp pvk_vk_alphaB_g1_precomp =
                                CurveType::affine_ate_precompute_G1(vk.alphaB_g1);
                            affine_ate_G2_precomp pvk_vk_alphaC_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.alphaC_g2);
                            affine_ate_G2_precomp pvk_vk_rC_Z_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.rC_Z_g2);
                            affine_ate_G2_precomp pvk_vk_gamma_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.gamma_g2);
                            affine_ate_G1_precomp pvk_vk_gamma_beta_g1_precomp =
                                CurveType::affine_ate_precompute_G1(vk.gamma_beta_g1);
                            affine_ate_G2_precomp pvk_vk_gamma_beta_g2_precomp =
                                pairing_policy::affine_ate_precompute_G2(vk.gamma_beta_g2);

                            const accumulation_vector<g1_type> accumulated_IC =
                                vk.encoded_IC_query.template accumulate_chunk<scalar_field_type>(
                                    primary_input.begin(), primary_input.end(), 0);
                            assert(accumulated_IC.is_fully_accumulated());
                            const g1_value_type &acc = accumulated_IC.first;

                            bool result = true;
                            affine_ate_G1_precomp proof_g_A_g_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_A.g);
                            affine_ate_G1_precomp proof_g_A_h_precomp =
                                CurveType::affine_ate_precompute_G1(proof.g_A.h);
                            typename Fqk_type::value_type kc_A_miller = CurveType::affine_ate_e_over_e_miller_loop(
                                proof_g_A_g_precomp, pvk_vk_alphaA_g2_precomp, proof_g_A_h_precomp,
                                pvk_pp_G2_one_precomp);
                            gt_value_type kc_A = pairing_policy::final_exponentiation(kc_A_miller);

                            if (kc_A != gt_value_type::one()) {
                                result = false;
                            }

                            affine_ate_G2_precomp proof_g_B_g_precomp =
                                pairing_policy::affine_ate_precompute_G2(proof.g_B.g);
                            affine_ate_G1_precomp proof_g_B_h_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_B.h);
                            typename Fqk_type::value_type kc_B_miller = pairing_policy::affine_ate_e_over_e_miller_loop(
                                pvk_vk_alphaB_g1_precomp, proof_g_B_g_precomp, proof_g_B_h_precomp,
                                pvk_pp_G2_one_precomp);
                            gt_value_type kc_B = pairing_policy::final_exponentiation(kc_B_miller);
                            if (kc_B != gt_value_type::one()) {
                                result = false;
                            }

                            affine_ate_G1_precomp proof_g_C_g_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_C.g);
                            affine_ate_G1_precomp proof_g_C_h_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_C.h);
                            typename Fqk_type::value_type kc_C_miller = 
                                pairing_policy::affine_ate_e_over_e_miller_loop(
                                    proof_g_C_g_precomp, pvk_vk_alphaC_g2_precomp, proof_g_C_h_precomp,
                                    pvk_pp_G2_one_precomp);
                            gt_value_type kc_C = pairing_policy::final_exponentiation(kc_C_miller);
                            if (kc_C != gt_value_type::one()) {
                                result = false;
                            }

                            affine_ate_G1_precomp proof_g_A_g_acc_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_A.g + acc);
                            affine_ate_G1_precomp proof_g_H_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_H);
                            typename Fqk_type::value_type QAP_miller =
                                pairing_policy::affine_ate_e_times_e_over_e_miller_loop(
                                    proof_g_H_precomp, pvk_vk_rC_Z_g2_precomp, proof_g_C_g_precomp,
                                    pvk_pp_G2_one_precomp, proof_g_A_g_acc_precomp, proof_g_B_g_precomp);
                            gt_value_type QAP = pairing_policy::final_exponentiation(QAP_miller);
                            if (QAP != gt_value_type::one()) {
                                result = false;
                            }

                            affine_ate_G1_precomp proof_g_K_precomp =
                                pairing_policy::affine_ate_precompute_G1(proof.g_K);
                            affine_ate_G1_precomp proof_g_A_g_acc_C_precomp =
                                pairing_policy::affine_ate_precompute_G1((proof.g_A.g + acc) + proof.g_C.g);
                            typename Fqk_type::value_type K_miller =
                                pairing_policy::affine_ate_e_times_e_over_e_miller_loop(
                                    proof_g_A_g_acc_C_precomp, pvk_vk_gamma_beta_g2_precomp,
                                    pvk_vk_gamma_beta_g1_precomp, proof_g_B_g_precomp, proof_g_K_precomp,
                                    pvk_vk_gamma_g2_precomp);
                            gt_value_type K = pairing_policy::final_exponentiation(K_miller);
                            if (K != gt_value_type::one()) {
                                result = false;
                            }

                            return result;
                        }
                    };
                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKSNARK_BASIC_VERIFIER_HPP

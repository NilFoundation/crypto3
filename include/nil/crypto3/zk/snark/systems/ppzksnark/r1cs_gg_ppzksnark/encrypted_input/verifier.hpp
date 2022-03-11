//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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
// @file Declaration of interfaces for a ppzkSNARK for BACS.
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
// The implementation is a straightforward combination of:
// (1) a BACS-to-R1CS reduction, and
// (2) a ppzkSNARK for R1CS.
//
//
// Acronyms:
//
// - BACS = "Bilinear Arithmetic Circuit Satisfiability"
// - R1CS = "Rank-1 Constraint System"
// - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_VERIFIER_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_VERIFIER_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/verifier.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename CurveType>
                class r1cs_gg_ppzksnark_verifier_strong_input_consistency<CurveType, proving_mode::encrypted_input> {
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, proving_mode::encrypted_input>
                        policy_type;
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, proving_mode::basic> basic_policy_type;

                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::template g1_type<> g1_type;
                    typedef typename CurveType::template g2_type<> g2_type;
                    typedef typename CurveType::gt_type gt_type;
                    typedef typename pairing::pairing_policy<CurveType>::g1_precomputed_type g1_precomputed_type;
                    typedef typename pairing::pairing_policy<CurveType>::g2_precomputed_type g2_precomputed_type;

                public:
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::proof_type proof_type;

                    // TODO: add type constraints on PublicKey
                    template<typename CipherTextIterator, typename PublicKey>
                    static inline typename std::enable_if<
                        std::is_same<typename g1_type::value_type,
                                     typename std::iterator_traits<CipherTextIterator>::value_type>::value,
                        bool>::type
                        process(CipherTextIterator first, CipherTextIterator last, const verification_key_type &gg_vk,
                                const PublicKey &pubkey, const primary_input_type &unencrypted_primary_input,
                                const proof_type &proof) {

                        const std::size_t input_size = gg_vk.gamma_ABC_g1.rest.size();
                        const std::size_t ct_size = std::distance(first, last);
                        assert(input_size - 1 > ct_size - 2);
                        assert(unencrypted_primary_input.size() + (ct_size - 2) == input_size);
                        assert(ct_size - 2 == pubkey.delta_s_g1.size());
                        assert(ct_size - 2 == pubkey.t_g1.size());
                        assert(ct_size - 2 == pubkey.t_g2.size() - 1);
                        typename g1_type::value_type acc = gg_vk.gamma_ABC_g1.first;
                        typename gt_type::value_type sum_cipher = gt_type::value_type::one();

                        auto it1 = first;
                        auto it2 = std::cbegin(pubkey.t_g2);
                        while (it1 != last - 1 && it2 != std::cend(pubkey.t_g2)) {
                            acc = acc + *it1;
                            sum_cipher = sum_cipher * algebra::pair_reduced<CurveType>(*it1++, *it2++);
                        }
                        assert((it1 == last - 1) && (it2 == std::cend(pubkey.t_g2)));

                        for (std::size_t i = ct_size - 2; i < input_size; ++i) {
                            acc = acc + unencrypted_primary_input[i - ct_size + 2] * gg_vk.gamma_ABC_g1.rest[i];
                        }
                        typename gt_type::value_type presum_cipher =
                            algebra::pair_reduced<CurveType>(*(last - 1), g2_type::value_type::one());
                        bool ans1 = (sum_cipher == presum_cipher);

                        // TODO: optimize
                        typename gt_type::value_type QAPl = algebra::pair_reduced<CurveType>(proof.g_A, proof.g_B);
                        typename gt_type::value_type QAPr = gg_vk.alpha_g1_beta_g2 *
                                                            algebra::pair_reduced<CurveType>(acc, gg_vk.gamma_g2) *
                                                            algebra::pair_reduced<CurveType>(proof.g_C, gg_vk.delta_g2);
                        // const g1_precomputed_type proof_g1_A_precomp = precompute_g1<CurveType>(proof.g_A);
                        // const g2_precomputed_type proof_g2_B_precomp = precompute_g2<CurveType>(proof.g_B);
                        //
                        // const g1_precomputed_type pk_g1_alpha_precomp =
                        //     precompute_g1<CurveType>(gg_keypair.first.alpha_g1);
                        // const g2_precomputed_type pk_g2_beta_precomp =
                        //     precompute_g2<CurveType>(gg_keypair.first.beta_g2);
                        //
                        // const g1_precomputed_type proof_g1_C_precomp = precompute_g1<CurveType>(proof.g_C);
                        // const g2_precomputed_type vk_g2_delta_precomp =
                        //     precompute_g2<CurveType>(gg_keypair.second.delta_g2);
                        //
                        // const g1_precomputed_type proof_g1_cn_precomp = precompute_g1<CurveType>(acc);
                        // const g2_precomputed_type vk_g2_gamma_precomp =
                        //     precompute_g2<CurveType>(gg_keypair.second.gamma_g2);
                        //
                        // typename gt_type::value_type QAPl_1 =
                        //     miller_loop<CurveType>(proof_g1_A_precomp, proof_g2_B_precomp);
                        // typename gt_type::value_type QAPl_2 = double_miller_loop<CurveType>(
                        //     proof_g1_C_precomp, vk_g2_delta_precomp, pk_g1_alpha_precomp, pk_g2_beta_precomp);
                        //
                        // typename gt_type::value_type QAPr_2 =
                        //     miller_loop<CurveType>(proof_g1_cn_precomp, vk_g2_gamma_precomp);
                        //
                        // typename gt_type::value_type QAPl = final_exponentiation<CurveType>(QAPl_1 *
                        // QAPl_2.inversed()); typename gt_type::value_type QAPr =
                        // final_exponentiation<CurveType>(QAPr_2);

                        bool ans2 = (QAPl == QAPr);

                        return (ans1 && ans2);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_VERIFIER_HPP

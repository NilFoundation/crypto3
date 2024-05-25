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

#ifndef CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_PROVER_HPP
#define CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_PROVER_HPP

#include <nil/crypto3/zk/snark/systems/ppzksnark/r1cs_gg_ppzksnark/prover.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /**
                 * A prover algorithm for the R1CS GG-ppzkSNARK.
                 *
                 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
                 * produces a proof (of knowledge) that attests to the following statement:
                 *               ``there exists Y such that CS(X,Y)=0''.
                 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
                 */
                template<typename CurveType>
                class r1cs_gg_ppzksnark_prover<CurveType, proving_mode::encrypted_input> {
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, proving_mode::encrypted_input>
                        policy_type;
                    typedef detail::r1cs_gg_ppzksnark_basic_policy<CurveType, proving_mode::basic> basic_policy_type;
                    typedef r1cs_gg_ppzksnark_prover<CurveType, proving_mode::basic> basic_prover_type;

                    typedef typename CurveType::scalar_field_type scalar_field_type;
                    typedef typename CurveType::template g1_type<> g1_type;
                    typedef typename CurveType::template g2_type<> g2_type;
                    typedef typename CurveType::gt_type gt_type;

                public:
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;
                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    // TODO: add type constraints on PublicKey
                    template<typename PublicKey>
                    static inline proof_type process(const proving_key_type &gg_proving_key,
                                                     const PublicKey &pubkey,
                                                     const primary_input_type &primary_input,
                                                     const auxiliary_input_type &auxiliary_input,
                                                     const typename scalar_field_type::value_type &r) {
                        proof_type proof = basic_prover_type::process(gg_proving_key, primary_input, auxiliary_input);

                        return proof_type(std::move(proof.g_A),
                                          std::move(proof.g_B),
                                          std::move(r * pubkey.gamma_inverse_sum_s_g1 + proof.g_C));
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_R1CS_GG_PPZKSNARK_ENCRYPTED_INPUT_PROVER_HPP

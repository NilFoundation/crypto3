//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_GATES_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_GATES_ARGUMENT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/merkle/tree.hpp>

#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType>
                class redshift_gates_argument {

                static constexpr std::size_t argument_size = 1;

                public:
                    static inline std::array<math::polynomial::polynomial<typename FieldType::value_type>,
                                             argument_size>    // TODO: fix fiat-shamir
                        prove_argument(
                            fiat_shamir_heuristic_updated<hashes::keccak_1600<512>> &transcript,
                            std::size_t circuit_rows,
                            std::size_t permutation_size,
                            std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                            const std::vector<math::polynomial::polynomial<typename FieldType::value_type>> w) {
                        
                        std::array<math::polynomial::polynomial<typename FieldType::value_type>, argument_size> F;
                        
                        return F;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size> verify_argument() {
                        /*typename transcript_hash_type::digest_type beta_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::beta>();

                        typename transcript_hash_type::digest_type gamma_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::gamma>();

                        typename FieldType::value_type beta = algebra::marshalling<FieldType>(beta_bytes);
                        typename FieldType::value_type gamma = algebra::marshalling<FieldType>(gamma_bytes);

                        transcript(proof.P_commitment);
                        transcript(proof.Q_commitment);

                        const math::polynomial::polynomial<typename FieldType::value_type> q_last;
                        const math::polynomial::polynomial<typename FieldType::value_type> q_blind;

                        F[0] = verification_key.L_basis[1] * (P - 1);
                        F[1] = verification_key.L_basis[1] * (Q - 1);
                        F[2] = P * p_1 - (P << 1);*/
                        std::array<typename FieldType::value_type, argument_size> F;

                        return F;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PROVER_HPP
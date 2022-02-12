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
#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/merkle/tree.hpp>

#include <nil/crypto3/zk/snark/transcript/fiat_shamir.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename FieldType,
                         typename TranscriptHashType = hashes::keccak_1600<512>,
                         std::size_t ArgumentSize = 1>
                struct redshift_gates_argument {
                    constexpr static const std::size_t argument_size = ArgumentSize;

                    static inline std::array<math::polynomial<typename FieldType::value_type>, argument_size>
                        prove_eval(const std::vector<math::polynomial<typename FieldType::value_type>> &constraints,
                                   fiat_shamir_heuristic_updated<TranscriptHashType> &transcript,
                                   std::size_t N_sel) {

                        typename FieldType::value_type teta = transcript.template challenge<FieldType>();

                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> F;
                        // std::vector<math::polynomial<typename FieldType::value_type>> gates(N_sel);

                        std::size_t nu = 0;

                        for (std::size_t i = 0; i <= N_sel - 1; i++) {
                            math::polynomial<typename FieldType::value_type> gate = {0};

                            for (std::size_t j = 0; j < constraints.size(); j++) {
                                gate = gate + preprocessed_data.constraints[j] * teta.pow(nu);
                                nu++;
                            }

                            // gate *= preprocessed_data.selectors[i];

                            F[0] += gate;
                        }

                        return F;
                    }

                    static inline std::array<typename FieldType::value_type, argument_size> verify_eval() {
                        /*typename transcript_hash_type::digest_type beta_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::beta>();

                        typename transcript_hash_type::digest_type gamma_bytes =
                            transcript.get_challenge<transcript_manifest::challenges_ids::gamma>();

                        typename FieldType::value_type beta = algebra::marshalling<FieldType>(beta_bytes);
                        typename FieldType::value_type gamma = algebra::marshalling<FieldType>(gamma_bytes);

                        transcript(proof.P_commitment);
                        transcript(proof.Q_commitment);

                        const math::polynomial<typename FieldType::value_type> q_last;
                        const math::polynomial<typename FieldType::value_type> q_blind;

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

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_GATES_ARGUMENT_HPP
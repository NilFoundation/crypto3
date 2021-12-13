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

#ifndef CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP
#define CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /*!
                 * @brief Fiat–Shamir heuristic.
                 * @tparam Hash Hash function, which serves as a non-interactive random oracle.
                 * @tparam TManifest Fiat-Shamir Heuristic Manifest in the following form:
                 * 
                 * template<typename ...>
                 * struct fiat_shamir_heuristic_manifest {
                 *
                 *     struct transcript_manifest {
                 *         std::size_t gammas_amount = 5;
                 *       public:
                 *         enum challenges_ids{
                 *             alpha,
                 *             beta,
                 *             gamma = 10,
                 *             delta = gamma + gammas_amount,
                 *             epsilon
                 *         }
                 *
                 *     }
                 * };
                 */
                template<typename TChallenges, typename Hash = hashes::sha2<256>>
                class fiat_shamir_heuristic {

                    accumulator_set<Hash> acc;
                public:
                    
                    fiat_shamir_heuristic() {
                        acc();
                    }

                    template <typename TAny>
                    void operator() (TAny data){
                        acc(data);
                    }

                    template <typename TChallenges::challenges_ids ChallengeId, typename FieldType>
                    typename Hash::digest_type get_challenge(){
                        acc(ChallengeId);
                        return accumulators::extract::hash<Hash>(acc);
                    }

                    template <typename TChallenges::challenges_ids ChallengeId, std::size_t Index, typename FieldType>
                    typename Hash::digest_type get_challenge(){
                        acc(ChallengeId + Index);
                        return accumulators::extract::hash<Hash>(acc);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP

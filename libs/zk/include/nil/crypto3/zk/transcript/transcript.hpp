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

#ifndef CRYPTO3_ZK_TRANSCRIPT_HPP
#define CRYPTO3_ZK_TRANSCRIPT_HPP

#include <tuple>

namespace nil {
    namespace crypto3 {
        namespace zk {

            /*!
             * @brief Transcript policy. Assumed to be inherited by particular algorithms.
             * @tparam TManifest Transcript Manifest in the following form:
             *
             *
             * class transcript_manifest {
             *
             *  std::size_t gammas_amount = 5;
             *
             *  public:
             *   enum challenges_ids{
             *      alpha,
             *      beta,
             *      gamma = 10,
             *      delta = gamma + gammas_amount,
             *      epsilon
             *   }
             *
             *   typedef std::tuple<...> challenges;
             *   typedef std::tuple<...> processors;
             * };
             *
             * In the case above we have following list of challenges: (\alpha, \beta,
             * \gamma_0, \gamma_1, \gamma_2, \gamma_3, \gamma_4, \delta, \varepsilon)
             *
             */
            template<typename TManifest>
            class transcript {

                typename TManifest::challenges challenges;

                std::size_t next_challenge_id = 0;

            public:
                transcript() {
                }

                transcript(std::tuple<> in_challenges) : challenges(in_challenges) {
                }

                /*!
                 * @brief For ordinary challenges. \alpha
                 * @tparam ChallengeId Ordinary challenge ID. In the example above it's \alpha.
                 *
                 */
                template<typename TManifest::challenges_ids ChallengeId>
                bool set_challenge(std::tuple_element<ChallengeId, typename TManifest::challenges> value) {
                    std::get<ChallengeId>(challenges) = value;

                    return (ChallengeId == next_challenge_id++);
                }

                /*!
                 * @brief For indexed challenges. (\alpha_0, ..., \alpha_n)
                 * @tparam ChallengeId Indexed challenge ID. In the example above it's \alpha.
                 * @tparam Index Index of the particular challenge. In the example above it's \alpha_i.
                 *
                 */
                template<typename TManifest::challenges_ids ChallengeId, std::size_t Index>
                bool set_challenge(
                    std::tuple_element<Index, std::tuple_element<ChallengeId, typename TManifest::challenges>>
                        value) {
                    std::get<Index>(std::get<ChallengeId>(challenges)) = value;

                    return (ChallengeId + Index == next_challenge_id++);
                }

                /*!
                 * @brief For ordinary challenges. \alpha
                 * @tparam ChallengeId Ordinary challenge ID. In the example above it's \alpha.
                 *
                 */
                template<typename TManifest::challenges_ids ChallengeId>
                std::tuple_element<ChallengeId, typename TManifest::challenges> get_challenge() const {
                    return std::get<ChallengeId>(challenges);
                }

                /*!
                 * @brief For indexed challenges. (\alpha_0, ..., \alpha_n)
                 * @tparam ChallengeId Indexed challenge ID. In the example above it's \alpha.
                 * @tparam Index Index of the particular challenge. In the example above it's \alpha_i.
                 *
                 */
                template<typename TManifest::challenges_ids ChallengeId, std::size_t Index>
                std::tuple_element<Index, std::tuple_element<ChallengeId, typename TManifest::challenges>>
                    get_challenge() const {
                    return std::get<Index>(std::get<ChallengeId>(challenges));
                }

                /*!
                 * @brief For ordinary challenges. \alpha
                 * @tparam ChallengeId Ordinary challenge ID. In the example above it's \alpha.
                 *
                 */
                template<typename TManifest::challenges_ids ChallengeId>
                std::tuple_element<ChallengeId, typename TManifest::processors>::result_type
                    get_challenge_result() {
                    return std::tuple_element<ChallengeId, typename TManifest::processors>(
                        get_challenge<ChallengeId>());
                }

                /*!
                 * @brief For indexed challenges. (\alpha_0, ..., \alpha_n)
                 * @tparam ChallengeId Indexed challenge ID. In the example above it's \alpha.
                 * @tparam Index Index of the particular challenge. In the example above it's \alpha_i.
                 *
                 */
                template<typename TManifest::challenges_ids ChallengeId, std::size_t Index>
                std::tuple_element<Index,
                                   std::tuple_element<ChallengeId, typename TManifest::processors>>::result_type
                    get_challenge_result() {
                    return std::tuple_element<Index,
                                              std::tuple_element<ChallengeId, typename TManifest::processors>>(
                        get_challenge<ChallengeId, Index>());
                }
            };
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TRANSCRIPT_HPP

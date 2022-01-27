//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP
#define CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

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
                    fiat_shamir_heuristic() : acc() {
                    }

                    template<typename TAny>
                    void operator()(TAny data) {
                        nil::marshalling::status_type status;
                        typename Hash::construction::type::block_type byte_data = nil::marshalling::pack(data, status);
                        acc(byte_data);
                    }

                    template<typename TChallenges::challenges_ids ChallengeId, typename FieldType>
                    typename FieldType::value_type get_challenge() {
                        // acc(ChallengeId);
                        typename Hash::digest_type hash_res = accumulators::extract::hash<Hash>(acc);

                        return FieldType::value_type::one();
                    }

                    template<typename TChallenges::challenges_ids ChallengeId, std::size_t Index, typename FieldType>
                    typename FieldType::value_type get_challenge() {
                        // acc(ChallengeId + Index);
                        typename Hash::digest_type hash_res = accumulators::extract::hash<Hash>(acc);

                        return FieldType::value_type::one();
                    }

                    template<typename TChallenges::challenges_ids ChallengeId, std::size_t ChallengesAmount,
                             typename FieldType>
                    std::array<typename FieldType::value_type, ChallengesAmount> get_challenges() {

                        std::array<typename Hash::digest_type, ChallengesAmount> hash_results;
                        std::array<typename FieldType::value_type, ChallengesAmount> result;

                        for (std::size_t i = 0; i < ChallengesAmount; i++) {

                            // acc(ChallengeId + i);
                            hash_results[i] = accumulators::extract::hash<Hash>(acc);
                        }

                        return result;
                    }
                };

                template<typename Hash = hashes::keccak_1600<256>>
                struct fiat_shamir_heuristic_updated {
                    typedef Hash hash_type;

                    template<typename InputRange>
                    fiat_shamir_heuristic_updated(const InputRange &r) : state(hash<hash_type>(r)) {
                    }

                    template<typename InputIterator>
                    fiat_shamir_heuristic_updated(InputIterator first, InputIterator last) :
                        state(hash<hash_type>(first, last)) {
                    }

                    template<typename InputRange>
                    void operator()(const InputRange &r) {
                        auto acc_convertible = hash<hash_type>(state);
                        state = accumulators::extract::hash<hash_type>(
                            hash<hash_type>(r, static_cast<accumulator_set<hash_type> &>(acc_convertible)));
                    }

                    template<typename InputIterator>
                    void operator()(InputIterator first, InputIterator last) {
                        auto acc_convertible = hash<hash_type>(state);
                        state = accumulators::extract::hash<hash_type>(
                            hash<hash_type>(first, last, static_cast<accumulator_set<hash_type> &>(acc_convertible)));
                    }

                    template<typename Field>
                    typename std::enable_if<(Hash::digest_bits >= Field::modulus_bits),
                                            typename Field::value_type>::type
                        get_challenge() {

                        state = hash<hash_type>(state);
                        nil::marshalling::status_type status;
                        nil::crypto3::multiprecision::cpp_int raw_result = nil::marshalling::pack(state, status);

                        return raw_result;
                    }

                    template<typename Field, std::size_t N>
                    typename std::enable_if<(Hash::digest_bits >= Field::modulus_bits),
                                            std::array<typename Field::value_type, N>>::type
                        get_challenges() {

                        std::array<typename Field::value_type, N> result;
                        for (auto &ch : result) {
                            ch = get_challenge<Field>();
                        }

                        return result;
                    }

                private:
                    typename hash_type::digest_type state;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TRANSCRIPT_FIAT_SHAMIR_HEURISTIC_HPP
